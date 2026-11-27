//! QR-assisted cable-free RemotePairing (device-initiated "Paired Macs", iOS 27+).
//!
//! Implements the responder side of pymobiledevice3's `serve_pairable_host`: advertise
//! `_remotepairing-pairable-host._tcp`, accept one device-initiated `RPPairing` connection,
//! run SRP pair-setup M1-M6, and persist a pairing record the existing Wi-Fi tunnel can read.
//! Also exposes an AirPlay-only onboarding QR mode (no SRP, no extra listener).
//!
//! Everything is pure std + existing crate helpers. No new runtime process, no cloud, no PIN logging.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::pair_qr_crypto::{
    opack_build_host_identity, opack_parse_identity, tlv_build, tlv_parse, PeerIdentity, SrpServer,
};
use crate::rp_wifi_tls::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, ed25519_public_from_seed, ed25519_sign,
};
use crate::wifi::{
    compute_auth_tag, host_alt_irk_path, host_identifier, hostname, load_or_create_host_alt_irk,
    safe_record_id, save_remote_record_ext, RecordExtra,
};
use crate::win_cng::{fill_random, hkdf_sha512_32};

/// Session lifetime. Builder may tune without changing the design.
pub const QR_SESSION_SECS: u64 = 180;
const PAIRABLE_HOST_SERVICE: &str = "_remotepairing-pairable-host._tcp.local.";
const PAIRABLE_HOST_MODEL: &str = "Mac17,7";
const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairQrMode {
    PairedMacs,
    AirPlayOnly,
}

impl PairQrMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PairQrMode::PairedMacs => "paired_macs",
            PairQrMode::AirPlayOnly => "airplay_only",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "paired_macs" | "paired-macs" | "ios27" => Some(PairQrMode::PairedMacs),
            "airplay_only" | "airplay-only" | "airplay" => Some(PairQrMode::AirPlayOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum PairQrSession {
    #[default]
    Idle,
    Advertising {
        pin: Option<String>,
        identifier: String,
        host_name: String,
        lan_ip: String,
        http_port: u16,
        pair_port: Option<u16>,
        mode: PairQrMode,
        started_epoch: u64,
        expires_epoch: u64,
    },
    Paired {
        udid: String,
        name: String,
        device_ip: String,
        record_path: String,
        mode: PairQrMode,
    },
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct PairQrSessionInfo {
    pub ok: bool,
    pub mode: PairQrMode,
    pub pin: Option<String>,
    pub identifier: String,
    pub host_name: String,
    pub lan_ip: String,
    /// Port of the local HTTP server that serves the `/q` landing page.
    pub port: u16,
    /// Ephemeral binary `RPPairing` listener advertised over mDNS; `None` in AirPlay-only mode.
    pub pair_port: Option<u16>,
    pub expires_in: u64,
    pub qr_url: String,
}

impl PairQrSessionInfo {
    pub fn to_json(&self) -> String {
        json!({
            "ok": self.ok,
            "mode": self.mode.as_str(),
            "pin": self.pin,
            "identifier": self.identifier,
            "host_name": self.host_name,
            "lan_ip": self.lan_ip,
            "port": self.port,
            "pair_port": self.pair_port,
            "expires_in": self.expires_in,
            "qr_url": self.qr_url,
        })
        .to_string()
    }
}

#[derive(Clone, Debug)]
pub struct QrPageInfo {
    pub mode: PairQrMode,
    pub pin: Option<String>,
    pub host_name: String,
    pub identifier: String,
}

#[derive(Default)]
struct SessionState {
    session: PairQrSession,
    cancel: Option<Arc<AtomicBool>>,
    /// Incremented on every `start()` so an old worker cannot clobber a newer session.
    generation: u64,
    page_token: String,
    page_identifier: String,
    page_mode: Option<PairQrMode>,
    page_expires_epoch: u64,
}

static STATE: OnceLock<Mutex<SessionState>> = OnceLock::new();

fn state() -> &'static Mutex<SessionState> {
    STATE.get_or_init(|| {
        Mutex::new(SessionState {
            session: PairQrSession::Idle,
            cancel: None,
            generation: 0,
            page_token: String::new(),
            page_identifier: String::new(),
            page_mode: None,
            page_expires_epoch: 0,
        })
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Start (or restart) a QR pairing session. Starting a new session cancels the previous one.
///
/// `http_port` is the port of the local HTTP server that serves `/q`; the QR URL must use it.
/// The binary `RPPairing` listener gets its own ephemeral port and is advertised over mDNS only.
pub fn start_qr_pairing(mode: PairQrMode, http_port: u16) -> Result<PairQrSessionInfo, String> {
    // Cancel any previous session first.
    {
        let mut guard = state().lock().map_err(|e| format!("state lock: {e}"))?;
        if let Some(flag) = guard.cancel.take() {
            flag.store(true, Ordering::SeqCst);
        }
        guard.generation = guard.generation.wrapping_add(1);
        guard.session = PairQrSession::Idle;
    }

    let host_name = hostname();
    let identifier = host_identifier(&host_name);
    let host_alt_irk = load_or_create_host_alt_irk()?;
    let lan_ip = detect_lan_ipv4();
    let started = now_secs();
    let expires = started.saturating_add(QR_SESSION_SECS);
    let cancel = Arc::new(AtomicBool::new(false));
    let generation = state()
        .lock()
        .map(|g| g.generation)
        .map_err(|e| format!("state lock: {e}"))?;

    let (pin, token, pair_port, listener) = match mode {
        PairQrMode::PairedMacs => {
            let pin = random_pin()?;
            let listener = TcpListener::bind("0.0.0.0:0")
                .map_err(|e| format!("bind pairable-host listener: {e}"))?;
            listener
                .set_nonblocking(true)
                .map_err(|e| format!("set nonblocking: {e}"))?;
            let pair_port = listener
                .local_addr()
                .map_err(|e| format!("listener addr: {e}"))?
                .port();
            (Some(pin.clone()), pin, Some(pair_port), Some(listener))
        }
        PairQrMode::AirPlayOnly => {
            let token = random_hex(16)?;
            (None, token, None, None)
        }
    };

    let qr_url = format!(
        "http://{}:{}/q?i={}&c={}&m={}",
        lan_ip,
        http_port,
        percent_encode(&identifier),
        percent_encode(&token),
        mode.as_str()
    );

    let mdns_port = if mode == PairQrMode::PairedMacs {
        pair_port.ok_or_else(|| "missing pairable-host port".to_string())?
    } else {
        http_port
    };

    {
        let mut guard = state().lock().map_err(|e| format!("state lock: {e}"))?;
        guard.cancel = Some(cancel.clone());
        guard.page_token = token;
        guard.page_identifier = identifier.clone();
        guard.page_mode = Some(mode);
        guard.page_expires_epoch = expires;
        guard.session = PairQrSession::Advertising {
            pin: pin.clone(),
            identifier: identifier.clone(),
            host_name: host_name.clone(),
            lan_ip: lan_ip.clone(),
            http_port,
            pair_port,
            mode,
            started_epoch: started,
            expires_epoch: expires,
        };
    }

    if mode == PairQrMode::PairedMacs {
        // The TXT record carries the base64 form of the 6-byte auth tag.
        let auth_tag_bytes = compute_auth_tag(&host_alt_irk, &identifier);
        let auth_tag = base64_encode(&auth_tag_bytes);
        let txt = vec![
            ("name".to_string(), host_name.clone()),
            ("identifier".to_string(), identifier.clone()),
            ("authTag".to_string(), auth_tag),
            ("model".to_string(), PAIRABLE_HOST_MODEL.to_string()),
            ("flags".to_string(), "1".to_string()),
            ("ver".to_string(), "26".to_string()),
            ("minVer".to_string(), "17".to_string()),
        ];
        let mdns_cancel = cancel.clone();
        let mdns_host = host_name.clone();
        let mdns_ident = identifier.clone();
        let mdns_lan_ip = lan_ip.clone();
        std::thread::Builder::new()
            .name("pair-qr-mdns".to_string())
            .spawn(move || {
                serve_mdns(
                    mdns_cancel,
                    txt,
                    mdns_port,
                    &mdns_lan_ip,
                    &mdns_host,
                    &mdns_ident,
                    expires,
                );
            })
            .map_err(|e| format!("spawn mDNS: {e}"))
            .map_err(|e| {
                let _ = cancel_qr_pairing();
                e
            })?;

        if let Some(listener) = listener {
            let pin_for_worker = pin.clone().unwrap_or_default();
            let worker_cancel = cancel.clone();
            let guard_cancel = cancel.clone();
            let worker_ident = identifier.clone();
            let worker_host = host_name.clone();
            std::thread::Builder::new()
                .name("pair-qr-worker".to_string())
                .spawn(move || {
                    let result = accept_and_pair(
                        listener,
                        worker_cancel.clone(),
                        pin_for_worker,
                        worker_ident,
                        worker_host,
                        host_alt_irk,
                        expires,
                    );
                    if worker_cancel.load(Ordering::SeqCst) {
                        return;
                    }
                    let mut guard = match state().lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    // A restarted session owns the state now; never publish a stale result.
                    if guard.generation != generation
                        || guard
                            .cancel
                            .as_ref()
                            .map(|c| !Arc::ptr_eq(c, &guard_cancel))
                            .unwrap_or(true)
                    {
                        return;
                    }
                    guard.session = match result {
                        Ok(paired) => paired,
                        Err(e) => PairQrSession::Failed(e),
                    };
                    guard.cancel = None;
                })
                .map_err(|e| format!("spawn pairing worker: {e}"))
                .map_err(|e| {
                    let _ = cancel_qr_pairing();
                    e
                })?;
        }
    }

    Ok(PairQrSessionInfo {
        ok: true,
        mode,
        pin,
        identifier,
        host_name,
        lan_ip,
        port: http_port,
        pair_port,
        expires_in: QR_SESSION_SECS,
        qr_url,
    })
}

/// Cancel the active session and clear the setup PIN from memory.
pub fn cancel_qr_pairing() -> bool {
    let mut guard = match state().lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    if let Some(flag) = guard.cancel.take() {
        flag.store(true, Ordering::SeqCst);
    }
    guard.session = PairQrSession::Idle;
    guard.page_token.clear();
    guard.page_identifier.clear();
    guard.page_mode = None;
    guard.page_expires_epoch = 0;
    true
}

pub fn current_session() -> PairQrSession {
    state()
        .lock()
        .map(|g| g.session.clone())
        .unwrap_or(PairQrSession::Failed("state lock poisoned".to_string()))
}

pub fn status_json() -> String {
    let snap = current_session();
    match snap {
        PairQrSession::Idle => json!({"ok": true, "state": "idle"}).to_string(),
        PairQrSession::Advertising {
            pin,
            identifier,
            host_name,
            lan_ip,
            http_port,
            pair_port,
            mode,
            started_epoch,
            expires_epoch,
        } => json!({
            "ok": true,
            "state": "advertising",
            "mode": mode.as_str(),
            "pin": pin,
            "identifier": identifier,
            "host_name": host_name,
            "lan_ip": lan_ip,
            "port": http_port,
            "pair_port": pair_port,
            "expires_in": expires_epoch.saturating_sub(now_secs()),
            "started_epoch": started_epoch,
        })
        .to_string(),
        PairQrSession::Paired {
            udid,
            name,
            device_ip,
            record_path,
            mode,
        } => json!({
            "ok": true,
            "state": "paired",
            "mode": mode.as_str(),
            "udid": udid,
            "name": name,
            "device_ip": device_ip,
            "record_path": record_path,
        })
        .to_string(),
        PairQrSession::Failed(e) => json!({"ok": false, "state": "failed", "error": e}).to_string(),
    }
}

/// Validate the narrow LAN `/q` page token. Never exposes anything to loopback-unauthorized paths.
pub fn qr_page_info(identifier: &str, token: &str, mode: &str) -> Option<QrPageInfo> {
    let requested = PairQrMode::parse(mode)?;
    let guard = state().lock().ok()?;
    if now_secs() >= guard.page_expires_epoch {
        return None;
    }
    if guard.page_identifier != identifier
        || guard.page_token.is_empty()
        || guard.page_token != token
        || guard.page_mode != Some(requested)
    {
        return None;
    }
    let (pin, host_name) = match &guard.session {
        PairQrSession::Advertising { pin, host_name, .. } => (pin.clone(), host_name.clone()),
        _ => return None,
    };
    Some(QrPageInfo {
        mode: requested,
        pin,
        host_name,
        identifier: identifier.to_string(),
    })
}

/// Render the QR image for the Slint UI.
pub fn qr_rgba_for_url(url: &str) -> Result<(Vec<u8>, u32, u32), String> {
    let matrix = crate::pair_qr_qr::encode_qr(url)?;
    crate::pair_qr_qr::qr_to_rgba(&matrix, 4, 4)
}

// ------------------------------ pairing worker ------------------------------

fn accept_and_pair(
    listener: TcpListener,
    cancel: Arc<AtomicBool>,
    pin: String,
    identifier: String,
    host_name: String,
    host_alt_irk: [u8; 16],
    expires_epoch: u64,
) -> Result<PairQrSession, String> {
    let deadline = Instant::now() + Duration::from_secs(QR_SESSION_SECS.max(1));
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".to_string());
        }
        if Instant::now() >= deadline || now_secs() >= expires_epoch {
            return Err("QR pairing session expired".to_string());
        }
        match listener.accept() {
            Ok((s, peer)) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(12)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(12)));
                let device_ip = match peer.ip() {
                    IpAddr::V4(v4) => v4.to_string(),
                    IpAddr::V6(v6) => v6.to_string(),
                };
                let mut s = s;
                match device_initiated_pair_setup(
                    &mut s,
                    &pin,
                    &identifier,
                    &host_name,
                    &host_alt_irk,
                    cancel.clone(),
                    deadline,
                ) {
                    Ok((udid, name)) => {
                        let record_id = if udid.is_empty() {
                            "device".to_string()
                        } else {
                            safe_record_id(&udid)
                        };
                        let record_path = host_alt_irk_path()
                            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                            .unwrap_or_default()
                            .join(format!("remote_{record_id}.plist"))
                            .to_string_lossy()
                            .to_string();
                        return Ok(PairQrSession::Paired {
                            udid,
                            name,
                            device_ip,
                            record_path,
                            mode: PairQrMode::PairedMacs,
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("accept device: {e}")),
        }
    }
}

fn device_initiated_pair_setup(
    stream: &mut TcpStream,
    pin: &str,
    identifier: &str,
    host_name: &str,
    host_alt_irk: &[u8; 16],
    cancel: Arc<AtomicBool>,
    deadline: Instant,
) -> Result<(String, String), String> {
    let mut seq = 0u64;

    // Handshake: device must ask for pair-setup, not pair-verify.
    let request = recv_frame(stream, &cancel, deadline)?;
    let handshake = jget(&request, &["request", "_0", "handshake", "_0"])
        .ok_or_else(|| "device sent no handshake".to_string())?;
    if jget(handshake, &["hostOptions", "attemptPairVerify"])
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("device requested pair-verify; only new pairing is supported".to_string());
    }
    let response = json!({
        "response": {
            "forRequestIdentifier": 0,
            "_1": {
                "handshake": {"_0": {
                    "wireProtocolVersion": 26,
                    "minimumSupportedWireProtocolVersion": 8,
                    "deviceOptions": {
                        "allowsPairSetup": true,
                        "allowsPinlessPairing": false,
                        "allowsIncomingTunnelConnections": false,
                        "allowsUpgradeOfLockdownPairings": false,
                        "allowsSharingSensitiveInfo": false
                    },
                    "peerDeviceInfo": {
                        "udid": "",
                        "deviceKVSIncludesSensitiveInfo": false,
                        "identifier": identifier,
                        "name": host_name,
                        "model": PAIRABLE_HOST_MODEL
                    }
                }}
            }
        }
    });
    send_frame(stream, &response, &mut seq, &cancel, deadline)?;

    // M1.
    let m1 = tlv_parse(&recv_pairing_data(stream, &mut seq, &cancel, deadline)?);
    ensure_no_error(&m1, "M1")?;
    expect_state(&m1, 1)?;

    // M2: salt + server public (regenerate until the device-sized 384-byte value appears).
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    salt[0] |= 0x80;
    let mut srp = None;
    for _ in 0..16 {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".to_string());
        }
        let candidate = SrpServer::new(pin, &salt)?;
        if candidate.public_bytes().len() == 384 {
            srp = Some(candidate);
            break;
        }
    }
    let srp = srp.ok_or_else(|| "could not generate SRP server public key".to_string())?;
    let server_public = srp.public_bytes();
    send_pairing_data(
        stream,
        &mut seq,
        &tlv_build(&[
            (0x06, vec![2]),
            (0x02, salt.to_vec()),
            (0x03, server_public),
        ]),
        &cancel,
        deadline,
    )?;

    // M3: client public + proof.
    let m3 = tlv_parse(&recv_pairing_data(stream, &mut seq, &cancel, deadline)?);
    ensure_no_error(&m3, "M3")?;
    expect_state(&m3, 3)?;
    let client_public = m3
        .get(&0x03)
        .cloned()
        .ok_or_else(|| "M3 missing client public key".to_string())?;
    let client_proof = m3
        .get(&0x04)
        .cloned()
        .ok_or_else(|| "M3 missing client proof".to_string())?;
    let mut srp = srp;
    srp.process(&client_public)?;
    if !srp.verify_client_proof(&client_proof) {
        // Match pairing-standard M4 error response instead of dropping the connection.
        send_pairing_data(
            stream,
            &mut seq,
            &tlv_build(&[(0x06, vec![4]), (0x07, vec![2])]),
            &cancel,
            deadline,
        )?;
        return Err("PIN did not match (SRP proof verification failed)".to_string());
    }

    // M4: server proof.
    send_pairing_data(
        stream,
        &mut seq,
        &tlv_build(&[(0x06, vec![4]), (0x04, srp.server_proof().to_vec())]),
        &cancel,
        deadline,
    )?;

    let session_key = srp.session_key();
    let setup_key = hkdf_sha512_32(
        &session_key,
        b"Pair-Setup-Encrypt-Salt",
        b"Pair-Setup-Encrypt-Info",
    );

    // M5: device identity (encrypted TLV).
    let m5 = tlv_parse(&recv_pairing_data(stream, &mut seq, &cancel, deadline)?);
    ensure_no_error(&m5, "M5")?;
    expect_state(&m5, 5)?;
    let encrypted = m5
        .get(&0x05)
        .cloned()
        .ok_or_else(|| "M5 missing encrypted data".to_string())?;
    let m5_plain = chacha20_poly1305_decrypt(&setup_key, &ps_nonce("PS-Msg05"), &encrypted, &[])?;
    let device_tlv = tlv_parse(&m5_plain);
    let info = device_tlv
        .get(&0x11)
        .ok_or_else(|| "M5 identity missing INFO".to_string())?;
    let peer: PeerIdentity = opack_parse_identity(info)?;

    // M6: our accessory identity.
    let accessory_x = hkdf_sha512_32(
        &session_key,
        b"Pair-Setup-Accessory-Sign-Salt",
        b"Pair-Setup-Accessory-Sign-Info",
    );
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    let ltpk = ed25519_public_from_seed(&seed);
    let mut sign_buf = Vec::with_capacity(32 + identifier.len() + 32);
    sign_buf.extend_from_slice(&accessory_x);
    sign_buf.extend_from_slice(identifier.as_bytes());
    sign_buf.extend_from_slice(&ltpk);
    let signature = ed25519_sign(&seed, &sign_buf);
    let host_info =
        opack_build_host_identity(identifier, host_alt_irk, PAIRABLE_HOST_MODEL, host_name, "");
    let m6_plain = tlv_build(&[
        (0x01, identifier.as_bytes().to_vec()),
        (0x03, ltpk.to_vec()),
        (0x0A, signature.to_vec()),
        (0x11, host_info),
    ]);
    let m6_cipher = chacha20_poly1305_encrypt(&setup_key, &ps_nonce("PS-Msg06"), &m6_plain, &[]);
    send_pairing_data(
        stream,
        &mut seq,
        &tlv_build(&[(0x05, m6_cipher), (0x06, vec![6])]),
        &cancel,
        deadline,
    )?;

    ensure_session_alive(&cancel, deadline)?;
    // Persist in the exact layout our tunnel readers expect.
    let key_udid = if peer.udid.is_empty() {
        peer.account_id.clone()
    } else {
        peer.udid.clone()
    };
    let extra = RecordExtra {
        host_identifier: identifier.to_string(),
        host_alt_irk: *host_alt_irk,
        peer_udid: peer.udid.clone(),
        peer_model: peer.model.clone(),
        peer_name: peer.name.clone(),
    };
    let _written = save_remote_record_ext(&key_udid, &peer.alt_irk, &seed, &ltpk, &extra)?;
    Ok((key_udid, peer.name))
}

fn expect_state(tlv: &BTreeMap<u8, Vec<u8>>, expected: u8) -> Result<(), String> {
    match tlv.get(&0x06).and_then(|v| v.first()) {
        Some(v) if *v == expected => Ok(()),
        other => Err(format!(
            "pairing steps out of order: expected {expected}, got {other:?}"
        )),
    }
}

fn ensure_no_error(tlv: &BTreeMap<u8, Vec<u8>>, stage: &str) -> Result<(), String> {
    match tlv.get(&0x07).and_then(|v| v.first()) {
        Some(code) => Err(format!("device reported pairing error {code} in {stage}")),
        None => Ok(()),
    }
}

fn ensure_session_alive(cancel: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) {
        return Err("cancelled".to_string());
    }
    if Instant::now() >= deadline {
        return Err("QR pairing session expired".to_string());
    }
    Ok(())
}

fn ps_nonce(label: &str) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(label.as_bytes());
    nonce
}

fn jget<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let mut cur = value;
    for key in keys {
        cur = cur.get(*key)?;
    }
    Some(cur)
}

fn send_frame(
    stream: &mut TcpStream,
    value: &Value,
    seq: &mut u64,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(), String> {
    ensure_session_alive(cancel, deadline)?;
    // `RPPairing` frames carry a `RemotePairing.ControlChannelMessageEnvelope`. The
    // responder (us) sends `originatedBy: "device"`; the plain request lives under
    // `message.plain._0` exactly like pymobiledevice3's `PairableHost._send_plain`.
    let envelope = json!({
        "message": {"plain": {"_0": value}},
        "originatedBy": "device",
        "sequenceNumber": *seq,
    });
    *seq = seq.wrapping_add(1);
    let body = serde_json::to_vec(&envelope).map_err(|e| format!("json encode: {e}"))?;
    if body.len() > u16::MAX as usize {
        return Err("pairing frame too large".to_string());
    }
    let mut frame = Vec::with_capacity(10 + body.len());
    frame.extend_from_slice(b"RPPairing");
    frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
    frame.extend_from_slice(&body);
    stream
        .write_all(&frame)
        .map_err(|e| format!("send pairing frame: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))
}

fn read_exact_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        ensure_session_alive(cancel, deadline)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("QR pairing session expired".to_string());
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_secs(12))))
            .map_err(|e| format!("set pairing read timeout: {e}"))?;
        match stream.read_exact(buf) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read pairing frame: {e}")),
        }
    }
}

fn recv_frame(
    stream: &mut TcpStream,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Value, String> {
    let mut magic = [0u8; 9];
    read_exact_deadline(stream, &mut magic, cancel, deadline)?;
    if &magic != b"RPPairing" {
        return Err("unexpected pairing frame magic".to_string());
    }
    let mut len_bytes = [0u8; 2];
    read_exact_deadline(stream, &mut len_bytes, cancel, deadline)?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    let mut body = vec![0u8; len];
    read_exact_deadline(stream, &mut body, cancel, deadline)?;
    let envelope: Value =
        serde_json::from_slice(&body).map_err(|e| format!("bad pairing JSON: {e}"))?;
    jget(&envelope, &["message", "plain", "_0"])
        .cloned()
        .ok_or_else(|| "pairing frame has no plain message".to_string())
}

fn send_pairing_data(
    stream: &mut TcpStream,
    seq: &mut u64,
    data: &[u8],
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<(), String> {
    let event = json!({
        "event": {"_0": {"pairingData": {"_0": {
            "data": base64_encode(data),
            "startNewSession": false,
            "kind": "setupManualPairing"
        }}}}
    });
    send_frame(stream, &event, seq, cancel, deadline)
}

fn recv_pairing_data(
    stream: &mut TcpStream,
    seq: &mut u64,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let _ = seq; // sequence numbers advance only when this side sends a frame
    let response = recv_frame(stream, cancel, deadline)?;
    let event =
        jget(&response, &["event", "_0"]).ok_or_else(|| "unexpected pairing reply".to_string())?;
    if let Some(data) = jget(event, &["pairingData", "_0", "data"]).and_then(Value::as_str) {
        return base64_decode(data);
    }
    if let Some(reason) = jget(
        event,
        &[
            "pairingRejectedWithError",
            "wrappedError",
            "userInfo",
            "NSLocalizedDescription",
        ],
    )
    .and_then(Value::as_str)
    {
        return Err(format!("device rejected pairing: {reason}"));
    }
    Err("device sent an unexpected pairing message".to_string())
}

// ------------------------------ mDNS responder ------------------------------

fn serve_mdns(
    stop: Arc<AtomicBool>,
    txt: Vec<(String, String)>,
    port: u16,
    lan_ip: &str,
    host_name: &str,
    identifier: &str,
    expires_epoch: u64,
) {
    if crate::connection::is_loopback_only_test_mode() {
        return;
    }
    let Ok(ip) = lan_ip.parse::<Ipv4Addr>() else {
        return;
    };
    let sock = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED);
    let _ = sock.join_multicast_v4(&MDNS_ADDR, &ip);
    let _ = sock.set_multicast_ttl_v4(255);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
    let target = dns_labels(&format!("{}.local.", dns_safe_label(host_name)));
    let instance = format!("{identifier}.{PAIRABLE_HOST_SERVICE}");
    let mut response = build_mdns_response(120, &txt, port, ip, &target, &instance);
    response.goodbye = build_mdns_response(0, &txt, port, ip, &target, &instance).answer_bytes;

    // Unsolicited announcements help the phone's Paired Macs browse find us promptly.
    for _ in 0..3 {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let _ = sock.send_to(&response.full(0), SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
        std::thread::sleep(Duration::from_millis(300));
    }

    let mut buf = [0u8; 4096];
    while !stop.load(Ordering::SeqCst) && now_secs() < expires_epoch {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let lower: Vec<u8> = buf[..n].iter().map(|b| b.to_ascii_lowercase()).collect();
                if find_bytes(&lower, b"_remotepairing-pairable-host") {
                    let query_id = if n >= 2 {
                        u16::from_be_bytes([buf[0], buf[1]])
                    } else {
                        0
                    };
                    let _ = sock.send_to(&response.full(query_id), peer);
                }
            }
            Err(_) => continue,
        }
    }
    let _ = sock.send_to(&response.goodbye, SocketAddrV4::new(MDNS_ADDR, MDNS_PORT));
}

struct MdnsResponse {
    header_tail: [u8; 10],
    answer_bytes: Vec<u8>,
    goodbye: Vec<u8>,
}

impl MdnsResponse {
    fn full(&self, id: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.answer_bytes.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&self.header_tail);
        out.extend_from_slice(&self.answer_bytes);
        out
    }
}

fn build_mdns_response(
    ttl: u32,
    txt: &[(String, String)],
    port: u16,
    ip: Ipv4Addr,
    target: &[u8],
    instance: &str,
) -> MdnsResponse {
    let service_labels = dns_labels(PAIRABLE_HOST_SERVICE);
    let instance_labels = dns_labels(instance);
    let mut answers = Vec::new();
    answers.extend(dns_answer(&service_labels, 12, ttl, &instance_labels));
    let mut srv = Vec::with_capacity(6 + target.len());
    srv.extend_from_slice(&0u16.to_be_bytes());
    srv.extend_from_slice(&0u16.to_be_bytes());
    srv.extend_from_slice(&port.to_be_bytes());
    srv.extend_from_slice(target);
    answers.extend(dns_answer(&instance_labels, 33, ttl, &srv));
    let mut txt_rdata = Vec::new();
    for (k, v) in txt {
        let mut item = format!("{k}={v}").into_bytes();
        if item.len() > 255 {
            item.truncate(255);
        }
        txt_rdata.push(item.len() as u8);
        txt_rdata.extend_from_slice(&item);
    }
    answers.extend(dns_answer(&instance_labels, 16, ttl, &txt_rdata));
    answers.extend(dns_answer(target, 1, ttl, &ip.octets()));
    MdnsResponse {
        header_tail: [
            0x84, 0x00, // response + authoritative
            0x00, 0x00, // QDCOUNT
            0x00, 0x04, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ],
        answer_bytes: answers,
        goodbye: Vec::new(),
    }
}

fn dns_answer(name: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + 10 + rdata.len());
    out.extend_from_slice(name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn dns_labels(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let safe = dns_safe_label(label);
        if safe.is_empty() {
            continue;
        }
        out.push(safe.len() as u8);
        out.extend_from_slice(safe.as_bytes());
    }
    out.push(0);
    out
}

fn dns_safe_label(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

// ------------------------------ small helpers ------------------------------

fn detect_lan_ipv4() -> String {
    if crate::connection::is_loopback_only_test_mode() {
        return "127.0.0.1".to_string();
    }
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip().to_string();
                if !ip.starts_with("127.") && !ip.starts_with("169.254.") && ip != "0.0.0.0" {
                    return ip;
                }
            }
        }
    }
    "127.0.0.1".to_string()
}

fn random_pin() -> Result<String, String> {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes)?;
    let n = u64::from_le_bytes(bytes) % 1_000_000;
    Ok(format!("{n:06}"))
}

fn random_hex(len: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; len];
    fill_random(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn base64_decode(data: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => None,
            _ => None,
        }
    }
    let bytes = data.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = val(chunk[0]).ok_or_else(|| "invalid base64 byte".to_string())? as u32;
        let b = val(chunk[1]).ok_or_else(|| "invalid base64 byte".to_string())? as u32;
        let c = val(chunk[2]).unwrap_or(0) as u32;
        let d = val(chunk[3]).unwrap_or(0) as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            out.push((n >> 8) as u8);
        }
        if chunk[3] != b'=' {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_STATE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_pair_qr_base64_roundtrip() {
        for input in [
            b"".as_slice(),
            b"a".as_slice(),
            b"ab".as_slice(),
            b"abc".as_slice(),
            b"abcd".as_slice(),
        ] {
            let encoded = base64_encode(input);
            assert_eq!(base64_decode(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn test_pair_qr_mode_parse() {
        assert_eq!(
            PairQrMode::parse("paired_macs"),
            Some(PairQrMode::PairedMacs)
        );
        assert_eq!(
            PairQrMode::parse("airplay-only"),
            Some(PairQrMode::AirPlayOnly)
        );
        assert_eq!(PairQrMode::parse("bogus"), None);
    }

    #[test]
    fn test_pair_qr_tlv_chunking_and_merge() {
        let data = vec![7u8; 600];
        let encoded = tlv_build(&[(0x05, data.clone())]);
        let parsed = tlv_parse(&encoded);
        assert_eq!(parsed.get(&0x05), Some(&data));
    }

    #[test]
    fn test_pair_qr_error_tlv_is_detected() {
        let tlv = tlv_parse(&tlv_build(&[(0x06, vec![4]), (0x07, vec![2])]));
        assert!(ensure_no_error(&tlv, "M3").is_err());
        assert!(ensure_no_error(&tlv_parse(&tlv_build(&[(0x06, vec![3])])), "M3").is_ok());
    }

    #[test]
    fn test_pair_qr_page_token_rejects_unknown() {
        let _guard = TEST_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(qr_page_info("nope", "nope", "paired_macs").is_none());
    }

    #[test]
    fn test_pair_qr_page_token_valid_then_expired() {
        let _guard = TEST_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut guard = state().lock().unwrap();
            guard.page_token = "abc123".to_string();
            guard.page_identifier = "host-id".to_string();
            guard.page_mode = Some(PairQrMode::PairedMacs);
            guard.page_expires_epoch = now_secs() + 60;
            guard.session = PairQrSession::Advertising {
                pin: Some("123456".to_string()),
                identifier: "host-id".to_string(),
                host_name: "Desk".to_string(),
                lan_ip: "192.168.1.10".to_string(),
                http_port: 8765,
                pair_port: Some(8765),
                mode: PairQrMode::PairedMacs,
                started_epoch: now_secs(),
                expires_epoch: now_secs() + 60,
            };
        }
        let info = qr_page_info("host-id", "abc123", "paired_macs").expect("valid page token");
        assert_eq!(info.mode, PairQrMode::PairedMacs);
        assert_eq!(info.pin.as_deref(), Some("123456"));
        assert_eq!(info.host_name, "Desk");
        assert!(qr_page_info("host-id", "wrong", "paired_macs").is_none());
        assert!(qr_page_info("host-id", "abc123", "airplay_only").is_none());

        {
            let mut guard = state().lock().unwrap();
            guard.page_expires_epoch = now_secs().saturating_sub(1);
        }
        assert!(qr_page_info("host-id", "abc123", "paired_macs").is_none());

        {
            let mut guard = state().lock().unwrap();
            guard.session = PairQrSession::Idle;
            guard.page_token.clear();
            guard.page_identifier.clear();
            guard.page_mode = None;
            guard.page_expires_epoch = 0;
        }
    }

    #[test]
    fn test_pair_qr_cancel_signals_worker_and_clears_session() {
        let _guard = TEST_STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let flag = Arc::new(AtomicBool::new(false));
        {
            let mut guard = state().lock().unwrap();
            guard.cancel = Some(flag.clone());
            guard.page_token = "secret".to_string();
            guard.session = PairQrSession::Advertising {
                pin: Some("123456".to_string()),
                identifier: "host-id".to_string(),
                host_name: "Desk".to_string(),
                lan_ip: "192.168.1.10".to_string(),
                http_port: 8765,
                pair_port: Some(8765),
                mode: PairQrMode::PairedMacs,
                started_epoch: now_secs(),
                expires_epoch: now_secs() + 60,
            };
        }
        assert!(cancel_qr_pairing());
        assert!(flag.load(Ordering::SeqCst));
        assert!(matches!(current_session(), PairQrSession::Idle));
        {
            let guard = state().lock().unwrap();
            assert!(guard.page_token.is_empty());
            assert!(guard.cancel.is_none());
        }
    }

    #[test]
    fn test_pair_qr_random_pin_is_six_digits() {
        let pin = random_pin().expect("random PIN");
        assert_eq!(pin.len(), 6);
        assert!(pin.bytes().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn test_pair_qr_mdns_response_contains_pairable_host_txt() {
        let txt = vec![
            ("name".to_string(), "Desk".to_string()),
            (
                "identifier".to_string(),
                "D45C330B-B1B7-4E60-842C-C3ED8C81C91B".to_string(),
            ),
            ("authTag".to_string(), "MxMIjju5".to_string()),
            ("model".to_string(), PAIRABLE_HOST_MODEL.to_string()),
            ("flags".to_string(), "1".to_string()),
            ("ver".to_string(), "26".to_string()),
            ("minVer".to_string(), "17".to_string()),
        ];
        let instance = format!("D45C330B-B1B7-4E60-842C-C3ED8C81C91B.{PAIRABLE_HOST_SERVICE}");
        let response = build_mdns_response(
            120,
            &txt,
            8765,
            Ipv4Addr::new(192, 168, 1, 10),
            &dns_labels("Desk.local."),
            &instance,
        );
        let bytes = response.full(0x1234);
        assert_eq!(&bytes[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &[0x84, 0x00]);
        assert_eq!(&bytes[6..8], &0x0004u16.to_be_bytes());
        for (key, value) in &txt {
            assert!(find_bytes(&bytes, format!("{key}={value}").as_bytes()));
        }
        assert!(find_bytes(&bytes, &8765u16.to_be_bytes()));
        assert!(find_bytes(&bytes, &[192, 168, 1, 10]));
        assert_eq!(&ps_nonce("PS-Msg05")[4..], b"PS-Msg05");
        assert_eq!(&ps_nonce("PS-Msg06")[4..], b"PS-Msg06");
    }
}
