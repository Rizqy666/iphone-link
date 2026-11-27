# QR-assisted cable-free iPhone pairing — design

Date: 2026-11-27
Status: implemented (QR-first native pairing added; full workspace build/test still blocked by the missing gitignored vendor cache; manual device verification pending)

## Intent and why

The user wants to remove the one-time USB cable requirement from iPhone Link's Wi‑Fi setup. Today `POST /api/wifi/pair` calls `prepare_wifi_over_usb()` and fails with "plug in the iPhone, unlock it, tap Trust This Computer". The user wants a QR method on the Windows side that lets an iPhone connect with **no cable at all**, while keeping the same full experience after connection (Wi‑Fi HEVC 60 fps + HID).

Primary source for the new path: current `pymobiledevice3` documentation and CLI (`remote pair-host`, `serve_pairable_host`). It implements **device-initiated RemotePairing** for iOS 27+: the PC advertises `_remotepairing-pairable-host._tcp`, the iPhone opens Settings → Developer → Paired Macs, taps the PC under "Other Devices", and types a 6-digit PIN shown by the PC. The resulting pair record is the same `remote_<id>.plist` shape our Wi‑Fi tunnel already consumes. QR's job is to carry the PIN + host identity to the phone and show clear instructions — it does **not** replace Apple's trust model.

## Goals

- Pair an iPhone to this Windows app over Wi‑Fi with **zero USB cable** on iOS 27+.
- Show a QR code on the native Slint UI; scanning it gives the iPhone the PC's LAN address, host identifier, and one-time 6-digit PIN.
- Persist the resulting pairing record so the existing `rp_wifi_tls` tunnel, HEVC mirroring and HID control work unchanged.
- Provide an explicit **AirPlay-only** QR fallback for iOS 17–26 (no USB, but H.264 + limited control, no RemoteXPC HID).
- Keep everything local: no Apple ID, no cloud, no WebView2, no Python, no new runtime process.

## Non-goals

- Auto-opening iOS Settings from a QR code (iOS deep-link restrictions make this unreliable; we show instructions instead).
- Making RemoteXPC pairing work cable-free on iOS < 27 (Apple does not offer device-initiated pairing there for iPhones).
- Making USB a prerequisite in any user-facing setup flow. QR is the primary path; the existing USB `Set up Wi‑Fi` flow remains only as an advanced fallback/debug action and is never presented as the first step.
- Reworking the AirPlay transport or video pipeline.

## Anti-goals (would make this a failure)

- Persisting or logging the setup PIN in plaintext.
- Opening any LAN listener without a hard expiry and a strict allowlist. The RemotePairing handshake is a binary `RPPairing`-framed protocol and cannot be multiplexed on the HTTP receiver, so one **short-lived ephemeral-port listener** is allowed only while a QR session is active: single pending connection, LAN peer only, closed on success/failure/cancel/180 s expiry. No persistent second listener.
- Breaking existing `remote_<udid>.plist` records or the current tunnel handshake.
- Adding an external crate/runtime that breaks the single-binary, zero-WebView2, zero-Python packaging.

## Constraints

- Pure Rust 5.0.0 binary (`iphone-link-desktop` + `iphone-link-apple`), Slint UI, DirectComposition renderer.
- `rust-v4/vendor/` is gitignored and absent in a fresh clone; the build normally restores it. Prefer implementing QR + SRP inside `iphone-link-apple` with primitives already in the crate/vendored `idevice` rather than adding a new crate. If a new vendored crate is unavoidable, the build script must be updated.
- Existing record format: `remote_<udid>.plist` with `peer_alt_irk` (16 bytes), `private_key`, `public_key`, `remote_unlock_host_key`. `wifi::records()` / `find_record()` must read what we write. New QR records add extra keys but keep those four intact. The record key is `peer_device.udid` (the M5 `remotepairing_udid`), falling back to `accountID` only if UDID is empty — same rule as pymobiledevice3's `PairableHost.pair_record_path`. Sanitize the filename to `[A-Za-z0-9._-]`.
- Existing mDNS responder (`airplay::mdns::MdnsAdvertiser`) is AirPlay-specific; the pairable-host service needs its own TXT records and query matching.
- LAN receiver today allows only `/c?u=` on port 8765 (`docs/llms-full.txt` privacy guarantee). Any QR landing page must be a second, narrow, token-scoped path and must not broaden the existing guard.

## Approaches considered

1. **QR → Paired Macs (iOS 27+), chosen primary.** Implement the `serve_pairable_host` responder in Rust: advertise `_remotepairing-pairable-host._tcp` with TXT `name`, `identifier`, `authTag`, `model` (Mac-style id, e.g. `Mac17,7`), `flags=1`, `ver=26`, `minVer=17`; accept one device-initiated TCP connection; run SRP pair-setup M1–M6 (username `Pair-Setup`, 3072-bit group, 16-byte salt with high bit set, random 6-digit PIN); parse M5 identity, send M6 identity; persist pairing record; notify UI. The QR carries a short-lived local URL with `pin`, `identifier`, host IP/port. After success, the normal Wi‑Fi Connect path works with no cable. Cost: new SRP/TLV/OPACK code, iOS 27+ only, Developer Mode required, user must navigate Settings manually.
2. **QR → AirPlay only (iOS 17–26), chosen fallback.** QR carries receiver name + LAN IP + one-time onboarding token; landing page shows how to open Control Center → Screen Mirroring → `iPhone Link`. Reuses existing receiver and Pair-Verify. Cost: no RemoteXPC HID, H.264 instead of HEVC; mostly UI + narrow endpoint work.
3. **iCloud/Apple ID pairing.** Zero cable but needs an account and cloud service, directly against project's "no account/no cloud" promise. Rejected.
4. **Keep one-time USB and use QR only for reconnect.** Does not meet the stated need. Rejected.

The user's "gas" after the recommendation is taken as approval of **1 + 2**; if they meant primary only, drop approach 2 before implementation.

## Design

### Modules and state

New module `rust-v4/crates/iphone-link-apple/src/pair_qr.rs` exposing:

- `PairQrSession` with states `Idle`, `Advertising { pin, identifier, http_port, pair_port, started_at }`, `Paired { udid, name, device_ip, record_path }`, `Failed(String)`. One active session at a time; `start()` cancels any previous session, increments a generation counter so a stale worker cannot overwrite the newer session, and sends the mDNS goodbye.
- `start_qr_pairing(mode: PairQrMode, http_port: u16) -> Result<PairQrSessionInfo, String>` where mode is `PairedMacs` or `AirPlayOnly`. `http_port` must be the real bound port of the local HTTP server; the QR URL uses it, while the binary `RPPairing` listener keeps its own ephemeral port for mDNS.
- `poll_qr_pairing() -> PairQrSession` and `cancel_qr_pairing()`.
- `PairQrSessionInfo { pin: Option<String>, identifier: String, host_name: String, lan_ip: String, port: u16, pair_port: Option<u16>, expires_in_secs: u64, mode }`. On success the session also carries `device_ip`, captured from the accepted TCP socket's peer address — M5 identity has no IP, so this is what lets the UI select/probe the device immediately.
- For `PairedMacs`, `start()` binds a TCP listener on `0.0.0.0:0` (OS-chosen ephemeral port), advertises that port via mDNS, accepts at most one connection, and tears everything down on success/failure/cancel/timeout. This is a second, temporary listener by protocol necessity, not a new persistent service.
- Timeout (180 s) enforced across every frame read/write and immediately before persistence; a wrong PIN sends the standard `state=4, ERROR=2` response and fails that session, after which the UI Retry button starts a fresh session. PIN is generated in memory via OS CSPRNG, never written to disk or logs.
- `PairQrMode::AirPlayOnly` does not run SRP and binds no extra listener; it only ensures the existing AirPlay receiver is up and returns receiver info for the QR. Its `c` value is a page-authorization token, not an AirPlay PIN.

### Protocol details (from `pymobiledevice3` primary source)

- Framing: each message is `RPPairing` magic + big-endian u16 length + JSON body. Envelopes use `originatedBy: "device"` and an incrementing `sequenceNumber`; payload values that are bytes are base64 strings. `XpcInt64Type`/`XpcUInt64Type` are Python `int` subclasses in `pymobiledevice3/remote/xpc_message.py`, so `json.dumps` emits them as plain JSON numbers; our numeric `sequenceNumber`/version fields are wire-compatible (verified against source, not guessed).
- mDNS service `_remotepairing-pairable-host._tcp`, TXT: `name`, `identifier`, `authTag = b64(compute_auth_tag(host_alt_irk, identifier))`, `model` (Mac-style id such as `Mac17,7`), `flags=1`, `ver=26`, `minVer=17`. Advertise the OS-chosen ephemeral listener port.
- Host identity: `identifier = wifi::host_identifier(&wifi::hostname())` — the same stable UUID v3 value the existing USB/Wi-Fi flow uses, so an already-paired device recognizes us. `host_alt_irk` is a random 16-byte value generated once and persisted in the pairing dir (`host_alt_irk.bin`); reusing it across sessions keeps advertised `authTag` and reconnect validation stable, matching pymobiledevice3's "persist alt_irk" guidance.
- Handshake: device sends `handshake` with no `attemptPairVerify`; reply with `wireProtocolVersion=26`, `minimumSupportedWireProtocolVersion=8`, device options `allowsPairSetup=true`, `allowsPinlessPairing=false`, `allowsIncomingTunnelConnections=false`, and `peerDeviceInfo` (`udid` empty for us, `identifier`, `name`, `model`, `deviceKVSIncludesSensitiveInfo=false`).
- Pair-setup uses `kind: "setupManualPairing"`; TLV8 (type, len<=255, concatenated duplicate types) with state/salt/public key/proof/encrypted data/error. SRP-3072 via the `idevice`/vendored SRP implementation, username `Pair-Setup`; 16-byte salt with first byte OR `0x80`; server public key regenerated until exactly the expected size. PIN is 6 digits from OS CSPRNG, shown in UI/QR, never stored.
- M5: decrypt with ChaCha20-Poly1305 nonce `\0\0\0\0PS-Msg05`, parse TLV8, reject `ERROR` TLVs, then parse the OPACK `INFO` payload with `accountID`, `altIRK` (exactly 16 bytes), `model`, `name`, and optional `remotepairing_udid`. Missing or wrong-typed required fields fail before M6 is sent, matching `PeerDeviceInfo.from_info_dict`.
- M6: HKDF-SHA512 with `Pair-Setup-Accessory-Sign-Salt/Info` → `AccessoryX`; Ed25519 signature over `AccessoryX || identifier || LTPK`; identity TLV encrypted with nonce `\0\0\0\0PS-Msg06`. Both M5 and M6 encrypted-data components are chunked at 255 bytes.
- Record: save via an extension of `wifi::save_remote_record()` keyed by `peer_device.udid` (fallback `accountID`). Keep the four legacy keys intact and add `host_identifier`, `host_alt_irk`, `peer_udid`, `peer_model`, `peer_name`, `remote_unlock_host_key=""` for pymobiledevice3 parity. If the target file already exists, back it up to `remote_<id>.plist.bak-<nanoseconds>-<counter>` before writing; a failed backup aborts the write instead of silently destroying a USB-created record. A USB record keyed by a different `UniqueDeviceID` simply coexists.
- Capture the accepted socket's peer IP as `device_ip` and return it with the success status so the UI can seed device selection/probing without waiting for a fresh scan.

### QR and local onboarding page

- Pure-Rust QR encoder in `pair_qr_qr.rs`, ported from `handset/qr_bridge.py::generate_qr_test_image` (ISO/IEC 18004, versions 1–10, EC level M, quiet zone 4). No new crate. Render into an RGBA byte buffer exposed to Slint as an image; do not add PNG dependency.
- Payload (compact, short-lived): `http://<pc-lan-ip>:<http-port>/q?i=<identifier>&c=<pin-or-onboarding-token>&m=<mode>`. `<http-port>` is the real bound port of the local HTTP server (8765 by default, but not assumed). For `PairedMacs`, `c` is the 6-digit setup PIN and the page shows it large; for `AirPlayOnly`, `c` is only a one-time authorization token for the page — our AirPlay receiver has no user-facing PIN, and the page just explains Control Center → Screen Mirroring → `iPhone Link`.
- The existing LAN guard gains a **single narrow path** `/q` with token validation and expiry, reusing the same security style as `/c?u=`. It serves a tiny local HTML page: steps to open Settings → Developer → Paired Macs, the 6-digit PIN in large text, and the exact host name to tap. It must not expose any API or file read.
- QR image plus large readable PIN are both shown in the Slint panel; scanning is convenience, manual entry must work.

### UI changes (`ui/main_window.slint`, `native_ui.rs`)

- In the connectivity/Wi‑Fi card add a `Pair via QR` button next to the existing Wi‑Fi pair control.
- Slint callbacks: `pair-qr()`, `cancel-pair-qr()`, `pair-qr-airplay-only()`; properties: `qr-image`, `qr-pin`, `qr-mode-label`, `qr-steps`, `qr-state`, `qr-countdown`, `qr-message`.
- `native_ui.rs` callbacks spawn a worker thread, call the in-process API endpoints, then marshal results back with `slint::invoke_from_event_loop`, matching the existing `on_pair_wifi` pattern.
- On success: refresh device/status, select the newly paired device using the `device_ip` reported by the pairing session, show "Pasangan QR berhasil / QR pairing complete", close the panel. On failure: keep the panel open with a localized message and a Retry button.
- i18n strings in `i18n.rs` / Slint bilingual literals for ID and EN; no plaintext PIN in action logs (log only length, matching PIN safe-guard convention).

### Server endpoints (`server_v4.rs`)

- `POST /api/pair/qr/start` body `{ "mode": "paired_macs" | "airplay_only" }` → `{ ok, pin?, identifier, host_name, lan_ip, port, pair_port, expires_in, mode, qr_url }`, where `port` is the local HTTP port used by `qr_url` and `pair_port` is the ephemeral `RPPairing` port advertised over mDNS (null in AirPlay-only mode).
- `GET /api/pair/qr/status` → current state; on success also `{ udid, name, device_ip, record_path }`, on failure `{ error }`. Never include the PIN after it has been used.
- `POST /api/pair/qr/cancel` → stops advertiser, closes the ephemeral listener, and clears the PIN.
- All three bound to loopback API only; reuse existing path dispatch and test harness style (`test_tahap...` naming). Add tests modelled on `test_tahap227_native_inprocess_wifi_endpoints`.

### Verification

- Unit tests: QR encode/decode roundtrip with vectors from `generate_qr_test_image`; TLV8 encode/decode; SRP session against known pymobiledevice3 vectors (skip if unavailable offline); mDNS TXT record bytes; `authTag` computed from persisted `host_alt_irk`; record written is readable by `wifi::records()` and contains all parity keys; conflicting record is backed up rather than overwritten; state machine transitions, timeout and cancel (including ephemeral listener teardown); LAN `/q` rejects bad/expired token and never serves other paths; Slint selftest asserts new callbacks/properties exist and no PIN is logged.
- Manual verification (not CI): Windows 11 + iPhone 17 Pro iOS 27.2 with Developer Mode ON — scan QR, open Paired Macs, enter PIN, confirm pairing record appears, then start mirroring and verify HEVC 60 fps + HID. iOS 17–26 device for AirPlay-only fallback.
- Verification done in this workspace: the isolated `pqcheck` harness (same `pair_qr*.rs` sources) passes 22/22 tests; the Slint source compiles through `i-slint-compiler` 1.19.0 and the generated Rust API contains every new callback/property setter used by `native_ui.rs`. Tests cover mDNS TXT, PIN/token expiry/cancel, QR encode, TLV chunking, OPACK identity validation, ERROR-TLV detection, record backup uniqueness, and the server endpoint's non-default HTTP port. The stray `libpair_qr_qr.rmeta` build artifact was removed. Two source audits found and fixed: QR URL using the wrong port, wrong-mode retry, English-only startup errors, USB-first onboarding and stale Wi-Fi diagnostic copy, unvalidated M5 identity, ignored ERROR TLVs, stale-worker/cancel races, and unreliable record backups.
- Build caveat: `rust-v4/vendor/` is gitignored and absent here; the registry-cache substitute diverges from the patched release vendor crates, and this machine has no `dlltool.exe`/MSVC `link.exe`/`lld` for a full desktop link. Restore the release vendor cache and linker before running the full `cargo test`. Full workspace compile/test is therefore **unverified**, not passed.

## Files expected to change

- `rust-v4/crates/iphone-link-apple/src/pair_qr.rs`, `pair_qr_crypto.rs`, `pair_qr_qr.rs` (new) and `src/lib.rs` exports.
- `rust-v4/crates/iphone-link-apple/src/wifi.rs` (record fields, identity, backups, QR-first status text).
- `rust-v4/crates/iphone-link-apple/src/link.rs`, `mirror.rs`, `physical_stream.rs`, `rp_wifi_tls.rs` (QR-first Wi-Fi diagnostics; USB kept only as advanced fallback).
- `rust-v4/apps/iphone-link-desktop/src/server_v4.rs` (3 endpoints + LAN `/q` guard + QR-first diagnostics).
- `rust-v4/apps/iphone-link-desktop/src/native_ui.rs` (callbacks/status marshalling + QR-first hints).
- `rust-v4/apps/iphone-link-desktop/ui/main_window.slint` (button + panel + QR-first guide).
- UI strings were added inline in Slint/native UI rather than `i18n.rs`; README was left unchanged.
- `docs/superpowers/specs/...` (this doc).

## Calls made by the writer (builder may treat as settled)

- Primary + fallback scope (approaches 1 and 2) because the user said "gas" after that recommendation.
- QR payload is a narrow local HTTP URL on the app's actual local HTTP port (8765 by default), not a custom URI scheme, because iOS camera reliably opens http URLs. It is never the ephemeral binary `RPPairing` port.
- iOS version is not auto-detected without USB; the user picks the mode explicitly in the UI.
- QR encoder is ported in-tree; no new external crate.
- 180 s session expiry; 5 wrong-PIN attempts; these are defaults the builder may tune without asking.
- Canonical record key is M5 `remotepairing_udid` (fallback `accountID`), verified against pymobiledevice3 `PairableHost.pair_record_path`.
- Host `identifier` reuses `wifi::host_identifier(hostname)`; `host_alt_irk` is random-once and persisted in the pairing dir so `authTag` stays stable.
- A short-lived ephemeral TCP listener is acceptable because the `RPPairing` protocol cannot share port 8765; it must die with the session.
- Conflicting existing records are backed up, not replaced.
- `AirPlayOnly` `c` is a page token only; no AirPlay PIN is generated or shown.
- Success status carries the device IP captured from the accepted socket so the UI can select it immediately.

## Left to the builder

- Exact SRP group constants and OPACK subset needed for M5/M6, from `pymobiledevice3/remote/srp.py` and `pymobiledevice3/remote/pair_setup.py` (protocol flow itself is settled by `remote/tunnel_service.py::PairableHost`).
- Concrete Slint image API usage for an RGB buffer with this Slint version.
- Whether the QR landing page should offer an optional `shortcuts://` link (nice-to-have, not required for v1).
- Restore/build strategy for the gitignored vendor cache in this environment.
