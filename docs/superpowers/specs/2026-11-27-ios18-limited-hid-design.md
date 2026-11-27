# iOS 18 limited HID — short design

Tanggal: 2026-11-27

## Intent / why

User memakai iPhone iOS 18 dan ingin **kontrol (touch/keyboard)** tanpa kabel. Kontrol native penuh
(CoreDevice display stream + HEVC 60 fps) tidak mungkin di iOS 18: Apple hanya mengirim stream itu di
iOS 27+ (dokumentasi pymobiledevice3: *"Older versions don't send the stream"*). Pairing QR
`Paired Macs` juga eksplisit iOS 27+. Yang masih bisa: **AirPlay video/audio + HID gate-only**
lewat jalur `HybridAirPlayCoreDeviceHid` yang sudah ada di kode untuk iOS 17.4–26, asalkan ada
record RemotePairing yang dipercaya (`remote_<udid>.plist`). Record itu dibuat **sekali lewat USB**
(`Set up Wi-Fi` / `prepare_wifi_over_usb`), tanpa Apple ID; setelah itu kabel boleh dilepas.

Juga ditemukan masalah terpisah: mode QR AirPlay-only tidak menyalakan receiver AirPlay, sehingga
Screen Mirroring kosong sampai tombol Start ditekan manual.

## Goals

1. Klik QR **AirPlay-only** langsung menyalakan receiver AirPlay + mDNS (`_airplay._tcp.local.`),
   tanpa perlu pencet Start dulu.
2. Kalau record RemotePairing sudah ada, start AirPlay dengan `hybrid_hid = true` (UDID + iOS
   version + IP Wi-Fi dari cache) supaya touch/keyboard iOS 18 dicoba.
3. Kalau record belum ada, tetap mirror AirPlay dan tampilkan panduan one-time USB `Set up Wi-Fi`
   (bukan Apple ID) secara jujur di UI.

## Non-goals / anti-goals

- Tidak menjanjikan kontrol penuh / HEVC native 60 fps di iOS 18 (batasan OS, bukan bug kita).
- Tidak menambah Apple ID/iCloud, WebView2, Python, PowerShell, atau crate baru.
- Tidak mengaktifkan QR `Paired Macs` di iOS 18 (iOS 27+ saja).
- Tidak mengubah prioritas USB sebagai fallback; QR tetap jalur utama.

## Constraints

- Binary Rust tunggal, local-only, tanpa PIN logging, teks ID/EN tetap ada.
- Perubahan hanya di `native_ui.rs` (alur QR + teks), `main_window.slint` (teks panduan), dan
  dokumentasi. Tidak menyentuh protokol SRP/RPPairing, `resolve_ios_mirror_route`, atau routing
  `/api/screen/start` di `server_v4.rs`.
- `rust-v4/vendor/` dan perbaikan build yang belum di-commit dibiarkan apa adanya.
- Jangan pakai `run.bat` / `iPhone Link.bat`; jangan sentuh `_update_staging/`.

## Approaches (sudah dipilih di percakapan)

- **A — dipilih:** auto-start receiver + deteksi record + hybrid HID saat record ada, panduan USB
  one-time saat tidak ada. Paling realistis dan bisa diverifikasi di perangkat user.
- **B — ditolak:** paksa QR `Paired Macs` di iOS 18. Dokumentasi menyatakan iOS 27+, besar
  kemungkinan tidak ada menu/pencarian host di perangkat.
- **C — ditolak:** iOS 18 mirror-only. User secara eksplisit ingin mencoba kontrol terbatas.

## How (keputusan builder)

Di `spawn_pair_qr_flow`, cabang `PairQrMode::AirPlayOnly`, setelah `/api/pair/qr/start` sukses:

- Panggil `inprocess_api(..., "POST", "/api/screen/start", body)` dengan
  `advertiseMdns: true`, `transport: "wifi"`.
- Jika `iphone_link_apple::wifi::wifi_paired_udids()` tidak kosong: ambil UDID pertama yang punya
  **record asli** (`wifi::find_record(udid).is_some()`) dan `ios_version` di rentang 17.4–26 (dari
  `read_device_metadata_from_wifi_state`), kirim `mode: "auto"`, `udid`, `iosVersion`. Routing yang
  ada akan memilih `IosMirrorRoute::HybridAirPlayCoreDeviceHid` → `hybrid_hid = true`. Flag
  `wifi_enabled_on_device` saja tidak cukup, karena bisa ada tanpa plist RemotePairing.
- Jika tidak ada record: kirim `mode: "airplay"` → video/audio AirPlay saja, `hidControlAvailable: false`.
- Teks langkah QR AirPlay-only dan akordion panduan di `main_window.slint` diperbarui:
  iOS 18 = gambar + audio lewat Screen Mirroring; untuk touch/keyboard lakukan **sekali** `Atur Wi-Fi`
  lewat USB (tanpa Apple ID), lalu lepas kabel; kontrol penuh butuh iOS 27+.

Tidak ada perubahan pada logika pairing QR `Paired Macs` (iOS 27+), tidak ada listener baru.

## Verification

- `cargo check --offline -p iphone-link-apple` dan `cargo build --release -p iphone-link-desktop`
  tetap exit 0 (PATH MinGW seperti biasa).
- Setelah klik QR AirPlay-only tanpa Start manual: `/api/status` menunjukkan
  `airplayActive: true`, `airplayPort: 7100`, listener TCP 7100 + UDP 5353 aktif.
- Tanpa record: `hidControlAvailable: false` dan panduan USB muncul.
- Dengan record dari `Set up Wi-Fi`: `hidControlAvailable: true` saat start (attempt; fail-soft ke
  false jika DDI/Developer Mode belum siap — sudah diuji dengan UDID dummy tanpa record). Tidak ada
  PIN di log.
- Uji perangkat iOS 18 oleh user: Control Center → Screen Mirroring → "iPhone Link", lalu coba
  touch/keyboard.

## Left to builder

Pemilihan kata final untuk teks ID/EN, penempatan helper kecil di `native_ui.rs`, dan menjalankan
build + verifikasi API. Tidak ada keputusan produk yang terbuka.
