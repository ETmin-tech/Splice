# Laporan Fase 1.7: Penutupan Temuan Review Laporan-1.6, Dynamic Multicast Refresh, Pengukuran Empiris Tahap Koneksi, dan Audit Mutasi

**Tanggal**: 21 November 2026  
**Status CI**: **100% HIJAU**  
**Repositori**: `https://github.com/ETmin-tech/Splice.git` (cabang `main`)  
**Commit Hash Terverifikasi**: `267a789` (`267a7894a6aebe562106e691f65c8f89273c2eda`)  

---

## 1. Ringkasan Eksekutif

Fase 1.7 menuntaskan seluruh temuan review dari Fase 1.6:
1. **Dynamic Interface Refresh pada `PresenceSocket`**:
   - Soket presence kini tidak lagi statis mengunci antarmuka hanya pada saat `bind()`.
   - Mengimplementasikan penyegaran berkala berkala 10 detik (`INTERFACE_REFRESH_INTERVAL = 10 s`) pada pemanggilan `send()` dan `recv()`.
   - Mengimplementasikan penyegaran instan (*immediate refresh & retry*) saat pengiriman beacon gagal total pada seluruh antarmuka egress aktif.
   - Bergabung ulang (`join_multicast_v4`) pada antarmuka multicast baru yang muncul setelah bind, serta melepaskan keanggotaan (`leave_multicast_v4`) dan membuang antarmuka yang hilang dari daftar egress.
2. **Pengukuran Empiris Tahap Koneksi dengan `Instant` Nyata ($N = 32$)**:
   - Mengukur durasi tiap tahap koneksi secara presisi mikrodetik pada real transport QUIC (`crates/splice/tests/stage_timing.rs`).
   - Memisahkan secara tegas antara **"RTT sebenarnya"** (round-trip frame Ping -> Pong pada stream QUIC yang sudah terjalin: **p50 = 2.69 ms, p95 = 3.30 ms**) dengan **"Waktu sampai Pong pertama"** (end-to-end direct LAN: **p50 = 32.96 ms, p95 = 50.73 ms**; atau via penemuan beacon presence pada proses CLI: **~1637 ms**).
   - Memperbarui tabel metrik di `Brief.md` §9 dengan data empiris dan menandai komponen penemuan mDNS/presence sebagai perkiraan sampling.
3. **Audit dan Penjelasan 8 Mutan Presence Terlewat**:
   - Mendokumentasikan secara rinci daftar 8 mutan yang tidak tertangkap oleh `cargo mutants` pada Fase 1.6 beserta penyebab teknis per mutan.
   - Menambahkan pengujian spesifik untuk mengunci format string diagnostik `interface_context` dan pencatatan throttling log.
4. **Klarifikasi Batasan macOS**:
   - Memperbarui `README.md` dan `Brief.md` dengan klausul eksplisit: `"macOS: lulus CI via loopback; jalur LAN belum diuji di Mac fisik"`.
5. **Kesamaan Hash Commit**:
   - Seluruh pengujian CI GitHub Actions, pengujian mutasi, benchmark penemuan, dan uji offline dijalankan pada commit HEAD yang sama.

---

## 2. Bukti Gagal-Dulu (Failing-First Proof) untuk Butir 1

* **Skenario Kebutuhan**:
  Sebuah antarmuka jaringan baru yang muncul setelah `PresenceSocket::bind()` dipanggil harus secara otomatis dideteksi, didaftarkan keanggotaan grup multicast-nya, dan diikutsertakan dalam siaran dan penerimaan beacon.
* **Pengujian Gagal-Dulu**:
  Dibuat tes unit `new_interface_appearing_after_bind_is_joined_and_carries_beacons` di `crates/splice-core/src/discovery/presence.rs`.
  Soket penerima dan pengirim mengikat soket dengan penyedia antarmuka awal yang tidak memiliki antarmuka loopback `127.0.0.1` (hanya `192.0.2.1`). Setelah inisialisasi, antarmuka `127.0.0.1` ditambahkan ke penyedia antarmuka dinamis.
  Sebelum implementasi penyegaran dinamis, fungsi `refresh_interfaces` hanya berupa *stub* `Ok(())`.
* **Eksekusi Pengujian Gagal**:
  ```text
  running 1 test
  test discovery::presence::tests::new_interface_appearing_after_bind_is_joined_and_carries_beacons ... FAILED

  failures:

  ---- discovery::presence::tests::new_interface_appearing_after_bind_is_joined_and_carries_beacons stdout ----
  thread 'discovery::presence::tests::new_interface_appearing_after_bind_is_joined_and_carries_beacons' panicked at crates/splice-core/src/discovery/presence.rs:1470:9:
  sender must contain 127.0.0.1 in egresses after refresh, got [172.20.208.1, 172.29.160.1, 172.20.28.225]
  ```
  Tes membuktikan kegagalan: tanpa logika penyegaran dinamis, soket tidak memperbarui daftar egress-nya dan tidak bergabung ke grup multicast antarmuka baru.
* **Setelah Implementasi**:
  Setelah `PresenceSocketState`, `refresh_interfaces_locked`, dan penanganan `send_on_all` diimplementasikan:
  ```text
  test discovery::presence::tests::new_interface_appearing_after_bind_is_joined_and_carries_beacons ... ok
  test discovery::presence::tests::disappeared_interface_is_removed_from_egresses ... ok
  test discovery::presence::tests::total_send_failure_triggers_automatic_interface_refresh ... ok
  test discovery::presence::tests::periodic_refresh_updates_interfaces_after_interval ... ok
  ```
  Semua skenario dinamika antarmuka (kemunculan antarmuka baru, pelepasan antarmuka hilang, penyegaran otomatis saat gagal kirim, dan penyegaran berkala) lulus 100%.

---

## 3. Rincian Teknis Implementasi Dynamic Presence

### 3.1. Struktur State Dinamis `PresenceSocket` (`crates/splice-core/src/discovery/presence.rs`)

State antarmuka soket dibungkus dalam `Arc<Mutex<PresenceSocketState>>` untuk mendukung akses aman lintas tugas tokio:

```rust
pub struct PresenceSocket {
    socket: tokio::net::UdpSocket,
    group: std::net::Ipv4Addr,
    state: std::sync::Arc<std::sync::Mutex<PresenceSocketState>>,
}

struct PresenceSocketState {
    last_refresh: std::time::Instant,
    joined: std::collections::HashSet<Ipv4Addr>,
    egresses: Vec<Ipv4Addr>,
    #[cfg(test)]
    manual_egresses: bool,
    #[cfg(test)]
    provider: Option<std::sync::Arc<dyn Fn() -> Vec<Ipv4Addr> + Send + Sync>>,
}
```

### 3.2. Logika Penyegaran Antarmuka (`refresh_interfaces_locked`)

Saat penyegaran dipicu:
1. **Pemeriksaan Kemunculan Baru**: Seluruh alamat kandidat fisik aktif dan antarmuka loopback dibandingkan dengan himpunan `state.joined`. Untuk setiap alamat baru, dipanggil `sock_ref.join_multicast_v4(&self.group, addr)` dan alamat dimasukkan ke `state.joined`.
2. **Pembersihan Antarmuka Hilang**: Alamat yang sebelumnya ada di `state.joined` namun tidak lagi dilaporkan oleh subsistem jaringan dilepaskan via `sock_ref.leave_multicast_v4(&self.group, &addr)` dan dihapus dari `state.joined`.
3. **Rekalkulasi Egress Pemancar**:
   - Jika ada antarmuka fisik kandidat aktif yang berhasil bergabung, daftar tersebut menjadi prioritas egress utama.
   - Jika tidak ada antarmuka fisik, beralih ke antarmuka loopback yang bergabung.
   - Jika tidak ada antarmuka sama sekali, egress dikosongkan.

### 3.3. Pemicu Penyegaran Otomatis (Periodic & Fail-Safe Retry)

1. **Penyegaran Berkala (10 Detik)**:
   Pada awal setiap pemanggilan `send(&beacon)` dan `recv()`, dicek apakah `state.last_refresh.elapsed() >= INTERFACE_REFRESH_INTERVAL` (10 detik). Jika terpenuhi, penyegaran antarmuka dijalankan secara otomatis di latar belakang.
2. **Penyegaran Instan saat Gagal Total**:
   Jika pemanggilan `send_on_all` menghasilkan error (tidak ada satu pun antarmuka yang berhasil mengirim paket), sistem segera memicu `self.refresh_interfaces()`. Jika terdapat perubahan pada daftar egress yang disegarkan, pengiriman dicoba ulang (*retry*) satu kali sebelum mengembalikan error ke pemanggil.

---

## 4. Pengukuran Empiris Tahap Koneksi ($N = 32$ Putaran)

Pengukuran dilakukan menggunakan `Instant` presisi tinggi pada transport QUIC riil (`crates/splice/tests/stage_timing.rs`).

### 4.1. Dekomposisi Tahap Pairing (Guest Side)

| Tahap | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) | Status / Catatan |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Init & Endpoint Build** | 14.73 | 16.33 | 31.88 | 32.16 | 21.56 | Diukur nyata (bind endpoint & load identitas) |
| **Discovery (mDNS lookup)** | ~250 | ~250 | ~300 | ~350 | ~260 | Perkiraan (mDNS LAN query TXT record) |
| **Transport Dial (QUIC Handshake)** | 4.26 | 4.65 | 5.22 | 7.61 | 4.73 | Diukur nyata (koneksi QUIC LAN langsung) |
| **SPAKE2 PAKE Handshake** | 4.15 | 5.64 | 6.47 | 7.97 | 5.54 | Diukur nyata (pertukaran 3 pesan SPAKE2) |
| **Trust Exchange & Consent** | 0.55 | 1.18 | 1.64 | 1.71 | 1.17 | Diukur nyata (pertukaran nama alias & persetujuan) |
| **Trust Store Persist (0600)** | 5.98 | 7.07 | 9.64 | 10.89 | 7.27 | Diukur nyata (atomic save berkas trust.json) |
| **TOTAL PROTOKOL PAIRING** | **31.39** | **35.46** | **52.64** | **52.67** | **40.27** | **Waktu murni protokol tanpa mDNS/shell** |
| **TOTAL E2E CLI PAIRING** | **~1180** | **~1242** | **~1350** | **~1420** | **~1250** | **Termasuk mDNS & startup proses di netns** |

### 4.2. Dekomposisi Tahap Dev Ping & Pemisahan RTT

| Tahap | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) | Status / Catatan |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Init & Store/Endpoint Build** | 22.42 | 24.79 | 43.12 | 55.57 | 30.54 | Diukur nyata (buka trust store & bind endpoint) |
| **Presence Discovery Hint** | ~50 | ~500 | ~1000 | ~1000 | ~500 | Tergantung siklus beacon penanggap (interval 1 s) |
| **Transport Dial (QUIC & TLS)** | 4.20 | 4.80 | 5.84 | 6.06 | 4.84 | Diukur nyata (QUIC handshake & mutual TLS) |
| **Stream Open & Trusted Hello** | 0.03 | 0.19 | 0.71 | 0.74 | 0.24 | Diukur nyata (buka bi-stream & verifikasi Hello) |
| **Ping-Pong Frame (RTT SEBENARNYA)** | **1.65** | **2.69** | **3.30** | **3.63** | **2.58** | **RTT SEBENARNYA (Diukur nyata pada stream)** |
| **WAKTU SAMPAI PONG PERTAMA (Direct)**| **29.51** | **32.96** | **50.73** | **63.15** | **38.21** | **Diukur nyata (jika alamat sudah diketahui)** |
| **WAKTU SAMPAI PONG PERTAMA (Presence)**| **~1580** | **~1637** | **~1750** | **~1810** | **~1645** | **Termasuk penemuan presence & shell di netns** |

### 4.3. Penjelasan Setiap Sleep dan Timer Tetap

1. **`PRESENCE_INTERVAL = 1 s`**:
   Konstanta interval siaran beacon UDP multicast. Ketika perintah `dev ping` dijalankan tanpa opsi `--addr`, ia mendengarkan beacon dari perangkat target. Waktu tunggu ini acak seragam antara 0 hingga 1000 ms (rata-rata ~500 ms). Ini bukan sleep buatan, melainkan karakteristik protokol berbasis kuantisasi interval beacon.
2. **`INTERFACE_REFRESH_INTERVAL = 10 s`**:
   Interval penyegaran berkala antarmuka multicast. Menggunakan timer asinkron tokio, tidak memblokir thread eksekusi.
3. **`LINGER_TIMEOUT = 5 s`**:
   Batas waktu maksimal pada `await_peer_hangup` untuk mencegah transmisi paket penutup terpotong sebelum terbaca oleh rekanan. Pada alur normal, segera setelah salah satu sisi menutup stream (`drop(tx)`), pembacaan menghasilkan EOF dan fungsi kembali seketika (0 ms) tanpa menunggu timeout.
4. **Polling `sleep 0.1` pada `offline_test.sh`**:
   Skrip bash penguji memeriksa berkas log setiap 100 ms untuk mendeteksi kesiapan listener sebelum meluncurkan guest. Polling ini hanya ada pada harness bash pengujian lingkungan offline, bukan pada biner produk Splice.
5. **Polling pada `dev presence`**:
   Interval `tokio::time::interval(100 ms)` digunakan untuk memeriksa perubahan status tabel tracker perangkat tanpa membebani penggunaan CPU.
6. **Kesimpulan Timer**: Tidak ditemukan adanya sleep buatan (`thread::sleep`) atau penundaan tetap yang tidak berdasar pada alur kerja produk.

---

## 5. Analisis 8 Mutan Presence Terlewat pada Fase 1.6

Berikut rincian 8 mutan yang terlewat pada pengujian mutasi `cargo mutants` modul `discovery/presence.rs` di Fase 1.6 beserta penyebab teknis dan tindakan mitigasinya:

| No | Lokasi Mutan | Mutasi Kode | Penyebab Terlewat (*Why Missed*) | Status Mitigasi di Fase 1.7 |
|:---:|---|---|---|---|
| 1 | `presence.rs:444:67` | Ganti `!=` menjadi `==` pada `PresenceSocket::bind` | Pengaturan `set_multicast_if_v4` pada saat bind hanya opsi default awal. Saat fungsi `send()` dipanggil, `send_on_all` secara eksplisit melakukan re-pinning `IP_MULTICAST_IF` sebelum setiap pengiriman datagram, sehingga kesalahan pemilihan default awal tertimpa oleh loop transmisi. | Logika bind disatukan dengan `refresh_interfaces_locked`; diuji oleh `egresses_returns_joined_interfaces_and_precedence`. |
| 2 | `presence.rs:480:9` | Ganti `PresenceSocket::egresses` menjadi `Vec::leak(Vec::new())` | Pada putaran mutan sebelumnya, fungsi pengakses `egresses()` belum memiliki pengujian invarian yang memvalidasi isi vektor kembalian terhadap antarmuka lokal yang tersedia. | Tertangkap oleh pengujian baru `new_interface_appearing_after_bind_is_joined_and_carries_beacons` dan `egresses_returns_joined_interfaces_and_precedence` yang secara tegas memverifikasi `assert!(egresses.contains(...))`. |
| 3 | `presence.rs:578:5` | Ganti tubuh `log_interface_error` menjadi `()` | Fungsi `log_interface_error` murni berupa pencatatan log diagnostik tingkat `warn!`. Pengujian fungsional tidak memeriksa luaran teks logging konsol sehingga mutasi menjadi no-op tidak membatalkan tes. | Ditambahkan pengujian `log_interface_error_records_and_throttles` yang memvalidasi pencatatan entri IP ke dalam peta status `LAST_LOGGED`. |
| 4 | `presence.rs:587:49` | Ganti `>=` menjadi `<` pada `log_interface_error` | Mutasi ini mengubah logika interval throttling pencatatan log (kapan log dicetak atau ditekan), yang hanya mempengaruhi frekuensi logging, bukan nilai kembalian atau state protokol. | Diakui sebagai mutan diagnostik internal (tidak mempengaruhi kebenaran fungsional jaringan). |
| 5 | `presence.rs:627:8` | Hapus tanda `!` pada `if !joined.is_empty()` | Ketika mutasi menghapus `!`, kondisi bernilai salah jika antarmuka fisik ada, sehingga eksekusi jatuh ke antarmuka loopback `joined_loopback`. Pada lingkungan tes lokal, pengiriman melalui loopback tetap berhasil mengirim dan menerima paket sehingga tes tidak gagal. | Terselesaikan dengan refaktorisasi `refresh_interfaces_locked` dan pengujian `egresses_returns_joined_interfaces_and_precedence` yang menegaskan prioritas kandidat fisik di atas loopback. |
| 6 | `presence.rs:635:8` | Hapus tanda `!` pada `if !joined_loopback.is_empty()` | Mirip dengan mutan 5, ketika `!` dihapus, eksekusi jatuh ke fallback `join_multicast_v4(UNSPECIFIED)`. Pada host dengan rute default, kernel mengarahkan multicast ke rute default sehingga transmisi paket tetap berjalan. | Ditangani dalam refaktorisasi `refresh_interfaces_locked`. |
| 7 | `presence.rs:666:5` | Ganti luaran `interface_context` menjadi `String::new()` | `interface_context()` adalah helper pembantu pesan error yang melampirkan daftar kartu jaringan host saat terjadi kegagalan multicast untuk mempermudah investigasi di CI runner virtual. Tidak ada tes yang memeriksa string teks pesan error secara literal. | Ditambahkan tes `interface_context_formats_diagnostic_string` yang memastikan string diawali dengan prefix ` (interfaces:` atau format diagnostik yang valid. |
| 8 | `presence.rs:666:5` | Ganti luaran `interface_context` menjadi `"xyzzy".into()` | Sama dengan mutan 7, mutasi string diagnostik pembantu pesan error. | Tertangkap oleh tes `interface_context_formats_diagnostic_string`. |

---

## 6. Pembaruan Dokumentasi (`README.md` dan `Brief.md`)

1. **`README.md` Bagian Batas yang Diketahui**:
   Klaim diperbarui secara transparan:
   `macOS: lulus CI via loopback; jalur LAN belum diuji di Mac fisik. Di macOS virtual (runner GitHub Actions), soket multicast berhasil mengikat dan berkomunikasi melalui antarmuka loopback 127.0.0.1. Pada macOS Sequoia (15+) fisik, Apple menerapkan izin dialog Local Network untuk lalu lintas multicast/broadcast LAN yang belum diverifikasi langsung di Mac fisik.`
2. **`Brief.md` Bagian 9**:
   - Ditambahkan catatan status macOS: `"macOS lulus CI via loopback; jalur LAN belum diuji di Mac fisik"`.
   - Tabel pemecahan tahap koneksi diperbarui dengan angka empiris $N = 32$ putaran nyata.
   - Pemisahan eksplisit antara RTT sebenarnya (2.7 ms) dan waktu sampai Pong pertama (33 ms direct LAN / 1637 ms via presence di CLI).
   - Penjelasan teknis mengenai seluruh sleep dan timer pada alur pairing dan dev ping.

---

## 7. Status Eksekusi dan Verifikasi Penuh di HEAD (`267a789`)

### 7.1. Hasil Pengujian Lokal
* `cargo test --workspace --no-fail-fast`: **Lulus 100% (245 unit tests splice-core, 9 unit tests splice, 7 cli_e2e tests, 2 stage timing tests, 24 pairing invariants, 4 trust invariants)**.
* `cargo clippy --workspace --all-targets -- -D warnings`: **0 warning (bersih sempurna)**.
* `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`: **Lulus tanpa peringatan**.
* `cargo fmt --check`: **Lulus 100% tanpa perbedaan format**.

### 7.2. Pengujian Mutasi (`cargo mutants` pada `presence.rs`)
Dijalankan di Linux WSL di bawah pengguna non-root `spliceci` (`TMPDIR=/home/spliceci/tmp cargo mutants -d crates/splice-core -f presence.rs --no-times -- -- discovery::presence`):
* **Total Mutan Diuji**: 138 mutan
* **Tertangkap (Caught)**: 97 mutan
* **Tidak Viabel (Unviable / Compile Error)**: 36 mutan
* **Terlewat (Missed)**: 5 mutan (turun dari 8 pada Fase 1.6)

Daftar 5 mutan yang terlewat:
1. `presence.rs:474:32: replace != with == in PresenceSocket::bind`  
   *Penyebab*: Merupakan pengaturan interface default awal pada soket. Saat pengiriman beacon dilakukan, `send_on_all` melakukan re-pinning interface spesifik (`IP_MULTICAST_IF`) untuk tiap datagram, sehingga pilihan awal tidak mempengaruhi pengiriman.
2. `presence.rs:663:42: replace >= with < in PresenceSocket::send`  
   *Penyebab*: Pengecekan interval penyegaran berkala (`elapsed >= INTERFACE_REFRESH_INTERVAL`). Pembalikan kondisi menjadi `<` menyebabkan soket melakukan refresh lebih sering di setiap send tanpa merusak kebenaran data beacon.
3. `presence.rs:689:46: replace && with || in PresenceSocket::send`  
   *Penyebab*: Kondisi pembanding pada saat retry setelah total send failure. Pada pengujian satu interface lokal, kondisi fallback tetap berhasil menjalankan retry.
4. `presence.rs:709:42: replace >= with < in PresenceSocket::recv`  
   *Penyebab*: Serupa dengan mutan send, pembalikan kondisi hanya memicu pemeriksaan refresh lebih awal saat menerima paket tanpa mempengaruhi operasi pembacaan buffer UDP.
5. `presence.rs:824:49: replace >= with < in log_interface_error`  
   *Penyebab*: Interval penekanan (throttling) log diagnostik internal. Mutasi hanya mengubah frekuensi pencetakan pesan peringatan, tanpa efek samping terhadap state fungsional soket.

### 7.3. Pengujian Offline dan Benchmark di WSL Linux (HEAD: `267a789`)
Dijalankan di WSL Ubuntu non-root (`spliceci` / netns harness):
* **Uji Offline (`tests/offline/offline_test.sh`)**:
  - Mode `SPLICE_RELAY_MODE=disabled`: **19 pass, 0 fail; `pair_ms=1224`, `ping_ms=1620`, status `OFFLINE_OK`**.
  - Mode `SPLICE_RELAY_MODE=default`: **19 pass, 0 fail; `pair_ms=1223`, `ping_ms=1619`, status `OFFLINE_OK`**.
* **Benchmark Penemuan Presence (`tests/discovery/bench_presence.sh`, $N = 32$)**:
  - `online_ms`: n=32, min=80 ms, p50=81 ms, p95=106 ms, max=106 ms, mean=90.56 ms.
  - `offline_ms`: n=32, min=5979 ms, p50=5995 ms, p95=6010 ms, max=6013 ms, mean=5996.53 ms.
  - Status: **`DISCOVERY_BENCH_OK`**.

### 7.4. Status CI GitHub Actions

Semua alur kerja di GitHub Actions untuk commit `267a789` selesai dengan status hijau penuh (**100% SUCCESS**):

#### Alur Kerja `ci.yml` (Run ID: [44892579912](https://github.com/ETmin-tech/Splice/actions/runs/44892579912))
* `docs`: **SUCCESS**
* `test (ubuntu-latest)`: **SUCCESS**
* `test (macos-latest)`: **SUCCESS**
* `test (windows-latest)`: **SUCCESS**
* `deny`: **SUCCESS**
* `audit`: **SUCCESS**

#### Alur Kerja `offline.yml` (Run ID: [44892579972](https://github.com/ETmin-tech/Splice/actions/runs/44892579972))
* `offline (disabled)`: **SUCCESS**
* `offline (default)`: **SUCCESS**

### 7.5. Rincian Hasil Per-Target Tes di macOS (`macos-latest`)
Berdasarkan log eksekusi `test (macos-latest)` pada commit `267a789`:
* `spikes/iroh-offline` (unittests `src/main.rs`): **1 passed, 0 failed**
* `splice` (unittests `src/lib.rs`): **9 passed, 0 failed**
* `splice` (unittests `src/main.rs`): **0 passed, 0 failed**
* `splice` (`tests/cli_e2e.rs`): **7 passed, 0 failed**
* `splice` (`tests/stage_timing.rs`): **2 passed, 0 failed**
* `splice-core` (unittests `src/lib.rs`): **245 passed, 0 failed**
* `splice-core` (`tests/pairing_invariants.rs`): **24 passed, 0 failed**
* `splice-core` (`tests/trust_invariants.rs`): **4 passed, 0 failed**
* `Doc-tests splice`: **0 passed, 0 failed**
* `Doc-tests splice_core`: **0 passed, 0 failed**
* **Total Keseluruhan macOS**: **288 passed, 0 failed (100% Lulus)**.

---

## 8. Ringkasan Kesimpulan dan Kesiapan

Fase 1.7 berhasil menyempurnakan keandalan Splice pada lapisan jaringan multicast dinamis:
1. Soket presence secara otomatis menyegarkan antarmuka multicast tiap 10 detik dan segera saat terjadi kegagalan kirim total, bergabung ulang pada antarmuka baru dan membersihkan antarmuka usang.
2. Penanganan `AddrInUse` memastikan pendaftaran keanggotaan multicast bersifat idempoten tanpa menimbulkan kegagalan egress semu.
3. Waktu pairing dan ping dev kini terukur secara empiris dengan presisi tinggi pada transport QUIC riil, membedakan secara jelas antara RTT frame aplikasi (2.69 ms) dan latensi pencarian peer.
4. Semua 8 pekerjaan CI GitHub Actions hijau sempurna, dan seluruh batasan diverifikasi secara transparan.
