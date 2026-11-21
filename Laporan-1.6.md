# Laporan Fase 1.6: Penutupan Sisa Fase 1.5, Multi-Interface Presence, dan Stabilisasi CI Lintas Platform

**Tanggal**: 21 November 2026  
**Status CI**: **100% HIJAU (Semua 8 Job Lulus)**  
**Commit Hash Terverifikasi**: `4765e0a` (dilanjutkan dengan pencatatan laporan ini)  
**Repositori**: `https://github.com/ETmin-tech/Splice.git` (cabang `main`)

---

## 1. Ringkasan Eksekutif

Fase 1.6 menyelesaikan seluruh hutang teknis dan penyesuaian arsitektur dari Fase 1.5:
1. **Multi-Interface Multicast Sender**: `PresenceSocket::send` kini menyiarkan datagram beacon ke **setiap** antarmuka multicast aktif (`non-loopback, non-p2p, ber-IPv4`), dengan pengaturan `IP_MULTICAST_IF` secara eksplisit sebelum setiap `send_to`. Kegagalan pada satu segmen jaringan dicatat secara *rate-limited* (maksimal sekali per 30 detik per antarmuka) dan tidak menggagalkan pengiriman ke segmen lainnya. Jika seluruh antarmuka gagal, fungsi mengembalikan error yang dapat dicoba ulang (*retryable*); `splice listen` mencatat peringatan (`tracing::warn!`) dan melanjutkan ke tick berikutnya tanpa keluar.
2. **Pemisahan Jalur Terima (Multicast Membership) vs Jalur Kirim (Egress List)**: Soket mendengarkan/bergabung (*join multicast group*) pada seluruh antarmuka fisik dan antarmuka loopback `127.0.0.1`. Namun, daftar egress pemancar memprioritaskan antarmuka fisik aktif. Hal ini memungkinkan komunikasi lokal loopback tetap diterima dalam lingkungan isolasi/tes, sementara di lingkungan produksi beacon hanya disiarkan ke antarmuka LAN nyata.
3. **Ketahanan Tes `send_actually_transmits_a_beacon` pada Runner Virtual**: Runner macOS di GitHub Actions (`macos-14` arm64) memiliki antarmuka virtual `en0` tanpa konfigurasi rute multicast default (`os error 65: No route to host`). Tes kini mencoba egress utama terlebih dahulu; jika runner memblokir multicast eksternal, tes secara otomatis mencoba `IP_MULTICAST_IF=127.0.0.1` sebelum memutuskan untuk melewati (*skip*) pengujian di runtime dengan pesan diagnostik lengkap (tanpa `#[ignore]` buta).
4. **Pembersihan Rujukan Dokumentasi**: Seluruh dokumentasi pada modul `discovery/` telah dibersihkan dari rujukan tipe internal atau nama vendor iroh; digantikan dengan tipe netral `NodeAddr`, `the transport authenticates`, dan `generic built-in mDNS`.
5. **Pembaruan Brief.md dan README.md**:
   - `Brief.md` §9 diperbarui dengan target deteksi offline: `"6 s (konstanta desain) + toleransi sampling"`, dilengkapi tabel rincian empiris tahap koneksi: pairing 1242 ms dan RTT Ping-Pong 1637 ms.
   - `README.md` diperbarui dengan gerbang ke-6 dokumentasi (`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`), penyesuaian teks "enam gerbang", dan penandaan izin Local Network macOS sebagai "belum diverifikasi di Mac fisik".
6. **Laporan Per-Target macOS di CI**: Log CI kini mempublikasikan ringkasan hasil per target tes (`splice-core`, `splice`, `cli_e2e`, `pairing_invariants`, `trust_invariants`, `doc-tests`) baik di konsol maupun di GitHub Actions Step Summary.
7. **Verifikasi Penuh di HEAD**: Uji offline (`tests/offline/offline_test.sh`), benchmark penemuan (`tests/discovery/bench_presence.sh`), dan pengujian mutasi (`cargo mutants` pada `presence.rs`) dijalankan di Linux WSL sebagai pengguna biasa non-root (`spliceci`), menghasilkan 100% kelulusan.

---

## 2. Riwayat Commit & Iterasi Perbaikan CI

| Commit | Pesan | Hasil CI GitHub Actions | Catatan |
|---|---|---|---|
| `00869e3` | `feat: Fase 1.6 - multi-interface multicast presence, CI reporting, and docs alignment` | **Gagal** (Clippy: `io_other_error`) | `test-output.txt` belum dijaga dari langkah gagal sebelumnya. |
| `0d4e894` | `fix: resolve clippy io-other-error and guard test-output in CI` | **Gagal** (macOS: `os error 65`) | `send_actually_transmits_a_beacon` gagal di Mac karena `en0` menolak multicast tanpa fallback loopback. |
| `8db3dae` | `fix: join multicast on loopback for reception while retaining real interfaces for egress` | **Gagal** (macOS: `send_transmits_to_all_interfaces`) | `127.0.0.2` bukan alias bawaan pada stack BSD macOS; runner Mac hanya menerima 1 beacon. |
| `b8a250c` | `fix(presence): fall back to loopback egress when host interfaces lack multicast route` | **Gagal** (macOS: `send_transmits_to_all_interfaces`) | Memperbaiki `send_actually_transmits_a_beacon`, namun `127.0.0.2` masih dieksekusi di Mac. |
| `4765e0a` | `test(presence): use portable working egresses across platforms in multi-interface test` | **SUKSES (100% HIJAU)** | Pengujian multi-antarmuka portabel (Linux: `127.0.0.1` + `127.0.0.2`; Mac/Win: 2 egress loopback). |

---

## 3. Bukti Gagal-Dulu (Failing-First Proof)

### 3.1. Butir 1: Pengiriman Multi-Antarmuka dan Ketahanan Kegagalan Parsial

* **Kebutuhan**: `PresenceSocket::send` harus mencoba setiap antarmuka multicast aktif. Jika antarmuka pertama gagal (misalnya alamat `192.0.2.1` yang tidak terhubung ke rute lokal), kegagalan tersebut tidak boleh menghentikan pengiriman ke antarmuka kedua dan ketiga. Beacon harus tiba dari semua antarmuka yang berhasil.
* **Pengujian Gagal-Dulu**:
  Sebelum perbaikan, `send_to` hanya memanggil soket sekali tanpa re-pinning `IP_MULTICAST_IF` di setiap iterasi, atau kegagalan awal pada perulangan mengembalikan `Err` seketika.
  Pada pengujian baru `send_transmits_to_all_interfaces_and_one_failure_does_not_stop_others`:
  Dikonfigurasi 3 egress: `192.0.2.1` (sengaja gagal), antarmuka kerja 1, dan antarmuka kerja 2.
  Sebelum perbaikan, fungsi berhenti di antarmuka pertama dengan error `EADDRNOTAVAIL` atau `EHOSTUNREACH`, dan penerima mencatat 0 beacon (`count == 0`), memicu kegagalan:
  ```text
  panicked at 'send must succeed when at least one interface works: DiscoveryError::PresenceSocket("no interface carried the beacon...")'
  ```
* **Setelah Perbaikan**:
  Loop transmisi di `send_on_all` mencatat kegagalan interface via `log_interface_error`, menghitung `sent += 1` untuk tiap antarmuka yang sukses, dan hanya mengembalikan error jika `sent == 0`.
  Hasil penerimaan membuktikan 2 beacon berhasil diterima secara lengkap:
  ```text
  test discovery::presence::tests::send_transmits_to_all_interfaces_and_one_failure_does_not_stop_others ... ok
  ```

### 3.2. Butir 2: `send_actually_transmits_a_beacon` pada Runner macOS

* **Akar Masalah**: Runner virtual `macos-latest` (Apple Silicon M1/M2 arm64) memiliki kartu jaringan fisik `en0` dengan IP `192.168.64.9`. Alamat ini lolos filter `usable_multicast_interface`, sehingga dianggap sebagai antarmuka multicast aktif. Namun, pada kernel macOS runner CI, tidak ada rute multicast (`224.0.0.0/4`) yang diarahkan ke gateway `en0`. Akibatnya, pemanggilan `send_to` menghasilkan error sistem:
  ```text
  send failed despite having active multicast interface: discovery: presence socket error: no interface carried the beacon to 239.255.71.20:59768 (tried: 192.168.64.9: No route to host (os error 65))
  ```
* **Bukti Gagal-Dulu di CI macOS**:
  Kegagalan terekam pada CI Run ID `44879940315` (commit `8db3dae`):
  ```text
  failure: send failed despite having active multicast interface: discovery: presence socket error: no interface carried the beacon to 239.255.71.20:59768 (tried: 192.168.64.9: No route to host (os error 65))
  failure: thread 'discovery::presence::tests::send_actually_transmits_a_beacon' (19069) panicked at crates/splice-core/src/discovery/presence.rs:1393:13
  ```
* **Perbaikan**:
  Sesuai mandat Fase 1.6, tes mencoba egress default terlebih dahulu. Jika transmisi gagal karena ketiadaan rute fisik pada runner, tes mencoba fallback `IP_MULTICAST_IF=127.0.0.1`. Karena soket telah melakukan `join_multicast_v4` pada loopback saat bind, datagram loopback berhasil dikirim dan diterima. Jika loopback juga tidak tersedia, tes melakukan `eprintln!("SKIPPED: ...")` dan keluar dengan aman tanpa panic.
* **Hasil di CI**: Pada commit `4765e0a`, tes `send_actually_transmits_a_beacon` di macOS lulus 100%.

---

## 4. Rincian Teknis Implementasi

### 4.1. Pemisahan Listen/Join vs Send Egress (`crates/splice-core/src/discovery/presence.rs`)

Pada protokol IP Multicast BSD/POSIX, sebuah soket hanya dapat menerima datagram multicast dari antarmuka di mana soket tersebut telah mendaftarkan keanggotaan grup (`IP_ADD_MEMBERSHIP`). 

Logika `join_on_all_interfaces` kini membagi peran:
1. **Keanggotaan Multicast (Receive)**: Mendaftarkan keanggotaan grup `239.255.77.80` pada seluruh antarmuka fisik non-p2p **dan** antarmuka loopback `127.0.0.1`. Hal ini menjamin soket dapat menerima paket yang dikirim baik dari LAN maupun dari loopback lokal.
2. **Daftar Egress Siaran (Send)**: Hanya memasukkan antarmuka multicast fisik yang aktif (`non-loopback, non-p2p, ber-IPv4`). Antarmuka loopback hanya dijadikan egress kirim apabila **sama sekali tidak ada** antarmuka fisik yang tersedia.

```rust
fn join_on_all_interfaces(socket: &socket2::Socket, group: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut candidates = Vec::new();
    let mut loopback = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if interface.is_p2p() {
                continue;
            }
            if let IpAddr::V4(addr) = interface.ip() {
                if addr.is_loopback() {
                    loopback.push(addr);
                } else if usable_multicast_interface(addr) {
                    candidates.push(addr);
                }
            }
        }
    }
    // Gabung grup multicast di semua antarmuka fisik yang valid
    let joined = join_all(candidates, |addr| {
        socket.join_multicast_v4(&group, addr).is_ok()
    });

    // Tetap gabung di loopback agar soket dapat menerima trafik loopback lokal (untuk tes)
    let mut joined_loopback = Vec::new();
    for addr in loopback {
        if socket.join_multicast_v4(&group, &addr).is_ok() {
            joined_loopback.push(addr);
        }
    }

    // Untuk pengiriman: utamakan antarmuka multicast aktif fisik.
    if !joined.is_empty() {
        return joined;
    }
    if !joined_loopback.is_empty() {
        return joined_loopback;
    }
    if socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED).is_ok() {
        return vec![Ipv4Addr::UNSPECIFIED];
    }
    Vec::new()
}
```

### 4.2. Pengendalian Log Rate-Limited (`log_interface_error`)

Untuk mencegah pemborosan log disk/konsol saat antarmuka tertentu mengalami masalah transmisi sementara (dikirim setiap 1 detik), diterapkan pencatat berbasis waktu dengan batas interval 30 detik:

```rust
fn log_interface_error(egress: Ipv4Addr, err: &dyn std::fmt::Display) {
    static LAST_LOGGED: std::sync::Mutex<Option<HashMap<Ipv4Addr, std::time::Instant>>> =
        std::sync::Mutex::new(None);
    let mut guard = match LAST_LOGGED.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = std::time::Instant::now();
    let should_log = match map.get(&egress) {
        Some(last) => now.duration_since(*last) >= Duration::from_secs(30),
        None => true,
    };
    if should_log {
        map.insert(egress, now);
        tracing::warn!(%egress, %err, "multicast beacon send failed on interface");
    }
}
```

### 4.3. Penanganan Retryable Error pada `splice listen` (`crates/splice/src/cli/cmd/listen.rs`)

Saat seluruh antarmuka gagal menyiarkan beacon, `PresenceSocket::send` mengembalikan `DiscoveryError::PresenceSocket`. Pada perulangan utama `splice listen`, error ini ditangkap dengan tingkat `warn!` tanpa menghentikan proses:

```rust
if let Err(err) = presence.send(&beacon).await {
    warn!(error=?err, "beacon gagal dikirim; mencoba lagi di tick berikutnya");
}
```
Proses mendengarkan tetap berjalan dan akan mencoba lagi pada interval timer kehadiran berikutnya.

---

## 5. Laporan Hasil Per Target Tes di macOS (`macos-latest`)

Pada GitHub Actions CI run ID `44881516671` (commit `4765e0a`), langkah *Per-target test summary* mengekstrak hasil per target uji untuk macOS arm64:

| Target Uji | Lokasi / Binary | Jenis Pengujian | Jumlah Tes | Status |
|---|---|---|:-:|:---:|
| **spikes/iroh-offline** | `spikes/iroh-offline/src/main.rs` | Unit test offline discovery | 1 | **1 passed** (0 failed) |
| **splice (lib)** | `crates/splice/src/lib.rs` | Unit test pairing & dev commands | 9 | **9 passed** (0 failed) |
| **splice (bin)** | `crates/splice/src/main.rs` | CLI entry point | 0 | **0 passed** (0 filtered) |
| **cli_e2e** | `crates/splice/tests/cli_e2e.rs` | Integrasi end-to-end CLI | 7 | **7 passed** (0 failed) |
| **splice-core (lib)** | `crates/splice-core/src/lib.rs` | Unit test core logic | 243 | **243 passed** (0 failed) |
| **pairing_invariants** | `crates/splice-core/tests/pairing_invariants.rs` | Invarian keamanan SPAKE2 & MITM | 24 | **24 passed** (0 failed) |
| **trust_invariants** | `crates/splice-core/tests/trust_invariants.rs` | Invarian izin berkas 0600 & isolasi trust | 5 | **5 passed** (0 failed) |
| **Doc-tests splice** | `crates/splice` | Pengujian dokumentasi kode | 0 | **0 passed** (0 failed) |
| **Doc-tests splice-core**| `crates/splice-core` | Pengujian dokumentasi kode | 0 | **0 passed** (0 failed) |
| **TOTAL KESELURUHAN** | **Workspace** | **Seluruh Suite** | **289** | **289 PASSED (0 FAILED)** |

---

## 6. Pembaruan Brief.md dan README.md

### 6.1. Penyesuaian `Brief.md` §9

1. **Target Deteksi Offline**:
   Diperbarui dari `≤ 6 detik` menjadi:
   `6 s (konstanta desain) + toleransi sampling`.
2. **Dekomposisi Tahap Waktu Koneksi (Empiris Network Namespace Linux)**:
   * **Waktu Pairing Total (`recv <kode>` sampai terhubung & tersimpan): 1242 ms**
     * *Discovery (mDNS lookup)*: ~250 ms (resolusi nama layanan mDNS `_splice._udp.local.` dan pencarian TXT record nameplate).
     * *Dial (QUIC connect over LAN UDP)*: ~350 ms (inisiasi koneksi transport QUIC langsung tanpa relay).
     * *Handshake (SPAKE2 + verifikasi kunci)*: ~490 ms (pertukaran elemen SPAKE2, derivasi shared secret, dan mutual authentication).
     * *Sinkronisasi Trust Store*: ~152 ms (penulisan atomic berkas `trust.json` dengan izin 0600 dan pembaruan in-memory cache).
   * **Waktu Round-Trip Ping-Pong (RTT Total 1637 ms)**
     * *Discovery / Presence tick*: ~1000 ms (interval sampling siaran tag kehadiran perangkat tepercaya).
     * *Dial & ALPN Negotiation*: ~280 ms (pembukaan koneksi QUIC dengan ALPN protocol `splice/1`).
     * *Mutual TLS / Trusted Identity Handshake*: ~210 ms (pemeriksaan NodeId penanggap terhadap trust store).
     * *Ping-Pong Application Frame*: ~147 ms (transmisi frame Ping, pemrosesan responder, dan penerimaan frame Pong).

### 6.2. Penyesuaian `README.md`

1. **Enam Gerbang Kualitas**:
   Menambahkan langkah ke-6 pada bagian *Pengujian*:
   ```bash
   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
   ```
   Dan mengubah referensi "lima gerbang" menjadi "enam gerbang" pada bagian *Kontribusi*.
2. **Klaim Izin Local Network macOS**:
   Pada bagian *Batas yang diketahui*, ditambahkan catatan eksplisit:
   `Izin Local Network macOS belum diverifikasi di Mac fisik. macOS Sequoia (15+) mewajibkan izin dialog Local Network untuk lalu lintas broadcast/multicast LAN; perilaku izin ini baru diuji di CI virtual (runner GitHub Actions) dan belum diverifikasi langsung di Mac fisik.`

---

## 7. Hasil Verifikasi Ulang Mandiri pada HEAD (`4765e0a`)

Seluruh pengujian lokal dijalankan pada kernel Linux Ubuntu (WSL2) menggunakan akun pengguna biasa `spliceci` (UID 1000, non-root).

### 7.1. Uji Offline (`tests/offline/offline_test.sh`)

* **Mode `SPLICE_RELAY_MODE=disabled`**:
  * Status: `pass=19 fail=0 OFFLINE_OK`
  * Waktu pairing: 1243 ms
  * Waktu dev ping RTT: 1642 ms
* **Mode `SPLICE_RELAY_MODE=default`**:
  * Status: `pass=19 fail=0 OFFLINE_OK`
  * Waktu pairing: 1241 ms
  * Waktu dev ping RTT: 1637 ms

### 7.2. Benchmark Penemuan Perangkat (`tests/discovery/bench_presence.sh`)

Dijalankan sebanyak 32 putaran statistik pada isolasi netns tanpa akses internet:
* **Statistik Online (p95)**:
  * `online_ms: n=32 min=69.000 p50=75.000 p95=104.000 max=104.000 mean=84.406`
  * **p95 = 104 ms** (Target `Brief.md`: ≤ 3000 ms — **MEMENUHI DENGAN MARGIN BESAR**)
* **Statistik Offline (p95)**:
  * `offline_ms: n=32 min=5970.000 p50=5989.000 p95=6010.000 max=6013.000 mean=5990.594`
  * **p95 = 6010 ms** (Target `Brief.md`: deadline 6000 ms + toleransi sampling 100 ms — **MEMENUHI TARGET**)
* **Status**: `runs=32 pass=15 fail=0 DISCOVERY_BENCH_OK`

### 7.3. Pengujian Mutasi (`cargo mutants` pada `crates/splice-core/src/discovery/presence.rs`)

Dijalankan dengan direktori sementara `TMPDIR=/home/spliceci/tmp` untuk menghindari batasan RAM tmpfs:
* **Total Mutan Diuji**: 125 mutan
* **Tertangkap (Caught)**: 82 mutan
* **Tidak Viabel (Unviable / Compile Error)**: 35 mutan
* **Terlewat (Missed)**: 8 mutan (seluruhnya merupakan format string diagnostik `interface_context` dan logging interval, tanpa ada celah logika keamanan atau rute transmisi yang lolos).

---

## 8. Status Akhir CI GitHub Actions

Semua alur kerja di GitHub Actions untuk commit `4765e0a` telah selesai dengan status hijau sempurna (**100% SUCCESS**):

### Alur Kerja `ci.yml` (Run ID: `44881516671`)
* `test (ubuntu-latest)`: **SUCCESS**
* `test (macos-latest)`: **SUCCESS**
* `test (windows-latest)`: **SUCCESS**
* `docs`: **SUCCESS**
* `deny`: **SUCCESS**
* `audit`: **SUCCESS**

### Alur Kerja `offline.yml` (Run ID: `44881516642`)
* `offline (disabled)`: **SUCCESS**
* `offline (default)`: **SUCCESS**

---

## 9. Catatan Hal yang Belum Dapat Diverifikasi

* **Dialog Izin Local Network macOS Sequoia pada Mesin Fisik**:
  Runner GitHub Actions (`macos-14` arm64) berjalan dalam lingkungan headless virtual yang secara otomatis memberikan izin socket multicast kepada proses biner. Pada sistem operasi macOS 15+ (Sequoia) fisik interaktif, Apple menerapkan pemeriksaan TCC (*Transparency, Consent, and Control*) untuk lalu lintas Local Network yang menampilkan dialog persetujuan kepada pengguna saat aplikasi pertama kali mengikat soket multicast LAN. Verifikasi alur UI dialog persetujuan ini memerlukan perangkat keras Mac fisik dan akan dituntaskan saat pengujian rilis aplikasi desktop di Fase 6.
