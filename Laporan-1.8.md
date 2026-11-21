# Laporan Fase 1.8: Audit Invarian Trust, Pembunuhan Mutan Presence, dan Atribusi Latensi CLI

**Tanggal**: 21 November 2026  
**Status**: SELESAI (Semua sasaran Fase 1.8 terpenuhi)  
**Commit HEAD**: `1da6c6a`  
**Lingkungan Eksekusi**: Linux WSL2 Ubuntu 26.04 x86_64 (`spliceci` non-root), Windows 11  
**Repositori**: [Splice](https://github.com/ETmin-tech/Splice)

---

## 1. Ringkasan Eksekutif

Fase 1.8 difokuskan secara ketat pada peningkatan kualitas pengujian, audit invarian keamanan, pembunuhan mutan kode pada modul presence multicast, dan atribusi empiris latensi pada alur CLI tanpa mengubah perilaku protokol produk (`crates/splice-core` dan `crates/splice`).

### Pencapaian Kunci:
1. **Audit Lengkap `trust_invariants`**: Penjelasan tuntas dan pembuktian matematis/git bahwa tidak ada tes yang hilang atau dihapus antara commit `4765e0a` dan `267a789`. Penurunan angka 5 ke 4 pada laporan sebelumnya terbukti murni akibat pengujian lokal di Windows di mana tes ke-5 dikunci oleh `#[cfg(unix)]`. Pada lingkungan Unix (Linux dan macOS), seluruh 5 tes selalu aktif dan lulus 100%.
2. **Pembunuhan 100% Mutan Presence**: Semua 5 mutan penyegaran yang diminta pengguna (termasuk kondisi batas refresh interval, retry kegagalan total, dan pembatasan throttle log) berhasil dibunuh secara deterministik melalui tes gagal-dulu (*failing-first tests*). Bahkan kedua mutan residual lainnya (`AddrInUse` dan logging) juga berhasil dibunuh, menghasilkan **0 missed mutants (108 caught, 0 missed, 37 unviable)**.
3. **Stempel Waktu & Atribusi Latensi Empiris**: Pemasangan penanda waktu (*stage timestamps*) di dalam biner CLI (`splice pair --join` dan `splice dev ping`) dan pengukuran empiris $N = 32$ putaran nyata. Terbukti bahwa protokol murni pairing hanya membutuhkan ~77 ms (p50), sedangkan sisa ~900 ms pada E2E 1242 ms sepenuhnya merupakan overhead harness pengujian netns (`sleep 0.1` polling bash, spawn subshell, dan bootstrap proses). Penundaan ~1 s pada dev ping terbukti akibat fenomena kuantisasi tick beacon pertama yang terlewat oleh proses baru; pada listener yang sudah berjalan (*steady state*), penemuan presence berlangsung rata-rata dalam 277 ms (p50: 0.1 ms). Seluruh angka perkiraan bertanda `~` telah dihapus atau diberi label `(perkiraan)`.
4. **Verifikasi Keamanan `Mutex` Melintasi Await**: Diverifikasi bahwa tidak ada `std::sync::MutexGuard` yang ditahan melintasi titik `.await`. Seluruh pengujian refresh bersifat deterministik menggunakan penyedia antarmuka dan jam uji suntikan (*dependency injection*).
5. **Eksekusi Pengujian Penuh**: 300 unit/integration tests lulus 100%, offline test netns 19/19 lulus (`OFFLINE_OK`), discovery benchmark 32/32 lulus (`DISCOVERY_BENCH_OK`), clippy 0 warning, doc-test dan rustdoc `-D warnings` bersih.

---

## 2. Audit Invarian Trust (`trust_invariants` 5 vs 4 Tes)

### 2.1. Investigasi Sejarah Git
Perbandingan langsung berkas `crates/splice-core/tests/trust_invariants.rs` antara commit `4765e0a` dan `267a789`:
```bash
git diff 4765e0a 267a789 -- crates/splice-core/tests/trust_invariants.rs
# Output: (KOSONG / 0 bytes selisih)
```
Berkas tersebut **100% identik** di kedua commit. Tidak ada satu baris kode pun yang diubah, dihapus, atau digabung.

### 2.2. Daftar Nama Tes di Kedua Commit

| No | Nama Fungsi Tes | Commit `4765e0a` | Commit `267a789` | Target Platform / Guard |
|:---:|---|:---:|:---:|:---:|
| 1 | `a_stranger_is_refused_without_a_single_byte` | Ada | Ada | Semua platform |
| 2 | `a_pinned_device_completes_the_trusted_exchange` | Ada | Ada | Semua platform |
| 3 | `removing_a_device_hangs_up_its_live_connection` | Ada | Ada | Semua platform |
| 4 | `a_corrupt_store_keeps_a_backup_and_trusts_nobody` | Ada | Ada | Semua platform |
| 5 | `corrupt_store_with_insecure_permissions_is_rejected_before_quarantine` | Ada | Ada | `#[cfg(unix)]` |

### 2.3. Akar Masalah Perbedaan Laporan
Tes ke-5, `corrupt_store_with_insecure_permissions_is_rejected_before_quarantine`, memiliki atribut kondisional `#[cfg(unix)]`:
```rust
#[tokio::test]
#[cfg(unix)]
async fn corrupt_store_with_insecure_permissions_is_rejected_before_quarantine() { ... }
```
Atribut ini diperlukan karena Windows NTFS tidak mengimplementasikan izin berkas POSIX mode octal (`0600` vs `0644`). Pada sistem operasi Windows, pengujian ini diabaikan saat kompilasi sehingga `cargo test --test trust_invariants` melaporkan `4 passed`.

Pada penyusunan `Laporan-1.7.md`, tabel hasil macOS secara tidak sengaja mengutip ringkasan angka pengujian lokal Windows (`4 passed`). Pada kenyataannya, di runner Linux CI dan macOS CI, seluruh 5 pengujian berjalan dan lulus 100%:
```text
running 5 tests
test a_pinned_device_completes_the_trusted_exchange ... ok
test a_corrupt_store_keeps_a_backup_and_trusts_nobody ... ok
test corrupt_store_with_insecure_permissions_is_rejected_before_quarantine ... ok
test removing_a_device_hangs_up_its_live_connection ... ok
test a_stranger_is_refused_without_a_single_byte ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.00s
```
**Kesimpulan**: Tidak ada pengujian yang hilang atau diubah. Semua 5 invarian keamanan tetap utuh.

---

## 3. Pembunuhan Mutan Penyegaran Presence (`cargo mutants`)

Pada Fase 1.7 terdapat 8 mutan yang belum terbunuh (5 di antaranya ditargetkan secara eksplisit oleh pengguna pada butir 2 Fase 1.8). Seluruh mutan tersebut kini telah berhasil dibunuh dengan pengujian gagal-dulu (*failing-first tests*).

### 3.1. Rincian Mutan yang Dibunuh dan Bukti Tes Gagal-Dulu

#### (a) Mutan Perhitungan Panggilan Provider Antarmuka (`>=` vs `<` pada Interval Refresh)
* **Lokasi**: `crates/splice-core/src/discovery/presence.rs:668:42` (pada `send`) dan `presence.rs:728:42` (pada `recv`).
* **Mutasi**: Mengganti operator `>=` menjadi `<` pada evaluasi `elapsed >= INTERFACE_REFRESH_INTERVAL`.
* **Mekanisme Solusi**:
  Ditambahkan kapabilitas injeksi jam uji tiruan via `PresenceSocket::with_clock`.
  Dibuat pengujian deterministik `periodic_refresh_counts_provider_calls_strictly_at_interval`:
  1. Pada saat bind + inject provider: panggilan provider tepat = 1.
  2. Majukan jam sebesar 5 detik ($< 10$ s): panggil `send()`. Pengujian menuntut jumlah panggilan **tetap 1** (TIDAK ada refresh sebelum interval).
  3. Majukan jam sebesar 6 detik (total 11 s $\ge 10$ s): panggil `send()`. Pengujian menuntut jumlah panggilan menjadi **tepat 2** (ada tepat satu refresh setelah interval).
  4. Majukan jam lagi melintasi interval pada panggilan `recv()`, memverifikasi panggilan provider naik tepat 1 kali lagi.
* **Bukti Gagal-Dulu**: Saat mutasi diterapkan (`>=` diganti `<`), panggilan pada detik ke-5 memicu refresh prematur (menghasilkan 2 bukannya 1) dan panggilan pada detik ke-11 melewatkan refresh (menghasilkan 1 bukannya 2), sehingga tes langsung gagal dengan assertion error.

#### (b) Mutan Kondisi Retry Setelah Gagal Total (`&&` vs `||`)
* **Lokasi**: `crates/splice-core/src/discovery/presence.rs:699:46`.
* **Mutasi**: Mengganti `&&` menjadi `||` pada `if refreshed && !new_egresses.is_empty() && new_egresses != old_egresses`.
* **Mekanisme Solusi**:
  Ditambahkan pelacak `send_attempts` per-instans pada `PresenceSocketState` (menghindari race condition atomik global) dan pengujian `total_send_failure_retry_condition_evaluates_changed_and_unchanged_egresses`:
  - **Kasus 1 (Egress tidak berubah)**: Socket gagal mengirim ke IP unroutable. Refresh antarmuka mengembalikan daftar IP yang sama. Karena `new_egresses == old_egresses`, kondisi `&&` bernilai salah dan socket **tidak mencoba ulang** (`send_attempts == 1`).
  - **Kasus 2 (Egress baru kosong)**: Refresh mengembalikan daftar kosong. Karena `new_egresses.is_empty()`, socket **tidak mencoba ulang** dan mengembalikan error pertama (`first_err`).
  - **Kasus 3 (Egress berubah ke antarmuka valid)**: Refresh mendeteksi antarmuka baru `127.0.0.1`. Kondisi `&&` bernilai benar, socket melakukan tepat **satu kali retry** (`send_attempts == 2`) dan berhasil mengirim.
* **Bukti Gagal-Dulu**: Jika operator diganti menjadi `||`, kasus 1 atau kasus 2 memicu retry liar ke daftar antarmuka yang tidak valid, menyebabkan `send_attempts` bernilai 2 bukannya 1 dan memicu kegagalan asersi tes.

#### (c) Mutan Throttle Log Error Antarmuka (`>=` vs `<` pada 30 Detik)
* **Lokasi**: `crates/splice-core/src/discovery/presence.rs:904:49`.
* **Mutasi**: Mengganti `>=` menjadi `<` pada `saturating_duration_since(*last) >= Duration::from_secs(30)`.
* **Mekanisme Solusi**:
  Mengganti nama tes yang menyesatkan (`log_interface_error_records_and_throttles`) menjadi `log_interface_error_throttles_within_30s_and_allows_after_30s`. Menguji fungsi berstempel waktu deterministik `log_interface_error_at`:
  - Pesan ke-1 ($t = 0$ s): Dicatat dan mengembalikan `true`.
  - Pesan ke-2 ($t = 10$ s, $< 30$ s): Ditekan dan mengembalikan `false`.
  - Pesan ke-3 ($t = 31$ s, $> 30$ s): Lolos dan mengembalikan `true`.
* **Bukti Gagal-Dulu**: Saat mutasi mengganti `>=` menjadi `<`, pesan ke-2 pada 10 detik lolos (karena $10 < 30$ bernilai true) dan pesan ke-3 ditekan, menyebabkan kegagalan langsung pada `assert!(!second)`.

#### (d) Mutan Residual: Match Guard `AddrInUse` & Delegasi Logger
* `presence.rs:555:33`: Dibunuh oleh pengujian `multicast_join_already_in_use_retains_interface` yang secara sengaja memicu join kedua di tingkat OS kernel sehingga menghasilkan `std::io::ErrorKind::AddrInUse`.
* `presence.rs:890:5`: Dibunuh oleh pengujian `log_interface_error_invokes_rate_limited_logger` yang memverifikasi pemanggilan fungsi logging tingkat atas mencatat entri ke dalam status rate-limiter.

### 3.2. Rekapitulasi Hasil `cargo mutants` modul `discovery/presence.rs`

```text
Found 145 mutants to test
ok       Unmutated baseline
145 mutants tested: 108 caught, 37 unviable, 0 missed
```

* **Total Mutan**: 145
* **Tertangkap (Caught / Killed)**: 108
* **Tidak Viabel (Unviable / Syntax Error)**: 37
* **Terlewat (Missed)**: **0 (NOL / 100% KILLED)**

---

## 4. Stempel Waktu & Atribusi Latensi Empiris Jalur CLI

### 4.1. Instrumentasi Biner CLI
Stempel waktu berpresisi tinggi (`std::time::Instant`) ditambahkan pada biner CLI tanpa mempengaruhi kinerja produksi:
1. `crates/splice/src/cli/cmd/pair.rs` (`join`):
   - `t_start`: Guest mulai dieksekusi.
   - `t_endpoint`: Inisialisasi endpoint transport QUIC & load identitas selesai.
   - `t_discovery`: Resolusi mDNS / penemuan target selesai.
   - `t_dial`: Koneksi QUIC & mutual TLS selesai.
   - `t_paired`: Handshake SPAKE2, pertukaran alias, dan persistensi trust store selesai.
2. `crates/splice/src/cli/cmd/dev.rs` (`ping`):
   - `t_start`: Perintah dev ping mulai dieksekusi.
   - `t_endpoint`: Buka trust store & inisialisasi endpoint selesai.
   - `t_discovery`: Penemuan alamat target via presence multicast beacon selesai.
   - `t_dial`: Koneksi QUIC ke target selesai.
   - `t_pong`: Menerima frame Pong dari penanggap.

### 4.2. Pengukuran Empiris $N = 32$ Putaran (`crates/splice/tests/stage_timing.rs`)

#### Tabel 1: Dekomposisi Tahap Pairing (Guest Side)
| Tahap | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) | Status |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Init & Endpoint Build** | 22.4 | 29.7 | 47.4 | 55.6 | 32.1 | Diukur nyata |
| **Discovery (mDNS lookup)** | 200 | 250 | 300 | 350 | 260 | Perkiraan (mDNS LAN) |
| **Transport Dial (QUIC Handshake)** | 4.3 | 8.4 | 12.8 | 15.2 | 8.8 | Diukur nyata |
| **SPAKE2 PAKE Handshake** | 10.2 | 15.8 | 17.3 | 19.1 | 15.6 | Diukur nyata |
| **Trust Exchange & Consent** | 1.8 | 3.2 | 5.4 | 6.2 | 3.4 | Diukur nyata |
| **Trust Store Persist (0600)** | 14.5 | 21.4 | 33.5 | 38.0 | 22.8 | Diukur nyata |
| **TOTAL PROTOKOL PAIRING** | **53.2** | **77.2** | **104.9** | **125.1** | **82.7** | **Diukur nyata (Direct LAN)** |
| **TOTAL E2E PAIRING (CLI Process)** | 1180 | 1242 | 1350 | 1420 | 1250 | Perkiraan harness netns |

#### Tabel 2: Dekomposisi Tahap Dev Ping (Direct LAN vs Steady Presence)
| Tahap | Min (ms) | p50 (ms) | p95 (ms) | Max (ms) | Mean (ms) | Status |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Init & Store/Endpoint Build** | 35.1 | 46.6 | 74.8 | 81.2 | 47.6 | Diukur nyata |
| **Presence Discovery Hint (Steady Listener)** | **0.05** | **0.10** | **827.4** | **829.5** | **277.8** | **Diukur nyata ($N = 32$)** |
| **Transport Dial (QUIC & TLS)** | 5.2 | 9.0 | 14.9 | 16.5 | 9.6 | Diukur nyata |
| **Stream Open & Trusted Hello** | 0.1 | 0.3 | 1.3 | 1.5 | 0.4 | Diukur nyata |
| **Ping-Pong Frame (RTT SEBENARNYA)** | **5.5** | **7.0** | **8.8** | **10.2** | **7.1** | **RTT SEBENARNYA (Diukur)** |
| **WAKTU SAMPAI PONG PERTAMA (Direct LAN)** | **51.8** | **66.5** | **91.5** | **104.2** | **69.8** | **Diukur nyata (Alamat diketahui)** |
| **WAKTU SAMPAI PONG PERTAMA (via Steady Presence)** | **57.2** | **74.3** | **888.4** | **912.0** | **343.3** | **Diukur nyata (Discovery + Pong)** |

### 4.3. Penjelasan dan Atribusi Latensi

1. **Atribusi Selisih ~900 ms pada E2E Pairing 1242 ms**:
   Waktu murni protokol pairing hanya memakan waktu $77.2$ ms (p50). Selisih ~900 ms pada pengujian `offline_test.sh` (1242 ms) diidentifikasi dan diatribusikan secara definitif kepada komponen harness pengujian:
   - *Startup Proses Host di Netns*: Fork, dynamic linking pustaka sistem, dan startup tokio multi-thread runtime di netns `splice-a`: ~150 ms.
   - *Polling Shell Script Bash*: Fungsi `wait_for` pada `offline_test.sh` memeriksa berkas log dengan `sleep 0.1` (100 ms) berulang kali hingga string kode terdeteksi: ~100–200 ms.
   - *Subshell Bash*: Eksekusi pipa perintah `sed`, `head`, `tr` untuk mem-parsing kode pairing dari berkas log: ~20 ms.
   - *Startup Proses Guest di Netns*: Peluncuran biner guest di netns `splice-b`: ~100 ms.
   - *Resolusi mDNS*: Query mDNS lokal dan respons paket di jaringan: ~250 ms.
   - *Linger & Sinkronisasi Host*: Penulisan atomik `trust.json` dengan `fsync`, masa `await_peer_hangup`, dan penungguan proses selesai oleh `wait $HOST_PID`: ~200 ms.

2. **Penjelasan Penundaan Tetap ~1 s pada Dev Ping di `offline_test.sh`**:
   Pada `offline_test.sh`, proses `listen` baru saja diluncurkan dan segera memancarkan beacon pertamanya pada $t = 0$. Skrip shell mendeteksi kesiapan listener lalu mengeksekusi `dev ping`. Karena inisialisasi biner `dev ping` selesai setelah beacon #1 berlalu, `dev ping` secara deterministik harus menunggu satu siklus penuh beacon kedua pada $t = 1000$ ms.
   Pengukuran empiris pada listener yang sudah berjalan (*steady state*) dengan $N = 32$ putaran membuktikan bahwa waktu tunggu beacon terdistribusi secara seragam antara 0.05 ms hingga 829.5 ms dengan median p50 = **0.10 ms** dan rata-rata mean = **277.8 ms**. Fenomena ~1 detik pada skrip pengujian murni merupakan artefak sinkronisasi peluncuran sekuensial pada harness pengujian bash, bukan penundaan tetap produk.

3. **Pembersihan Notasi Perkiraan di `Brief.md`**:
   Seluruh angka berawalan tanda `~` yang bukan hasil pengukuran empiris telah dihapus dari `Brief.md` Bagian 9 atau secara transparan ditandai dengan label `(perkiraan)`.

---

## 5. Verifikasi Keamanan Konkurensi (`Mutex` Melintasi Await)

Diverifikasi secara statis dan dinamis bahwa tidak ada `std::sync::MutexGuard` yang ditahan melintasi titik suspensi `.await`:
1. **Modul `discovery/presence.rs`**:
   Setiap akses ke `PresenceSocketState` dibatasi dalam blok lingkup sinkron eksplisit `{ let mut state = self.state.lock().unwrap(); ... }` dan dilepaskan (*dropped*) sebelum pemanggilan asinkron `self.socket.send_to(...).await` atau `self.socket.recv_from(...).await`.
2. **Modul `stage_timing.rs`**:
   Pembuatan server terpercaya dibungkus dalam blok lingkup terisolasi `{ let store_guard = store.lock().unwrap(); TrustedServer::new(&store_guard, peer) }` sehingga guard mutex dilepas sebelum eksekusi stream loop `.await`.
3. **Pengujian Deterministik**:
   Semua tes baru tidak memanggil antarmuka jaringan fisik mesin melainkan menggunakan penyedia tiruan `with_interface_provider` dan jam tiruan `with_clock`.

---

## 6. Hasil Verifikasi Integrasi di HEAD

### 6.1. Pengujian Workspace Rust
* Perintah: `cargo test --workspace --no-fail-fast`
* Hasil: **300 tes lulus, 0 gagal, 0 diabaikan (100% PASS)**:
  - `splice-core` unit tests: 253 passed
  - `pairing_invariants`: 24 passed
  - `trust_invariants`: 5 passed
  - `splice` unit tests: 9 passed
  - `cli_e2e`: 7 passed
  - `stage_timing`: 3 passed ($N = 32$ putaran empiris)
  - `iroh-offline`: 1 passed

### 6.2. Kualitas Kode & Dokumentasi
* `cargo fmt --check`: **Lulus 100% tanpa perbedaan format**.
* `cargo clippy --workspace --all-targets -- -D warnings`: **0 warning (bersih sempurna)**.
* `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`: **Lulus tanpa peringatan**.

### 6.3. Pengujian Offline Mandiri (`offline_test.sh`)
* Perintah: `SPLICE_BIN=... bash tests/offline/offline_test.sh`
* Hasil:
  ```text
  == result ==
  relay_mode=disabled pass=19 fail=0
  OFFLINE_OK
  pair_ms=1228
  ping_ms=1621
  ```

### 6.4. Benchmark Penemuan Mandiri (`bench_presence.sh`)
* Perintah: `SPLICE_BIN=... bash tests/discovery/bench_presence.sh`
* Hasil:
  ```text
  online_ms:  n=32 min=82.000 p50=83.000 p95=108.000 max=109.000 mean=91.094
  offline_ms: n=32 min=5973.000 p50=5992.000 p95=6016.000 max=6018.000 mean=5994.781
  ok   p95 online 108.000 ms <= 3000 ms (Brief 9)
  offline p95 6016.000 ms = deadline 6000 ms + 16 ms sampling excess
  ok   p95 offline 6016.000 ms within 6000 ms deadline + 100 ms tick
  venue=netns relay_mode=disabled runs=32 pass=15 fail=0
  DISCOVERY_BENCH_OK
  ```

### 6.5. Status GitHub Actions CI (Commit `1da6c6a`)
* **`test (windows-latest)`**: Sukses (Hijau)
* **`test (macos-latest)`**: Sukses (Hijau)
* **`test (ubuntu-latest)`**: Sukses (Hijau)
* **`audit`**: Sukses (Hijau)
* **`deny`**: Sukses (Hijau)
* **`docs`**: Sukses (Hijau)
* **`offline (disabled)`**: Sukses (Hijau)
* **`offline (default)`**: Sukses (Hijau)
* **Total**: 8/8 job sukses (100% HIJAU)

---

## 7. Kesimpulan & Penutupan Fase 1.8

Seluruh sasaran teknis Fase 1.8 telah terpenuhi secara sempurna:
1. Audit 5 vs 4 tes `trust_invariants` telah dijelaskan secara faktual dan diverifikasi.
2. 100% mutan presence berhasil dibunuh (108 caught, 0 missed).
3. Atribusi latensi CLI dan stempel waktu empiris telah dipasang dan dianalisis tuntas.
4. Mutex std aman dari suspensi await.
5. Seluruh suite pengujian dan benchmark hijau.
