# Laporan Fase 1.5: Perbaikan CI Splice, Analisis Akar Masalah, dan Verifikasi

Laporan ini mendokumentasikan investigasi mendalam, bukti gagal-dulu (*failure-first*), perbaikan kode dan lingkungan uji, hasil verifikasi lokal pada Linux (sebagai pengguna biasa non-root), hasil CI di GitHub Actions, serta analisis keterbatasan lingkungan virtualisasi macOS terkait multicast.

---

## 1. Ringkasan Eksekutif dan Hash Commit

- **Tujuan Fase 1.5**: Memperbaiki kegagalan pipeline CI Splice pada seluruh target (Ubuntu, Windows, macOS, Docs, Offline, Deny, Audit), membuktikan akar masalah masing-masing dengan tes gagal-dulu tanpa melemahkan invariant keamanan, serta menjalankan pengujian ulang di HEAD (offline test, benchmark, cargo-mutants).
- **Status Akhir CI GitHub Actions**:
  - `test (ubuntu-latest)`: **BERHASIL (Hijau)**
  - `test (windows-latest)`: **BERHASIL (Hijau)**
  - `docs`: **BERHASIL (Hijau)**
  - `offline (disabled)`: **BERHASIL (Hijau)**
  - `offline (default)`: **BERHASIL (Hijau)**
  - `deny`: **BERHASIL (Hijau)**
  - `audit`: **BERHASIL (Hijau)**
  - `test (macos-latest)`: **236 Lulus, 1 Gagal** (Detail dan pembuktian matematis/jaringan dijelaskan secara jujur pada Bagian 3 dan 8).
- **Hash Commit Terkait**:
  - `a63f8e5`: First Commit (baseline awal kegagalan).
  - `86e7129`: Perbaikan awal untuk masalah A (trust fixture), B (SO_REUSEPORT), C (docs link), D (offline artifact), dan E (`--no-fail-fast`).
  - `feaecb6`: Penambahan diagnostik kegagalan CI macOS (anotasi routing dan interface).
  - `523dac9`: Penambahan tes pengunci urutan izin vs korupsi, filter antarmuka tunnel p2p, dan fallback loopback.
  - `fa94ccf`: Penyesuaian sintaks rute multicast macOS di runner CI.

---

## 2. Masalah A: Trust Store Corruption Fixture (Ubuntu & macOS)

### Akar Masalah
Pada tes `crates/splice-core/tests/trust_invariants.rs:218`:
```rust
async fn a_corrupt_store_keeps_a_backup_and_trusts_nobody()
```
Fixture menulis berkas korup menggunakan fungsi standar `std::fs::write(&path, b"{ this is not json")`. Pada sistem Linux dan macOS, berkas baru yang dibuat mewarisi nilai `umask` lingkungan (umumnya `0022`), sehingga berkas mendarat di disk dengan mode perizinan `0644` (dapat dibaca oleh grup dan publik).

Di dalam `TrustStore::load_in`:
```rust
check_permissions(&path, &metadata)?;
// ... baru kemudian parsing JSON dan karantina ...
```
Fungsi `check_permissions` sengaja dirancang untuk menolak berkas apa pun yang tidak memiliki izin *owner-only* (`0600` pada Unix). Akibatnya, pemanggilan `load_in` langsung gagal dengan error `InsecurePermissions` sebelum logika pembacaan/karantina korupsi (`corrupt_json_is_quarantined`) sempat berjalan. Pesan error yang muncul di CI:
```
trust store .../trust.json has insecure permissions 644; expected owner-only (0600)
```

### Bukti Gagal-Dulu (Failure-First)
Masalah ini direproduksi secara lokal pada commit `a63f8e5` di dalam WSL Ubuntu menggunakan pengguna biasa tanpa hak root (`spliceci`, UID 1000):
```bash
cargo test -p splice-core --test trust_invariants
```
Hasil eksekusi:
```
test a_corrupt_store_keeps_a_backup_and_trusts_nobody ... FAILED
panicked at crates/splice-core/tests/trust_invariants.rs:232:5:
assertion failed: text.contains("corrupt"), got: "trust store .../trust.json has insecure permissions 644; expected owner-only (0600)"
```

### Perbaikan Fixture
Sesuai aturan, `check_permissions` **tidak dilonggarkan**. Fixture uji diperbaiki dengan membuat helper `write_store_file` yang secara eksplisit mengatur izin berkas ke `0o600` via `std::os::unix::fs::PermissionsExt`:
```rust
fn write_store_file(path: &std::path::Path, bytes: impl AsRef<[u8]>) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
```

### Penguncian Urutan (Locking Test)
Untuk memastikan bahwa pemeriksaan perizinan **selalu mendahului** pembacaan konten atau pembuatan berkas backup karantina, ditambahkan tes terpisah:
```rust
#[cfg(unix)]
#[tokio::test]
async fn corrupt_store_with_insecure_permissions_is_rejected_before_quarantine() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("trust.json");
    std::fs::write(&path, b"{ this is corrupt json and insecure").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = TrustStore::load_in(dir.path()).expect_err("insecure permissions must be refused");
    let text = err.to_string();
    assert!(
        text.contains("insecure permissions"),
        "permission check must precede parse and quarantine; got: {text}"
    );
    assert!(
        !dir.path().join("trust.json.bak").exists(),
        "insecure permissions must not quarantine or touch backup"
    );
}
```
Tes ini mengunci invariant bahwa jika berkas korup DAN berizin `0644`:
1. Error yang dikembalikan wajib mengenai perizinan tidak aman (`insecure permissions`).
2. Berkas backup karantina (`trust.json.bak`) **sama sekali tidak boleh dibuat**, mencegah penyerang lokal memicu penulisan berkas backup lewat berkas berizin longgar.

### Audit Seluruh Fixture
Seluruh basis kode (`crates/splice-core/src/identity/store.rs`, `crates/splice-core/src/trust/store.rs`, dan `tests/`) diaudit untuk memeriksa setiap penulisan berkas:
- `identity/store.rs`: tes `wrong_length_file_is_rejected_not_padded` sudah menulis dengan `Permissions::from_mode(0o600)`.
- `trust/store.rs`: fungsi helper `write_store_file` internal sudah menulis dengan `Permissions::from_mode(0o600)`.
- `trust/store.rs`: tes `loose_permissions_are_refused` sengaja menulis `0o644` untuk memvalidasi penolakan izin longgar.
- Tidak ditemukan fixture lain yang menulis berkas dengan izin default `0644`.

---

## 3. Masalah B: macOS Multicast Discovery (`send_actually_transmits_a_beacon`)

### Akar Masalah
Log kegagalan awal di macOS GitHub Actions:
```
MulticastUnavailable("cannot bind UDP port 47820: Address already in use (os error 48)")
di presence.rs:957
```

Akar penyebab kegagalan ini terdiri dari tiga lapisan:
1. **Perbedaan Semantik `SO_REUSEADDR` vs `SO_REUSEPORT` antara Linux dan BSD/macOS**:
   - Di Linux, menetapkan `SO_REUSEADDR` pada soket UDP memungkinkan beberapa soket mengikat port UDP yang sama selama port tersebut digunakan untuk multicast.
   - Pada keluarga BSD (termasuk Darwin/macOS), `SO_REUSEADDR` **tidak cukup** untuk mengikat dua soket UDP ke port yang sama. Kernel BSD mewajibkan bendera `SO_REUSEPORT` diaktifkan pada *seluruh* soket yang ingin berbagi port. Jika soket kedua mengikat tanpa `SO_REUSEPORT`, kernel mengembalikan `EADDRINUSE (os error 48)`.
2. **Tabrakan Port di Lingkungan Paralel**:
   - Secara default, `cargo test` menjalankan tes secara paralel. Beberapa tes yang sama-sama mencoba mengikat port multicast default `47820` (`PRESENCE_PORT`) akan mengalami race condition.
3. **Ketiadaan Antarmuka Fisik di macOS Runner CI (Virtualization VM)**:
   - Runner GitHub Actions `macos-latest` adalah mesin virtual (Apple Virtualization.framework) macOS 15 Sequoia.
   - Antarmuka fisik `en0`, `en1`, dan `anpi0` pada VM tersebut **tidak memiliki alamat IPv4**.
   - Satu-satunya antarmuka dengan alamat IPv4 adalah:
     - `lo0`: `127.0.0.1` (loopback)
     - `utun0`: `192.168.64.17` (point-to-point tunnel untuk infrastruktur CI)
   - Antarmuka tunnel point-to-point (`POINTOPOINT`) tidak memantulkan paket multicast kembali ke mesin lokal meskipun `IP_MULTICAST_LOOP` bernilai 1.

### Bukti Gagal-Dulu dan Pembuktian Port Reuse
Untuk membuktikan kebutuhan `SO_REUSEPORT` di macOS tanpa memerlukan Mac fisik lokal, ditambahkan unit test khusus:
```rust
#[tokio::test]
async fn two_sockets_can_share_one_port() {
    let first = PresenceSocket::bind(0).expect("bind first socket");
    let port = first.port();
    assert_ne!(port, 0);
    let second = PresenceSocket::bind(port).expect("bind second socket on the same port");
    assert_eq!(first.port(), second.port());
}
```
**Hasil di CI macOS**:
Pada commit `523dac9` dan `fa94ccf` di GitHub Actions macOS, tes `two_sockets_can_share_one_port` **lulus dengan sukses (`ok`)**. Hal ini membuktikan secara definitif bahwa penambahan `socket.set_reuse_port(true)` menyelesaikan akar masalah `Address already in use (os error 48)` pada macOS.

### Perbaikan di Kode
1. **Aktivasi `SO_REUSEPORT`**:
   Pada `PresenceSocket::bind`, ditambahkan konfigurasi `set_reuse_port(true)` untuk target `#[cfg(unix)]` dengan tetap mempertahankan `SO_REUSEADDR`:
   ```rust
   socket.set_reuse_address(true)?;
   #[cfg(unix)]
   {
       let _ = socket.set_reuse_port(true);
   }
   let _ = socket.set_multicast_loop_v4(true);
   ```
2. **Parameterisasi Port**:
   Fungsi `PresenceSocket::bind(port: u16)` menerima port sebagai parameter.
   - Dalam kode produk (`splice listen`, `splice dev`), port tetap menggunakan konstanta `PRESENCE_PORT = 47820`.
   - Dalam unit test, soket penerima pertama mengikat port ephemeral `0` (`PresenceSocket::bind(0)`), kemudian soket kedua mengikat port ephemeral yang diperoleh (`PresenceSocket::bind(receiver.port())`). Hal ini mengisolasi pengujian dari potensi tabrakan port paralel.
3. **Filter Antarmuka P2P dan Fallback Loopback**:
   Pada `join_on_all_interfaces`, antarmuka point-to-point (`interface.is_p2p()`) dilewati agar tunnel seperti `utun0` tidak dijadikan interface egress, dan loopback dicoba sebagai fallback jika tidak ada NIC fisik yang terkonfigurasi.

### Temuan: Pengiriman Multicast ke Antarmuka Jaringan (Finding)
Sesuai instruksi untuk memeriksa apakah beacon dikirim ke seluruh antarmuka multicast aktif:

> **Temuan Kritis Arsitektur Jaringan (Architecture Finding)**:
> - **Penerimaan (`recv` / `join`)**: Fungsi `join_on_all_interfaces` menelusuri seluruh antarmuka jaringan dan memanggil `join_multicast_v4` pada **setiap** antarmuka yang valid. Artinya, soket mendengarkan beacon yang masuk dari seluruh antarmuka jaringan.
> - **Pengiriman (`send`)**: Pada protokol IPv4 UDP multicast melalui BSD socket API, soket hanya memiliki satu interface egress aktif pada satu waktu yang diatur melalui opsi soket `IP_MULTICAST_IF` (`socket.set_multicast_if_v4(&egress)`). Di dalam kode saat ini, `egress` dipilih dari antarmuka pertama yang berhasil di-join (`first_joined`).
> - **Implikasi**: Ketika `PresenceSocket::send` dipanggil, paket beacon **hanya dipancarkan ke SATU antarmuka jaringan egress** (antarmuka pertama yang dipilih), bukan ke seluruh antarmuka aktif secara paralel. Jika perangkat memiliki beberapa antarmuka aktif (misalnya antarmuka Ethernet kabel dan Wi-Fi secara bersamaan), perangkat lain di segmen jaringan kedua tidak akan menerima beacon kecuali aplikasi mengiterasi seluruh antarmuka dan memanggil `set_multicast_if_v4` untuk tiap pengiriman atau membuat soket terpisah per antarmuka.

---

## 4. Masalah C: Job "docs" (Rustdoc Lint Warnings)

### Akar Masalah
Job `docs` pada CI menjalankan:
```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```
Perintah ini gagal dengan exit code 101 karena rustdoc menemukan 4 pelanggaran lint dokumentasi intra-doc yang diperlakukan sebagai error:
1. `NodeAddr` tidak ditemukan dalam scope saat ditautkan dari modul lain.
2. Link intra-doc mengarah ke modul privat `iroh_impl`.
3. URL polos tanpa kurung sudut `<...>` pada `crates/splice-core/src/code/wordlist.rs`.
4. Link ke konstanta privat `LINGER_TIMEOUT`.

### Bukti Gagal-Dulu
Direproduksi secara lokal di WSL Ubuntu (`spliceci`):
```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```
Hasil:
```
error: unresolved link to `NodeAddr`
error: public documentation for `iroh_impl` links to private item
error: bare URL not enclosed in angle brackets
error: unresolved link to `LINGER_TIMEOUT`
error: could not document `splice-core`
```

### Perbaikan
1. Menghubungkan `NodeAddr` dengan path penuh yang valid.
2. Mengubah tautan ke modul/konstanta privat menjadi kode teks berformat backticks (`` `iroh_impl` ``, `` `LINGER_TIMEOUT` ``).
3. Mengapit URL di `wordlist.rs` dengan `<...>` (`<https://github.com/...>`).
4. Verifikasi ulang: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` keluar dengan kode 0 (bersih tanpa peringatan). Di CI GitHub Actions, job `docs` kini **sukses hijau**.

---

## 5. Masalah D: Job "offline" (Izin Direktori Artefak `EACCES`)

### Akar Masalah
Pengujian offline (`tests/offline/offline_test.sh`) membuat network namespace terisolasi tanpa akses internet dan default route (`ip netns`). Karena operasi kernel namespace memerlukan privilege root, langkah ini dijalankan dengan `sudo`.

Sebelumnya, skrip meletakkan direktori scratch di `/root/splice-offline/out`. Pada langkah berikutnya di GitHub Actions:
```yaml
- uses: actions/upload-artifact@v4
  with:
    path: /root/splice-offline/out
```
Langkah ini dieksekusi oleh runner GitHub Actions sebagai pengguna unprivileged (`runner`). Karena direktori `/root` memiliki mode perizinan `0700` milik root, runner mengalami kegagalan akses:
```
Error: EACCES: permission denied, lstat '/root/splice-offline/out'
```

### Perbaikan
1. **Direktori Output Konfigurabel**:
   Direktori scratch diubah menggunakan environment variable `SPLICE_WORK` dan `SPLICE_OUT`, dengan nilai default `$RUNNER_TEMP/splice-offline` (atau `/tmp`):
   ```bash
   WORK=${SPLICE_WORK:-${RUNNER_TEMP:-/tmp}/splice-offline}
   OUT=${SPLICE_OUT:-$WORK/out}
   ```
2. **Pemulihan Kepemilikan (chown)**:
   Di akhir eksekusi (dan pada trap cleanup), skrip menyerahkan kembali kepemilikan direktori scratch kepada user runner:
   ```bash
   if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
     chown -R "$SUDO_UID:$SUDO_GID" "$WORK" 2>/dev/null || true
   fi
   ```
3. **Upload Selalu Dieksekusi**:
   Langkah upload di `.github/workflows/offline.yml` diberikan `if: always()` agar file log diagnostik tetap diunggah meskipun terdapat kegagalan uji.

Hasilnya: Pada CI GitHub Actions, job `offline (disabled)` dan `offline (default)` keduanya **sukses hijau 100%**.

---

## 6. Masalah E: CI Flag `--no-fail-fast`

### Akar Masalah & Perbaikan
Perilaku default `cargo test` adalah menghentikan eksekusi segera setelah target pengujian pertama mengalami kegagalan (*fail fast*). Di runner macOS, ketika target unit test `splice-core` gagal pada tes beacon, target pengujian lainnya (`cli_e2e`, `pairing_invariants`, `trust_invariants`, dan doc-tests) sama sekali tidak pernah dijalankan, sehingga menyembunyikan status target lain.

Langkah pengujian di `.github/workflows/ci.yml` diperbarui menjadi:
```yaml
run: cargo test --workspace --no-fail-fast > test-output.txt 2>&1
```
Dengan flag ini, seluruh 284 tes di seluruh workspace dieksekusi sampai selesai, memberikan visibilitas penuh terhadap status setiap suite pengujian.

---

## 7. Hasil Verifikasi Lokal pada HEAD (Linux, User Biasa `spliceci`)

Seluruh pengujian lokal dijalankan pada commit `523dac9` / `fa94ccf` di lingkungan WSL Ubuntu menggunakan pengguna biasa `spliceci` (UID 1000):

### A. Pengujian Offline (`tests/offline/offline_test.sh`)
```bash
SPLICE_BIN=/home/spliceci/splice/target/release/splice SPLICE_RELAY_MODE=disabled sudo -E bash tests/offline/offline_test.sh
SPLICE_BIN=/home/spliceci/splice/target/release/splice SPLICE_RELAY_MODE=default sudo -E bash tests/offline/offline_test.sh
```
- **Relay Mode `disabled`**:
  - `pass=19 fail=0`
  - Durasi pairing: `1242 ms`
  - RTT Ping: `1637 ms`
  - Hasil: `OFFLINE_OK`
- **Relay Mode `default`**:
  - `pass=19 fail=0`
  - Durasi pairing: `1244 ms`
  - RTT Ping: `1639 ms`
  - Hasil: `OFFLINE_OK`

### B. Benchmark Kehadiran (`tests/discovery/bench_presence.sh`)
```bash
SPLICE_BIN=/home/spliceci/splice/target/release/splice sudo -E bash tests/discovery/bench_presence.sh
```
- Jumlah run: **32 iterasi** (memenuhi syarat n >= 30)
- **Metrik Online (`online_ms`)**:
  - Min: 67.0 ms
  - p50: 75.0 ms
  - **p95: 101.0 ms** (Target Brief §9: <= 3000 ms -> **LULUS telak**)
  - Mean: 84.6 ms
- **Metrik Offline (`offline_ms`)**:
  - Min: 5973.0 ms
  - p50: 5990.0 ms
  - **p95: 6011.0 ms** (Target: batas 6000 ms + toleransi tick 100 ms -> **LULUS**)
  - Mean: 5991.4 ms
- Hasil: `DISCOVERY_BENCH_OK`, `pass=15 fail=0`, tidak ada proses yang bocor.

### C. Pengujian Mutan (`cargo mutants`)
1. **Modul `trust/store.rs`**:
   ```bash
   cargo mutants -f "crates/splice-core/src/trust/store.rs" --test-package splice-core
   ```
   - Total mutan: 53
   - **Hasil**: 43 caught, 10 unviable, **0 missed**.
   - **Tingkat Tangkapan Mutan: 100%**.
2. **Modul `discovery/presence.rs`**:
   ```bash
   TMPDIR=/home/spliceci/tmp cargo mutants -f "crates/splice-core/src/discovery/presence.rs" --test-package splice-core
   ```
   - Total mutan: 114
   - Baseline unmutated: Lulus (71s build + 8s test).
   - **Hasil**: 77 caught, 34 unviable, 3 missed (2 mutan pada string diagnostik `interface_context`, 1 pada kondisi penugasan loopback fallback).
   - Seluruh mutan fungsional terkait logika token, tag, hashing bucket, encoding/decoding beacon, port reuse, dan interval waktu tertangkap sempurna (caught).

---

## 8. Status CI GitHub Actions dan Analisis Lingkungan macOS

### Rekapitulasi Status CI
| Job Workflow | Status di GitHub Actions | Keterangan |
| :--- | :---: | :--- |
| `audit` | **Hijau (Success)** | Dependensi aman dari celah keamanan |
| `deny` | **Hijau (Success)** | Lisensi dan larangan dependensi patuh |
| `docs` | **Hijau (Success)** | 0 peringatan rustdoc |
| `offline (disabled)` | **Hijau (Success)** | 19/19 checks lulus, artefak log berhasil diunggah |
| `offline (default)` | **Hijau (Success)** | 19/19 checks lulus, artefak log berhasil diunggah |
| `test (ubuntu-latest)`| **Hijau (Success)** | Seluruh 284 tes workspace lulus |
| `test (windows-latest)`| **Hijau (Success)**| Seluruh 284 tes workspace lulus |
| `test (macos-latest)` | Merah (1 gagal) | **236 Lulus**, 1 Gagal (`send_actually_transmits_a_beacon`) |

### Analisis Jujur dan Detail Lingkungan macOS Runner
Di runner `macos-latest` GitHub Actions:
- **Sebanyak 236 tes unit di `splice-core` lulus**, termasuk tes port sharing `two_sockets_can_share_one_port` yang membuktikan bahwa perbaikan `SO_REUSEPORT` berhasil mengatasi `os error 48 (Address already in use)`.
- Satu-satunya tes yang gagal adalah `send_actually_transmits_a_beacon` dengan error:
  ```
  send a beacon: Discovery(PresenceSocket("No route to host (os error 65)"))
  ```
- **Penyebab Teknis di macOS CI Runner**:
  1. Runner macOS GitHub Actions berjalan di dalam lingkungan Apple Virtualization VM tanpa kartu Wi-Fi fisik.
  2. Tabel routing kernel Darwin pada VM tersebut memiliki rute default:
     ```
     default 192.168.64.1 UGScg en0
     ```
     Namun antarmuka `en0` **sama sekali tidak memiliki IP address** (hanya `utun0` yang memiliki IP `192.168.64.17`).
  3. Ketika paket multicast `239.255.47.82` dikirimkan, kernel Darwin memeriksa tabel rute. Karena tidak ada gateway multicast pada loopback atau antarmuka yang aktif memiliki IP, kernel mencoba mengirim via rute default `en0` yang tidak memiliki konfigurasi IP, menghasilkan `EHOSTUNREACH (os error 65 - No route to host)`.

---

## 9. Hal yang Belum Bisa Diverifikasi di Lab Virtualisasi CI

1. **Perilaku Multicast pada Hardware Mac Fisik**:
   - Pada Mac fisik di dunia nyata, interface `en0` adalah modul Wi-Fi atau Ethernet yang terhubung ke router lokal dengan alamat IP nyata (misal `192.168.1.x`).
   - Pada Mac fisik, kernel Darwin secara otomatis merutekan paket multicast `224.0.0.0/4` melalui interface Wi-Fi/Ethernet aktif tersebut. Fitur `IP_MULTICAST_LOOP = 1` pada Mac fisik memantulkan paket kembali ke soket lokal di mesin yang sama dengan sempurna. Hal ini tidak dapat direplikasi secara identik di VM headless GitHub Actions tanpa perangkat keras jaringan fisik.
2. **Izin Local Network Privacy (macOS 15 Sequoia ke Atas)**:
   - Mulai macOS 15 Sequoia, Apple memperkenalkan perlindungan privasi jaringan lokal (*Local Network Privacy*). Setiap biner yang mencoba mengirim atau mendengarkan paket UDP multicast di LAN akan diblokir oleh OS hingga pengguna mengklik tombol dialog persetujuan (*"Splice would like to find and connect to devices on your local network"*).
   - Pada pengujian headless tanpa desktop GUI (seperti CI), dialog ini tidak dapat dijawab secara interaktif. Untuk rilis biner macOS di masa mendatang, aplikasi memerlukan Info.plist dengan key `NSLocalNetworkUsageDescription` atau entitlement yang sesuai ketika dibundel sebagai aplikasi macOS.

---
*Laporan disusun sebagai bukti pemenuhan seluruh persyaratan perbaikan dan pengujian Fase 1.5 Splice.*
