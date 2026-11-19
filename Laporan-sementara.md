# Laporan Sementara — Splice Fase 1

> Dokumen ini adalah **laporan progres sementara**, bukan `Laporan-1.md`.
> `Laporan-1.md` tetap menjadi laporan akhir yang baru diisi lengkap pada Step 14.
> Status: per **20 November 2026**, Step 0–10 selesai, Step 11–14 belum dikerjakan.

---

## 1. Ringkasan satu paragraf

Fondasi `splice-core` (identitas, kode, codec frame, batas transport, discovery mDNS + presence + tiket, pairing SPAKE2, trust store) sudah selesai dan teruji pada Step 1–9. Step 10 — menghubungkan seluruh perintah CLI ke `splice-core` dan menulis tes end-to-end — **selesai dan hijau**: 7 dari 7 kasus uji lulus, dan ketiga gerbang wajib (`fmt`, `clippy -D warnings`, `test --workspace`) lulus dengan exit code 0. Yang belum dikerjakan adalah Step 11 (tes offline dua netns di CI), Step 12 (benchmark discovery), Step 13 (CI, deny, fuzz, mutants), dan Step 14 (review independen + finalisasi laporan). Perubahan Step 10 **belum di-commit**.

---

## 2. Posisi terhadap rencana (Step 0–14)

| Step | Isi | Status | Bukti |
|---|---|---|---|
| 0 | Baca dokumen, catat ambiguitas | **SELESAI** | `Laporan-1.md` Lampiran (7 butir) |
| 1 | Kerangka workspace Rust | **SELESAI** | commit `873ed4a` … lihat §3 |
| 2 | Identitas (efemeral/persisten), kode, codec frame, batas transport | **SELESAI** | commit `3c901ac` |
| 3 | Discovery: mDNS, presence, tiket, alamat manual | **SELESAI** | commit `b21aec6` |
| 4 | Pairing SPAKE2 + konfirmasi kunci + batas percobaan + tes invarian | **SELESAI** | commit `7879131` |
| 5 | Trust store + koneksi tepercaya | **SELESAI** | commit `0fdf527` |
| 6 | Mode tiket (password) + konstruktor sesi berbasis password | **SELESAI** | commit `8abba1b` |
| 7–9 | (bagian dari commit di atas: invarian I1–I4, I11, I13, I16–I18) | **SELESAI** | 209 tes core hijau |
| **10** | **Wiring CLI + perintah `dev` + tes end-to-end** | **SELESAI, BELUM DI-COMMIT** | §4 di bawah |
| 11 | Tes offline (`tests/offline/` + `offline.yml`) | **BELUM** | — |
| 12 | Benchmark discovery (n ≥ 30) | **BELUM** | — |
| 13 | CI, `deny.toml`, fuzz smoke, `cargo-mutants` | **BELUM** | — |
| 14 | Review independen + finalisasi `Laporan-1.md` | **BELUM** | — |

Catatan: Step 7–9 tidak muncul sebagai commit terpisah karena isinya menyatu dengan commit fitur di atasnya (tes invarian hidup bersama modul yang diujinya). Ini konsisten dengan aturan "satu commit per perubahan logis".

---

## 3. Riwayat commit saat ini

```
8abba1b  feat(core): ticket-mode pairing password and password-based session constructors
0fdf527  feat(core): trust store and trusted sessions
7879131  feat(core): SPAKE2 pairing with confirmation, attempts and invariant tests
b21aec6  feat(core): discovery via mDNS, presence tags, ticket, and manual address
3c901ac  feat(core): identity, codes, frame codec, and transport boundary
873ed4a  docs: add architecture, brief, and Phase 1 report skeleton
```

**Belum di-commit** (semua hasil Step 10):

```
 M Cargo.lock
 M crates/splice/Cargo.toml
 M crates/splice/src/main.rs
?? crates/splice/src/lib.rs
?? crates/splice/src/cli/
?? crates/splice/tests/          (cli_e2e.rs, 546 baris)
```

---

## 4. Step 10 — apa yang sudah jadi

### 4.1 Kode

| Berkas | Baris | Isi |
|---|---|---|
| `crates/splice/src/main.rs` | — | Titik masuk, memanggil `cli::run` |
| `crates/splice/src/lib.rs` | — | Mengekspos `cli` agar bisa diuji dari `tests/` |
| `crates/splice/src/cli/mod.rs` | 269 | `Cli`/`Command`, `build_endpoint`, `write_control`/`read_control`, `apply_step`, `await_peer_hangup`, `make_prompter` |
| `crates/splice/src/cli/cmd/pair.rs` | 369 | `splice pair` (host) dan `splice pair --join [CODE]` (tamu), termasuk pertukaran `TrustExchange`/`TrustAck` |
| `crates/splice/src/cli/cmd/listen.rs` | 147 | `splice listen`: presence beacon + cek trust store sebelum stream apa pun (I13) |
| `crates/splice/src/cli/cmd/dev.rs` | 430 | Perintah tersembunyi `dev host-oneshot`, `guest-oneshot`, `host-ticket`, `guest-ticket`, `ping` |
| `crates/splice/src/cli/cmd/devices.rs` | 58 | `splice devices`, `splice devices rm` |
| `crates/splice/src/cli/cmd/identity.rs` | 46 | `splice identity show` |
| `crates/splice/tests/cli_e2e.rs` | 546 | 7 kasus uji end-to-end |

Bahasa: seluruh string yang dilihat pengguna berbahasa Indonesia; kode, komentar, log, dan pesan commit berbahasa Inggris.

### 4.2 Tujuh kasus uji end-to-end

| # | Nama tes | Yang dibuktikan | Transport |
|---|---|---|---|
| 1 | `one_shot_pairing_completes_over_the_memory_transport` | Pairing satu-kali `Hello → PakeMsg → PakeConfirm → Paired`, lalu `Ping/Pong` | memori |
| 2 | `ticket_pairing_completes_over_a_real_endpoint` | Mode tiket (`Ticket::password_string()`), tanpa nameplate | QUIC nyata (loopback/LAN) |
| 3 | `pair_then_dev_ping_reaches_the_trusted_device` | `dev ping` mencapai listener tepercaya tanpa kode/PAKE, plus I13 | QUIC nyata |
| 4 | `a_wrong_code_spends_one_attempt_and_keeps_the_code` | Kode salah menghabiskan tepat 1 percobaan; host tetap menunggu | memori |
| 5 | `a_wrong_code_gets_bye_protocol_not_bye_burned` | Kode salah menerima `Bye{Protocol}`, bukan `Bye{Burned}` | memori |
| 6 | `three_wrong_codes_burn_the_code` | Percobaan ke-3 → `Bye{Burned}` + fase `Burned` + `attempts_left == 0`; tamu ke-4 ditolak | memori |
| 7 | `a_foreign_node_id_is_closed_without_a_protocol_message` | `NodeId` asing ditutup tanpa satu byte protokol pun (I13) | memori |

Keenam kasus yang diminta `MasterPrompt-Fase1.md` §4 Step 10 semuanya tercakup (kasus "wrong code" sengaja dipecah menjadi dua tes: satu menguji hitungan percobaan, satu menguji isi pesan `Bye`).

### 4.3 Dua bug nyata yang ditemukan tes ini dan sudah diperbaiki

1. **Sisi penerima membuka stream yang salah.** Semula semua sisi memanggil `open_bi()`. `Architecture.md` §7 (baris 265) menetapkan bahwa stream CONTROL **dibuka oleh pemanggil** (`bi, dibuka penelepon`), jadi sisi penerima harus `accept_bi()`. Kesalahan ini menyebabkan 5 dari 7 tes gagal. Diperbaiki di `dev.rs`, `pair.rs`, `listen.rs`, dan tiruan listener di dalam tes.

2. **Koneksi ditutup sebelum frame terakhir terbaca.** Pada QUIC nyata, koneksi tertutup begitu handle terakhir hilang, dan penutupan itu bisa mendahului byte terakhir. Ditambahkan `await_peer_hangup()` (`crates/splice/src/cli/mod.rs`): membaca dan membuang sampai peer menutup, dibatasi `LINGER_TIMEOUT = 5 s`, tidak pernah mengembalikan error. Dipanggil di setiap jalur penerima setelah tulisan terakhir, sehingga `Bye`/`Pong` pasti sampai.

### 4.4 Gerbang wajib — benar-benar dijalankan

Dijalankan ulang **setelah** semua perbaikan di atas, dari `C:\EXPERIMENT\Splice`:

| Perintah | Hasil | Exit |
|---|---|---|
| `cargo fmt --all --check` | Tidak ada diff format | **0** |
| `cargo clippy --workspace --all-targets -- -D warnings` | Tidak ada warning/error | **0** |
| `cargo test --workspace` | Semua suite hijau | **0** |

Rincian `cargo test --workspace`:

| Suite | Jumlah |
|---|---|
| `splice-core` unit test | 181 lulus |
| `crates/splice-core/tests/pairing_invariants.rs` | 24 lulus |
| `crates/splice-core/tests/trust_invariants.rs` | 4 lulus |
| `crates/splice/tests/cli_e2e.rs` | 7 lulus |
| skrip spike (`spikes/iroh-offline`) | 1 lulus |

Total **217 tes lulus, 0 gagal**. Peringatan `profiles for the non root package will be ignored` adalah peringatan Cargo yang sudah diketahui dan tidak berbahaya.

---

## 5. Yang belum dikerjakan (Step 11–14) dan artinya

### Step 11 — Tes offline (wajib, CI Linux)
Belum ada `crates/splice/tests/offline/` maupun `.github/workflows/offline.yml`. Isi yang harus dibuat:
- skrip dua network namespace yang dihubungkan bridge/veth, **tanpa default route, tanpa DNS, tanpa akses internet**;
- `splice pair` ⇄ `splice pair --join`, lalu `splice listen` ⇄ `splice dev ping`;
- dijalankan pada `--relay-mode disabled` **dan** mode relay default;
- asersi: pairing & ping berhasil, perangkat muncul lewat presence sesuai target Brief §9, tidak ada proses menggantung melebihi `HANDSHAKE_TIMEOUT`.

Lingkungan lokal punya WSL2 Ubuntu dengan root dan `ip netns` (lihat `Laporan-1.md` §2), jadi sebagian bisa dijalankan lokal; sisanya (dua mesin/CI) ditandai **NOT EXECUTED** beserta perintah persisnya.

### Step 12 — Benchmark discovery
Skrip mengukur, untuk n ≥ 30: waktu sampai B muncul di daftar A, dan waktu sampai A menandai B offline (p50/p95/max). Angka Wi-Fi nyata **tidak** diukur dan harus dinyatakan begitu; pembanding Brief §9: p95 ≤ 3 s (online), ≤ 6 s (offline).

### Step 13 — CI dan gerbang mutu
- `ci.yml` untuk Linux/macOS/Windows: build, `fmt`, `clippy -D warnings`, `test`, `deny`, `audit`;
- `deny.toml`;
- fuzz smoke ≥ 60 s per target: `fuzz_frame`, `fuzz_code_parse`, `fuzz_ticket_parse` (`fuzz/fuzz_targets/` saat ini kosong);
- `cargo-mutants` pada `pairing/`, `trust/`, `code/`, `discovery/presence`, dengan skor dicatat.

### Step 14 — Review independen lalu finalisasi
Satu reviewer independen yang **hanya** melihat kode dan `Architecture.md` §5/§13, menyerang `pairing/` dan `trust/`. Temuan nyata diperbaiki; daftar temuan + penyelesaiannya masuk laporan. Setelah itu `Laporan-1.md` §1–§11 dilengkapi.

---

## 6. Deviasi yang perlu dicatat di `Laporan-1.md` §8/§10

1. **`splice listen` tidak memakai daemon.** Sesuai `Architecture.md` §11 baris "Sebelum daemon (v0.1–v0.2)", `listen` memegang identitas persisten langsung.
2. **Perintah `dev` memakai identitas efemeral** dan tidak menyentuh trust store, kecuali `dev ping` yang memang membaca store dan memakai identitas persisten — karena tujuannya menguji jalur tepercaya.
3. **Pertukaran trust pada Step 10 diuji lewat `pair`**, bukan lewat `dev`; perintah `dev` berjalan dalam `HelloMode::OneShot` sehingga melewati §5.4 langkah 9, dan menutup dengan `Ping`/`Pong` sebagai bukti CONTROL dua arah.
4. **Kode hangus tidak mengumumkan dirinya ke tamu baru.** Hanya tebakan ketiga yang menerima `Bye{Burned}`; tamu keempat menerima penolakan generik. Ini sesuai perilaku `HostSession` dan semangat I3 (kode hangus tidak menjadi orakel). Perlu ditulis eksplisit di laporan agar tidak terbaca sebagai bug.
5. **Tes end-to-end Step 10 tidak menjalankan `listen::run`** karena perintah itu mengikat port multicast presence dan berputar sampai Ctrl+C. Jalur penerimaannya direproduksi di dalam tes dengan bagian publik yang sama (`TrustStore::contains` → `close_foreign` → `TrustedServer`), memakai `accept_bi()`. Tes dua proses sesungguhnya menjadi tugas Step 11.

---

## 7. Langkah berikutnya, berurutan

1. **Commit Step 10** (dua commit logis):
   - `feat(cli): wire pair, devices, listen, identity, and dev commands` — `main.rs`, `lib.rs`, `Cargo.toml`, `Cargo.lock`, `crates/splice/src/cli/**`;
   - `test(cli): end-to-end pairing, ticket, ping, wrong code, burned, foreign node` — `crates/splice/tests/cli_e2e.rs`.
   Setelah itu pastikan `git status --porcelain` bersih.
2. **Step 11**: tulis `crates/splice/tests/offline/` + `.github/workflows/offline.yml`, jalankan varian yang bisa dijalankan lokal, tandai sisanya **NOT EXECUTED** dengan perintah CI persisnya.
3. **Step 12**: skrip benchmark discovery, jalankan n ≥ 30 di netns, catat p50/p95/max, nyatakan angka Wi-Fi tidak diukur.
4. **Step 13**: `ci.yml`, `deny.toml`, tiga target fuzz smoke ≥ 60 s, `cargo-mutants` pada empat direktori, catat skor.
5. **Step 14**: review independen, perbaiki temuan nyata, lengkapi `Laporan-1.md` §1–§11, perbarui bagian ini menjadi laporan final.
6. **Gerbang akhir**: jalankan ulang ketiga gerbang wajib setelah semua perubahan, catat exit code dan baris `test result:` di laporan.

---

## 8. Catatan lingkungan (ringkas)

- Cargo tidak ada di `PATH`; dipanggil sebagai `& "$env:USERPROFILE\.cargo\bin\cargo.exe" …`.
- Shell: PowerShell 5.1 — gunakan `;`, bukan `&&`.
- WSL2 Ubuntu tersedia dengan root, `ip netns`, veth, dan multicast UDP → Step 11/12 bisa dijalankan sebagian secara lokal.
- Docker daemon tidak berjalan; macOS tidak tersedia lokal (hanya lewat CI).