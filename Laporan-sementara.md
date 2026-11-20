# Laporan Sementara — Splice Fase 1

> Dokumen ini adalah **ringkasan progres** untuk dibaca cepat, bukan pengganti
> `Laporan-1.md`. Laporan akhir tetap `Laporan-1.md`; berkas ini hanya memadatkan
> isinya dan menautkan ke bagian yang relevan.
> Status: per **20 November 2026**, Step 0–14 **SELESAI**, HEAD `38b3276`.

---

## 1. Ringkasan satu paragraf

Fase 1 selesai: seluruh lima belas langkah (0–14) dikerjakan, dan setiap klaim di
bawah berasal dari perintah yang benar-benar dijalankan di mesin ini, bukan dari
perkiraan. `splice-core` berisi identitas (persisten 0600/0700 + efemeral),
2048 kata BIP-39, parser kode dan nameplate, codec frame dengan batas 1 MiB,
boundary transport (memory + iroh 1.4.1), discovery sendiri (mDNS untuk nameplate
+ presence beacon bertag berputar), tiket, pairing SPAKE2 dengan konfirmasi kunci
dan tiga percobaan, serta trust store dengan pencabutan. `crates/splice`
menghubungkan semuanya ke enam perintah CLI yang sudah ditetapkan. Hasil yang
paling penting secara angka: **279 tes lulus, 0 gagal**; discovery online
**p95 = 105 ms** (target 3000 ms); discovery offline **p95 = 6011 ms** terhadap
kontrak 6000 ms + 100 ms tick pengamat; pairing tanpa internet **pass=19 fail=0**
di kedua mode relay; fuzz 3 target × 65 s **0 crash**; dan tidak ada mutan yang
bertahan tanpa penjelasan di empat modul yang diwajibkan. Enam temuan tinjauan
independen nyata ditemukan dan semuanya diperbaiki dengan tes yang gagal lebih
dulu. Fase 2 belum dimulai.

---

## 2. Posisi terhadap rencana (Step 0–14)

| Step | Isi | Status | Bukti |
|---|---|---|---|
| 0 | Baca dokumen, catat ambiguitas | **SELESAI** | `Laporan-1.md` Lampiran (7 butir) |
| 1 | Spike S1: iroh tanpa internet di netns | **SELESAI** | `Laporan-1.md` §4 |
| 2 | Workspace, `Secret<T>`, error, konstanta | **SELESAI** | §5 (I11), §6 |
| 3 | Identitas efemeral + persisten, tulis atomik | **SELESAI** | §5 (I16) |
| 4 | 2048 kata, parser kode, nameplate, prompt tersembunyi | **SELESAI** | §5 (I1) |
| 5 | Codec frame, pesan postcard, byte tipe stream | **SELESAI** | §5 (I9) |
| 6 | Batas transport, memory + iroh, hint alamat | **SELESAI** | §4.2 |
| 7 | mDNS, tag presence, tiket, alamat manual | **SELESAI** | §5 (I17) |
| 8 | SPAKE2, konfirmasi kunci, 3 percobaan, MITM | **SELESAI** | §5 (I2–I4) |
| 9 | Trust store, sesi tepercaya, pencabutan | **SELESAI** | §5 (I13, I16, I18) |
| 10 | CLI `pair`/`devices`/`listen`/`identity`/`dev` | **SELESAI** | `cli_e2e` 7 kasus |
| 11 | Uji offline end-to-end di dua netns | **SELESAI** | §10.2, `pass=19 fail=0` |
| 12 | Benchmark discovery 32 putaran | **SELESAI** | §7 |
| 13 | CI, `deny.toml`, fuzz crate, gerbang mutan | **SELESAI** | §10.4, `.github/workflows/` |
| 14 | Tinjauan independen, perbaikan, laporan final | **SELESAI** | §9.6, §6.5 |

Tidak ada langkah yang ditandai selesai tanpa bukti. Yang **tidak** bisa
dieksekusi di mesin ini tetap ditandai apa adanya: macOS hanya lewat CI, Docker
daemon mati, dan Wi-Fi venue sungguhan tidak tersedia (§8, §9).

---

## 3. Riwayat commit

Satu commit per perubahan logis, seluruhnya di `main`:

```text
38b3276  test(core): kill the last three pairing mutants the clean run found
ad0e16f  test(core): kill the pairing and trust mutants the last runs left unexplained
0a8078d  fix(cli): treat a missing TrustAck as a protocol failure        → temuan 6
da36911  fix(core): refuse a code-mode Hello that omits the nameplate    → temuan 5
071eac2  fix(core): stop the guest from claiming the code burned         → temuan 4
e714c36  fix(core): hold the session key back until the peer's MAC verifies → temuan 3
c4c8d98  fix(cli): stop accepting guests once the code is burned         → temuan 2
dcc94e9  fix(core): strip invisible formatting characters from aliases   → temuan 1
56b4df0  test(core): kill the surviving presence mutants
474e56d  test(core): kill the four trust mutants that survived in the sessions
53bf979  test(core): kill ten mutants that survived in the pairing sessions
baeef38  test(core): kill the two mutants that survived in the code parsers
9daf274  ci: run the Phase 1 gates on Linux, macOS and Windows
b41fb53  test(core): fuzz the frame, code and ticket parsers
4a73ce9  chore: drop heapless from the graph and record the advisories we accept
ed3de29  test(cli): measure how long presence takes to appear and expire
2ec1071  feat(cli): observe presence transitions for the discovery benchmark
206da52  fix(core): never hand a guest an IPv6 link-local address
959382b  fix(core): pick nameplates across the whole range, not just the first
865fd01  test(cli): prove pairing and trusted ping work with no internet
c2e54ad  fix(cli): name the peer with the alias it sent, not our own
58b6a16  test(core): write fixture files owner-only so the loader sees their content
19b284f  fix(core): pin multicast egress for presence beacons
606234a  fix(core): report dialable local addresses from the transport
d2da6c9  docs: add interim Phase 1 progress report
685aa66  test(cli): end-to-end pairing, ticket, ping, wrong code, burned, foreign node
895ed29  feat(cli): wire pair, devices, listen, identity, and dev commands
8abba1b  feat(core): ticket-mode pairing password and password-based session constructors
0fdf527  feat(core): trust store and trusted sessions
7879131  feat(core): SPAKE2 pairing with confirmation, attempts and invariant tests
b21aec6  feat(core): discovery via mDNS, presence tags, ticket, and manual address
3c901ac  feat(core): identity, codes, frame codec, and transport boundary
873ed4a  docs: add architecture, brief, and Phase 1 report skeleton
```

Pola yang dipakai konsisten: `feat(cli)` untuk perintah, `fix(core)`/`fix(cli)`
untuk temuan, `test(core)`/`test(cli)` untuk tes yang dibuktikan gagal dulu,
`ci:`/`chore:`/`docs:` untuk sisanya.

---

## 4. Hasil gerbang (semua benar-benar dijalankan)

Dijalankan dari `C:\EXPERIMENT\Splice` setelah perubahan terakhir
(HEAD `38b3276`), memakai `& "$env:USERPROFILE\.cargo\bin\cargo.exe"`:

| Gerbang | Perintah | Hasil | Exit |
|---|---|---|---|
| Format | `cargo fmt --all --check` | tidak ada diff | **0** |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `Finished` tanpa warning/error | **0** |
| Tes | `cargo test --workspace` | semua `test result:` ok, **279 tes, 0 gagal** | 1 *(quirk Windows, lihat catatan)* |
| Lisensi | `cargo deny check` | ok, 2 advisory "unmaintained" di-ignore per ID | **0** |
| Audit | `cargo audit` | 446 crate, 2 warning diterima | **0** |

Catatan penting supaya angka ini tidak disalahbaca:

- Di Windows, `cargo test --workspace` kadang keluar dengan kode 1 meski semua
  `test result:` hijau, karena quirk stderr proses anak. Yang dibaca adalah baris
  `test result:`. Di CI Linux tidak terjadi.
- `cargo deny`/`cargo audit` melaporkan **dua advisory** (`paste`
  RUSTSEC-2024-0436 dan `chrono` RUSTSEC-2026-0543). Keduanya berstatus
  *unmaintained*, bukan kerentanan, dan keduanya berasal dari iroh 1.4.1 yang
  diwajibkan. Di-ignore **per ID**, bukan per paket, supaya advisory lain untuk
  crate yang sama tetap muncul.

Rincian `cargo test --workspace`:

| Suite | Jumlah |
|---|---|
| `splice-core` lib (unit + invarian modul) | 234 lulus |
| `crates/splice-core/tests/pairing_invariants.rs` | 24 lulus |
| `crates/splice-core/tests/trust_invariants.rs` | 4 lulus |
| `crates/splice/tests/cli_e2e.rs` | 7 lulus |
| `splice` lib | 9 lulus |
| `splice` main | 0 |
| spike `spikes/iroh-offline` | 1 lulus |
| doc-tests | 0 |
| **total** | **279 lulus, 0 gagal** |

Yang **tidak** dieksekusi di mesin ini, dengan perintah CI persisnya:

| Hal | Status | Perintah |
|---|---|---|
| macOS (build + gerbang) | **NOT EXECUTED** | `runs-on: macos-latest` di `.github/workflows/ci.yml` |
| Docker | **NOT EXECUTED** | daemon tidak berjalan; tidak dipakai Fase 1 |
| Wi-Fi venue nyata | **NOT EXECUTED** | tidak ada AP yang bisa dikendalikan (§9) |

---

## 5. Gerbang mutan (Step 14)

`cargo-mutants` 27.1.0, per modul, `--in-place --baseline skip --timeout 120`.
"Unviable" berarti mutan tidak bisa dikompilasi, jadi tidak dihitung sebagai bukti
tes — angkanya dicantumkan supaya skor tidak dibandingkan dengan penyebut salah.

| Modul | Diuji | Bertahan | Diselesaikan | Skor |
|---|---|---|---|---|
| `code/` + `nameplate.rs` | 62 + 22 = **84** | 1 + 2 → **0** | 3 dibunuh (`baeef38`) | **100%** |
| `discovery/presence` | 99 lalu 106 | 20 → 3 → **0** | 23 dibunuh (`56b4df0`) | **100%** |
| `pairing/` | **225** | 6 → **3 setara** | 3 dibunuh (`38b3276`) + 10 (`53bf979`) | **98%** (147/150 viabel) |
| `trust/` | **88** | 6, semua di `#[cfg(unix)]` | 4 dibunuh (`474e56d`) + 2 metode dihapus | **100%** mutan yang bisa dicapai |

Kebijakan: mutan yang **mengubah perilaku nyata** dibunuh dengan menambah tes,
bukan dijelaskan di laporan. Mutan yang setara dibuktikan setara. Rincian dan
bukti FAIL-first ada di `Laporan-1.md` §6.5; dua mutan `pairing/` yang setara
(`guest.rs:219`, `guest.rs:222`) dan satu `host.rs:266` dijelaskan di sana dengan
alasan per input, bukan dengan "tes kami tidak menyentuhnya".

---

## 6. Enam temuan tinjauan independen (Step 14)

Tinjauan dilakukan dengan membaca kode sebagai penyerang, hanya berbekal
`Architecture.md` §5 dan §13. Enam temuan nyata; semuanya diperbaiki dengan tes
yang **gagal lebih dulu** terhadap kode yang belum diperbaiki.

| # | Temuan | Akibat kalau dibiarkan | Perbaikan |
|---|---|---|---|
| 1 | Alias menerima karakter bidi/format tak terlihat (`Cf`) | baris persetujuan bisa dibalik atau disamarkan; "ya" diberikan pada nama yang salah | `dcc94e9` — `is_invisible_format` di `sanitize_alias` **dan** `TrustRecord::into_entry` |
| 2 | Kode hangus tetap dilayani sampai TTL habis | LAN mengiklankan kode yang mustahil berhasil, melanggar §5.4 langkah 7 | `c4c8d98` — `Burned` terminal di `accept_loop`, jalur `mdns.withdraw` berjalan |
| 3 | `session_key()` bisa dibaca sebelum MAC peer terverifikasi | jendela MITM; kunci belum disahkan sudah bisa dipakai pemanggil | `e714c36` — aksesor hanya mengembalikan kunci pada fase `Paired` |
| 4 | Tamu menyetel `Burned` untuk semua jalan keluar terminal | tamu mengklaim otoritas yang hanya dimiliki host; pesan menyesatkan | `071eac2` — fase baru `Aborted`; `Burned` hanya dari `Bye{Burned}` host |
| 5 | `Hello` mode-kode tanpa nameplate diterima | **kode benar yang tidak pernah dijalankan**: host memulai PAKE tanpa memeriksa nameplate (cabang `else if` tidak mungkin menyala) | `da36911` — satu perbandingan langsung terhadap `Some(plate)` |
| 6 | `TrustAck` yang hilang dilaporkan sebagai sukses | `splice pair` exit 0 dan mencetak sukses padahal tidak ada yang tersimpan | `0a8078d` — `Bye{Protocol}` + gagal di kedua sisi; `confirm_trust_ack` |

Temuan 5 dan 6 adalah dua yang paling berbahaya karena bentuknya *senyap*: satu
adalah pemeriksaan yang tidak pernah berjalan, satu lagi adalah keberhasilan palsu.
Detail lengkap: `Laporan-1.md` §9.6.

---

## 7. Deviasi dan penafsiran yang perlu diketahui

| # | Hal | Keputusan | Alasan |
|---|---|---|---|
| D9 | `splice listen` tidak ada di daftar perintah `Architecture.md` §5 | ditambahkan | Step 11/12 butuh sisi penerima yang hidup lebih lama dari satu percobaan |
| D10 | `splice dev presence <alias>` tersembunyi | ditambahkan | pengamat harus menjalankan `PresenceTracker` yang sebenarnya, bukan tiruan |
| D11 | `TrustEntry::shorthand` dihapus | dihapus | tidak punya pemanggil; semua jalur memakai `node_id.shorthand()` |
| §8.3 | Tamu keempat setelah kode hangus menerima `Bye{Protocol}`, bukan `Burned` | dipilih | supaya penebak tidak bisa membedakan "salah" dari "sudah mati" |

Penafsiran (bukan deviasi), semuanya di `Laporan-1.md` §8.5: CONTROL dibuka
pemanggil (`open_bi`/`accept_bi`), `local_addrs()` dari `endpoint.addr()`,
antarmuka egress multicast dipin, `postcard` tanpa default features, dua advisory
di-ignore per ID, dan `fuzz/` sebagai workspace sendiri.

---

## 8. Yang tersisa

Tidak ada pekerjaan Fase 1 yang menggantung. Yang tersisa adalah hal yang memang
di luar lingkup atau butuh lingkungan yang tidak ada di sini:

1. **Benchmark Wi-Fi venue sungguhan.** Risiko terbesar yang belum terukur:
   multicast sering dibuang AP. Rencana: ulangi `tests/discovery/bench_presence.sh`
   di dua laptop fisik, satu hari. Kalau gagal, jalur cadangan tiket (§11.1).
2. **Dua host dengan jam berbeda.** `match_now` hanya toleran ±1 bucket (300 s).
3. **macOS** hanya diuji lewat CI, belum di mesin.
4. **Risiko operasional yang diterima, bukan bug:** batas 3 percobaan bisa
   dihabiskan penyerang (DoS terkendali), metadata peer tetap terlihat (§9.4),
   dan zeroize tidak menjangkau salinan di dalam crate `spake2` (§9.2).

---

## 9. Catatan lingkungan (ringkas)

- Cargo tidak ada di `PATH`: `& "$env:USERPROFILE\.cargo\bin\cargo.exe" …`.
- Shell PowerShell 5.1 — pakai `;`, bukan `&&`.
- WSL2 Ubuntu 26.04 dengan root, `ip netns`, veth, dan multicast UDP: dipakai
  untuk Step 11/12, dengan binary **native Linux** (binary Windows lewat interop
  tidak melihat netns, dan hasilnya salah tanpa terlihat salah).
- Tooling tambahan: `cargo-deny`, `cargo-audit`, `cargo-mutants` 27.1.0,
  `cargo-fuzz` 0.13.2 + nightly 1.102.0.
- `cargo-mutants --in-place` menulis ulang sumber di tempat. Setelah setiap run
  diperiksa `git status --short` (tidak boleh ada `.rs`) dan
  `grep -r "changed by cargo-mutants" crates/` (harus kosong).
- Docker daemon mati; macOS tidak tersedia lokal.
