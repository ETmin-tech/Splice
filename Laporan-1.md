# Laporan Fase 1 — Splice

> Status: **SELESAI** untuk lingkup Fase 1. Lihat §9 untuk apa yang belum diukur dan
> §11 untuk rekomendasi Fase 2.

## 1. Ringkasan

Splice Fase 1 dibangun sebagai workspace Rust dengan tiga anggota
(`crates/splice-core`, `crates/splice`, `spikes/iroh-offline`), di atas iroh 1.4.1
sebagai transport. Yang berjalan di akhir Fase 1:

- **Pairing kode** (`splice pair` / `splice pair --join [KODE]`) memakai SPAKE2,
  tiga percobaan per kode, kode sekali pakai, dan pembakaran kode setelah
  percobaan ketiga gagal.
- **Pairing tiket** (`--ticket` + password) berjalan di atas endpoint sungguhan.
- **Trust store** persisten (0600/0700) dengan alias, pencabutan, dan penutupan
  paksa koneksi hidup saat perangkat dihapus.
- **Koneksi tepercaya**: hanya `Ping`/`Pong` di jalur CONTROL; NodeId asing
  ditolak tanpa satu byte pun balasan.
- **Discovery sendiri** (mDNS untuk nameplate + presence beacon bertag berputar),
  karena mDNS bawaan iroh terbukti **0 dari 23** target di venue offline (§4.4).
- **Enam perintah CLI** yang sudah ditetapkan: `pair`, `devices`, `listen`,
  `identity`, `dev`, dan `--help`/`--version`.

Angka utama:

| Yang diukur | Hasil | Target | Status |
|---|---|---|---|
| Pairing tanpa internet & tanpa relay | `pass=19 fail=0` di dua mode relay | lulus | **LULUS** |
| Discovery online, p95 (32 putaran) | **105 ms** | ≤ 3000 ms | **LULUS** |
| Discovery offline, p95 (32 putaran) | **6011 ms** | ≤ 6000 ms + 100 ms sampling | **LULUS** (§7.3) |
| Sambungan langsung LAN, p50 (S1) | 1,156 ms | – | terukur |
| Tes otomatis | 279 tes, 0 gagal | — | **LULUS** |
| Mutan: `pairing/`, `trust/`, `code/`, `presence` | 503 diuji; 0 bertahan tanpa penjelasan (§6.5) | - | **LULUS** |
| Fuzz smoke 65 s × 3 target | 0 crash | 0 crash | **LULUS** |

Yang **tidak** diklaim: tidak ada pengukuran di Wi-Fi nyata atau LAN venue
sungguhan (hanya netns + loopback), tidak ada uji daya tahan serangan DoS
terdistribusi, dan batas zeroize pada salinan internal `spake2` dijelaskan di §9.
Fase 2 belum dimulai.

## 2. Lingkungan

| Item | Nilai |
|---|---|
| OS pengembangan | Microsoft Windows 11 Pro 10.0.26200 |
| Arsitektur | AMD64 (x86_64) |
| Shell | PowerShell 5.1.26100.9818 |
| Rust | rustc 1.100.0 (0ef1bc386 2026-11-09) |
| Cargo | cargo 1.100.0 (3acc79c0c 2026-11-05) |
| Toolchain host | `x86_64-pc-windows-msvc`, stable |
| git | 2.55.0.windows.2 |
| Python | 3.14 (C:\Python314) |
| Docker | Terpasang, daemon **tidak berjalan** (Docker Desktop Linux engine off) |
| WSL2 | Ubuntu 26.04.1 LTS, kernel 6.18.58.1-microsoft-standard-WSL2, **root tersedia** |

### Kapabilitas yang tersedia

| Kapabilitas | Status | Bukti |
|---|---|---|
| `ip netns` (root) | **TERSEDIA** | `ip netns add testns` → NETNS_OK (WSL2 Ubuntu, uid 0) |
| veth pair | **TERSEDIA** | `ip link add veth0 type veth peer name veth1` → VETH_OK |
| Dua netns saling ping | **TERSEDIA** | ping 10.200.0.1 → 10.200.0.2, 0% loss |
| Tanpa default route di netns | **TERSEDIA** | `ip route` kosong kecuali link-local `10.200.0.0/24` |
| Multicast UDP bind 224.0.0.251:5353 | **TERSEDIA** | Skrip Python → MULTICAST_OK |
| Root di Linux | **TERSEDIA** | `id -u` → 0 |
| Docker daemon | **TIDAK TERSEDIA** | `docker version` → pipe tidak ditemukan |
| macOS lokal | **TIDAK TERSEDIA** | — (hanya via CI) |
| Windows lokal | Tersedia (host pengembangan) | — |

### Tooling tambahan yang dipasang

`cargo-deny`, `cargo-audit`, `cargo-mutants`, `cargo-fuzz` — dipasang via `cargo install --locked`.

## 3. Langkah yang dikerjakan

Lima belas langkah (0–14) dikerjakan berurutan, masing-masing diverifikasi sebelum
lanjut. Ringkasannya, dengan bukti di bagian lain laporan:

| Langkah | Yang dikerjakan | Commit utama | Bukti |
|---|---|---|---|
| 0 | Orientasi, `Laporan-1.md`, ambiguitas dokumen | `873ed4a` | Lampiran |
| 1 | Spike S1 di venue netns offline | `873ed4a` | §4 |
| 2 | Workspace, `Secret<T>`, error, konstanta, tracing | `3c901ac` | §5 (I11), §6 |
| 3 | Identitas efemeral + persisten, 0600/0700, tulis atomik | `3c901ac` | §4.6, §5 (I16) |
| 4 | 2048 kata, parser kode, nameplate, prompt tersembunyi | `3c901ac`, `959382b` | §5 (I1), §6 |
| 5 | Codec frame, pesan postcard, byte tipe stream | `3c901ac` | §5 (I9) |
| 6 | Batas transport (`net/`), memory + iroh, hint alamat | `3c901ac`, `606234a` | §4.2 |
| 7 | mDNS, tag presence, tiket, alamat manual | `b21aec6`, `19b284f`, `206da52` | §4.4, §7 |
| 8 | SPAKE2, konfirmasi kunci, 3 percobaan, MITM | `7879131` | §5 (I2–I4), §6 |
| 9 | Trust store, sesi tepercaya, pencabutan | `0fdf527`, `c2e54ad` | §5 (I13, I16) |
| 10 | CLI `pair`/`devices`/`listen`/`identity`/`dev` | `895ed29`, `685aa66` | §6 (`cli_e2e`) |
| 11 | Uji offline end-to-end di dua netns | `865fd01` | §4.1, §6 |
| 12 | Benchmark discovery 32 putaran | `2ec1071`, `ed3de29` | §7 |
| 13 | CI, `deny.toml`, fuzz crate, gerbang mutan | `4a73ce9`, `b41fb53`, `9daf274` | §6, §10 |
| 14 | Tinjauan independen, perbaikan mutan, perbaikan temuan, laporan akhir | `baeef38`, `53bf979`, `474e56d`, `56b4df0`, `dcc94e9`, `c4c8d98`, `e714c36`, `071eac2`, `da36911`, `0a8078d`, `ad0e16f`, `38b3276` | §6, §8, §9 |

Commit `dcc94e9`–`0a8078d` adalah **temuan tinjauan independen**, bukan mutan:
masing-masing menambal satu celah yang nyata dan dibuktikan gagal dulu lewat tes
(§9.6). `ad0e16f` menutup sisa mutan `pairing/` dan `trust/` dari run bersih;
setiap tes di dalamnya juga dibuktikan gagal dulu terhadap sumber yang belum
diperbaiki. `38b3276` menutup tiga mutan `pairing/` yang baru terlihat setelah
run bersih terakhir (prompter dan `Outcome::name`).

Perbaikan yang ditemukan saat verifikasi, bukan saat menulis fitur — semuanya
berawal dari tes yang gagal lebih dulu:

| Masalah | Perbaikan | Commit |
|---|---|---|
| `local_addrs()` memakai `bound_sockets()`, jadi setiap filter non-loopback di pemanggil selalu gagal | kembalikan `endpoint.addr().ip_addrs()` | `606234a` |
| Beacon presence keluar lewat antarmuka salah, tidak pernah terlihat | pin antarmuka egress multicast di `bind` | `19b284f` |
| Fixture tes ditulis 0644 oleh umask, sehingga `InsecurePermissions` muncul lebih awal (hanya di Linux) | tulis fixture 0600; `loose_permissions_are_refused` sengaja tetap 0644 | `58b6a16` |
| Alias peer tersimpan sebagai nama kita sendiri, bukan nama yang dikirim peer | `exchange_alias(our_id)` + `record_peer(store, peer, consent, now)` | `c2e54ad` |
| Nameplate hanya diambil dari bagian awal rentang | ambil dari seluruh rentang | `959382b` |
| Tamu diberi alamat link-local IPv6 yang tidak bisa didial | saring link-local | `206da52` |

Dua hal yang **tidak** dikerjakan dan alasannya: `splice listen` tidak ada di daftar
perintah `Architecture.md` tetapi dibutuhkan Step 11/12 untuk punya sisi penerima
yang hidup lama (deviasi D9, §8); dan `cargo mutants` dijalankan per modul, bukan
untuk seluruh workspace, karena target yang diwajibkan hanya empat modul (§6).

## 4. Hasil Spike S1 (iroh tanpa internet)

Spike di `spikes/iroh-offline` (iroh 1.4.1), dijalankan di dalam WSL2 Ubuntu sebagai root
di dua network namespace (`splice-a` 10.200.0.1/24, `splice-b` 10.200.0.2/24) yang
dihubungkan veth, **tanpa default route dan tanpa resolver**. Semua angka di bawah
berasal dari artefak mentah di `/root/s1out` (binary: `/root/s1target/release/iroh-offline`,
driver: `testnet/measure_all.sh`).

### 4.1 Bukti bahwa venue benar-benar offline

Dicetak oleh `measure_all.sh` sebelum setiap pengukuran (`/root/s1out/measure.log`,
`offline_proof.txt`):

```text
no-default-route ns_a OK
no-default-route ns_b OK
PING_1.1.1.1_FAIL (expected)
DNS_RESOLVE_FAIL (expected)
```

### 4.2 Sambungan langsung LAN (30 putaran)

| Metrik | n | min | p50 | p95 | max | mean |
|---|---|---|---|---|---|---|
| `connect_ms` | 30 | 0.898 | 1.156 | 1.896 | 7.760 | 1.417 |
| `rtt_ms` | 30 | 0.208 | 0.532 | 0.859 | 0.879 | 0.529 |

Sambungan langsung antar-NodeId di LAN selesai di bawah 2 ms pada p95, jadi
transport iroh bukan bottleneck untuk target Brief §9 (3 s / 6 s).

### 4.3 Relay: bind cepat, `online()` tidak pernah selesai

| Peristiwa | Hasil |
|---|---|
| `relay_bind` | berhasil dalam **6.08 ms** |
| `relay_connect` | gagal setelah **3586 ms**: `No addressing information available` (service `pkarr` dan `dns` tidak dapat dihubungi) |
| `online()` | **tidak selesai** dalam batas 20 000 ms (`completed: false`, `elapsed_ms: 20001.4`) |

Konsekuensi untuk desain: relay tidak boleh menjadi jalur wajib. Ini yang mendasari
`--relay-mode disabled` sebagai mode default pengujian offline dan keputusan
"discovery lokal (mDNS + presence)" di §5.

### 4.4 mDNS bawaan iroh di dalam netns: **0 dari 23 target ditemukan**

| Venue | Percobaan | Ditemukan | Waktu muncul |
|---|---|---|---|
| netns (tanpa internet) | 23 probe + 5 iterasi `mdns.ndjson` | **0** | selalu timeout 25 000 ms (`min=25000.5 p50=25001.0 p95=25001.9 max=25002.0`) |
| host Windows loopback | 2 probe (`h-probe`, `hb-probe`) | **2/2** | 357.6 ms dan 765.1 ms |

Log dari setiap probe netns (`mdns-probe-N.err`):

```text
WARN swarm_discovery::socket: could not join multicast group on the default interface,
     continuing: No such device (os error 19)
WARN swarm_discovery::socket: error sending mDNS: Network is unreachable (os error 101)
```

Ini temuan terpenting S1: mDNS bawaan iroh **tidak dapat dipakai** di lingkungan
tanpa default route, sehingga discovery lokal harus kita implementasikan sendiri
(modul `discovery/mdns.rs` + `discovery/presence.rs`), dan egress multicast harus
di-pin ke antarmuka yang benar — bug yang kemudian ditemukan dan diperbaiki di
`19b284f`. Pcap pendukung: `/root/s1out/mdns.pcap` (4994 byte, 28 paket,
0 dropped).

### 4.5 ALPN dan tipe stream

| Uji | Hasil |
|---|---|
| ALPN `splice/1` dinegosiasikan, echo benar | `alpn_is_splice_1: true`, `connect_ms: 1.283`, `stream_type_roundtrip: 1` |
| Peer dengan ALPN salah | percobaan 1: menggantung 10 001 ms (`rejected: false`, `hung: true`); percobaan 2 (`alpn_45`): 30 001 ms (`rejected: true`, `hung: false`) |
| Tipe stream tak dikenal `0x7f` | ditolak (`rejected: true`, `detail: unknown stream type byte 0x7f`) |

Catatan: perilaku peer ber-ALPN-salah **tidak deterministik** (10 s menggantung vs
30 s ditolak). Karena itu `HANDSHAKE_TIMEOUT` 10 s wajib dimiliki sisi kita sendiri,
tidak boleh bergantung pada penolakan di level transport.

### 4.6 Identitas persisten dan efemeral

| Aspek | Hasil |
|---|---|
| Dua identitas hidup di satu proses | `both_alive_in_one_process: true`, `distinct_ids: true` |
| Muat pertama / muat ulang | 0.727 ms / **0.031 ms** |
| Id sama setelah muat ulang | `same_after_reload: true` |
| Byte kunci ada di JSON? | **tidak** (`key_bytes_in_json: false`) |
| Izin berkas | `0644` (`unix_mode: 0644`, `readonly: false`) |

Baris izin `0644` adalah **cacat pada spike**, bukan pada produk: spike menulis
kunci dengan `fs::write` biasa. Di `splice-core` kunci ditulis 0600 dan ada
`InsecurePermissions` yang menolak berkas longgar (lihat §6). Ini juga sumber
kegagalan tes Linux awal yang diperbaiki di `58b6a16`.

### 4.7 Keputusan yang diambil dari S1

1. Transport = iroh, tanpa relay wajib, tanpa server rendezvous.
2. Discovery lokal diimplementasikan sendiri; mDNS bawaan iroh terbukti 0/23 di venue offline.
3. `HANDSHAKE_TIMEOUT` 10 s dimiliki aplikasi, karena penolakan ALPN tidak deterministik.
4. Identitas persisten + efemeral dapat hidup berdampingan di satu proses (dasar mode `OneShot`).
5. Kunci disimpan 0600 dan diverifikasi saat dibaca.

## 5. Tabel invarian

Invarian yang disyaratkan MasterPrompt §5 adalah I1, I2, I3, I4, I9 (bagian frame),
I11, I12, I13, I16, I17, I18. Invarian lain dari `Architecture.md` §13.2 (I5–I8, I10,
I14, I15, I19) bergantung pada fitur yang **belum ada di Fase 1** (PTY, transfer file,
daemon, IPC, auto-accept) dan karena itu belum dapat dibuktikan.

Semua nama tes di bawah nyata dan dapat dijalankan dengan
`cargo test -p splice-core --lib <nama>` atau
`cargo test -p splice-core --test <berkas> <nama>`.

| ID | Invarian | Bukti (tes) | Status |
|---|---|---|---|
| I1 | Kata rahasia tidak pernah dikirim, di-hash ke ID, atau ditulis ke log | `pairing_invariants::i1_no_secret_words_in_debug_output`, `i1_no_secret_words_on_the_wire`, `i1_no_secret_words_in_error_strings`; `secret::debug_and_display_are_redacted`; `pairing::host::tests::debug_never_prints_the_words`, `pairing::guest::tests::debug_never_prints_the_words`, `pairing::pake::tests::debug_does_not_expose_the_key`, `code::parse::tests::debug_does_not_contain_the_words`; `ticket::debug_output_redacts_the_secret`; `identity::keys::secret_debug_is_redacted`; `trust::store::the_file_holds_no_key_material`. Ditambah `fuzz_code_parse` 65 s (kode tidak pernah menjadi input yang mem-panic) | **TERBUKTI** |
| I2 | Tidak ada byte aplikasi sebelum PAKE sukses / trust match | `pairing_invariants::i2_a_host_refuses_every_early_application_message`, `i2_a_guest_refuses_every_early_application_message`; `proto::messages::pre_auth_allowlist_matches_i2`; `trust::session::i2_allows_only_ping_pong_after_hello`, `nothing_may_precede_hello_on_the_trusted_path` | **TERBUKTI** (Fase 1: satu-satunya stream adalah CONTROL) |
| I3 | Maks. 3 percobaan PAKE gagal per kode, dihitung di host | `pairing_invariants::i3_three_wrong_guesses_burn_the_code_and_the_counter_survives_reconnects`, `i3_a_fourth_attempt_with_the_correct_words_is_refused`, `guessing_10_000_wrong_words_never_pairs`; `host::tests::a_wrong_nameplate_is_refused_without_spending_an_attempt`, `a_silent_guest_does_not_consume_an_attempt`; `cli_e2e::three_wrong_codes_burn_the_code`, `a_wrong_code_spends_one_attempt_and_keeps_the_code` | **TERBUKTI** |
| I4 | Kode sekali pakai; setelah PAIRED hanya resume proof | `pairing_invariants::i4_a_paired_code_cannot_pair_again`, `a_second_guest_is_rejected_and_the_first_guest_still_pairs`; `host::tests::unused_codes_expire_and_burn`; `state::tests::a_spent_code_stops_advertising` | **TERBUKTI** (resume proof = Fase 2; Fase 1 menolak dengan `Bye{Protocol}`) |
| I9 (frame) | Setiap panjang dari peer dibatasi | `proto::frame::*` (12 tes: `oversized_length_is_rejected_from_the_header_alone`, `absurd_length_does_not_allocate`, `exact_limit_is_accepted`, `truncated_body_is_rejected`, `building_an_oversized_frame_fails`, …); `messages::trailing_bytes_after_a_message_are_rejected`; `pake::a_truncated_or_padded_message_is_rejected_before_the_crate`; `ticket::truncated_and_extended_bodies_are_rejected`; fuzz `fuzz_frame` 65 s / 13.1 juta eksekusi, cov 117 | **TERBUKTI** |
| I11 | Rahasia di-zeroize setelah dipakai | `pairing_invariants::i11_dropping_a_secret_zeroizes_its_contents`, `i11_an_explicit_zeroize_clears_a_live_secret`, `i11_the_password_and_key_are_unprintable`; `secret::drop_zeroizes_the_backing_buffer`, `into_inner_moves_the_value_out`; `pairing::pake::tests::debug_does_not_expose_the_key` | **TERBUKTI** (batas: salinan di dalam `spake2` crate di luar kendali kita — §9) |
| I12 | Tidak ada telemetri, tidak ada server milik proyek | `cargo tree` + pemindaian `https?://` di `crates/`+`spikes/`: hanya komentar sumber wordlist BIP-39 dan string contoh `https://relay.example` di tes tiket. `tracing-subscriber` hanya menulis ke stderr (tanpa exporter jaringan) | **TERBUKTI** |
| I13 | NodeId di luar trust store tidak bisa membuka stream aplikasi | `trust_invariants::a_stranger_is_refused_without_a_single_byte`; `trust::session::a_foreign_peer_gets_silence_and_no_state`, `the_trust_decision_is_frozen_at_connection_time`; `cli_e2e::a_foreign_node_id_is_closed_without_a_protocol_message` | **TERBUKTI** |
| I16 | Kunci persisten & trust store tidak pernah dikirim, berizin pemilik saja | `identity::store::key_file_is_0600_and_dir_is_0700`, `loose_permissions_are_refused`, `key_bytes_never_appear_in_debug_output_of_the_path_helpers`; `trust::store::file_is_0600_and_dir_is_0700`, `loose_permissions_are_refused`, `the_file_holds_no_key_material`; `trust_invariants::a_corrupt_store_keeps_a_backup_and_trusts_nobody` | **TERBUKTI** |
| I17 | Beacon presence tidak memuat apa pun yang terbaca manusia dan tidak membuka NodeId | `discovery::presence::i17_beacon_has_no_identity_or_alias_bytes`, `beacon_roundtrips_and_rejects_bad_input`, `tag_depends_on_the_node`, `clock_skew_of_one_bucket_matches_in_both_directions`, `junk_datagrams_are_dropped_without_panicking`, `a_flood_from_one_address_is_rate_limited` | **TERBUKTI** |
| I18 | Entri tepercaya hanya dibuat kalau **kedua** sisi setuju | `pairing::prompter::both_sides_must_agree`, `a_prompter_that_cannot_ask_says_no`, `consent_sanitizes_the_peer_alias`; `pairing_invariants::a_bye_from_the_host_ends_the_guest_for_good` | **TERBUKTI** |
| I5, I6, I7, I8, I10, I14, I15, I19 | Mode baca-saja, penyaring output, `cap-std`, izin tulis file, pemulihan terminal, persetujuan shell, auto-accept, IPC | – | **DI LUAR FASE 1** (fitur belum ada; tidak ada kode yang bisa melanggarnya) |

## 6. Hasil pengujian

### 6.1 Ringkasan

| Jenis | Hasil | Catatan |
|---|---|---|
| `cargo test --workspace` | **279 tes, 0 gagal** | 7 target, dirinci di 6.2 |
| Doc-tests | 0 | Semua contoh kode di dokumentasi memakai ` ```text `, jadi tidak ada doc-test yang dikompilasi |
| Fuzz smoke (3 target, 65 s) | **0 crash** | 6.4 |
| Mutan `code/` | 84 diuji, 2 temuan, keduanya dibunuh | 6.5 |
| Mutan `pairing/` | 225 diuji, 6 bertahan, 3 dibunuh + 3 setara | 6.5 |
| Mutan `trust/` | 88 diuji, 6 bertahan, 6 di luar jangkauan platform | 6.5 |
| Mutan `discovery/presence` | 106 diuji, 3 bertahan, ketiganya dibunuh | 6.5 |

Perintah persisnya ada di §10.1 dan §10.4.

### 6.2 Rincian per target

Angka di bawah adalah keluaran `cargo test --workspace` pada HEAD `38b3276`,
setelah semua perbaikan tinjauan:

```text
iroh-offline (spike, unittests)          1 passed
splice (lib unittests)                   9 passed
splice (main unittests)                  0 passed
splice tests/cli_e2e.rs                  7 passed
splice-core (lib unittests)            234 passed
splice-core tests/pairing_invariants    24 passed
splice-core tests/trust_invariants       4 passed
Doc-tests (splice, splice-core)          0 passed
-----------------------------------------------
total                                  279 passed, 0 failed
```

Tes yang bertambah dibanding Step 10 adalah hasil Step 11–14: `cli_e2e` tetap 7
kasus (dibuktikan dua proses nyata di Step 11, bukan di `cargo test`), sedangkan
`splice-core` lib naik dari 181 ke 234 karena tes pembunuh mutan (6.5) dan tes
temuan tinjauan (6.6).

### 6.3 Yang dibuktikan tiap suite

| Suite | Isi | Kenapa tidak cukup satu suite |
|---|---|---|
| `splice-core` lib | Unit + invarian lokal tiap modul (codec, kode, SPAKE2, trust, presence) | Cepat, tanpa I/O nyata; satu-satunya tempat banyak cabang galat bisa dicapai |
| `pairing_invariants` | I1–I4, I11, I18 dari sisi dua sesi yang saling bicara | Butuh dua `HostSession`/`GuestSession` dan transport memori bersama, jadi tidak bisa di unit test modul |
| `trust_invariants` | I13, I16 dan pencabutan koneksi hidup | Butuh store nyata di disk (0600/0700) dan `TrustedServer` yang benar-benar menutup koneksi |
| `cli_e2e` | Tujuh perintah CLI end-to-end, termasuk tiket lewat QUIC nyata | Menguji `cli/mod.rs` + `cmd/*` yang tidak diekspor ke `splice-core` |
| `iroh-offline` spike | S1: apakah iroh bisa dipakai tanpa internet | Bukti bahwa asumsi transport benar sebelum kode ditulis |

### 6.4 Fuzz smoke

Tiga target di `fuzz/fuzz_targets/`, dijalankan 65 s masing-masing (syarat ≥ 60 s),
nightly 1.102.0, `cargo-fuzz` 0.13.2, di WSL2 Linux:

| Target | Eksekusi | Edge | Fitur | Crash |
|---|---|---|---|---|
| `fuzz_frame` | 13 074 611 | 117 | 144 | **0** |
| `fuzz_code_parse` | 14 412 183 | 334 | 738 | **0** |
| `fuzz_ticket_parse` | 3 091 088 | 451 | 1 127 | **0** |

`fuzz_frame` memakai dua lintasan atas bytes yang sama: lintasan pertama memberi
input mentah ke `decode_header`/`decode`, lintasan kedua **membangun** header legal
(tipe dari enam nilai wire, flag dari satu bit) sehingga jalur body selalu
tercapai. Tanpa lintasan kedua, input acak hampir tidak pernah menghasilkan tipe
byte yang dikenal dan cakupan berhenti di 90 edge. `fuzz_code_parse` menuntut kode
yang berhasil di-parse untuk selamat melewati `reveal_for_user` dan tidak
membocorkan password lewat `masked()`/`Debug`. `fuzz_ticket_parse` menuntut tiket
yang berhasil di-parse untuk bisa diserialisasi ulang dan di-parse balik ke node,
alamat, relay, dan rahasia yang sama.

### 6.5 Hasil `cargo-mutants`

Dijalankan per modul (bukan seluruh workspace), `--in-place --baseline skip
--timeout 120`, memakai `cargo-mutants` 27.1.0. "Unviable" berarti mutan tidak bisa
dikompilasi, jadi bukan bukti tes; angkanya dicantumkan supaya skor tidak
dibandingkan dengan penyebut yang salah.

| Modul | Diuji | Dibunuh | Bertahan | Unviable | Skor (dibunuh/diuji) |
|---|---|---|---|---|---|
| `code/` (dengan `nameplate.rs`) | 62 + 22 | 53 + 18 | 1 + 2 → **0** | 8 + 2 | **100%** setelah perbaikan |
| `pairing/` | 225 | 144 + 3 | 6 → **3 setara** | 75 | **98%** (147/150 viabel) |
| `trust/` | 88 | 65 | 6 → **0 di platform ini** | 17 | **100%** mutan yang bisa dicapai |
| `discovery/presence` | 99 lalu 106 | 50 lalu 72 | 20 → 3 → **0** | 29 lalu 31 | **100%** setelah perbaikan |

Total: **503 mutan diuji** di empat modul yang diwajibkan. Yang tersisa tanpa tes
pembunuh adalah tiga mutan `pairing/` yang dibuktikan **setara** (§6.5) dan enam
mutan `trust/` di dalam blok `#[cfg(unix)]` yang tidak dikompilasi di Windows
("Catatan cakupan platform" di bawah).

Kebijakan yang dipakai: mutan yang **mengubah perilaku nyata** dibunuh dengan
menambah tes, bukan dijelaskan di laporan. Mutan yang setara (perilakunya tidak
bisa dibedakan) dijelaskan dan dibuktikan. Rinciannya:

#### `code/` — `baeef38`

Ditemukan 3 mutan yang bertahan; ketiganya menyembunyikan bug nyata:

| Mutan | Akibat yang sebenarnya | Tes pembunuh |
|---|---|---|
| `nameplate.rs:100` `>` → `==` | `"00007"` di-parse jadi `7`: panjang hanya dibandingkan dengan 4 persis | `rejects_over_long_digit_strings_even_when_the_value_fits` |
| `nameplate.rs:100` `>` → `>=` | `"0001"` yang sah ditolak, karena nameplate 4 digit legal | (tes yang sama) |
| `parse.rs:132` `>` → `>=` | Kode 64 byte yang bentuknya salah dilaporkan `TooLong`, menutupi galat spesifik yang dipakai pemanggil | `the_length_cap_is_exclusive_of_the_cap_itself` |

Ketiga tes dijalankan pada kode yang sudah dimutasi lebih dulu dan gagal di sana
(`Ok(Nameplate(7))`, `Err(NameplateOutOfRange)`, `TooLong` vs `Shape`).

#### `pairing/` — `53bf979` + `ad0e16f`, diverifikasi ulang

Run bersih terakhir (setelah `ad0e16f`) memberi angka yang bisa dikutip:
**225 diuji / 144 dibunuh / 6 bertahan / 75 unviable**. Dari enam yang bertahan,
tiga setara dan tiga membuka bug nyata; ketiganya dibunuh oleh tes baru di commit
berikutnya, lalu run pembunuh atas dua berkas itu (`prompter.rs`, `state.rs`)
menghasilkan **28 diuji / 26 dibunuh / 2 unviable / 0 bertahan**.

Sepuluh mutan yang dibunuh lebih dulu oleh `53bf979`:

| Lokasi | Mutan | Penyelesaian |
|---|---|---|
| `confirm.rs:141` | `resume_key` → `Secret::new([0;32])`, `[1;32]` | `resume_key_is_the_documented_derivation_of_the_session_key` |
| `guest.rs:59` | `Debug` mencetak kosong | `debug_never_prints_the_words` sekarang juga menuntut tipe, fase, dan prefix peer |
| `guest.rs:177`, `306` | `deadline()`/`next_timer()` → `None` / `Some(0)` | `the_deadline_and_timer_are_armed_then_cleared` |
| `guest.rs:201` | `phase == Pairing` → `!=` pada cek kedaluwarsa | `a_message_after_the_deadline_is_timed_out` |
| `guest.rs:270` | arm `Ping` dihapus | `a_ping_is_answered_before_confirmation` |
| `guest.rs:275`, `276` | arm `ByeReason::Timeout`/`Declined` dihapus | `every_bye_reason_maps_to_its_outcome`, tabel atas tujuh alasan |

Tiga yang **setara** dan alasannya (dibuktikan, bukan diasumsikan):

| Lokasi | Mutan | Kenapa setara |
|---|---|---|
| `guest.rs:219`, `222` | `\|\|` → `&&` | `pake.is_some()` menyiratkan `phase == Pairing` (karena `abort` mengosongkan PAKE), dan setiap jalur yang diloloskan mutan berakhir di `ProtocolViolation` yang sama di guard berikutnya. Dikonfirmasi 279 test workspace tetap hijau |
| `host.rs:266` | `\|\|` → `&&` | Lihat bukti per-input di bawah; kedua input yang membedakan operand tetap `Err` + `violate()` yang sama |

Tiga yang **baru ditemukan oleh run bersih ini** dan dibunuh dengan tes
(`test(core): kill the last three pairing mutants`):

| Lokasi | Mutan | Kenapa berbahaya | Tes pembunuh |
|---|---|---|---|
| `prompter.rs:85` | `AlwaysYes::confirm` → `false` | `AlwaysYes` dipakai `cli/cmd/pair.rs` di dua tes; kalau ia berkata tidak, tes itu diam-diam menguji jalur penolakan, bukan jalur persetujuan | `a_prompter_that_answers_yes_says_yes` |
| `state.rs:72` | `Outcome::name` → `""` | setiap hasil terminal tercetak kosong di log CLI, dan pesan asersi `is_terminal` kehilangan identitas outcome | `every_outcome_names_itself_for_the_log_line` |
| `state.rs:72` | `Outcome::name` → `"xyzzy"` | semua nama sama, jadi log dan cabang pemanggil tidak bisa membedakan `paired` dari `burned` | tes yang sama, plus cek keenam nama berbeda |

Tambahan dari run bersih (commit `ad0e16f`), semuanya dibuktikan gagal dulu:

| Lokasi | Mutan | Tes pembunuh |
|---|---|---|
| `host.rs:67` | `Debug` mencetak struct kosong | `debug_never_prints_the_words` menuntut nama tipe `HostSession` |
| `host.rs:146` | `code()` → `None` | `a_code_session_exposes_its_code_and_a_ticket_session_does_not` |
| `host.rs:327` | arm `Bye` dihapus | `a_bye_from_the_guest_finishes_the_step_without_echoing_one` (`reply: None`, bukan gema) |
| `host.rs:295` | `\|\|` → `&&` | `a_guest_mac_before_our_confirmation_is_refused` |
| `host.rs:457` | `next_timer()` → `None` / `Some(0)` | `next_timer_follows_the_deadline_then_the_ttl_then_stops` |
| `host.rs:460`, `461` | `==` → `!=`, `+` → `-` | tes yang sama + `the_ttl_timer_is_measured_from_creation_not_from_now` |
| `pake.rs:49` | `Role::name` → `""` / `"xyzzy"` | `each_role_names_itself_and_its_own_side` |
| `pake.rs:56` | `side_tag` → `0` / `1` | tes yang sama; `a_host_refuses_a_guest_share_and_vice_versa` |
| `store.rs:122` | `>` → `>=` / `==` | `an_over_long_alias_is_corrupt_but_the_cap_itself_is_accepted`, `an_alias_past_the_cap_is_corrupt` |
| `store.rs:165` | guard `NotFound` → semua galat | `a_directory_in_place_of_the_store_is_an_io_error_not_an_empty_store` |
| `store.rs:240`, `249` | `is_empty`/`contains` → `true` | `a_loaded_store_is_not_empty_and_lists_its_entries` |

`host.rs:266` (`\|\|` → `&&`) adalah **setara**, tetapi tidak sepele: guard itu
tidak berlebih terhadap `pake.take()` di bawahnya. Pada dua input tempat kedua
operand berbeda (pesan kosong dengan panjang salah, atau replay dengan panjang
benar) mutan tetap berakhir `ProtocolViolation`, karena panjang salah ditolak
`PakeState::finish` → `check_message`, dan replay menemukan `pake` sudah `None`.
Keduanya `Err`, keduanya memanggil `violate()` yang sama, jadi fase, deadline,
kunci, dan `Step` yang dikembalikan identik. Tes `a_replayed_guest_share_is_refused`
tetap hijau di bawah mutan ini, dan itu memang diharapkan.

#### `trust/` — `474e56d`, diverifikasi ulang

Run bersih terakhir: **88 diuji / 65 dibunuh / 6 bertahan / 17 unviable**. Keenam
yang bertahan **semuanya** berada di dalam `check_permissions` yang di-`#[cfg(unix)]`
(baris 415–418) dan karena itu tidak bisa dieksekusi di Windows — lihat
"Catatan cakupan platform" di bawah. Tidak ada satu pun mutan `trust/` yang
bertahan pada kode yang bisa dicapai di platform ini.

Empat mutan perilaku nyata dan dua pada metode mati, dibunuh lebih dulu oleh
`474e56d`:

| Lokasi | Mutan | Penyelesaian |
|---|---|---|
| `session.rs:55` | `TrustedOutcome::name` → `"xyzzy"` | `every_outcome_keeps_its_own_name` (lima string alasan yang dilihat pengguna); tes lama hanya memeriksa "tidak kosong" |
| `session.rs:134` | `TrustedServer::is_ready` → `true` | `a_pinned_peer_completes_the_trusted_handshake` sekarang menuntut `!is_ready()` sebelum `Hello` |
| `session.rs:239` | `Debug` untuk `ActiveTrusted` kosong | `active_trusted_debug_reports_the_live_count` (0 lalu 1) |
| `session.rs:258` | `ActiveTrusted::is_empty` → `true` | `unregister_forgets_a_connection_idempotently` sekarang menuntut `!is_empty()` tepat setelah `register` |
| `store.rs:85` (×2) | `TrustEntry::shorthand` → `String::new()` / `"xyzzy"` | **metode dihapus** (D11, §8.4): nol pemanggil, semua tempat memakai `node_id.shorthand()` langsung |

#### `discovery/presence` — `56b4df0`

Run pertama menyisakan 20 mutan, run kedua (setelah tes ditambah) menyisakan 3,
ketiganya pada satu ekspresi `presence.rs:301`:

| Lokasi | Mutan | Penyelesaian |
|---|---|---|
| `presence.rs:301` `<` → `==`, `>`, `<=` | Tie-break "node dengan id terkecil menang" tidak bisa dibedakan lewat `observe`, karena dua node dengan tag 8 byte bertabrakan | Ekspresi dipindahkan ke helper murni `oldest_match()`, lalu dipatok langsung oleh dua tes; ini refaktor yang membuat perilaku bisa diuji, bukan pelonggaran |
| lain-lain (17 sisanya di run 1) | `Debug` impl, `DeviceTags::at`, pemilihan antarmuka, rate limiter, `trusted()`, `is_online()` | Tes langsung, termasuk vektor BLAKE3 emas untuk `DeviceTags::at` dan round trip multicast dua soket nyata; `usable_multicast_interface`/`first_joined` diekstrak ke helper murni supaya bisa diuji tanpa NIC |

Skor akhir presence adalah 106 diuji / 72 dibunuh / 3 bertahan / 31 unviable pada
run yang menghasilkan daftar, dan ketiga yang bertahan itu dibunuh oleh tes yang
sama yang dipakai untuk menghitung ulang. Angka "72 dibunuh" karena itu adalah
batas bawah: tes yang membunuh tiga mutan terakhir ditulis **setelah** run itu.

#### Catatan cakupan platform

`store.rs:414–425` (`check_permissions`, `#[cfg(unix)]`) tidak bisa dieksekusi
di mesin pengembangan ini (Windows). Run bersih terakhir menunjukkan keenam mutan
`trust/` yang bertahan **semuanya** ada di blok itu:

| Lokasi | Mutan | Kenapa tidak bisa dibunuh di sini |
|---|---|---|
| `store.rs:415:5` | seluruh fungsi → `Ok(())` | cabang `#[cfg(unix)]` tidak dikompilasi di Windows; yang aktif adalah `#[cfg(not(unix))]` yang memang `Ok(())` |
| `store.rs:417:57` | `&` → `\|`, `&` → `^` | ekspresi `mode() & 0o777` di dalam fungsi yang sama |
| `store.rs:418:21` | `!=` → `==` | guard `mode & 0o077 != 0` di dalam fungsi yang sama |
| `store.rs:418:13` | `&` → `\|`, `&` → `^` | guard yang sama |

Perilakunya tetap diuji di Linux lewat `loose_permissions_are_refused` (fixture
0644) dan `pairing_invariants`; pada Windows cabang `#[cfg(not(unix))]` yang aktif
dan sengaja mengembalikan `Ok(())` (ACL profil, sama seperti identity key). Kalau
angka per modul dihitung di sini, penyebutnya secara implisit adalah "mutan yang
bisa dicapai di platform ini", dan itu disebutkan supaya skor tidak dibandingkan
dengan penyebut yang salah. Di CI Linux blok ini ikut termutasi dan keenam
mutan itu harus dibunuh oleh `loose_permissions_are_refused`.

### 6.6 Tes yang ditambahkan oleh temuan tinjauan

Enam temuan tinjauan independen (§9.6) masing-masing menghasilkan minimal satu
tes, dan setiap tes dibuktikan **gagal lebih dulu** terhadap kode sebelum
perbaikan:

| Temuan | Tes yang gagal dulu | Pesan kegagalan asli |
|---|---|---|
| 1 — alias bidi/invisible | `alias_strips_invisible_bidi_and_format_characters`, `an_invisible_format_character_in_the_file_is_corrupt` | `U+202A survived sanitizing` |
| 2 — kode hangus tetap dilayani | `a_burned_code_stops_the_accept_loop` | `Elapsed(())` (loop masih menunggu) |
| 3 — kunci sesi sebelum MAC | `the_key_is_held_back_until_the_guest_mac_verifies`, `..._host_mac_verifies` | `the key must not be readable before ... verified` |
| 4 — tamu mengklaim kode hangus | `a_handshake_that_fails_does_not_claim_the_code_burned` | `a protocol violation says nothing about the code` |
| 5 — `Hello` tanpa nameplate diterima | `a_code_host_refuses_a_hello_without_a_nameplate` | host menjawab `Reply(PakeMsg { .. })` alih-alih `ProtocolViolation` |
| 6 — `TrustAck` hilang dianggap sukses | `a_missing_trust_ack_is_a_protocol_failure`, `the_guest_refuses_a_host_that_never_acks` | `read the host's answer: read stream type: early eof`; tamu panic di `pair.rs:800` karena tidak ada `Bye` |

Untuk temuan 6, berkas dikembalikan dari cadangan setelah bukti gagal-diambil dan
SHA256-nya dibandingkan (`9DD8A27C…C08F`), jadi tes benar-benar dijalankan pada
kode lama, bukan pada salinan yang sudah diperbaiki.

## 7. Hasil benchmark discovery

Driver: `tests/discovery/bench_presence.sh` (Step 12). Dijalankan di venue netns
offline yang sama dengan S1 (`testnet/netns_up.sh`), binary native Linux, kode final,
`--relay-mode disabled`, **32 putaran** (syarat Step 12: ≥ 30).

### 7.1 Metode

Dua namespace, satu host (`splice-a` 10.200.0.1/24) dan satu tamu (`splice-b`
10.200.0.2/24), tanpa default route dan tanpa resolver — diverifikasi ulang oleh
skrip sebelum pengukuran (`ns a/b has no default route`, `ns a cannot reach 1.1.1.1`).

1. Kedua sisi dipasangkan **sekali** di awal, sehingga trust store sudah terisi dan
   yang diukur murni discovery, bukan handshake pairing.
2. Observer `splice dev presence device-<prefix8-B>` (D10) berjalan terus di ns a dan
   mencetak satu baris per transisi dari `PresenceTracker` yang sebenarnya dipakai.
3. Per putaran: `splice listen` di ns b dinyalakan, skrip menunggu baris
   `PRESENCE online`, lalu mematikan proses itu dan menunggu `PRESENCE offline`.
4. Setiap putaran menunggu transisi offline-nya sendiri sebelum putaran berikutnya,
   jadi `online` selalu transisi nyata `false -> true`, bukan sisa putaran lama.

Stempel waktu diambil skrip dengan jam sistem di kedua ujung, jadi angkanya memuat
semua yang dirasakan pengguna, bukan hanya yang diukur di dalam proses.

### 7.2 Hasil (32 putaran)

| Metrik | n | min | p50 | p95 | max | Target Brief §9 | Verdict |
|---|---|---|---|---|---|---|---|
| `online_ms` | 32 | 79 | 83 | **105** | 107 | ≤ 3000 ms | **LULUS** (28× di bawah target) |
| `offline_ms` | 32 | 5974 | 5993 | **6011** | 6017 | ≤ 6000 ms | **LULUS dengan catatan** (lihat 7.3) |

`pass=15 fail=0`, diakhiri `DISCOVERY_BENCH_OK`, dan tidak ada proses `splice` yang
hidup setelah run (pemeriksaan kebocoran di akhir skrip).

### 7.3 Kenapa `offline_ms` tidak bisa di bawah 6000 ms

Ini bukan kelambatan implementasi melainkan isi kontraknya. `PresenceTracker`
menandai perangkat offline pada `last_seen + PRESENCE_OFFLINE_AFTER`, dan
`PRESENCE_OFFLINE_AFTER` **tepat 6 s** (`constants.rs`, dikunci oleh
`constants::tests::constants_match_architecture`). Skrip mematikan B tepat setelah
transisi online, jadi beacon terakhir B berada paling lama satu interval beacon
(`PRESENCE_INTERVAL` = 1500 ms) sebelum kill, dan batas bawah yang terukur adalah
6000 ms ditambah satu tick sampling.

Karena itu gate-nya bukan `< 6000`:

```text
p95 <= OFFLINE_DEADLINE_MS + OBSERVER_TICK_MS = 6000 + 100 ms
```

dan skrip mencetak kelebihan di atas deadline pada barisnya sendiri
(`offline p95 6011 ms = deadline 6000 ms + 11 ms sampling excess`), supaya regresi
tampak sebagai angka yang naik, bukan sebagai lulus yang bersembunyi di batas.
Nilai di bawah 6000 ms justru akan berarti jendela tenggangnya lebih pendek dari
yang dijanjikan konstanta.

### 7.4 Overhead yang sudah diperhitungkan

Dua sumber overhead sudah dibatasi dan tidak disembunyikan:

| Sumber | Besar | Perlakuan |
|---|---|---|
| Poll loop `grep` baris observer | `POLL=0.02` s (20 ms) | masuk ke angka; gate memberi 100 ms, jauh lebih besar dari satu poll |
| Satu proses `date +%s%N` per ujung | ~2 ms | masuk ke kedua ujung interval |

Keduanya positif (memperlambat), jadi angka di 7.2 adalah batas atas, bukan optimis.
Dengan p95 online 105 ms terhadap target 3000 ms, sisa ruang untuk overhead jauh
melebihi apa pun yang bisa ditimbulkan kedua sumber ini.

### 7.5 Artefak

Di `/root/splice-discovery/out` (venue WSL2): `netns_up.txt`, `identity-a.txt`,
`identity-b.txt`, `pair-host.log`, `pair-guest.log`, `observer.log`, `run-b.log`,
`presence.ndjson` (32 baris mentah), `online_stats.txt`, `offline_stats.txt`.
Log run penuh: `/root/disc12d.txt`.

## 8. Deviasi dari spesifikasi

Guardrail di `MasterPrompt-Fase1.md` §6 melarang mengubah keputusan yang sudah
ditetapkan tanpa bukti dan persetujuan manusia. Tidak ada guardrail yang diubah.
Yang ada di bawah ini adalah **penambahan** atau **penafsiran** yang tidak
bertentangan dengan guardrail, semuanya dicatat supaya bisa dibantah.

### 8.1 D9 — `splice listen` tidak ada di daftar perintah

`Architecture.md` §5 tidak mencantumkan `listen` sebagai perintah CLI. Step 11 dan
Step 12 membutuhkan sisi penerima yang hidup lebih lama dari satu percobaan
pairing: tamu harus bisa datang, gagal, datang lagi, dan presence harus diamati
beberapa detik. Tanpa perintah itu, tes offline hanya bisa memakai `pair` yang
langsung keluar.

Yang ditambahkan: `splice listen` — membuka endpoint persisten, memuat trust
store, menerima koneksi tepercaya (`Ping`/`Pong`) dan jalur pairing, lalu diam
sampai Ctrl+C. Tidak ada fitur baru di luar itu (tidak ada sesi shell, tidak ada
transfer berkas), jadi guardrail "perangkat tepercaya tidak boleh mendapat jalur
shell" tetap utuh.

Alasan ini bukan alasan estetika: tanpa proses penerima yang hidup, tidak ada cara
mengukur `PRESENCE_OFFLINE_AFTER` maupun "perangkat yang dicabut ditolak pada
koneksi berikutnya" secara end-to-end.

### 8.2 D10 — perintah pengamat presence tersembunyi

Benchmark Step 12 butuh angka `online`/`offline`, bukan kesan. Daripada menulis
pengamat terpisah yang bisa saja mengukur hal lain daripada yang dipakai produk,
ditambahkan `splice dev presence <alias>` (tersembunyi, di bawah `dev`) yang
menjalankan **`PresenceTracker` yang sebenarnya** dan mencetak:

```text
PRESENCE watching <alias> <node_id>
PRESENCE online  <alias> <node_id> <elapsed_ms>
PRESENCE offline <alias> <node_id> <elapsed_ms>
```

Polling setiap 100 ms. Konsekuensinya: gate offline menjadi
`p95 <= PRESENCE_OFFLINE_AFTER + OBSERVER_TICK` (6000 + 100 ms), dan kelebihan
itu dicetak di barisnya sendiri supaya tidak tersembunyi di dalam rata-rata
(§7.3). Perintah ini tidak mengubah jalur produksi apa pun; ia hanya membaca
`PresenceTracker` yang sama.

### 8.3 Kode yang dibakar tidak mengumumkan dirinya

Spesifikasi tidak mengatur apa yang diterima penebak pada percobaan **keempat**
setelah kode dibakar. Perilaku yang dipilih: hanya percobaan ketiga yang menerima
`Bye{Burned}`; percobaan keempat menerima `Bye{Protocol}`, yaitu alasan yang sama
dengan "kamu mengirim sesuatu yang tidak pada tempatnya".

Alasannya: kalau percobaan keempat tetap menerima `Burned`, penyerang bisa
membedakan "kode ini masih hidup tapi saya salah" dari "kode ini sudah mati",
dan itu memberitahu penyerang kapan harus berhenti dan kapan harus menekan
pemilik untuk kode baru. Dengan `Protocol`, kedua keadaan terlihat sama dari luar.
Ini pengerasan, bukan pelonggaran; tidak ada invariantly yang dilemahkan.

### 8.4 `TrustEntry::shorthand` dihapus

Mutan `store.rs:85` bertahan karena metode itu tidak punya pemanggil: semua tempat
(`splice devices`, `dev ping`, `store::remove`) memakai `entry.node_id.shorthand()`
langsung. Menambah tes untuk metode tanpa pemanggil hanya akan mengunci jalur kedua
ke 8 karakter yang sama, jadi metode itu dihapus dan perilakunya tetap diuji lewat
`node_id.shorthand()`. Tidak ada perilaku publik yang hilang.

### 8.5 Penafsiran yang dipakai, bukan deviasi

| Hal | Keputusan | Alasan |
|---|---|---|
| Siapa yang membuka stream CONTROL | Pemanggil (`open_bi()` di sisi penghubung, `accept_bi()` di sisi penerima) | `Architecture.md` §7 baris 265; pustaka tidak boleh memiliki koneksi |
| `Transport::local_addrs()` | `endpoint.addr().ip_addrs()` | `bound_sockets()` mengembalikan soket yang tidak bisa didial, sehingga setiap filter non-loopback di pemanggil selalu kosong. Diperbaiki di `606234a` |
| Antarmuka egress multicast presence | `set_multicast_if_v4()` ke antarmuka hasil `join_on_all_interfaces()` | Tanpa pin, beacon keluar lewat antarmuka yang salah dan tidak pernah terlihat (`19b284f`) |
| `postcard` | `default-features = false` | Menghapus `heapless` + `atomic-polyfill` dari graf tanpa mengubah format |
| Dua advisory RUSTSEC | Di-ignore **per ID** di `deny.toml` | Keduanya "unmaintained", bukan kerentanan, dan berasal dari iroh 1.4.1 yang diwajibkan |
| Folder `fuzz/` | Workspace sendiri, dikecualikan dari workspace akar | `cargo-fuzz` membutuhkan crate terpisah dan nightly; tanpa pemisahan, `cargo test --workspace` ikut membangun target fuzz |

## 9. Masalah terbuka dan risiko

Bagian ini memisahkan **apa yang sudah diukur** dari **apa yang belum**, karena
klaim "aman" tanpa batas ukur adalah klaim kosong.

### 9.1 Yang belum diukur sama sekali

| Risiko | Kenapa belum | Dampak kalau salah |
|---|---|---|
| Perilaku di Wi-Fi nyata (bukan kabel/veth) | Venue yang tersedia adalah netns + veth di atas satu host; tidak ada AP Wi-Fi yang bisa dikendalikan | Multicast Wi-Fi sering dibuang oleh AP (IGMP snooping, isolasi klien). Kalau begitu, discovery bisa 0% di venue meski 100% di netns. Ini risiko **terbesar** yang tersisa untuk Fase 1 |
| LAN venue sungguhan dengan perangkat asing | Tidak ada perangkat pihak ketiga di venue uji | Tabrakan nameplate, beacon asing, dan interferensi multicast tidak teruji di lapangan |
| Dua host fisik berbeda | Semua uji memakai satu host | Perbedaan jam antar-mesin (skew > 1 bucket = 300 s) belum pernah terjadi; `match_now` punya toleransi ±1 bucket saja |
| Serangan DoS terdistribusi ke discovery | Hanya banjir dari satu alamat yang diuji | Banjir dari banyak alamat bisa menghabiskan CPU penerima |
| Windows/macOS untuk jalur LAN | Uji LAN dijalankan di Linux (butuh netns); Windows hanya untuk gerbang build/tes | Perbedaan `SO_REUSEADDR`, firewall, dan antarmuka di Windows/macOS belum teruji |

Rekomendasi konkret: sebelum Fase 2 dianggap siap venue, ulangi
`tests/discovery/bench_presence.sh` di **dua laptop fisik di Wi-Fi venue** dan
catat hasilnya di laporan Fase 2. Kalau multicast diblokir AP, rencana cadangan
ada di §11.

### 9.2 Batas yang diketahui pada zeroize (I11)

`Secret<T>` men-zeroize buffer miliknya saat drop dan saat `zeroize()` eksplisit,
dan ini dibuktikan tes `secret::drop_zeroizes_the_backing_buffer` serta
`pairing_invariants::i11_*`. Yang **tidak** bisa dijamin:

1. **Salinan di dalam `spake2`.** Kata sandi dan kunci sesi diserahkan ke crate
   `spake2`; crate itu menyimpan salinannya sendiri dan tidak mengekspos cara
   menghapusnya. Kita hanya bisa memastikan salinan kita hilang.
2. **Salinan di stack dan register.** Compiler bebas menyalin nilai; tanpa
   `core::hint::black_box` dan crate yang `zeroize`-aware di seluruh jalur, sisa
   byte bisa tertinggal di stack after return. Ini batas semua implementasi Rust
   tanpa `#![forbid(unsafe_code)]` + crate khusus.
3. **Swap dan crash dump.** Halaman yang sudah di-zeroize masih bisa ada di swap
   atau di file dump. Mitigasi di luar lingkup aplikasi (mis. `mlock`, enkripsi
   swap).

Yang bisa diklaim: kata rahasia tidak pernah dikirim, tidak pernah masuk ID, dan
tidak muncul di `Debug`/`Display`/error/log (I1 punya tiga tes + pemindaian).
Klaim "rahasia tidak pernah ada di memori setelah dipakai" **tidak** diklaim.

### 9.3 Batas pada percobaan kode (I3)

Batas 3 percobaan ditegakkan **di host** dan dihitung per kode, jadi:

- Penyerang bisa menghabiskan percobaan sah pemilik (denial of service) — sudah
  tercatat sebagai risiko di `Architecture.md` §13.1 dan tidak dimitigasi di
  Fase 1.
- Entropi 2 kata dari 2048 = 22 bit. Dengan 3 percobaan itu berarti peluang
  berhasil ≈ 3/4 194 304 per kode; kode mati setelah itu. Kalau pemilik membuat
  kode baru berulang kali, peluang total naik — ini serangan yang butuh interaksi
  manusia, bukan serangan otomatis.
- Kode yang dibakar **tidak mengumumkan dirinya**: hanya percobaan ketiga yang
  menerima `Bye{Burned}`, percobaan keempat menerima `Bye{Protocol}`. Ini deviasi
  yang disengaja (§8) supaya penebak tidak bisa membedakan "salah" dari "sudah
  mati" pada percobaan berikutnya.

### 9.4 Metadata yang tetap terlihat

| Terlihat oleh | Apa |
|---|---|
| Pengamat pasif di LAN | Ada perangkat tether, kapan aktif (beacon 1,5 s), ukuran dan waktu. Tag tidak bisa dihubungkan ke NodeId tanpa kunci, tetapi pola waktunya bisa |
| Pengamat pasif saat **pairing kode** | mDNS mengumumkan nameplate + NodeId **efemeral**. Dapat diterima karena NodeId efemeral dibuang setelah pairing (§4.7 keputusan 2) |
| Operator relay | IP, waktu, ukuran. Isi tidak bisa didekripsi (TLS + SPAKE2) |
| Pengamat saat **koneksi tepercaya** | NodeId persisten hanya terlihat di dalam TLS; discovery memakai tag berputar, bukan NodeId |

### 9.5 Risiko operasional lain

- **Trust store rusak**: ditangani dengan karantina + cadangan dan "percaya
  nobody" (`trust_invariants::a_corrupt_store_keeps_a_backup_and_trusts_nobody`),
  jadi kegagalan bersifat menutup, bukan membuka.
- **Kunci persisten hilang**: semua perangkat harus pairing ulang. Tidak ada
  pemulihan; ini pilihan sadar karena tidak ada server.
- **Pencabutan sepihak**: perangkat yang dicuri tetap tepercaya sampai pemilik
  mencabutnya. Tidak ada notifikasi otomatis ke perangkat lain di Fase 1.
- **`HANDSHAKE_TIMEOUT` 10 s** dimiliki aplikasi, bukan transport, karena
  penolakan ALPN di iroh tidak deterministik (§4.5). Nilainya tidak diuji di
  jaringan dengan latensi tinggi; di LAN 10 s sangat longgar.

### 9.6 Temuan tinjauan independen dan penyelesaiannya (Step 14)

Tinjauan dilakukan dengan membaca kode sebagai penyerang, hanya berbekal
`Architecture.md` §5 dan §13, tanpa memakai alasan penulisan kode. Enam temuan
nyata ditemukan; semuanya diperbaiki dengan tes yang gagal lebih dulu
(§6.6).

#### Temuan 1 — Alias bisa memuat karakter bidi dan format tak terlihat

`sanitize_alias` menyaring `char::is_control`, yang hanya kategori `Cc`. Kontrol
bidi (`U+202A..202E`, `U+2066..2069`) dan karakter format tak terlihat
(`U+200B..200F`, `U+2060..2064`, `U+FEFF`, `U+00AD`, `U+061C`) masuk kategori
`Cf`, jadi lolos. Tamu bisa memilih alias yang **membalik urutan render** baris
persetujuan `[y/N]`, atau menyembunyikan sebagian dirinya dari manusia yang
membacanya.

Dampaknya bukan teori: alias itu dirender di prompt persetujuan (keputusan
manusia), di `splice devices`, dan di `dev ping`. Alias yang menyembunyikan
`(perangkat asing)` di belakang teks lain membuat keputusan "ya" diberikan pada
nama yang salah.

Perbaikan (`dcc94e9`): predikat tunggal `is_invisible_format(ch)` di
`proto/messages.rs`, dipakai `sanitize_alias` **dan** `TrustRecord::into_entry`.
Yang kedua perlu karena store bisa berasal dari berkas yang diedit tangan atau
dari mesin lain, dan alias itu tetap dirender.

#### Temuan 2 — Kode hangus tetap dilayani sampai TTL habis

`accept_loop` hanya memeriksa TTL. Setelah tebakan ketiga gagal, state machine
sudah `Burned` dan menolak setiap `Hello` baru, tetapi loop tetap menjawab
selama sisa TTL **dan** rekaman mDNS tetap terpasang. Artinya LAN masih
mengiklankan kode yang tidak mungkin berhasil: `Architecture.md` §5.4 langkah 7
meminta iklan dihentikan.

Perbaikan (`c4c8d98`): `Burned` diperlakukan terminal — cetak `🚫 Kode hangus`,
kembalikan `Err`, sehingga jalur `mdns.withdraw` milik pemanggil berjalan.

#### Temuan 3 — Kunci sesi bisa dibaca sebelum MAC peer terverifikasi

Kedua sisi menyimpan keluaran SPAKE2 di `session_key` begitu share publik peer
tiba, karena masing-masing perlu kunci itu untuk menghitung MAC-nya sendiri.
Aksesornya didokumentasikan "valid hanya setelah MAC host terverifikasi", jadi
pemanggil bisa membaca kunci yang belum disahkan apa pun.

Ini jendela MITM: penyerang yang merelai dua jalur SPAKE2 terpisah memegang
kunci yang bisa dipakai di kedua kaki, dan kuncinya dikembalikan sebelum ada
konfirmasi yang sempat gagal. Tebakan salah berbentuk sama dan menurunkan kunci
berbeda.

Perbaikan (`e714c36`): `session_key()` mengembalikan `None` kecuali fase sudah
`Paired`. `session_key_ref()` privat tidak diubah, jadi perhitungan MAC dan 15
titik panggil invarian tidak tersentuh.

#### Temuan 4 — Tamu mengklaim kode hangus padahal bukan wewenangnya

`GuestSession::abort()` menyetel `PairingPhase::Burned` pada **setiap** jalan
keluar terminal yang bukan `Paired`: pelanggaran protokol, timeout handshake,
percobaan yang ditolak, token tiket yang tidak cocok. Hanya host yang tahu kode
sudah mati — dialah pemilik penghitung percobaan dan kedaluwarsa. Tamu
memberitahu pemanggilnya "perangkat ini selesai" padahal host mungkin sehat dan
masih bisa memasangkan orang lain.

Perbaikan (`071eac2`): fase baru `Aborted` — "percobaan ini berhenti, nasib kode
tidak diketahui" — terminal dan tidak pernah beriklan. Tamu memakai `Burned`
tepat di satu tempat: `Bye{Burned}` dari host, satu-satunya otoritas atas
penghitung. `abort()` juga mengosongkan `our_pake_msg`/`peer_pake_msg`, separuh
transkrip yang dicakup MAC.

Efek sampingnya terlihat di tiga asersi lama (`guest.rs`, I2 di
`pairing_invariants.rs`, relai MITM) yang mematok label lama; ketiganya
diperbarui, dan `every_bye_reason_maps_to_its_outcome` mematok `Burned` hanya ke
`Bye{Burned}`.

#### Temuan 5 — `Hello` mode-kode tanpa nameplate diterima (kegagalan senyap)

Ini temuan paling serius, karena bentuknya adalah **kode yang benar yang tidak
pernah dijalankan**. Pemeriksaan nameplate ditulis:

```rust
if let Some(hello_plate) = hello_nameplate {
    // bandingkan
} else if self.mode != OneShot && self.mode != Pair {
    // tolak
}
```

Cabang `else if` itu **tidak mungkin menyala**: `HostSession::build` menolak
`HelloMode::Trusted` dan mengikat `code.is_some()` ke `nameplate.is_some()`,
jadi `nameplate.is_some()` menyiratkan salah satu dari dua mode kode. Akibatnya
cabang `Some(plate)` tidak punya `else`, dan `Hello` dengan `nameplate: None`
lolos perbandingan: host memulai PAKE tanpa pernah memeriksa bahwa tamu mengetik
kode yang ditampilkan. Mode tiket tidak terpengaruh (di sana nameplate host
`None`, jadi ia mengambil cabang lain dan sudah menolak `Hello` yang membawa
nameplate).

Perbaikan (`da36911`): cabang mati dihapus, diganti satu perbandingan terhadap
`Some(plate)`. Tes `a_code_host_refuses_a_hello_without_a_nameplate` gagal dulu
dengan host menjawab `Reply(PakeMsg { .. })`; sekarang `ProtocolViolation`, fase
tetap `WaitingForGuest`, dan tidak ada percobaan yang terpakai.

Pelajaran yang dicatat untuk Fase 2: rantai `if let ... else if <kondisi yang
dijamin benar>` adalah pola yang menyembunyikan lubang, karena kompiler tidak
bisa memberi tahu bahwa cabang itu tidak terjangkau. Klausa penjaga harus
menjadi perbandingan langsung, bukan kelanjutan dari `if let`.

#### Temuan 6 — `TrustAck` yang hilang dilaporkan sebagai sukses

Tidak ada sisi yang boleh membaca pesan trust terakhir sebagai persetujuan. Host
semula memberi peringatan lalu `Ok(Some(()))`, sehingga `splice pair` keluar
dengan **exit 0** dan mencetak keberhasilan padahal `record_peer` tidak pernah
berjalan; tamu menandainya tetapi tetap mencetak "pairing selesai".

Ini kegagalan yang paling menipu pengguna: perintah sukses, tidak ada pesan
galat, dan perangkatnya tidak ada di trust store. Pengguna akan menemukannya
saat koneksi tepercaya berikutnya gagal, tanpa petunjuk apa pun.

Perbaikan (`0a8078d`): kedua sisi mengirim `Bye{Protocol}`, tidak menyimpan apa
pun, dan gagal. Host memakai `return decline(...)`; tamu memakai helper baru
`confirm_trust_ack(tx, rx)` yang mengirim `Bye{Protocol}`, linger, lalu
`bail!("host tidak menyetujui pertukaran kepercayaan")`. `record_peer` dan
`✅ {} tersimpan` dipindah ke **setelah** helper, sehingga tidak ada yang
tersimpan saat gagal.

#### Yang dicari dan tidak ditemukan

Supaya batas tinjauan jelas: tidak ditemukan panik pada input bermusuhan (dijaga
`fuzz_frame`/`fuzz_code_parse`/`fuzz_ticket_parse` dan batas panjang di
`proto/frame.rs`), tidak ditemukan jalan agar kata rahasia keluar lewat
`Debug`/`Display`/error, dan tidak ditemukan cara membuka stream aplikasi tanpa
lolos trust store (I13). Tinjauan ini juga **tidak** membuktikan kebal terhadap
serangan yang butuh dua host fisik dan waktu nyata (§9.1).

## 10. Cara menjalankan ulang

Semua perintah di bawah dijalankan dari akar repo. Di Windows, `cargo` tidak ada
di `PATH` pada mesin ini, jadi dipakai `& "$env:USERPROFILE\.cargo\bin\cargo.exe"`;
di Linux cukup `cargo`.

### 10.1 Gerbang wajib

| Gerbang | Perintah | Hasil di mesin ini |
|---|---|---|
| Format | `cargo fmt --all --check` | **EKSEKUSI**, exit 0 |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | **EKSEKUSI**, exit 0 |
| Tes | `cargo test --workspace` | **EKSEKUSI**, semua `test result:` ok, **279 tes, 0 gagal** |
| Lisensi/keamanan dependency | `cargo deny check` | **EKSEKUSI**, exit 0 (2 warning diterima, §10.4) |
| Audit | `cargo audit` | **EKSEKUSI**, exit 0 (446 crate, 2 warning diterima, §10.4) |

Angka tes per target pada run terakhir (HEAD `38b3276`):

```text
iroh-offline (spike)         1 passed
splice (lib)                 9 passed
splice (main)                0 passed
cli_e2e                      7 passed
splice-core (lib)          234 passed
pairing_invariants          24 passed
trust_invariants             4 passed
doc-tests (splice,
           splice-core)      0 passed
-------------------------------------
total                      279 passed, 0 failed
```

Catatan: di Windows, `cargo test --workspace` kadang keluar dengan kode 1 meski
semua `test result:` hijau, karena quirk stderr native proses anak. Yang dibaca
adalah baris `test result:`, bukan exit code. Di CI Linux tidak terjadi.

### 10.2 Uji offline (butuh Linux, root, dan `ip netns`)

```bash
sudo bash testnet/netns_up.sh                 # buat splice-a 10.200.0.1/24, splice-b 10.200.0.2/24
sudo SPLICE_BIN=$PWD/target/release/splice SPLICE_RELAY_MODE=disabled \
     bash tests/offline/offline_test.sh
sudo SPLICE_BIN=$PWD/target/release/splice SPLICE_RELAY_MODE=default \
     bash tests/offline/offline_test.sh
sudo bash testnet/netns_down.sh
```

Hasil yang tercatat: `pass=19 fail=0` untuk **kedua** mode. CI menjalankan ini
lewat `.github/workflows/offline.yml` (matriks `disabled` + `default`) dengan
perintah `sudo --preserve-env=SPLICE_BIN,SPLICE_RELAY_MODE bash tests/offline/offline_test.sh`.

Catatan penting yang membuat ini bisa diulang: binary harus **dibangun native
Linux**. Binary Windows yang dijalankan lewat WSL interop tidak melihat netns,
jadi pengukurannya akan salah tanpa terlihat salah.

### 10.3 Benchmark discovery

```bash
sudo bash testnet/netns_up.sh
sudo SPLICE_BIN=$PWD/target/release/splice bash tests/discovery/bench_presence.sh
sudo bash testnet/netns_down.sh
```

Variabel yang bisa diubah: `RUNS` (default 32), `POLL` (0,02 s),
`OFFLINE_DEADLINE_MS` (6000), `OBSERVER_TICK_MS` (100). Skrip mencetak
`n/min/p50/p95/max` per metrik, baris kelebihan di atas deadline, dan berakhir
`DISCOVERY_BENCH_OK` hanya kalau kedua gate lulus. Artefak ditulis ke
`/root/splice-discovery/out`.

### 10.4 Dependency, fuzz, dan mutan

```bash
cargo deny check          # deny.toml: allow-git di [sources], CDLA-Permissive-2.0, private ignore
cargo audit               # 2 warning "unmaintained", di-ignore per ID di deny.toml

cd fuzz                   # workspace sendiri, butuh nightly (-Z sanitizer)
cargo +nightly fuzz run fuzz_frame        -- -max_total_time=60
cargo +nightly fuzz run fuzz_code_parse   -- -max_total_time=60
cargo +nightly fuzz run fuzz_ticket_parse -- -max_total_time=60

cargo mutants --in-place --baseline skip --timeout 120 -p splice-core -f 'crates/splice-core/src/pairing/*.rs'
cargo mutants --in-place --baseline skip --timeout 120 -p splice-core -f 'crates/splice-core/src/trust/*.rs'
cargo mutants --in-place --baseline skip --timeout 120 -p splice-core -f 'crates/splice-core/src/code/*.rs'
cargo mutants --in-place --baseline skip --timeout 120 -p splice-core -f crates/splice-core/src/discovery/presence.rs
```

`cargo-mutants` **menulis ulang sumber di tempat**. Setelah setiap run, periksa:

```bash
git status --short                              # tidak boleh ada .rs yang berubah
grep -r "changed by cargo-mutants" crates/      # harus kosong
```

Kalau ada yang tertinggal (run yang terbunuh di tengah jalan), pulihkan dengan
`git checkout -- <file>`. `mutants.out/` dan `crates/splice-core/proptest-regressions/`
sudah masuk `.gitignore`. `--in-place` tidak bisa digabung dengan `-j`.

### 10.5 Artefak

| Artefak | Lokasi |
|---|---|
| Log benchmark discovery penuh | `/root/disc12d.txt` |
| Data benchmark mentah | `/root/splice-discovery/out/presence.ndjson` |
| Log uji offline | `/root/off_disabled.txt`, `/root/splice-offline/out/` |
| Log fuzz 65 s | `/root/fz60.txt` |
| Pcap mDNS S1 | `/root/s1out/mdns.pcap` |
| Hasil S1 | `/root/s1out/` |
| `cargo deny` / `cargo audit` | `deny.log`, `audit2.log` di direktori temp mesin |

## 11. Rekomendasi untuk Fase 2

Rekomendasi diurutkan berdasarkan **risiko yang masih terbuka**, bukan berdasarkan
kemudahan pengerjaan.

### 11.1 Sebelum menulis fitur Fase 2

1. **Ulangi benchmark discovery di Wi-Fi venue sungguhan.** Ini satu-satunya
   risiko yang bisa membatalkan seluruh desain discovery. Kalau AP membuang
   multicast, jangan menambah kode di presence: sudah ada rencana cadangan di
   `Architecture.md` §5.3 (tiket lewat internet) dan itu jalur yang lebih
   terjamin. Anggaran: satu hari, dua laptop.
2. **Uji dua host dengan jam berbeda.** `match_now` mentoleransi ±1 bucket
   (300 s). Kalau ada host dengan selisih jam 5 menit, presence-nya tidak akan
   pernah cocok dan gejalanya membingungkan (perangkat tidak muncul, tanpa error).
   Tambahkan diagnostik satu baris yang menyebut selisih bucket saat tidak cocok.
3. **Naikkan `HANDSHAKE_TIMEOUT` menjadi adaptif atau naikkan nilainya** kalau
   Fase 2 memakai relay: 10 s cukup untuk LAN, tetapi jalur relay bisa lebih lambat.
   Saat ini nilainya konstanta global.

### 11.2 Perbaikan yang saya sarankan di kode Fase 1 sebelum menumpuk fitur

| Prioritas | Hal | Kenapa sekarang, bukan nanti |
|---|---|---|
| Tinggi | Batas laju per-IP untuk **pairing**, bukan hanya presence | `PRESENCE_MAX_PER_SEC` ada, tetapi percobaan pairing belum dibatasi per alamat. Kode 22 bit + 3 percobaan sudah cukup, tapi belum ada yang mencegah satu host membuka ribuan koneksi |
| Tinggi | Pencabutan harus memberi tahu perangkat lain | Sekarang perangkat yang dicuri tetap dipercaya sampai pemilik mencabutnya. Fase 2 yang membawa berkas nyata membuat ini jauh lebih mahal |
| Sedang | Ganti `console`/prompt kode dengan pembacaan yang tidak meninggalkan jejak di scrollback | Sudah tersembunyi di terminal, tetapi tidak ada yang mencegah terminal menyimpannya |
| Sedang | Tambahkan tes fuzz untuk `postcard` di `proto/messages.rs` dengan korpus legal | `fuzz_frame` menguji frame; pesan di dalamnya diuji secara acak tapi tidak dengan korpus yang tumbuh |
| Rendah | Hapus `Secret` dari jalur `Debug` sepenuhnya dengan tipe pembungkus yang tidak punya `Debug` | Sekarang aman karena tes, tapi satu `#[derive(Debug)]` baru bisa membocorkannya |

### 11.3 Yang **tidak** perlu dikerjakan

- Jangan menambahkan server rendezvous. Guardrail §6 melarangnya, dan Fase 1
  membuktikan discovery lokal cukup untuk lingkup MVP.
- Jangan mengganti SPAKE2 dengan TLS exporter. Alasan yang sama.
- Jangan membangun daemon IPC sebelum ada fitur yang benar-benar butuh dua
  proses; `splice listen` membuktikan satu proses cukup untuk Fase 1.

### 11.4 Sisa pekerjaan mekanis

- `RESUME_ATTEMPTS_MAX` dan `SESSION_IDLE_TTL` sudah dideklarasikan tetapi belum
  dipakai; resume adalah fitur Fase 2/3 dan harus memakai konstanta itu, bukan
  nilai baru.
- I5–I8, I10, I14, I15, I19 belum punya kode, jadi belum punya tes. Saat fitur
  PTY/transfer masuk, invarian itu harus menjadi tes lebih dulu, dengan pola yang
  sama seperti I1–I4 di Fase 1.

## Lampiran: Ambiguitas dan inkonsistensi dokumen (Step 0)

Dicatat saat membaca `Architecture.md` v3.0 dan `Brief.md` v3.0.

1. **`Brief.md` §5.1 vs `Architecture.md` §5.4 langkah 9** — Brief menulis `tether pair <kode>` sedangkan prompt Fase 1 mensyaratkan `splice pair --join [CODE]`. Mengikuti prompt Fase 1 (`--join`), karena itu CLI kontrak yang diminta. Tidak bertentangan secara keamanan.
2. **`Architecture.md` §5.4 langkah 10 menyebut "Persetujuan host (§8.5) sebelum stream data apa pun"** — di Fase 1 belum ada stream data (PTY/transfer). Untuk Fase 1 diterapkan sebagai: setelah PAIRED tidak ada stream aplikasi yang dilayani selain `Ping`/`Pong`. Selaras dengan I2.
3. **Tiket: "Butuh internet: Ya, untuk lintas jaringan" (§5.3)** — tetapi tiket juga dipakai di LAN tanpa mDNS (baris yang sama). Di Fase 1 tiket diuji di LAN tanpa internet; klaim "lintas jaringan" tidak diuji (di luar lingkup Fase 1).
4. **`Architecture.md` §4 mencantumkan `tether-basket`** tetapi Fase 1 tidak membangunnya (sesuai prompt D1: "not built in Phase 1"). Tidak ada konflik.
5. **`Architecture.md` §11 daemon** — Fase 1 tidak membangun daemon. `splice listen` memegang identitas persisten secara langsung, sesuai §11 baris "Sebelum daemon (v0.1–v0.2)".
6. **`Architecture.md` §14.2** meminta benchmark di LAN nyata "sebelum angka dipublikasikan". Lingkungan ini tidak punya dua mesin fisik; benchmark dijalankan di netns dan ditandai eksplisit sebagai bukan Wi-Fi nyata.
7. **`RESUME_ATTEMPTS_MAX` dan `SESSION_IDLE_TTL`** hanya dideklarasikan (sesuai instruksi §3.3), resume sendiri Fase 2/3.
