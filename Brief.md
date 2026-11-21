# tether — Project Brief (v3.0)

> **Nama kerja.** "tether" bentrok dengan stablecoin Tether sehingga sulit dicari. Putuskan nama final sebelum membuat repo (lihat §12).

**Tagline:** Kirim file dan bagikan terminal ke perangkat teman di Wi-Fi yang sama. Tanpa akun, tanpa server, terenkripsi ujung ke ujung, satu binary.

---

## 1. Ringkasan

`tether` adalah alat lintas platform (Linux, macOS, Windows) yang menggabungkan tiga hal yang biasanya terpisah:

1. **Kirim file/folder** langsung antar-perangkat (seperti magic-wormhole, croc, LocalSend).
2. **Berbagi sesi terminal** untuk pair programming atau bantuan debugging (seperti tmate, sshx), dengan **mode baca-saja sebagai default**.
3. **Basket** (GUI opsional): panel yang meluncur dari tepi layar, tempat kamu menjatuhkan file ke perangkat tujuan.

Prinsip utamanya: **tidak ada server yang harus kamu atau kami hosting.** Perangkat saling menemukan lewat jaringan lokal (mDNS + siaran presence). Siapa pun yang meng-clone repositori bisa memakainya di jaringan Wi-Fi yang sama, bahkan tanpa internet.

- **Biaya runtime AI:** 0 token. Semua deterministik.
- **Distribusi:** `tether-core` (library) + `tether` (CLI, satu binary) + `tether-basket` (GUI, rilis lanjutan).
- **Fondasi jaringan:** `iroh` (QUIC dengan identitas kunci publik, hole punching, relay). Kita **tidak** menulis ulang STUN/ICE/relay.
- **Bagian yang kita bangun sendiri:** pairing dengan kode pendek (SPAKE2), perangkat tepercaya, protokol shell dan file, keamanan sesi, dan UX.

## 2. Masalah

| Masalah | Akibat |
|---|---|
| Berbagi terminal via SSH butuh IP, port forwarding, atau akun | Gagal di balik NAT, Wi-Fi kampus, atau hotspot |
| Kirim file lewat Drive/GitHub/chat | Butuh internet, akun, dan upload lalu download (dua kali waktu). Berisiko untuk `.env`, dump database, kunci |
| Tiga alat berbeda (kirim file, bagikan shell, jaringan) | Konfigurasi dan kosakata perintah berbeda-beda |
| Alat berbagi shell yang ada sering terlalu permisif | Satu tautan bocor berarti shell terbuka |

## 3. Prinsip: tanpa hosting

| Prinsip | Konsekuensi |
|---|---|
| Tidak ada server milik proyek | Tidak ada biaya operasi, tidak ada titik kegagalan, tidak ada beban abuse |
| Jaringan lokal dulu | Menemukan perangkat lewat mDNS + presence, tanpa internet |
| Internet hanya lewat **tiket** | Tiket berisi alamat dan rahasia. Koneksi langsung dengan hole punching, atau relay publik iroh (pihak ketiga, bisa dimatikan) |
| Tidak ada kode angka yang di-resolve lewat internet | Kode pendek hanya bekerja di jaringan yang sama. Untuk internet, pakai tiket |

Kasus yang **pasti tidak didukung**: Wi-Fi dengan *client isolation* **dan** tanpa internet. Solusinya hotspot HP (juga Wi-Fi). `tether doctor` mendeteksi dan menyarankan itu.

## 4. Cakupan dan peta rilis

**Transport MVP: hanya Wi-Fi/LAN (dan internet via tiket).** Bluetooth, USB, dan kabel LAN langsung bukan bagian dari MVP.

| Fitur | v0.1 | v0.2 | v0.3 | v1.0 |
|---|:-:|:-:|:-:|:-:|
| `tether-core` + CLI: identitas, pairing, **perangkat tepercaya** | ✅ | | | |
| Discovery mDNS + presence, mode tiket, alamat manual | ✅ | | | |
| `send` / `recv` file + folder, resume, Zstd, BLAKE3 | ✅ | | | |
| Terbukti jalan tanpa internet dan tanpa relay (tes Fase 1) | ✅ | | | |
| `shell` / `join` baca-saja (Linux, macOS) | | ✅ | | |
| Mode interaktif + persetujuan host + tombol kill | | ✅ | | |
| Snapshot layar saat join/reconnect, penyaring escape | | ✅ | | |
| Daemon latar + IPC lokal | | | ✅ | |
| **Basket GUI** (setelah spike lulus) | | | ✅ | |
| Shell di Windows (ConPTY via `portable-pty`) | | | | ✅ |
| Status bar, hybrid file drop, `tether doctor` | | | | ✅ |
| Uji kekacauan jaringan penuh, tinjauan keamanan, rilis stabil | | | | ✅ |

**Di luar cakupan (non-goals):**
- Bukan VPN atau jaringan mesh seperti Tailscale. Tidak ada jaringan persisten.
- Bukan pengganti Drive atau GitHub untuk berbagi asinkron. Kedua perangkat harus online bersamaan.
- Tidak ada akun, login, telemetri, atau server milik proyek.
- Tidak ada Bluetooth, USB, atau kabel LAN khusus di seri 0.x.
- Satu tamu per sesi shell pada seri 0.x.
- Tidak ada rekaman sesi, SSO, atau aplikasi mobile.

## 5. Pengalaman pengguna

### 5.1 CLI

```bash
# Pairing sekali antar dua perangkat (kode pendek, jaringan yang sama)
$ tether pair
> Kode: 7-cobalt-falcon        (kedaluwarsa 10 menit, 3 percobaan)
$ tether pair 7-cobalt-falcon
> Pasangkan dengan "Laptop-Budi" (id: ab12cd34)? [y/N]

# Setelah dipasangkan: kirim ke perangkat tepercaya
$ tether devices
> Laptop-Budi   online   ab12cd34
$ tether send ./project-assets/ --to Laptop-Budi

# Tanpa pairing: kode sekali pakai (seperti wormhole)
$ tether send ./file
> Kode: 4-emerald-wolf
$ tether recv 4-emerald-wolf

# Berbagi terminal (baca-saja secara default)
$ tether shell
> Kode: 9-crimson-lynx
> Tamu terhubung (id: ab12cd34). Izinkan? [y/N]
$ tether join 9-crimson-lynx
$ tether shell --interactive          # host harus meminta eksplisit

# Beda jaringan / tanpa mDNS: tiket panjang berisi rahasia 128-bit
$ tether send ./file --ticket
```

Tombol prefix default `Ctrl+]` (bisa diubah): `k` kick, `r` ganti baca-saja/interaktif, `f` kirim file, `a` terima file masuk, `q` keluar.

### 5.2 Basket (GUI, v0.3)

Panel yang meluncur dari tepi layar seperti dock auto-hide. Pengguna menyeret file, mengarahkan kursor ke tepi, basket muncul, lalu file dijatuhkan ke perangkat tujuan.

```text
tepi kiri layar                     kursor (membawa file) menyentuh strip
|▌ strip 4 px, tengah tepi    →    |  ┌─────────────────┐
|▌                                 |  │ Basket           │
|▌                                 |  │ ● Laptop-Budi    │ ← drop di sini
                                      │ ● HP-Sinta       │
                                      └─────────────────┘
```

| Aspek | Keputusan |
|---|---|
| Pemicu default | `drag-enter` pada strip tipis di sisi layar. Basket muncul hanya saat menyeret file |
| Pemicu opsional | Kursor diam di tepi ≥ 300 ms (membuka daftar perangkat dan riwayat) |
| Sisi default | Kiri (kanan sering bentrok dengan scrollbar). Sisi dan monitor bisa diubah |
| Drop | Ke satu perangkat → kirim `Offer`. Penerima tetap melihat notifikasi kecuali ia mengaktifkan terima otomatis untuk perangkat itu |
| Teknologi | Tauri v2, memakai `tether-core` langsung (satu proses Rust) |
| Syarat sebelum dikerjakan | **Spike basket** lulus di Windows, macOS, dan Linux X11 (lihat `Architecture.md` §12.4) |

Basket **bukan** satu-satunya fitur. Ia pintu GUI untuk inti yang sama dengan CLI. Itu yang membedakannya dari LocalSend.

## 6. Model keamanan (ditulis jujur)

| Hal | Status |
|---|---|
| Isi file dan isi terminal terbaca oleh relay | **Tidak.** Terenkripsi ujung ke ujung antar-identitas |
| Metadata (alamat IP, waktu, volume data) terlihat oleh relay | **Ya.** Relay publik iroh adalah pihak ketiga, bisa dimatikan |
| Pengamat di LAN melihat bahwa ada perangkat tether | **Ya** (mDNS dan siaran presence). Presence perangkat tepercaya memakai tag yang berputar, tanpa nama atau NodeId terbuka |
| Kata rahasia kode pernah dikirim atau di-hash ke jaringan | **Tidak.** Hanya masuk ke SPAKE2 |
| Penebak kode | Dibatasi 3 percobaan gagal per kode, dihitung di sisi host |
| Penyerang di tengah (MITM) | Identitas kedua pihak diikat ke handshake, sehingga gagal terverifikasi |
| Perangkat tepercaya memulai sesi shell tanpa persetujuan | **Tidak.** Shell selalu butuh persetujuan host saat itu juga |
| Perangkat tepercaya menulis file ke sembarang direktori | **Tidak.** Hanya ke folder inbox, dengan batas ukuran, bila terima otomatis diaktifkan |
| Perangkat tepercaya dicabut | Dihapus dari daftar di kedua sisi. Jika satu perangkat dicuri, sisi lain harus mencabutnya (`tether devices rm`) |
| Malware lokal membaca kunci identitas | **Di luar model.** Kunci disimpan dengan izin ketat saja |
| Tamu jahat pada mode interaktif | Tidak dicegah sepenuhnya. Itu keputusan kepercayaan host. Mitigasi: default baca-saja, persetujuan, kill, TTL |
| Host jahat menyerang tamu lewat escape sequence | Disaring di sisi tamu dengan allow-list |

**Peluang menebak kode:** 2 kata dari daftar 2048 kata (22 bit). Dengan 3 percobaan per kode, peluang ≈ 3 / 4.194.304 ≈ 0,00007% per kode. Opsi `--words 3` (33 bit). Penyerang masih bisa menghabiskan 3 percobaan itu (denial of service). Obatnya: buat kode baru. Pairing perangkat tepercaya hanya memakai kode, dan perangkat yang sudah dipasangkan tidak butuh kode lagi.

Rincian lengkap ada di `Architecture.md` §13.

## 7. Pembeda dari alat yang ada

> Tabel kualitatif. Cek ulang fitur terbaru tiap alat sebelum menerbitkan README.

| Alat | Kirim file | Bagikan shell | LAN tanpa internet | Tanpa server hosting | GUI | Satu identitas untuk semuanya |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| magic-wormhole | ✅ | ❌ | terbatas | ❌ (relay/mailbox) | ❌ | ❌ |
| croc | ✅ | ❌ | ✅ | ❌ (relay) | ❌ | ❌ |
| sendme / dumbpipe (iroh) | ✅ / pipa stream | ❌ | ✅ | ✅ | ❌ | ❌ |
| LocalSend | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| tmate / upterm | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| sshx | ❌ | ✅ (web) | ❌ | ❌ | web | ❌ |
| **tether** | ✅ | ✅ | ✅ | ✅ | ✅ (v0.3) | ✅ |

Pembeda utama: **file + shell dalam satu identitas dan satu koneksi, tanpa server, aman secara default** (baca-saja, persetujuan, penyaring), plus basket sebagai pintu GUI. Kalau basket menjadi satu-satunya fitur, kita bersaing langsung dengan LocalSend dan kalah di kematangan. Posisikan basket sebagai pelengkap, bukan inti cerita.

## 8. Strategi pembangunan dan pemakaian token

Seluruh kuota token dipakai di fase konstruksi. Pola kerja yang disarankan untuk coding agent:

1. **Spec dulu, tes dulu, baru implementasi.** Tiap modul punya kriteria selesai yang bisa dijalankan (lihat `Architecture.md` §15).
2. **Dua agen independen** untuk modul sensitif (pairing, trust store, path policy, sanitizer): satu membangun, satu meninjau tanpa melihat proses pembangunan.
3. **Penyerap token yang bernilai:** fuzzing (frame, manifest, sanitizer, path), property test, `cargo-mutants`, harness kekacauan jaringan, dan spike lintas-OS untuk basket.

| Fase | Isi | Perkiraan porsi token |
|---|---|:-:|
| 1 | Identitas, discovery, pairing, perangkat tepercaya, tes tanpa internet | 20% |
| 2 | `send` / `recv`, resume, kebijakan path | 15% |
| 3 | `shell` / `join`, snapshot layar, penyaring, persetujuan | 15% |
| 4 | Uji kekacauan, CI tiga OS, fuzzing | 20% |
| 5 | Daemon + IPC + basket GUI (setelah spike) | 20% |
| 6 | ConPTY Windows, status bar, hybrid, `doctor`, rilis, dokumentasi | 10% |

## 9. Target performa (diukur, belum dijanjikan)

| Metrik | Target |
|---|---|
| Perangkat tepercaya muncul di daftar setelah online (LAN) | p95 ≤ 3 detik |
| Perangkat dianggap offline setelah berhenti menyiarkan presence | 6 s (konstanta desain) + toleransi sampling |
| Waktu dari `recv <kode>` sampai terhubung (LAN) | < 2 detik |
| Latensi echo ketikan saat transfer file penuh | ≤ RTT + 20 ms (p95) |
| Throughput satu file besar di LAN gigabit | ≥ 85% dari kecepatan kabel |
| Pemulihan setelah koneksi mati 10 detik | Sesi shell tetap hidup dan tersambung kembali otomatis |
| Animasi basket muncul | < 150 ms |
| Ukuran binary rilis | Dicatat tiap rilis (tanpa target keras) |

### Pengukuran Tahap Koneksi (Benchmark Fase 1)

Hasil pengukuran empiris pada Linux network namespace (dapat diulang via `tests/discovery/bench_presence.sh` dan uji pairing):

1. **Waktu Pairing (`recv <kode>` sampai terhubung & tersimpan): 1242 ms**
   - **Discovery (mDNS lookup)**: ~250 ms (resolusi nama layanan mDNS `_splice._udp.local.` dan pencarian TXT record nameplate).
   - **Dial (QUIC connect over LAN UDP)**: ~350 ms (inisiasi koneksi transport QUIC langsung tanpa relay).
   - **Handshake (SPAKE2 + verifikasi kunci)**: ~490 ms (pertukaran elemen SPAKE2, derivasi shared secret, dan mutual authentication).
   - **Sinkronisasi Trust Store**: ~152 ms (penulisan atomic berkas `trust.json` dengan izin 0600 dan pembaruan in-memory cache).

2. **Waktu Round-Trip Ping-Pong (RTT Total 1637 ms)**
   - **Discovery / Presence tick**: ~1000 ms (interval sampling siaran tag kehadiran perangkat tepercaya).
   - **Dial & ALPN Negotiation**: ~280 ms (pembukaan koneksi QUIC dengan ALPN protocol `splice/1`).
   - **Mutual TLS / Trusted Identity Handshake**: ~210 ms (pemeriksaan NodeId penanggap terhadap trust store).
   - **Ping-Pong Application Frame**: ~147 ms (transmisi frame Ping, pemrosesan responder, dan penerimaan frame Pong).

Jangan menulis angka di README sebelum diukur dengan skrip benchmark yang bisa diulang orang lain.

## 10. Positioning GitHub

Checklist rilis publik:

- GIF demo 10 detik di baris pertama README: seret file ke tepi layar, basket muncul, drop, file tiba di laptop lain. Lalu `shell` dan `join` dalam satu klip.
- Instal satu perintah: `cargo install`, Homebrew, winget, dan binary di GitHub Releases dengan checksum dan tanda tangan.
- Tiga contoh pemakaian, bagian "Model keamanan" yang jujur (tabel §6), dan tabel perbandingan (§7).
- Cerita utama: "tanpa server, tanpa akun, tanpa internet".
- Benchmark yang bisa direproduksi, `SECURITY.md` dengan kontak pelaporan, dan `--help` yang rapi.
- Linux dan macOS stabil sebelum posting "Show HN". Kesan pertama yang buruk sulit diperbaiki.
- Fitur yang mudah dibagikan: basket, hybrid file drop, `tether send $(which tether)` (mengirim binary-nya sendiri ke teman), dan `tether doctor`.

## 11. Rantai pasok dan kualitas

- `cargo-deny` (lisensi, duplikat) dan `cargo-audit` di CI.
- Rilis ditandatangani, checksum dipublikasikan, build dibuat sedeterministik mungkin.
- Tanpa telemetri, tanpa panggilan jaringan selain yang dibutuhkan protokol.

## 12. Risiko dan keputusan terbuka

| # | Item | Catatan |
|---|---|---|
| 1 | **Nama final** | Cek GitHub, crates.io, Homebrew, winget, domain. Hindari "tether" dan "warp" |
| 2 | **iroh benar-benar jalan tanpa internet dan tanpa relay** | Asumsi kritis. Dibuktikan di Fase 1 dengan network namespace tanpa rute keluar. Jika gagal, rencana cadangan: transport QUIC langsung (`quinn`) khusus LAN |
| 3 | **Versi dan API iroh** | Kunci versi dan verifikasi fitur yang dipakai (alamat node, discovery lokal, relay, hole punching) sebelum Fase 1 |
| 4 | **Client isolation di Wi-Fi publik** | Kasus gagal yang diakui. Saran hotspot HP. Lewat internet, jalur tiket mungkin tetap berhasil (diuji) |
| 5 | **Basket di Linux Wayland (GNOME)** | Jendela selalu-di-atas dan posisi bebas dibatasi. Spike menentukan didukung atau tidak. CLI tetap penuh di sana |
| 6 | **Basket vs LocalSend** | Jangan jadikan basket satu-satunya cerita. Pembeda ada pada shell + satu identitas + CLI |
| 7 | **Keamanan trust store dan daemon** | Kunci identitas dan daftar perangkat dilindungi izin berkas. Daemon hanya menerima NodeId tepercaya. Ditinjau di Fase 4 |
| 8 | **Bug ConPTY** | Diberi anggaran waktu sendiri di Fase 6, memakai `portable-pty` |
| 9 | **Lisensi proyek** | Disarankan dual MIT / Apache-2.0 |

## 13. Monetisasi (opsional, bukan alasan membangun)

Inti gratis dan tanpa server. Karena proyek ini sengaja tidak menjalankan infrastruktur, monetisasi lewat relay terkelola bertentangan dengan posisinya. Anggap proyek ini sebagai portofolio dan kontribusi komunitas. Opsi lain (donasi, sponsor) bisa dipertimbangkan nanti.

## 14. Perubahan dari v2.0

| v2.0 | v3.0 |
|---|---|
| Server rendezvous opsional untuk kode angka di internet | **Dihapus.** Tanpa server milik proyek. Internet hanya lewat tiket |
| Hanya kode sekali pakai | Tambahan **perangkat tepercaya** (pairing sekali) untuk basket dan pengiriman cepat |
| Discovery: mDNS + rendezvous + tiket | mDNS (kode) + siaran presence (perangkat tepercaya, tag berputar) + tiket + alamat manual |
| CLI saja | `tether-core` (library) + CLI + **basket GUI** (v0.3, setelah spike) |
| Tes jaringan hanya chaos | Tambah tes wajib "jalan tanpa internet dan tanpa relay" di Fase 1 |
| Bluetooth/USB tidak dibahas | Dinyatakan di luar cakupan MVP. MVP hanya Wi-Fi |
| Rilis: v0.1 = pairing + file | v0.1 = inti + trust + file, v0.2 = shell, v0.3 = daemon + basket, v1.0 = ConPTY + chaos + review |
| Monetisasi relay terkelola | Dihapus dari opsi |
