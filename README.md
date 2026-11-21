# Splice

Kirim file dan bagikan terminal ke perangkat lain di Wi-Fi yang sama. Tanpa akun, tanpa server, terenkripsi ujung ke ujung.

> **Status: pra-rilis (Fase 1 dari 6).** Yang sudah jalan: pairing, perangkat tepercaya, dan penemuan perangkat di jaringan lokal. **Kirim file dan berbagi terminal belum ada.** Jangan dipakai untuk data sensitif sebelum tinjauan keamanan selesai.

## Prinsip

| Prinsip | Artinya |
|---|---|
| Tanpa server milik proyek | Perangkat saling menemukan lewat jaringan lokal (mDNS + siaran presence). Tidak ada yang perlu di-hosting |
| Jaringan lokal dulu | Jalan tanpa internet, selama kedua perangkat ada di Wi-Fi/LAN yang sama |
| Aman secara default | Kode pairing sekali pakai, maksimum 3 percobaan, perangkat dikenali lewat kunci, bukan nama |
| Transparan soal batas | Lihat bagian [Batas yang diketahui](#batas-yang-diketahui) |

## Status fitur

| Fitur | Status |
|---|---|
| Identitas perangkat (kunci efemeral dan persisten) | Ada |
| Pairing dengan kode pendek (`7-cobalt-falcon`) | Ada |
| Daftar perangkat tepercaya (tambah, lihat, cabut) | Ada |
| Penemuan perangkat lewat presence (tanpa membocorkan identitas) | Ada |
| Uji koneksi tepercaya (`Ping`/`Pong`) | Ada |
| Kirim dan terima file (`send` / `recv`) | **Belum** (Fase 2) |
| Berbagi terminal (`shell` / `join`) | **Belum** (Fase 3) |
| Basket GUI (seret file ke tepi layar) | **Belum** (Fase 5) |
| Shell di Windows (ConPTY) | **Belum** (Fase 6) |

Rencana lengkap ada di [`docs/Architecture.md`](docs/Architecture.md) (bagian 15) dan laporan per fase di [`Laporan-1.md`](Laporan-1.md).

## Persyaratan

- [Rust](https://rustup.rs) stable (versi yang dipakai tercatat di `Laporan-1.md`, bagian Lingkungan)
- `git`
- Windows 10/11, macOS, atau Linux
- Dua perangkat di Wi-Fi/LAN yang sama untuk mencoba pairing

## Build

```bash
git clone <URL-repo-ini>
cd splice
cargo build --release
```

Binary ada di `target/release/splice` (`splice.exe` di Windows). Untuk memudahkan, jalankan lewat `cargo run --release -- <perintah>` atau salin binary ke folder yang ada di `PATH`.

Cek bahwa terpasang benar:

```bash
splice --version
splice --help
```

## Cara pakai (Fase 1)

Contoh di bawah memakai dua perangkat, **A** dan **B**, di Wi-Fi yang sama. Jalankan `splice <perintah> --help` untuk melihat opsi yang tersedia di versi kamu.

### 1. Pairing sekali antar dua perangkat

Di **A** (host):

```bash
splice pair
```

Layar menampilkan kode, misalnya `7-cobalt-falcon`. Kode berlaku 10 menit dan hangus setelah 3 kali salah.

Di **B** (tamu):

```bash
splice pair --join 7-cobalt-falcon
# atau tanpa argumen, lalu ketik kodenya (tidak ditampilkan di layar):
splice pair --join
```

Kedua sisi akan ditanya persetujuan: *"Pasangkan dengan ... ? [y/N]"*. Perangkat baru disimpan **hanya jika kedua sisi menjawab `y`**.

Untuk sesi yang lebih sensitif, pakai kode 3 kata:

```bash
splice pair --words 3
```

### 2. Lihat dan cabut perangkat tepercaya

```bash
splice devices            # daftar: alias, id singkat, online/offline, terakhir terlihat
splice devices rm <alias> # cabut perangkat (koneksi yang sedang terbuka ikut ditutup)
```

Pencabutan hanya berlaku di perangkat yang kamu pakai. **Cabut juga di perangkat lainnya.**

### 3. Jadikan perangkat bisa ditemukan

Di perangkat yang ingin ditemukan:

```bash
splice listen
```

Perangkat ini menyiarkan presence dan menerima koneksi hanya dari perangkat tepercaya. Hentikan dengan `Ctrl+C`.

### 4. Uji koneksi ke perangkat tepercaya

```bash
splice dev ping <alias>
```

Mengirim `Ping` dan menunggu `Pong`. Ini perintah pengembang (tersembunyi dari `--help` biasa) dan akan diganti `send`/`recv` di Fase 2.

### 5. Identitas

```bash
splice identity show   # tampilkan NodeId publik perangkat ini
splice identity reset  # buat identitas baru (semua perangkat harus dipasangkan ulang)
```

### Opsi umum

| Opsi | Fungsi |
|---|---|
| `--relay-mode <default\|disabled>` | `disabled` = hanya koneksi langsung, tanpa relay pihak ketiga |
| `--relay-url <url>` | Pakai relay sendiri |
| `--addr <ip:port>` | Lewati penemuan dan sambung ke alamat tertentu |
| `--words <2\|3>` | Jumlah kata rahasia pada kode |

### Perintah pengembang (`splice dev ...`)

Dipakai untuk menguji tiap jalur pairing dari ujung ke ujung, termasuk mode tiket dan pemantau presence. Daftar lengkapnya: `splice dev --help`. Perintah ini bisa berubah atau dihapus tanpa pemberitahuan.

## Lokasi data

Kunci identitas dan daftar perangkat tepercaya disimpan di folder konfigurasi pengguna, **bukan** di repo:

| OS | Lokasi (biasanya) |
|---|---|
| Linux | `~/.config/splice/` |
| macOS | `~/Library/Application Support/splice/` |
| Windows | `%APPDATA%\splice\` |

Di Linux dan macOS, berkas dibuat dengan izin pemilik saja (`0600`/`0700`). Splice menolak memuat kunci yang izinnya terlalu longgar. Di Windows, perlindungan mengandalkan izin profil pengguna. **Jangan bagikan atau commit folder ini.**

## Pemecahan masalah

| Gejala | Kemungkinan penyebab | Coba |
|---|---|---|
| Perangkat tidak muncul di daftar | Wi-Fi memblokir antarperangkat (*client isolation*) atau membuang multicast | Pakai hotspot HP, atau sambung dengan `--addr` |
| Perangkat tidak muncul, jaringan normal | Firewall memblokir UDP masuk | Windows: izinkan Splice di Windows Defender Firewall saat diminta |
| Perangkat tidak muncul di laptop dengan banyak adapter | Adapter virtual (WSL, VPN, Hyper-V) mengganggu pemilihan antarmuka | Matikan adapter virtual sementara, lalu laporkan di issue beserta daftar adapter |
| Perangkat tidak pernah cocok padahal sudah dipasangkan | Selisih jam antar perangkat lebih dari ±5 menit | Samakan jam sistem |
| "Kode hangus" | 3 kali salah atau melewati 10 menit | Buat kode baru di perangkat host |
| Koneksi lambat tanpa internet | Mode relay default mencoba menghubungi relay | Tambahkan `--relay-mode disabled` |

## Pengujian

Semua perintah dijalankan dari akar repo.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --workspace
cargo deny check
cargo audit
```

### Uji offline (hanya Linux, perlu root dan `ip netns`)

Membuktikan pairing dan penemuan jalan tanpa internet dan tanpa relay, di dua network namespace.

```bash
cargo build --release
sudo bash testnet/netns_up.sh
sudo SPLICE_BIN=$PWD/target/release/splice SPLICE_RELAY_MODE=disabled bash tests/offline/offline_test.sh
sudo SPLICE_BIN=$PWD/target/release/splice SPLICE_RELAY_MODE=default  bash tests/offline/offline_test.sh
sudo bash testnet/netns_down.sh
```

Gunakan binary yang dibangun **native di Linux**. Binary Windows lewat WSL tidak melihat namespace dan hasilnya menyesatkan.

### Benchmark penemuan perangkat (Linux)

```bash
sudo bash testnet/netns_up.sh
sudo SPLICE_BIN=$PWD/target/release/splice bash tests/discovery/bench_presence.sh
sudo bash testnet/netns_down.sh
```

### Fuzz dan mutation testing (opsional, butuh Rust nightly)

```bash
cd fuzz
cargo +nightly fuzz run fuzz_frame        -- -max_total_time=60
cargo +nightly fuzz run fuzz_code_parse   -- -max_total_time=60
cargo +nightly fuzz run fuzz_ticket_parse -- -max_total_time=60
```

`cargo mutants` menulis ulang sumber di tempat. Pastikan `git status` bersih sebelum dan sesudah menjalankannya. Perintah lengkapnya ada di `Laporan-1.md` bagian 10.4.

## Struktur repo

```text
crates/splice-core/   library inti: identitas, kode, discovery, pairing, trust store, protokol
crates/splice/        CLI
spikes/iroh-offline/  spike S1: bukti transport jalan tanpa internet
fuzz/                 target fuzz (workspace terpisah)
testnet/              skrip network namespace
tests/                uji offline dan benchmark
docs/                 Brief.md dan Architecture.md (memakai nama kerja awal "tether")
```

## Keamanan

- Kata rahasia kode tidak pernah dikirim ke jaringan dan tidak ditulis ke log. Kata itu hanya masuk ke handshake SPAKE2.
- Tiap kode dibatasi 3 percobaan gagal, dihitung di sisi host, dan sekali pakai.
- Perangkat asing (yang tidak ada di daftar tepercaya) tidak bisa membuka koneksi aplikasi apa pun.
- Perangkat tepercaya tidak akan pernah bisa membuka sesi terminal tanpa persetujuan host saat itu juga (berlaku saat fitur shell ada).
- Siaran presence memakai tag yang berputar, tanpa nama atau identitas terbuka.

Model ancaman lengkap: [`docs/Architecture.md`](docs/Architecture.md) bagian 13. Laporkan temuan keamanan secara privat kepada maintainer (belum ada `SECURITY.md`; buat sebelum rilis publik).

## Batas yang diketahui

- **Belum ditinjau pihak luar.** Hanya ada tinjauan internal dan pengujian otomatis.
- **Belum diukur di Wi-Fi nyata dan dua mesin fisik.** Pengukuran sejauh ini memakai network namespace dan loopback.
- **Izin Local Network macOS belum diverifikasi di Mac fisik.** macOS Sequoia (15+) mewajibkan izin dialog Local Network untuk lalu lintas broadcast/multicast LAN; perilaku izin ini baru diuji di CI virtual (runner GitHub Actions) dan belum diverifikasi langsung di Mac fisik.
- Wi-Fi dengan *client isolation* **dan** tanpa internet tidak didukung. Gunakan hotspot HP.
- Pengamat di jaringan yang sama bisa tahu bahwa ada perangkat Splice dan kapan aktif (isi dan identitas tidak terbaca).
- Rahasia di memori di-zeroize di sisi kode kita, tetapi salinan di dalam pustaka `spake2` di luar kendali kita.
- Perangkat tepercaya yang dicuri tetap dipercaya sampai kamu mencabutnya di semua perangkat lain.

## Kontribusi

Sebelum membuka pull request, pastikan enam gerbang di bagian [Pengujian](#pengujian) lulus. Perubahan pada `pairing/` atau `trust/` wajib disertai tes yang **gagal lebih dulu** terhadap kode lama. Detail desain dan invarian keamanan ada di [`docs/Architecture.md`](docs/Architecture.md).

## Lisensi

Belum ditentukan. Disarankan dual MIT / Apache-2.0 sebelum rilis publik.
