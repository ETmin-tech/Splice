# tether — System Architecture (v3.0)

**Target:** library `tether-core` + CLI `tether` (satu binary) + GUI `tether-basket` (Linux, macOS, Windows)
**Bahasa:** Rust (`tokio`, transport `iroh`, GUI `tauri` v2)
**Prinsip:** zero-trust E2EE, LAN-first, **tanpa server milik proyek**, aman secara default, tanpa panggilan API AI saat runtime

Dokumen ini menggantikan v2.0. Pemetaan perubahan ada di **Lampiran A**.

---

## 1. Tujuan dan non-goals teknis

**Tujuan:** pairing dengan kode pendek, perangkat tepercaya, transfer file paralel dengan resume, shell bersama dengan penyaring dan persetujuan, dan basket GUI. Semuanya di atas satu koneksi QUIC, tanpa server yang harus dihosting.

**Non-goals (0.x):** VPN/mesh, akun, server rendezvous, Bluetooth/USB/kabel LAN khusus, multi-tamu pada shell, rekaman sesi, aplikasi mobile, telemetri.

## 2. Keputusan arsitektur

| # | Keputusan | Alasan |
|---|---|---|
| D1 | Transport memakai **iroh** (QUIC, identitas kunci publik, hole punching, relay) | NAT traversal buatan sendiri adalah risiko terbesar. Fokus kita di protokol dan keamanan |
| D2 | Pairing memakai **SPAKE2** dengan identitas = NodeId kedua pihak | Mengikat handshake ke koneksi QUIC yang sudah terautentikasi, tanpa bergantung pada API TLS exporter |
| D3 | Kode = **nomor (publik) + kata rahasia** | Hash dari kode bisa ditebak balik. Hanya kata yang rahasia. Nomor hanya untuk membedakan beberapa host di LAN yang sama |
| D4 | Percobaan gagal dihitung **di sisi host** | Berlaku sama untuk semua jalur, tidak bergantung pada server |
| D5 | Tipe stream ditentukan oleh **byte pertama** stream | ID stream QUIC dialokasikan dinamis |
| D6 | PTY memakai `portable-pty`, layar disnapshot dengan `vt100`, output disaring dengan `vte` | Jangan menulis ulang ConPTY dan emulator terminal |
| D7 | Penulisan file lewat `cap-std` | Mencegah path traversal dan symlink escape secara struktural |
| D8 | Prioritas stream: PTY di atas data file, dengan batas konkurensi | Mode hybrid tidak boleh membuat ketikan lag |
| D9 | Kriptografi minimal: `spake2` + `blake3` (derive_key, keyed_hash) | Sedikit dependensi, sedikit permukaan serangan |
| D10 | **Tanpa rendezvous.** Discovery lokal (mDNS + presence), internet hanya lewat tiket | Proyek tidak boleh bergantung pada server yang harus hidup terus |
| D11 | Dua mode identitas: **efemeral** (kode sekali pakai) dan **persisten** (perangkat tepercaya) | Kode sekali pakai tidak boleh meninggalkan jejak yang bisa dilacak. Basket butuh identitas tetap |
| D12 | Perangkat tepercaya dikenali lewat **pin NodeId**, bukan PAKE ulang | Pairing dilakukan sekali. Koneksi berikutnya diautentikasi oleh TLS QUIC + daftar tepercaya |
| D13 | Presence perangkat tepercaya memakai **tag yang berputar**, bukan NodeId terbuka | Pengamat LAN tidak bisa melacak perangkat. Hanya perangkat yang sudah tahu NodeId yang bisa mengenalinya |
| D14 | `tether-core` adalah library. CLI dan basket hanya lapisan tipis di atasnya | Satu implementasi protokol, dua antarmuka |
| D15 | Daemon latar memiliki identitas persisten. CLI dan GUI berbicara ke daemon lewat IPC lokal | Hanya satu proses yang boleh memegang endpoint dan identitas persisten |

## 3. Gambaran sistem

```text
+--------------------------------------------------------------+
|  tether (CLI)                |  tether-basket (GUI, Tauri)   |
|  send recv shell join pair   |  strip tepi, panel perangkat, |
|  devices doctor              |  drop, notifikasi terima      |
+--------------+---------------+---------------+---------------+
               |    in-process / IPC lokal     |
+--------------v-------------------------------v---------------+
|                       tether-core (library)                  |
|  +--------------------------------------------------------+  |
|  | Session Coordinator (state machine)                    |  |
|  | consent, kill, TTL, prioritas stream, kebijakan terima |  |
|  +-----+----------------+----------------+----------------+  |
|        |                |                |                   |
|  +-----v------+  +------v-------+  +-----v----------------+  |
|  | Identity & |  | PTY Engine   |  | Transfer Engine      |  |
|  | Pairing &  |  | host/guest,  |  | manifest, chunk,     |  |
|  | Trust store|  | snapshot,    |  | resume, path policy, |  |
|  |            |  | sanitizer    |  | inbox                |  |
|  +-----+------+  +------+-------+  +-----+----------------+  |
|        |                |                |                   |
|  +-----v----------------v----------------v----------------+  |
|  | Wire Protocol: tipe stream + frame (u8,u8,u32) + postcard |  |
|  +----------------------------+---------------------------+  |
|                               |                              |
|  +----------------------------v---------------------------+  |
|  | Transport: iroh endpoint (QUIC, ALPN "tether/1")       |  |
|  | jalur: LAN langsung | hole punching | relay terenkripsi|  |
|  +----------+-----------------------------+---------------+  |
|             |                             |                  |
|  +----------v-----------+      +----------v---------------+  |
|  | Discovery            |      | Infrastruktur pihak ke-3 |  |
|  | mDNS (kode)          |      | relay publik iroh        |  |
|  | presence (tepercaya) |      | (opsional, bisa dimatikan)|  |
|  | tiket, --addr        |      +--------------------------+  |
|  +----------------------+                                    |
+--------------------------------------------------------------+
```

## 4. Struktur repositori

```text
tether/
├── Cargo.toml                 # workspace; profil release (lto, strip)
├── deny.toml                  # cargo-deny
├── SECURITY.md  README.md  Brief.md  Architecture.md
├── .github/workflows/         # ci.yml (3 OS), chaos.yml (Linux netns), offline.yml, release.yml
├── crates/
│   ├── tether-core/           # library
│   │   └── src/
│   │       ├── lib.rs         # API publik: Node, events, commands
│   │       ├── error.rs       # tipe error terpadu
│   │       ├── identity/      # keys.rs (efemeral/persisten), store.rs (izin berkas)
│   │       ├── code/          # nameplate.rs, wordlist.rs, parse.rs
│   │       ├── discovery/     # mdns.rs, presence.rs (tag berputar), ticket.rs, manual.rs
│   │       ├── pairing/       # pake.rs, confirm.rs, attempts.rs, resume.rs
│   │       ├── trust/         # store.rs (perangkat tepercaya), policy.rs (auto-accept)
│   │       ├── net/           # endpoint.rs (iroh), paths.rs (info jalur)
│   │       ├── proto/         # frame.rs, kinds.rs, messages.rs (postcard)
│   │       ├── session/       # coordinator.rs, consent.rs, priority.rs
│   │       ├── pty/           # host.rs, guest.rs, screen.rs (vt100), sanitize.rs (vte)
│   │       ├── transfer/      # manifest.rs, sender.rs, receiver.rs, paths.rs, resume.rs, inbox.rs
│   │       └── ipc/           # server.rs, client.rs, schema.rs (daemon)
│   ├── tether/                # binary CLI
│   │   └── src/
│   │       ├── main.rs        # entrypoint, panic hook pemulih terminal
│   │       ├── cli.rs         # perintah clap
│   │       ├── ui/            # progress.rs, overlay.rs, terminal_guard.rs
│   │       └── doctor.rs      # diagnostik jaringan, mDNS, relay
│   └── tether-basket/         # GUI Tauri (Fase 5)
│       ├── src-tauri/         # jendela strip + panel, drag-drop, tray
│       └── ui/                # tampilan panel, animasi
├── spikes/
│   ├── iroh-offline/          # S1: bukti jalan tanpa internet dan tanpa relay
│   └── basket/                # S2: strip tepi + panel + drop file, tanpa jaringan
├── fuzz/                      # target fuzz: frame, manifest, sanitizer, paths, ipc
├── testnet/                   # skrip netns + tc netem + nftables NAT
└── tests/                     # integrasi, MITM, kekacauan, offline
```

## 5. Identitas, discovery, pairing, dan perangkat tepercaya

### 5.1 Identitas

| Mode | Kunci | Dipakai untuk | Masa hidup |
|---|---|---|---|
| **Efemeral** | Dibuat per sesi | `send`/`recv` dengan kode, `shell`/`join` | Hilang saat sesi selesai |
| **Persisten** | Dibuat sekali, disimpan di direktori konfigurasi pengguna | `pair`, perangkat tepercaya, daemon, basket | Sampai pengguna menghapusnya (`tether identity reset`) |

Penyimpanan: direktori konfigurasi platform (`dirs`). Berkas kunci dan daftar tepercaya dibuat dengan izin pemilik saja (`0600` di Unix; ACL pemilik di Windows, upaya terbaik dan diuji dengan smoke test). Kunci tidak pernah ditulis ke log. Kunci persisten tidak dikirim ke mana pun.

### 5.2 Format kode

`<nameplate>-<kata1>-<kata2>`, contoh `7-cobalt-falcon`.

| Bagian | Sifat | Sumber |
|---|---|---|
| `nameplate` (angka kecil) | **Publik**, hanya untuk memilih host di LAN | Acak lokal, dicek tidak bentrok dengan host lain yang terlihat di mDNS |
| `kata` | **Rahasia**, masukan SPAKE2 | CSPRNG, 2 kata dari daftar 2048 kata (22 bit). `--words 3` → 33 bit |

Daftar kata: 2048 kata dengan awalan 4 huruf unik (mis. daftar BIP39 atau daftar sendiri) agar bisa dieja lewat telepon dan di-autocomplete.

Aturan: kata rahasia **tidak pernah** dikirim, tidak di-hash ke ID apa pun, dan tidak ditulis ke log. `tether pair` dan `tether recv` boleh dipanggil tanpa argumen dan meminta input tersembunyi (menghindari kode terlihat di `ps`).

### 5.3 Discovery (tanpa server)

| Jalur | Dipakai untuk | Cara | Butuh internet |
|---|---|---|:-:|
| **mDNS** `_tether._udp.local.` | Kode sekali pakai dan `pair` | Host menyiarkan TXT: `np=<nameplate>`, `id=<NodeId efemeral>`, `v=1`. Tamu mencari berdasarkan nameplate | Tidak |
| **Presence** (UDP multicast) | Perangkat tepercaya | Beacon tiap **1,5 detik**: `{v, tag, port}`. Perangkat dianggap offline setelah **6 detik** tanpa beacon | Tidak |
| **Tiket** | Beda jaringan, atau LAN tanpa mDNS | String base32: alamat node iroh (NodeId, relay, alamat langsung) + rahasia acak 128-bit (sebagai password SPAKE2) | Ya, untuk lintas jaringan |
| **Alamat manual** | Jaringan yang memblokir multicast | `--addr 192.168.x.x:port` bersama kode | Tidak |

**Tag presence (D13):** `tag = blake3::keyed_hash(key = derive_key("tether presence v1", NodeId), msg = floor(t/300 s))[0..8]`. Perangkat tepercaya menghitung tag yang sama untuk tiap NodeId di daftarnya (jendela ±1 bucket untuk selisih jam) dan mencocokkan beacon yang masuk. Pengamat tanpa daftar tidak bisa mengaitkan tag dengan perangkat. Alamat IP sumber beacon dan `port` dipakai sebagai petunjuk alamat langsung untuk dial iroh berdasarkan NodeId. Beacon palsu hanya menghasilkan koneksi yang gagal terverifikasi.

**Keputusan implementasi yang menunggu spike S1:** apakah discovery lokal bawaan iroh dipakai, atau implementasi sendiri di atas. Kriteria: waktu temu (§14) dan apakah NodeId terbuka bocor ke LAN. Jika bawaan iroh dipakai dan membocorkan NodeId, hal itu **wajib dituliskan di README**.

### 5.4 Protokol pairing (kode)

Dipakai oleh dua mode: **sekali pakai** (hasil: sesi) dan **pair** (hasil: sesi + entri tepercaya).

1. **Host:** buat endpoint iroh. Mode sekali pakai: kunci efemeral. Mode pair: kunci persisten. Hasilkan kata rahasia (CSPRNG). Pilih nameplate. Umumkan lewat mDNS. Tampilkan kode.
2. **Tamu:** parse kode menjadi (nameplate, kata). Cari host lewat mDNS (atau `--addr`, atau tiket). Dial. **NodeId kedua pihak sudah terautentikasi oleh TLS QUIC.**
3. Tamu membuka stream **CONTROL** (§7) dan mengirim `Hello{version, mode: OneShot|Pair, nameplate}`.
4. Host memeriksa state `WaitingForGuest` dan nameplate cocok. Jika tidak, tutup dengan kode error generik. Hanya **satu pairing aktif** pada satu waktu. Pairing yang tidak selesai dalam 10 detik ditutup.
5. **SPAKE2:** password = kata (huruf kecil, dipisah `-`). Identitas A = NodeId tamu, identitas B = NodeId host. Tukar `PakeMsg`.
6. **Konfirmasi kunci:** transcript = `H(versi ‖ mode ‖ NodeId tamu ‖ NodeId host ‖ PakeMsg tamu ‖ PakeMsg host)`. Tiap pihak mengirim `PakeConfirm{mac}` dengan `blake3::keyed_hash` memakai subkunci `derive_key("tether v1 confirm <role>", K)`. Verifikasi dengan perbandingan waktu-konstan.
7. **Gagal:** host `failures += 1`, tutup koneksi. Jika `failures == 3`, keadaan **BURNED**: hentikan iklan mDNS, tolak pairing baru, tampilkan "Kode hangus". Tamu tidak mencoba ulang otomatis dan menampilkan pesan netral ("kode salah atau ada penyerang").
8. **Sukses:** keadaan **PAIRED**. Iklan mDNS dihapus segera (kode sekali pakai). Turunkan `resume_key = derive_key("tether v1 resume", K)`. Password dan K mentah di-zeroize.
9. **Hanya mode Pair:** kedua pihak saling mengirim `TrustExchange{alias}` (nama yang diusulkan, dibersihkan dari karakter kontrol, maksimum 32 karakter). Kedua pengguna melihat prompt "Pasangkan dengan *alias* (id: 8 karakter terakhir NodeId)? [y/N]". Entri tepercaya hanya disimpan jika **kedua sisi menjawab y**. Penolakan di salah satu sisi menutup sesi tanpa menyimpan apa pun.
10. **Persetujuan host** (§8.5) sebelum stream data apa pun dilayani pada mode sekali pakai.

Mode tiket memakai langkah yang sama, tanpa nameplate. Password SPAKE2 = rahasia 128-bit dari tiket.

### 5.5 Batas dan entropi

| Parameter | Nilai default |
|---|---|
| Percobaan gagal per kode | 3, dihitung di host |
| TTL pairing (kode belum dipakai) | 600 detik |
| Entropi kata | 22 bit (2 kata) / 33 bit (3 kata) |
| Peluang menebak per kode (2 kata, 3 percobaan) | ≈ 3 / 4.194.304 ≈ 7,2 × 10⁻⁷ |
| Timeout handshake | 10 detik |
| Beacon presence | tiap 1,5 detik, offline setelah 6 detik |
| Bucket waktu tag presence | 300 detik, toleransi ±1 bucket |

Catatan DoS: penyerang di LAN yang tahu nameplate bisa menghabiskan 3 percobaan. Itu menolak pairing, bukan membocorkan sesi. Pengguna membuat kode baru.

### 5.6 Perangkat tepercaya

**Data per entri:** `NodeId`, `alias`, `created_at`, `last_seen`, `auto_accept: bool` (default `false`), `auto_accept_max_bytes` (default 1 GiB).

**Koneksi ke perangkat tepercaya (tanpa kode):**
1. Penelepon menemukan perangkat lewat presence (tag cocok) dan dial berdasarkan NodeId.
2. TLS QUIC mengautentikasi NodeId kedua sisi. Penerima memeriksa NodeId ∈ daftar tepercaya. Jika tidak, tutup dengan error generik. Hanya jalur pairing (kode) yang bisa dipakai NodeId asing.
3. `Hello{mode: Trusted}`. Tidak ada PAKE. Setelah itu kebijakan stream berlaku (di bawah).

**Kebijakan perangkat tepercaya (invarian di §13):**

| Aksi dari perangkat tepercaya | Perlakuan |
|---|---|
| Menawarkan transfer file | `Offer` → penerima melihat notifikasi. Terima otomatis hanya jika `auto_accept = true`, ke folder **inbox**, di bawah batas ukuran. Di atas batas → tanya |
| Meminta sesi shell | **Tidak ada jalur dari perangkat tepercaya.** Shell hanya dimulai oleh host yang menjalankan `tether shell` dan menyetujui tamu saat itu |
| Mengirim input ke PTY | Tidak pernah dari koneksi tepercaya saja. Hanya dari sesi shell yang disetujui dan bermode interaktif |

**Pencabutan:** `tether devices rm <alias>` menghapus entri lokal dan menutup koneksi aktif. Sisi lain tidak diberi tahu otomatis, jadi pengguna harus mencabut di kedua sisi. Ini ditulis di README.

**Folder inbox:** default `~/Downloads/tether/`. Penulisan lewat `cap-std` (§9.5). Tidak bisa diubah oleh perangkat tepercaya.

### 5.7 Resume dan reconnect

Setelah PAIRED (mode sekali pakai), host menyimpan `session_id` dan `resume_key`. Jika koneksi putus:

1. Tamu menghubungi ulang alamat host yang sudah dikenal. Identitas tamu harus sama (proses tamu belum berhenti).
2. Tamu membuka CONTROL dan mengirim `Hello{resume: session_id}`.
3. Host membalas `ResumeChallenge{nonce}`. Tamu membalas `ResumeProof{keyed_hash(resume_key, nonce ‖ NodeId tamu)}`.
4. Host membatasi percobaan resume (5), lalu menutup sesi.

Sesi bisa dilanjutkan sampai **idle TTL** (default 30 menit, `--session-ttl`). Jika proses host mati, sesi hilang (didokumentasikan). Transfer file yang terputus saat proses mati dilanjutkan lewat `.part` (§9.4). Untuk perangkat tepercaya, reconnect tidak butuh resume token: cukup dial ulang.

### 5.8 State machine sesi

```text
Kode sekali pakai / pair:
WaitingForGuest -> Pairing -> Paired -> (consent) -> Active
      ^               |                    |           |
      |               v                    v           v
      +----------- BURNED              Rejected   Disconnected --(resume)--> Active
                                                       |
                                                       v  (TTL / kill / bye)
                                                     Closed

Perangkat tepercaya (daemon):
Listening -> (NodeId ∈ trust) -> Connected -> (offer, kebijakan terima) -> Transferring -> Connected
                  |
                  v (NodeId asing)
                Rejected
```

## 6. Jalur jaringan dan infrastruktur

| Prioritas | Jalur | Catatan |
|---|---|---|
| 1 | LAN langsung | mDNS/presence. Jika multicast diblokir (client isolation), jatuh ke tiket atau `--addr` |
| 2 | Langsung via hole punching | Ditangani iroh. Butuh internet untuk koordinasi awal |
| 3 | Relay terenkripsi | Fallback, **pihak ketiga**. Relay meneruskan paket QUIC yang sudah dienkripsi antar-identitas |

**Infrastruktur milik proyek: tidak ada.**

| Komponen | Pemilik | Kontrol pengguna |
|---|---|---|
| Relay iroh publik | Pihak ketiga | `--relay-url` (relay sendiri) atau `--relay-mode disabled` (hanya langsung) |
| Server STUN/pemetaan alamat (jika dipakai iroh) | Pihak ketiga | Mengikuti konfigurasi iroh. Didokumentasikan di README |

**Yang terlihat oleh relay:** alamat IP kedua peer, waktu, dan ukuran paket. **Yang tidak terlihat:** isi data. Pernyataan ini harus muncul di README.

**Kasus yang tidak didukung:** Wi-Fi dengan client isolation **dan** tanpa internet. `tether doctor` mendeteksi (mDNS/presence tidak terlihat padahal perangkat lain ada di jaringan, atau ping antar-klien gagal) dan menyarankan hotspot HP.

## 7. Protokol kawat

### 7.1 Tipe stream

Byte pertama pada setiap stream QUIC baru menyatakan tipenya. Tipe tak dikenal ditolak. Batas stream konkuren ditetapkan di konfigurasi QUIC.

| Byte | Nama | Arah | Jumlah | Keterangan |
|:-:|---|---|---|---|
| `0x01` | CONTROL | bi, dibuka penelepon | tepat 1 | Hello, pairing, trust, ping, mode, resume, bye |
| `0x02` | PTY | bi, dibuka host setelah persetujuan | tepat 1 | Host→tamu: Output, Resize, Snapshot. Tamu→host: Input |
| `0x03` | XFER_CTRL | bi, dibuka pengirim | 1 per transfer | Offer, ManifestPart, Accept/Reject, FileDone, Done |
| `0x04` | XFER_DATA | uni, pengirim→penerima | banyak | Satu chunk per stream |

### 7.2 Frame

```text
+----------+----------+------------------------+
| type: u8 | flags: u8|  len: u32 (big-endian) |
+----------+----------+------------------------+
|          body (len byte)                      |
+-----------------------------------------------+
```

- Header 6 byte. `MAX_FRAME_LEN = 1 MiB`, diperiksa **sebelum** alokasi. Lebih dari itu → tutup koneksi.
- Body pesan kontrol diserialisasi dengan `postcard`. Frame data mentah (Output, Input, ChunkData) membawa byte apa adanya.
- Versi protokol dinegosiasikan di `Hello`. Versi tak cocok → pesan error jelas, bukan crash.

### 7.3 Pesan utama

| Stream | Pesan |
|---|---|
| CONTROL | `Hello{version, mode: OneShot\|Pair\|Trusted, nameplate?, resume?}`, `PakeMsg`, `PakeConfirm`, `TrustExchange{alias}`, `TrustAck`, `Paired{caps}`, `ConsentResult`, `ModeChange{ReadOnly\|Interactive}`, `ResumeChallenge`, `ResumeProof`, `Ping`, `Pong`, `Bye{reason}` |
| PTY | `Output`, `Resize{cols,rows}`, `Snapshot`, `Input` |
| XFER_CTRL | `Offer`, `ManifestPart`, `ManifestEnd`, `Accept{have}`, `Reject`, `FileDone{file_idx, root}`, `Done` |
| XFER_DATA | header `{transfer_id, file_idx, chunk_idx, raw_len, hash}` + muatan Zstd |

## 8. Sesi shell

### 8.1 Host

- `portable-pty` membuat PTY dan menjalankan shell (`$SHELL`, atau PowerShell/cmd di Windows, `--cmd` untuk perintah lain).
- Terminal host masuk raw mode dengan **RAII guard** (§8.6). Input host dan input tamu (jika interaktif) digabung ke PTY master.
- Output PTY ditampilkan di host apa adanya, dimasukkan ke parser `vt100` untuk snapshot, dan dikirim ke tamu.
- Sesi shell memakai identitas **efemeral** dan kode sekali pakai. Perangkat tepercaya tidak bisa membuka shell (§5.6).

### 8.2 Ukuran layar

Ukuran **host menjadi otoritatif**. Resize host dikirim ke tamu. Jika terminal tamu lebih kecil dari grid host, tamu menampilkan peringatan lokal.

### 8.3 Snapshot saat join dan reconnect

Saat tamu bergabung atau tersambung kembali, host mengirim `Snapshot` yang dibuat dari layar `vt100`. Tamu menggambar layar itu lebih dulu, baru menerima `Output` berikutnya.

### 8.4 Penyaring output di sisi tamu (allow-list)

Output host disaring dengan parser `vte` sebelum menyentuh terminal tamu. Default **tolak**. Alasan: host jahat bisa menulis ke clipboard tamu (OSC 52) atau memancing balasan terminal yang kemudian terkirim sebagai input.

| Boleh | Ditolak secara default |
|---|---|
| Teks tercetak, `\n \r \t \b`, bel | OSC 52 (clipboard) |
| Gerak kursor, hapus, scroll region, sisip/hapus baris | OSC judul/warna/hyperlink dan semua OSC `?` (query) |
| SGR (warna dan gaya) | DCS, APC, PM, SOS |
| Mode DEC umum: layar alternatif (1049/1047/47), kursor tampil (25), autowrap (7), bracketed paste (2004), mouse (1000/1002/1003/1006) | Permintaan laporan: `CSI c`, `CSI n`, `CSI t`, XTVERSION, DECRQM, DECRQSS, query keyboard |

Aturan: allow-list **berdasarkan byte akhir CSI dan prefix**, dengan golden test untuk tiap kasus. Opsi `--unsafe-passthrough` di sisi tamu mematikan penyaring (tidak disarankan).

### 8.5 Izin, persetujuan, dan kill

| Aturan | Detail |
|---|---|
| Default | **Baca-saja**. Mode interaktif butuh `--interactive` dari host |
| Baca-saja | Semua byte `Input` dari tamu **dibuang di lapisan transport**, sebelum mencapai PTY master |
| Persetujuan host | Setelah PAIRED, sebelum stream PTY dibuka. Fase 3: prompt biasa sebelum shell dimulai. Fase 6: overlay saat sesi berjalan |
| Tombol prefix | `Ctrl+]` (bisa diubah): `k` kick, `r` ganti mode, `f` kirim file, `a` terima file masuk, `q` keluar, `]` kirim karakter prefix literal |
| TTL | `--session-ttl` (idle) dan `--max-duration` |
| Indikator | Banner awal di host. Fase 6: status bar dengan satu baris tersendiri (PTY dibuat dengan rows−1) |

### 8.6 Keamanan terminal

- `TerminalGuard` menyimpan flag awal (`termios` di Unix, mode konsol dan VT di Windows) dan memulihkannya di `Drop`.
- Panic hook, handler sinyal (SIGINT, SIGTERM, SIGHUP) dan handler Ctrl di Windows juga memulihkan terminal.
- Terminal dipulihkan saat peer memutus. Profil release memakai `panic = "unwind"` agar `Drop` berjalan.

## 9. Transfer file

### 9.1 Manifest

Entri: `{path: Vec<String> (komponen), kind: File|Dir, size: u64, exec: bool, mtime: Option<i64>}`. Jalur dikirim sebagai **komponen**, bukan string bergabung. Symlink **tidak dikirim** di 0.x (dilewati dan dilaporkan).

Manifest dikirim bertahap dalam frame `ManifestPart` (masing-masing ≤ 1 MiB). Penerima memberlakukan `max_entries` (default 1.000.000) dan `max_depth` (64).

### 9.2 Chunk

- Ukuran chunk 256 KiB (sebelum kompresi), dikompresi Zstd per chunk.
- `hash = BLAKE3(data mentah)` per chunk. Penerima mendekompresi dengan **batas keluaran = raw_len yang dideklarasikan** (mencegah zip bomb), lalu memverifikasi hash.
- `file_root = BLAKE3(hash_0 ‖ hash_1 ‖ …)`. Pengirim mengirim `FileDone{file_idx, root}`. Penerima menghitung dari hash chunk yang sudah terverifikasi.
- Pengiriman streaming: tidak ada arsip sementara di disk.

### 9.3 Alur persetujuan

1. Pengirim membuka XFER_CTRL dan mengirim `Offer{manifest_hash, jumlah_entri, total_byte}` lalu manifest.
2. Penerima memutuskan:
   - **Terima otomatis**, hanya untuk perangkat tepercaya dengan `auto_accept = true` dan `total_byte` ≤ batas. Ke folder inbox.
   - **Tanya**: CLI menampilkan prompt (`--yes` untuk melewati pada `recv` mandiri). Basket menampilkan notifikasi dengan tombol Terima/Tolak. Dalam sesi shell, lewat prefix `Ctrl+]` + `a`. Tanpa jawaban dalam **30 detik** (`--accept-timeout`) → tolak.
3. **Tidak ada byte tertulis di disk sebelum `Accept`**, termasuk file `.part`.
4. Penerima membalas `Accept{have}` (bitmap chunk yang sudah dimiliki, dikodekan run-length) atau `Reject`.

### 9.4 Resume

State disimpan di `<tujuan>/.tether/<manifest_hash>/` (bitmap dan file `.part` yang dialokasikan awal). Kuncinya `manifest_hash`, jadi transfer berbeda tidak akan salah dilanjutkan. Saat file selesai: verifikasi `file_root`, `fsync`, lalu `rename` atomik ke jalur akhir (satu filesystem karena `.tether/` berada di dalam direktori tujuan).

### 9.5 Kebijakan path penerima

Semua penulisan lewat `cap-std::fs::Dir` yang di-root pada direktori tujuan (inbox atau direktori yang dipilih penerima).

| Aturan | Detail |
|---|---|
| Komponen jalur | Tidak kosong, bukan `.` atau `..`, tanpa `/`, `\`, NUL, dan karakter kontrol |
| Windows | Tolak `:` (ADS), nama cadangan (CON, PRN, AUX, NUL, COM1–9, LPT1–9, dengan atau tanpa ekstensi), akhiran spasi atau titik |
| Panjang | ≤ 255 byte per komponen, total sesuai batas OS |
| Tabrakan huruf besar/kecil dan normalisasi Unicode (macOS, Windows) | Dideteksi, lalu diganti nama atau ditolak |
| Symlink | Tidak diikuti saat menulis, tidak dibuat |
| Mode | Hanya bit eksekusi yang dipertahankan. Buang setuid, setgid, sticky |
| File sudah ada | Default: ganti nama `nama (1).ext`. `--overwrite` eksplisit, `--no-clobber` untuk gagal |
| Ruang disk | Periksa `total_byte` + 5% sebelum Accept |

## 10. Prioritas dan latensi

- `set_priority` pada stream PTY (tertinggi) dan CONTROL, dengan XFER_DATA berprioritas terendah.
- Batas konkurensi stream chunk: default **2 saat sesi shell aktif**, 16 saat hanya transfer.
- Pengujian: benchmark p95 latensi echo saat transfer penuh. Target di Brief §9.

## 11. Daemon dan IPC lokal

**Tujuan:** hanya satu proses yang memegang endpoint iroh dan identitas persisten, sehingga CLI dan basket tidak berebut.

| Aspek | Keputusan |
|---|---|
| Perintah | `tether daemon` (latar), dijalankan otomatis oleh basket. Tersedia dari v0.3 |
| Sebelum daemon (v0.1–v0.2) | Perangkat tepercaya dipakai lewat `tether listen` (proses latar depan) yang memegang identitas |
| Kunci proses | Berkas kunci eksklusif (`fd-lock`). Proses kedua yang membutuhkan identitas persisten berbicara ke proses pertama lewat IPC, tidak membuka endpoint sendiri |
| Transport IPC | Unix domain socket (Linux, macOS) atau named pipe (Windows), lewat `interprocess` |
| Izin | Socket di direktori runtime pengguna dengan izin `0600`. Named pipe dengan ACL pengguna saja |
| Skema | Pesan `postcard`: `ListDevices`, `PairStart`, `PairJoin`, `Send{to, paths}`, `Accept{offer_id}`, `Reject{offer_id}`, `Subscribe{events}`, `DevicesRm` |
| Batasan | Panjang pesan IPC dibatasi (`MAX_FRAME_LEN`). Fuzz target `ipc` |
| Model kepercayaan | Proses lain milik pengguna yang sama dianggap tepercaya (sama dengan akses ke berkas kunci). Proses pengguna lain tidak bisa terhubung |
| Tanpa UI | Daemon tanpa basket menolak tawaran yang butuh persetujuan setelah 30 detik. `tether inbox` mendaftar riwayat |

## 12. Basket GUI

### 12.1 Perilaku

| Elemen | Detail |
|---|---|
| Strip pemicu | Jendela transparan tipis (3–6 px) di sepertiga tengah tepi layar, selalu di atas, tanpa ikon taskbar |
| Pemicu drag (default) | Event `drag-enter` pada strip → panel meluncur keluar (< 150 ms) |
| Pemicu hover (opsional) | Kursor diam di strip ≥ 300 ms → panel terbuka (daftar perangkat, riwayat, pengaturan) |
| Panel | Kartu perangkat tepercaya yang online (alias, status, jalur), dengan area drop per perangkat |
| Drop | Ke kartu perangkat → `Send{to, paths}` ke daemon → `Offer`. Tidak ada kartu aktif → pesan "tidak ada perangkat online" |
| Sisi dan monitor | Default kiri, monitor utama. Bisa diubah |
| Tray | Ikon tray untuk pairing, pengaturan, keluar |
| Notifikasi terima | Toast dengan Terima/Tolak. Timeout 30 detik |

### 12.2 Komponen

- `src-tauri`: jendela strip dan panel, penerimaan drop file, pengelolaan monitor, tray, jembatan ke daemon lewat IPC.
- `ui`: tampilan panel dan animasi. Tanpa logika protokol.
- Basket **tidak** membuka endpoint iroh sendiri. Ia klien IPC dari daemon (D15).

### 12.3 Risiko platform

| Platform | Risiko | Penanganan |
|---|---|---|
| Windows | Strip kecil bisa mencegat klik di tepi layar | Strip hanya di bagian tengah, lebar kecil, diuji dengan scrollbar dan tombol jendela |
| macOS | Aplikasi layar penuh menyembunyikan jendela selalu-di-atas | Atur perilaku koleksi jendela agar ikut semua Space. Game layar penuh eksklusif tidak didukung |
| Linux X11 | Aman dengan petunjuk jendela bertipe dock | Didukung |
| Linux Wayland | Jendela selalu-di-atas dan posisi bebas dibatasi | Perlu layer-shell. KDE, Sway, Hyprland mendukung, **GNOME tidak**. Spike menentukan dukungan |
| Semua | Transparansi webview kadang berkedip | Diuji di spike |
| Banyak monitor | Tepi layar ambigu | Monitor dan sisi dipilih eksplisit |

### 12.4 Spike basket (S2)

Dikerjakan di `spikes/basket/`, **tanpa jaringan sama sekali**. Dapat dijalankan paralel dengan Fase 1–4. Hasilnya menentukan cakupan GUI di Fase 5.

| Uji | Lulus jika |
|---|---|
| Windows 11 | Drag dari Explorer ke strip memicu panel. Drop terbaca dengan jalur file benar. Strip tidak mengganggu scrollbar di tepi |
| macOS | Sama, termasuk saat ada aplikasi layar penuh |
| Linux X11 | Sama |
| Linux GNOME Wayland | Catat apa yang gagal. Putuskan: didukung dengan keterbatasan, atau tidak didukung (CLI tetap penuh) |
| Animasi | Panel terbuka < 150 ms, area drop sudah aktif sebelum animasi selesai |
| Kedipan/transparansi | Tidak ada kedipan terlihat pada ketiga OS |

### 12.5 Keamanan GUI

- Daftar jalur file dari drop dikirim ke daemon apa adanya. Daemon yang memvalidasi (ukuran, symlink, akses baca).
- Alias perangkat ditampilkan sebagai teks biasa (tanpa HTML). Konten webview tidak memuat sumber daya jarak jauh (CSP ketat).
- Panel tidak pernah menampilkan kata rahasia kode di notifikasi atau log.

## 13. Model ancaman dan invarian keamanan

### 13.1 Aktor

| Aktor | Kemampuan | Mitigasi | Risiko sisa |
|---|---|---|---|
| Pengamat jaringan pasif (LAN) | Melihat paket, mDNS, beacon | QUIC TLS. Tag presence berputar | Tahu bahwa ada perangkat tether dan kapan. mDNS kode membocorkan nameplate + NodeId efemeral |
| Penyerang LAN aktif | Memalsukan beacon, membanjiri mDNS | Koneksi gagal terverifikasi. Batas laju dan satu pairing aktif | DoS terhadap discovery |
| Operator relay | Melihat IP, waktu, ukuran | Tidak bisa mendekripsi | Metadata |
| Penebak kode | Mencoba kode | 3 percobaan per kode, 22 bit | DoS dengan menghabiskan percobaan |
| MITM aktif | Menyisip di antara tamu dan host | NodeId masuk SPAKE2 dan transcript | Tidak ada pada model ini |
| Perangkat tepercaya yang dikompromikan | Menawarkan file, membanjiri tawaran | `auto_accept` default mati, inbox terbatas, batas ukuran, batas tawaran per menit. Tidak punya jalur ke shell | File berbahaya di inbox jika `auto_accept` aktif |
| Perangkat dicuri | Memakai identitas tepercaya | Pencabutan manual di sisi lain | Sampai dicabut, bisa menawarkan file |
| Malware lokal | Membaca kunci atau daftar tepercaya | Izin berkas | **Di luar model** |
| Tamu jahat (interaktif) | Mengetik di shell host | Default baca-saja, persetujuan, kill, TTL | Kepercayaan pada tamu adalah keputusan host |
| Tamu jahat (baca-saja) | Mengirim Input atau stream transfer | Input dibuang, stream tanpa Accept ditolak | – |
| Host jahat → tamu | Escape sequence, dorong file | Penyaring allow-list, path policy, wajib Accept | Bug render di emulator terminal tamu |
| Pengguna lokal lain | Membaca `ps`, env, socket | Input kode tersembunyi, kode sekali pakai, izin socket | Rendah |
| Rantai pasok | Dependensi atau rilis tercemar | `cargo-deny`, `cargo-audit`, rilis bertanda tangan | Residual |

### 13.2 Invarian (setiap butir wajib punya tes)

| ID | Invarian |
|---|---|
| I1 | Kata rahasia tidak pernah dikirim, di-hash ke ID channel, atau ditulis ke log |
| I2 | Tidak ada byte aplikasi (PTY/transfer) diproses sebelum konfirmasi PAKE sukses (mode kode) atau pencocokan trust store (mode tepercaya), dan persetujuan sesuai kebijakan |
| I3 | Maksimum 3 percobaan PAKE gagal per kode, di host. Setelah itu kode hangus |
| I4 | Kode sekali pakai. Setelah PAIRED, hanya `ResumeProof` yang diterima |
| I5 | Mode baca-saja membuang Input tamu sebelum PTY master |
| I6 | Output ke tamu disaring (allow-list) kecuali `--unsafe-passthrough` |
| I7 | Penulisan file hanya lewat `cap-std` Dir. Tidak ada path keluar, symlink diikuti, atau setuid |
| I8 | Tidak ada file ditulis sebelum penerima menerima (manual atau kebijakan terima otomatis) |
| I9 | Semua panjang dan ukuran dari peer dibatasi: frame, manifest, dekompresi, jumlah stream, pesan IPC |
| I10 | Terminal selalu dipulihkan (Drop, panic hook, sinyal), termasuk saat peer memutus |
| I11 | Rahasia (kata, K, resume key) di-zeroize setelah dipakai |
| I12 | Tidak ada telemetri dan tidak ada panggilan ke server milik proyek |
| I13 | NodeId yang tidak ada di trust store tidak bisa membuka stream aplikasi apa pun, hanya jalur pairing (mode kode) |
| I14 | Perangkat tepercaya tidak bisa memulai atau memasuki sesi shell tanpa persetujuan host saat itu |
| I15 | Terima otomatis hanya menulis ke folder inbox, hanya jika `auto_accept = true`, dan hanya di bawah batas ukuran |
| I16 | Kunci persisten dan daftar tepercaya tidak pernah dikirim, dan berkasnya berizin pemilik saja |
| I17 | Beacon presence tidak memuat alias, NodeId terbuka, atau data yang dapat dibaca manusia |
| I18 | Entri tepercaya hanya dibuat jika **kedua** sisi menyetujui pairing |
| I19 | IPC lokal hanya menerima koneksi dari pengguna yang sama |

## 14. Strategi pengujian

| Lapisan | Isi |
|---|---|
| Unit | Parse kode, SPAKE2 (benar dan salah), pembatas percobaan, tag presence (bucket, selisih jam), trust store, codec frame, sanitizer (golden test), path policy (table-driven + `proptest`) |
| Integrasi (loopback) | `send`/`recv` byte-identik. `pair` lalu `send --to`. `shell` baca-saja membuang Input. Mode interaktif dengan dan tanpa persetujuan |
| Keamanan | Harness MITM (relay yang menukar PakeMsg harus gagal), serangan tebak kode, NodeId asing ke daemon, tawaran file dengan `auto_accept` mati/menyala, escape sequence berbahaya, path berbahaya |
| Fuzz | `cargo-fuzz` untuk frame, manifest, sanitizer, path policy, pesan IPC |
| Kualitas tes | `cargo-mutants` pada modul pairing, trust, paths, sanitize |
| **Offline (Linux CI, wajib)** | Network namespace tanpa rute keluar dan tanpa DNS, relay dimatikan. Dua namespace dihubungkan lewat bridge. Asersi: `pair`, `send`/`recv`, dan penemuan perangkat tepercaya semuanya berhasil |
| Kekacauan (Linux CI) | `ip netns` + `tc netem` + `nftables` |
| Windows/macOS | Tes fungsional dan loopback di runner CI. Smoke test ConPTY. Pemeriksaan manual offline (matikan internet). Uji kekacauan jaringan **tidak** tersedia di dua OS ini |

### 14.1 Matriks kekacauan (Linux)

| Dimensi | Variasi |
|---|---|
| Gangguan netem | Loss 1% / 5% / 20%, delay 50 ms + jitter 20 ms, reorder 10%, bandwidth 1 Mbit, blackhole 10 detik |
| Profil NAT (nftables) | Full-cone, restricted-cone, port-restricted, symmetric, UDP diblok |
| Pasangan NAT | Semua kombinasi yang relevan (hanya untuk jalur tiket lintas jaringan) |

**Asersi:** hash file cocok. Sesi shell tetap hidup setelah blackhole dan tersambung kembali. Layar `vt100` tamu sama dengan layar host setelah resync. Jalur yang dipakai (langsung atau relay) **dicatat, tidak dijanjikan**; hasilnya ditentukan perilaku iroh.

### 14.2 Pengukuran discovery

Skrip benchmark mengukur: waktu dari proses B online sampai muncul di daftar A (p50/p95), dan waktu offline terdeteksi. Target di Brief §9. Dijalankan pada LAN nyata (bukan hanya namespace) sebelum angka dipublikasikan.

## 15. Fase implementasi dan kriteria selesai

| Fase | Isi | Kriteria selesai |
|---|---|---|
| 1 | Identitas (efemeral/persisten), kode, mDNS, presence, tiket, alamat manual, pairing SPAKE2, trust store, **spike S1** | Dua proses berpasangan via LAN tanpa internet dan tanpa relay (tes offline lulus). Kode salah ×3 menghanguskan kode. Harness MITM gagal. Perangkat tepercaya muncul dalam target waktu. I1–I4, I11, I13, I16–I18 teruji. S1 menetapkan keputusan discovery (iroh bawaan vs sendiri) |
| 2 | `send`/`recv` (kode dan `--to`), `tether listen`, inbox dan kebijakan terima, manifest, chunk, resume, path policy, batas sumber daya | Folder besar terkirim byte-identik. Resume berhasil setelah proses dimatikan. Fuzz path dan manifest bersih. I7–I9, I15 teruji |
| 3 | `shell`/`join` baca-saja (Linux, macOS), snapshot, sanitizer, lalu mode interaktif dengan persetujuan dan kill, prioritas stream | Join di tengah editor menampilkan layar benar. Input tamu terbuang di mode baca-saja. Golden test sanitizer lulus. I2, I5, I6, I10, I14 teruji. Benchmark latensi dicatat |
| 4 | Uji kekacauan (netns, netem, NAT), CI tiga OS, fuzz berkelanjutan, `cargo-mutants`, tinjauan keamanan trust store dan IPC | Matriks §14.1 lulus. CI hijau di tiga OS. Temuan tinjauan keamanan ditutup |
| 5 | Daemon + IPC, **spike S2 lulus** (§12.4), basket GUI, notifikasi terima, perangkat tepercaya di UI | Drag dari file manager ke strip, panel muncul, drop mengirim file ke perangkat online di LAN pada Windows, macOS, dan Linux X11. I19 teruji. Keputusan Wayland GNOME tercatat |
| 6 | ConPTY (`portable-pty`), status bar dan overlay, hybrid file drop, `tether doctor`, rilis, README, benchmark | Shell Windows stabil. Hybrid file drop wajib persetujuan. Rilis bertanda tangan dengan checksum |

Pemetaan rilis: **v0.1** = Fase 1–2, **v0.2** = Fase 3, **v0.3** = Fase 5, **v1.0** = Fase 4 + Fase 6 + tinjauan keamanan. Spike S2 dapat dikerjakan kapan pun sebelum Fase 5.

## 16. Dependensi dan build

> Versi dikunci saat implementasi. Periksa lisensi dengan `cargo-deny` dan verifikasi API iroh (discovery lokal, alamat node, relay) sebelum Fase 1.

| Fungsi | Crate |
|---|---|
| Runtime async | `tokio` |
| Transport | `iroh` |
| CLI | `clap` |
| Serialisasi | `serde`, `postcard` |
| PAKE dan hash/MAC | `spake2`, `blake3` |
| Zeroize dan acak | `zeroize`, `rand` / `getrandom` |
| Kompresi | `zstd` |
| PTY, layar, parser | `portable-pty`, `vt100`, `vte` |
| Terminal | `crossterm` |
| Sistem file aman | `cap-std` |
| LAN discovery (mDNS) | `mdns-sd` |
| Presence (UDP multicast) | `socket2`, `tokio` |
| Direktori konfigurasi | `dirs` |
| IPC lokal | `interprocess` |
| Kunci proses | `fd-lock` |
| GUI | `tauri` v2 |
| Progres UI | `indicatif` |
| Error dan log | `thiserror`, `anyhow`, `tracing` |
| Tes | `proptest`, `cargo-fuzz`, `cargo-mutants` |

Profil release:

```toml
[profile.release]
lto = "fat"
codegen-units = 1
strip = true
opt-level = 3
panic = "unwind"   # agar Drop pemulih terminal berjalan
```

---

## Lampiran A. Pemetaan perubahan v2.0 → v3.0

| # | Perubahan | Keputusan di v3.0 | Bagian |
|---|---|---|---|
| 1 | Server rendezvous dihapus | Discovery lokal, internet hanya lewat tiket | D10, §5.3, §6 |
| 2 | Crate `tether-rendezvous` dihapus | Tidak ada infrastruktur milik proyek | §4, I12 |
| 3 | Kode angka tidak lagi di-resolve lewat internet | Nameplate hanya untuk memilih host di LAN | §5.2 |
| 4 | Perangkat tepercaya | Pairing sekali, pin NodeId, kebijakan terima | D11, D12, §5.6 |
| 5 | Presence tanpa membocorkan identitas | Tag berputar, tanpa alias atau NodeId | D13, §5.3, I17 |
| 6 | Shell tidak boleh lewat trust | Hanya dari host yang menyetujui saat itu | §5.6, I14 |
| 7 | Terima otomatis | Opt-in per perangkat, hanya inbox, batas ukuran | §9.3, I15 |
| 8 | Struktur library + CLI + GUI | `tether-core`, `tether`, `tether-basket` | D14, §4 |
| 9 | Daemon dan IPC | Satu pemilik identitas persisten | D15, §11, I19 |
| 10 | Basket GUI | Strip tepi, panel, spike S2 sebagai syarat | §12 |
| 11 | Wi-Fi saja, kasus gagal dinyatakan | Client isolation tanpa internet tidak didukung. Saran hotspot | §6 |
| 12 | Bukti jalan tanpa internet | Tes offline wajib di CI, spike S1 | §14, §15 |
| 13 | Fase dan rilis | 6 fase, v0.1 sampai v1.0 | §15 |

Pemetaan temuan review v1 → v2 (stream, SPAKE2 dalam QUIC, sanitizer, kebijakan path, dll.) tetap berlaku dan sudah tercermin di bagian terkait.
