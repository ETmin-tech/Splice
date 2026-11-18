# Laporan Fase 1 — Splice

> Status: **SEDANG DIKERJAKAN**. Laporan ini diperbarui di akhir setiap langkah.

## 1. Ringkasan

(Belum selesai — diisi bertahap.)

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

(Belum selesai.)

## 4. Hasil Spike S1 (iroh tanpa internet)

(Belum selesai.)

## 5. Tabel invarian

(Belum selesai.)

## 6. Hasil pengujian

(Belum selesai.)

## 7. Hasil benchmark discovery

(Belum selesai.)

## 8. Deviasi dari spesifikasi

(Belum selesai.)

## 9. Masalah terbuka dan risiko

(Belum selesai.)

## 10. Cara menjalankan ulang

(Belum selesai.)

## 11. Rekomendasi untuk Fase 2

(Belum selesai.)

## Lampiran: Ambiguitas dan inkonsistensi dokumen (Step 0)

Dicatat saat membaca `Architecture.md` v3.0 dan `Brief.md` v3.0.

1. **`Brief.md` §5.1 vs `Architecture.md` §5.4 langkah 9** — Brief menulis `tether pair <kode>` sedangkan prompt Fase 1 mensyaratkan `splice pair --join [CODE]`. Mengikuti prompt Fase 1 (`--join`), karena itu CLI kontrak yang diminta. Tidak bertentangan secara keamanan.
2. **`Architecture.md` §5.4 langkah 10 menyebut "Persetujuan host (§8.5) sebelum stream data apa pun"** — di Fase 1 belum ada stream data (PTY/transfer). Untuk Fase 1 diterapkan sebagai: setelah PAIRED tidak ada stream aplikasi yang dilayani selain `Ping`/`Pong`. Selaras dengan I2.
3. **Tiket: "Butuh internet: Ya, untuk lintas jaringan" (§5.3)** — tetapi tiket juga dipakai di LAN tanpa mDNS (baris yang sama). Di Fase 1 tiket diuji di LAN tanpa internet; klaim "lintas jaringan" tidak diuji (di luar lingkup Fase 1).
4. **`Architecture.md` §4 mencantumkan `tether-basket`** tetapi Fase 1 tidak membangunnya (sesuai prompt D1: "not built in Phase 1"). Tidak ada konflik.
5. **`Architecture.md` §11 daemon** — Fase 1 tidak membangun daemon. `splice listen` memegang identitas persisten secara langsung, sesuai §11 baris "Sebelum daemon (v0.1–v0.2)".
6. **`Architecture.md` §14.2** meminta benchmark di LAN nyata "sebelum angka dipublikasikan". Lingkungan ini tidak punya dua mesin fisik; benchmark dijalankan di netns dan ditandai eksplisit sebagai bukan Wi-Fi nyata.
7. **`RESUME_ATTEMPTS_MAX` dan `SESSION_IDLE_TTL`** hanya dideklarasikan (sesuai instruksi §3.3), resume sendiri Fase 2/3.
