## 0. ROLE AND OBJECTIVE

You are a Principal Systems Engineer (Rust, networking, applied cryptography). You are building **Splice**: a cross-platform tool (Linux, macOS, Windows) that sends files and shares terminal sessions between devices on the same Wi-Fi/LAN, end-to-end encrypted, with **no server hosted by the project**.

Your job in this session is **Phase 1 only** of `docs/Architecture.md` §15 (release target v0.1, first half). Do not build later phases.

**Source of truth:** `docs/Architecture.md` (v3.0) and `docs/Brief.md` (v3.0). If this prompt and those documents disagree, **stop and write the conflict in `Laporan-1.md`**, then follow `Architecture.md` unless it is clearly a typo. Never silently invent a different design.

### Rename map (apply everywhere in code; leave the docs as they are)

| In the docs | In code |
|---|---|
| `tether` (binary, CLI) | `splice` |
| `tether-core` | `splice-core` |
| `tether-basket` | `splice-basket` (not built in Phase 1) |
| ALPN `"tether/1"` | `"splice/1"` |
| mDNS service `_tether._udp.local.` | `_splice._udp.local.` |
| KDF context strings `"tether v1 …"` | `"splice v1 …"` |
| config dir `tether/` | `splice/` |
| inbox `~/Downloads/tether/` | `~/Downloads/splice/` |

---

## 1. NON-NEGOTIABLE RULES

1. **Never claim something works without running it.** Every "passed" in your report must come from a command you actually ran, with its output summarized. If you could not run something (no root, no multicast, no other OS), say so plainly and mark it **NOT EXECUTED**. Do not hide failures.
2. **Never guess a crate API.** Check the exact version's docs/source (`cargo doc`, `~/.cargo/registry`, compile errors). Pin versions in `Cargo.lock`.
3. **No telemetry. No calls to servers owned by the project.** The only network traffic allowed is what the protocol needs. Network access during *build* is limited to crate registries.
4. **Secrets never reach logs.** The secret code words, SPAKE2 state, shared key `K`, resume key, identity secret key, and ticket secret must never appear in `tracing` output, errors, panics, or test snapshots. Use redacting wrapper types (`Secret<T>` with `Debug` printing `[redacted]`) and `zeroize`.
5. **Keep `iroh` isolated.** No `iroh` types may leak outside `crates/splice-core/src/net/` and `identity/`. Expose your own `NodeId`, `NodeAddr`, `Connection` newtypes/traits so the transport can be replaced (Brief §12 risk #2 has a fallback).
6. **Stay in scope.** Do NOT implement: `send`/`recv`, `shell`/`join`, daemon/IPC, basket GUI, ConPTY, status bar, file transfer, any rendezvous server. If you feel pulled toward them, write the idea into the report's "Next phase" section instead.
7. **Test first for security-critical code.** For pairing, trust store, code parsing, and presence tags: write failing tests, then implement.
8. **Commit per step** with clear messages (`git init` if needed). One logical change per commit.
9. Code quality gates (all must pass at the end, see §9): `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `cargo audit`. No `unsafe` without a `// SAFETY:` justification and a mention in the report.

---

## 2. THE REPORT: `Laporan-1.md` (MANDATORY)

Create `Laporan-1.md` in the **repository root at Step 0**, and **update it at the end of every step** (not only at the end), so progress survives interruptions. Write it **in Indonesian**, plain and factual. Do not pad it.

The "1" is the phase number. Later phases will produce `Laporan-2.md`, `Laporan-3.md`, and so on.

Required sections:

1. **Ringkasan** — 5–10 lines: what is done, what is not, overall status (HIJAU / KUNING / MERAH) and why.
2. **Lingkungan** — OS, Rust version, versions of `iroh`, `spake2`, `blake3`, `mdns-sd`, and other key crates. Which capabilities were available (root, `ip netns`, multicast, other OSes).
3. **Langkah yang dikerjakan** — per step (Step 0…N): what was done, commit hashes, files added.
4. **Hasil Spike S1 (iroh tanpa internet)** — a table of questions and **measured** answers (see §4 Step 1), plus the final decision: iroh built-in local discovery vs. own implementation, with data.
5. **Tabel invarian** — for each of I1, I2, I3, I4, I11, I12, I13, I16, I17, I18: the test name(s), the command to run, and status (LULUS / GAGAL / TIDAK DIJALANKAN).
6. **Hasil pengujian** — counts and outputs of unit, integration, security (MITM, guessing), fuzz smoke, `cargo-mutants` (score and notable surviving mutants), and the **offline test**.
7. **Hasil benchmark discovery** — p50/p95 time-to-appear and time-to-offline, with the environment (namespace vs. real LAN) stated honestly.
8. **Deviasi dari spesifikasi** — every place you differed from `Architecture.md`, with the reason.
9. **Masalah terbuka dan risiko** — known bugs, flaky tests, platform gaps (Windows ACL, macOS multicast, Wayland n/a), anything you are unsure about.
10. **Cara menjalankan ulang** — exact commands to reproduce build, tests, offline test, benchmark.
11. **Rekomendasi untuk Fase 2** — what you learned that changes or confirms the plan.

Honesty rule: a report that says "KUNING with 3 known gaps" is a good report. A report that says "all green" without evidence is a failure.

---

## 3. PHASE 1 SCOPE (what to build)

Implements `Architecture.md` §5 (all), §6, §7 (CONTROL stream messages only), §13 invariants I1–I4, I11–I13, I16–I18, §14 (offline test, security tests, discovery measurement), and spike S1.

### 3.1 Deliverables

| # | Deliverable |
|---|---|
| D1 | Cargo workspace: `crates/splice-core` (library), `crates/splice` (CLI), `spikes/iroh-offline`, `fuzz/`, `testnet/`, `tests/` |
| D2 | **Identity:** ephemeral and persistent keys; persistent store with owner-only permissions; `splice identity show` / `reset` |
| D3 | **Code:** `<nameplate>-<w1>-<w2>` (and `--words 3`), 2048-word list (unique 4-letter prefixes), parser, hidden-input prompt for guests |
| D4 | **Discovery:** mDNS (`_splice._udp.local.`, TXT `np`, `id`, `v=1`), **presence beacons** with rotating tag (every 1.5 s; offline after 6 s), **ticket** (base32, address + 128-bit secret), manual `--addr` |
| D5 | **Pairing:** SPAKE2 inside the CONTROL stream, key confirmation, 3-failure lockout (BURNED), one active pairing, 10 s handshake timeout, 600 s code TTL, zeroization |
| D6 | **Trust store:** persistent trusted devices, mutual-consent creation, `splice devices list` / `rm`, atomic writes, owner-only permissions |
| D7 | **Wire:** frame codec `(type u8, flags u8, len u32 BE)`, `MAX_FRAME_LEN = 1 MiB` checked before allocation, `postcard` messages for the CONTROL stream, stream-type byte `0x01` |
| D8 | **Minimal session coordinator:** pairing states and trusted-connection states from Architecture §5.8 |
| D9 | **Minimal `splice listen`:** announces presence, accepts connections only from trusted NodeIds, answers `Ping` with `Pong`. (File transfer is Phase 2. This minimal form exists so trusted-device discovery can be tested in Phase 1. Write this deviation into the report.) |
| D10 | **Dev subcommands** (hidden, to be removed or replaced in Phase 2): `splice dev host-oneshot`, `splice dev guest-oneshot <code>`, `splice dev host-ticket`, `splice dev guest-ticket <ticket>`, `splice dev ping <alias>`. They complete a handshake and exchange `Ping`/`Pong` so every path can be tested end to end |
| D11 | **Spike S1** in `spikes/iroh-offline/` and the discovery decision |
| D12 | **Offline test** (`tests/offline/` + `.github/workflows/offline.yml`) |
| D13 | **Security tests**: MITM harness, code-guessing, foreign NodeId, wire fuzzing |
| D14 | **CI:** `.github/workflows/ci.yml` (Linux, macOS, Windows: build, fmt, clippy, tests, deny, audit) |
| D15 | **Discovery benchmark script** and its measured results |
| D16 | `Laporan-1.md` |

### 3.2 CLI surface (Phase 1)

```text
splice pair                    # host: prints code, waits for a guest
splice pair --join [CODE]      # guest: CODE optional; if omitted, ask with hidden input
splice devices                 # list trusted devices (alias, id suffix, online/offline, last seen)
splice devices rm <alias>      # remove (also closes live connections)
splice listen                  # announce presence, accept trusted peers, answer Ping
splice identity show|reset     # show NodeId (public), or reset persistent identity
splice dev ...                 # hidden dev commands (D10)
Global flags: --relay-mode <default|disabled>, --relay-url <url>, --addr <ip:port>, --words <2|3>, --yes (tests only)
```

### 3.3 Constants (use these exact defaults; put them in one `constants.rs`)

| Name | Value |
|---|---|
| `MAX_FRAME_LEN` | 1 MiB |
| `PAIRING_ATTEMPTS_MAX` | 3 (counted on the host) |
| `PAIRING_CODE_TTL` | 600 s |
| `HANDSHAKE_TIMEOUT` | 10 s |
| `WORDLIST_LEN` | 2048 (2 words = 22 bits; 3 words = 33 bits) |
| `PRESENCE_INTERVAL` | 1.5 s |
| `PRESENCE_OFFLINE_AFTER` | 6 s |
| `PRESENCE_TAG_BUCKET` | 300 s (accept bucket −1, 0, +1) |
| `ALIAS_MAX_LEN` | 32 characters, control characters stripped |
| `RESUME_ATTEMPTS_MAX` | 5 (declare it; resume itself is Phase 2/3) |
| `SESSION_IDLE_TTL` | 30 min (declare only) |
| ALPN | `"splice/1"` |

---

## 4. EXECUTION STEPS (do them in order, verify each, update `Laporan-1.md` after each)

### Step 0 — Orientation and environment
- Read `docs/Architecture.md` and `docs/Brief.md` fully. List in the report any ambiguity or inconsistency you find.
- Record the environment (§2 item 2). Check for: `ip netns` (root), multicast on loopback/veth, Docker, `cargo-fuzz`, `cargo-mutants`, `cargo-deny`, `cargo-audit`. Install what is missing.
- Create `Laporan-1.md` with the skeleton of all required sections.

### Step 1 — Spike S1: does iroh work with no internet and no relay?
Build `spikes/iroh-offline/` (a throwaway crate). **Measure and record**, do not assume:

| Question | How to answer |
|---|---|
| Which `iroh` version and which API for endpoint builder, relay mode, NodeId, address hints? | Read the docs for the pinned version |
| Can two endpoints on one LAN (two network namespaces on a bridge, **no default route, no DNS**) connect with relay disabled, dialing by NodeId + direct address hint? | Run it. Record success/failure and connect latency |
| What happens with relay *enabled* (default) and no internet? Does it hang, slow down, or work? | Run it. Record time to connect |
| Does iroh have a built-in local discovery (mDNS-like)? How is it enabled, how fast does a peer appear (p50/p95 over ≥ 30 runs), and what does it announce (is the NodeId visible to a passive observer)? | Run it; capture packets with `tcpdump` if available |
| Can the endpoint use a persistent secret key and an ephemeral one in the same process? | Test |
| Can a custom ALPN and a bidirectional stream with a leading type byte be used as in Architecture §7.1? | Test |

**Decision output:** write the final decision in the report: use iroh's built-in local discovery, or implement our own (mDNS via `mdns-sd` + presence beacons). Criteria from Architecture §5.3: discovery time against the targets in Brief §9, and whether the NodeId leaks. For **one-shot codes** the NodeId is ephemeral, so mDNS exposure is acceptable. For **trusted devices** (persistent NodeId) a leak is not acceptable → use our own presence beacons with rotating tags unless iroh's discovery can be proven not to leak.

**If iroh cannot connect with no internet and no relay:** stop building on that transport. Write the evidence in `Laporan-1.md`, propose Plan B (a `quinn`-based LAN-only backend behind the same `net/` trait), and continue only with transport-independent work (identity, code, wordlist, presence tags, trust store, frame codec). Do not pretend the spike passed.

### Step 2 — Workspace, errors, constants, secrets
- Workspace layout from `Architecture.md` §4 (Phase 1 subset). Edition 2021 or newer, stable Rust.
- `Secret<T>` (redacting `Debug`/`Display`, `zeroize` on drop), unified error type (`thiserror`), `constants.rs`, `tracing` setup with a redaction test.

### Step 3 — Identity
- Ephemeral and persistent keys behind your own `NodeId`/`SecretKey` types.
- Persistent store in the platform config dir (`dirs`), file `identity.key`. Unix: mode `0600` (and parent dir `0700`). Windows: best effort, rely on the per-user profile ACL and add a smoke test that documents what is and is not verified. macOS: same as Unix.
- Atomic write (write temp, fsync, rename). Refuse to load a key file with loose permissions on Unix (and say why).
- Tests: roundtrip, permission check, reset, no key bytes in logs/Debug output (**I16**).

### Step 4 — Code and wordlist
- 2048-word list; tests assert count = 2048, all lowercase ASCII, **unique 4-letter prefixes**, no duplicates. (A BIP39-style English list satisfies this; check its license and note it in the report.)
- Code generation from the CSPRNG; nameplate chosen locally and checked against nameplates visible on the LAN.
- Parser: strict, case-insensitive, accepts `7-cobalt-falcon`, rejects malformed input with clear errors. `proptest`: parse(format(x)) == x, no panics on arbitrary strings. Fuzz target `fuzz_code_parse`.
- Hidden-input prompt for `splice pair --join` without argument.

### Step 5 — Wire protocol (CONTROL only)
- Frame codec per `Architecture.md` §7.2. **Reject `len > MAX_FRAME_LEN` before allocating.** Reject unknown frame types and flags. Version negotiation in `Hello`.
- Messages (postcard): `Hello{version, mode: OneShot|Pair|Trusted, nameplate?, resume?}`, `PakeMsg`, `PakeConfirm`, `TrustExchange{alias}`, `TrustAck`, `Paired{caps}`, `Ping`, `Pong`, `Bye{reason}`.
- Stream type byte `0x01` first on the CONTROL stream; unknown type bytes are rejected.
- Tests: roundtrip, truncated frames, oversized length, garbage; fuzz target `fuzz_frame`. Run each fuzz target for at least 60 s and record results (**I9** for the frame layer).

### Step 6 — Transport boundary (`net/`)
- Trait(s) for: create endpoint (persistent/ephemeral key, relay mode), dial by `NodeAddr`, accept, open/accept bidirectional streams, report path type (direct/relay/unknown) when available.
- iroh implementation of the traits, driven by the S1 results. An in-memory fake implementation for unit tests.

### Step 7 — Discovery
- **mDNS** (`mdns-sd`): host advertises `_splice._udp.local.` with TXT `np`, `id`, `v=1`; guest browses by nameplate. Withdraw the advertisement immediately after pairing succeeds or the code is BURNED.
- **Presence:** UDP multicast beacon `{v, tag, port}` every `PRESENCE_INTERVAL`. `tag = blake3::keyed_hash(key = blake3::derive_key("splice presence v1", node_id_bytes), msg = floor(unix_time / 300).to_be_bytes())[0..8]`. Receivers compute tags for every trusted NodeId for buckets −1, 0, +1 and match. Offline after `PRESENCE_OFFLINE_AFTER`. The beacon contains **no alias, no NodeId, nothing human-readable** (**I17**; add a test that scans serialized beacons for the alias and NodeId bytes).
- Inject a `Clock` trait so tests can move time (bucket edges, ±1 skew, expiry).
- **Ticket:** base32 of postcard `{version, node_addr, secret[16]}` with a visible prefix such as `sp1`. Parse and validate strictly. The 128-bit secret is the SPAKE2 password in ticket mode.
- **Manual:** `--addr ip:port` skips discovery.
- Multicast failure (client isolation, blocked multicast): report clearly and suggest ticket or `--addr`; never hang.
- Apply the S1 decision (built-in vs. own).

### Step 8 — Pairing (SPAKE2) — *highest-risk module, extra care*
Follow `Architecture.md` §5.4 exactly:
1. Host: endpoint (ephemeral key for OneShot, persistent for Pair), CSPRNG secret words, nameplate, mDNS advertisement, print code.
2. Guest: parse, find host (mDNS / `--addr` / ticket), dial. NodeIds are authenticated by the QUIC/TLS layer.
3. Guest opens CONTROL, sends `Hello`.
4. Host checks state `WaitingForGuest` and nameplate. **Only one active pairing at a time.** 10 s handshake timeout.
5. SPAKE2 with password = lowercase words joined by `-`, identity A = guest NodeId, identity B = host NodeId.
6. Key confirmation: `transcript = H(version ‖ mode ‖ guest NodeId ‖ host NodeId ‖ PakeMsg_guest ‖ PakeMsg_host)`; each side sends `PakeConfirm{mac}` using `blake3::keyed_hash` with a subkey from `derive_key("splice v1 confirm <role>", K)`. **Constant-time comparison.**
7. Failure: host `failures += 1`, close. At 3 → BURNED (withdraw advertisement, reject new pairings, print "Kode hangus"). Guest never auto-retries and prints a neutral message.
8. Success: PAIRED, withdraw advertisement, derive `resume_key`, **zeroize** password and `K`.
9. **Pair mode only:** exchange `TrustExchange{alias}` (sanitize, ≤ 32 chars). Both users get a prompt through an injectable `Prompter` trait ("Pair with <alias> (id: last 8 chars)? [y/N]"). The trust entry is written **only if both sides answer yes** (**I18**). One "no" closes the session and stores nothing.
10. Ticket mode: same flow without a nameplate; password = ticket secret.

Required tests (each is an invariant check; name them after the invariant):
- I3: three wrong guesses burn the code; a fourth attempt with the **correct** words is rejected; the counter lives on the host and is not reset by reconnecting.
- I1: scan logs, `Debug` output, error strings, and captured packets for the secret words (assert absence).
- I4: after PAIRED the same code cannot pair again.
- I11: secrets are zeroized (use a test type that records drops; assert memory cleared where feasible, and document limits).
- **MITM harness:** an attacker that sits between guest and host and (a) relays messages unchanged through a different NodeId, (b) runs its own SPAKE2 with each side using guessed words. Both must fail key confirmation. A transcript-binding test must show that changing any one NodeId breaks the confirmation MAC.
- Guessing simulation: 10 000 wrong-word attempts against fresh codes with 3 attempts each; assert 0 successes and record the attempt count.
- Timeouts: a guest that connects and stays silent is dropped after 10 s and does not consume an attempt (decide, document, and test that policy; the report must state it).
- Concurrency: a second guest during an active pairing is rejected without disturbing the first.

### Step 9 — Trust store and trusted connections
- File `trust.<fmt>` in the config dir (TOML or JSON, your choice, documented). Per entry: `node_id`, `alias`, `created_at`, `last_seen`, `auto_accept: false`, `auto_accept_max_bytes: 1 GiB`. Atomic writes, owner-only permissions (**I16**). Reject duplicate aliases (suggest a suffix).
- `splice devices`, `devices rm` (also closes live connections).
- Trusted connection: dial by NodeId (address hints from presence), TLS authenticates NodeIds, **the listener checks NodeId ∈ trust store; otherwise it closes with a generic error and allows only the pairing path** (**I13**). `Hello{mode: Trusted}`, no PAKE. Then `Ping`/`Pong`.
- **I2:** no application-level message other than the pairing messages and `Ping`/`Pong` is processed before confirmation succeeded (code modes) or the trust-store match succeeded (trusted mode). Test by sending forbidden messages early.
- Tests: foreign NodeId rejected; removed device rejected on its next connection and its live connection closed; corrupted store file → safe failure (no panic, clear message, no data loss: keep a backup).

### Step 10 — CLI wiring and dev commands
- Wire `pair`, `devices`, `listen`, `identity`, and the hidden `dev` commands to `splice-core`. Output messages in Indonesian (user-facing), code and logs in English.
- End-to-end integration tests (loopback and two processes): one-shot pairing, ticket pairing, pair-then-`dev ping`, wrong code, BURNED, foreign NodeId.

### Step 11 — Offline test (mandatory, Linux CI)
`tests/offline/` plus `.github/workflows/offline.yml`:
- Script creating two network namespaces joined by a bridge/veth, **no default route, no DNS, no route to the internet**.
- Run: `splice pair` ↔ `splice pair --join`, then `splice listen` ↔ `splice dev ping`, in both `--relay-mode disabled` and default relay mode.
- Assertions: pairing and ping succeed; trusted device appears via presence within the Brief §9 target; no process hangs on outbound attempts longer than the handshake timeout.
- If you lack root/netns locally: still write the script and workflow, run what you can (e.g. loopback-only variant), and mark the rest **NOT EXECUTED** in the report with the exact command to run in CI.

### Step 12 — Discovery benchmark
- Script that measures (n ≥ 30 runs): time from process B start until it appears in A's device list (p50, p95, max) and time until A marks B offline after B is killed.
- Run it in the namespace setup; state clearly that real-LAN numbers (Wi-Fi) are **not** measured unless you did measure them. Compare against Brief §9 (p95 ≤ 3 s online, ≤ 6 s offline).

### Step 13 — CI and quality gates
- `ci.yml` for Linux, macOS, Windows (build, `fmt`, `clippy -D warnings`, `test`, `deny`, `audit`). Add `deny.toml`.
- Fuzz smoke (≥ 60 s per target: `fuzz_frame`, `fuzz_code_parse`, `fuzz_ticket_parse`) and `cargo-mutants` on `pairing/`, `trust/`, `code/`, `discovery/presence`. Record score and fix or explain surviving mutants in security-critical code.

### Step 14 — Independent review pass, then finalize
- If you can run subagents, spawn **one independent reviewer** that sees only the code and `Architecture.md` §5 and §13 (not your reasoning) and attacks `pairing/` and `trust/`: protocol logic errors, timing, state-machine holes, secret leakage, panics on hostile input. Otherwise, do a clearly separated review pass yourself, reading the code as an attacker.
- Fix what is real. List every finding and its resolution in the report.
- Finish `Laporan-1.md` completely (all 11 sections).

---

## 5. SECURITY INVARIANTS TO PROVE IN PHASE 1

| ID | Invariant | Evidence required |
|---|---|---|
| I1 | The secret words are never sent, hashed into any ID, or logged | Test names + scan results |
| I2 | No application bytes processed before PAKE confirmation (code modes) or trust-store match (trusted mode) | Early-message tests |
| I3 | ≤ 3 failed PAKE attempts per code, counted on the host; then the code is dead | Lockout + simulation tests |
| I4 | A code is single use; after PAIRED only a resume proof is accepted | Replay test |
| I9 (frame/IPC-free part) | Every peer-supplied length is bounded | Codec tests + fuzz |
| I11 | Secrets are zeroized after use | Drop-recording tests, documented limits |
| I12 | No telemetry, no project-owned server | `cargo tree` review + grep for hard-coded hosts |
| I13 | A NodeId not in the trust store cannot open any application stream | Foreign-NodeId test |
| I16 | Persistent key and trust store are never sent and are owner-only | Permission tests |
| I17 | Presence beacons contain nothing human-readable and no open NodeId | Beacon scan test |
| I18 | A trust entry exists only if both sides approved | Both-yes / one-no tests |

---

## 6. DESIGN GUARDRAILS (decisions already made; do not reopen)

- Transport is **iroh**; do not write your own STUN/ICE/relay.
- **No rendezvous server.** Discovery is local (mDNS + presence); internet only via tickets.
- Pairing is **SPAKE2 inside the CONTROL stream** with identities = NodeIds. Do not use TLS exporters or a custom UDP handshake.
- Two identity modes: **ephemeral** (one-shot codes) and **persistent** (pair / trusted devices).
- Trusted devices are recognized by **pinned NodeId**, not by re-running PAKE.
- A trusted device can **never** start or enter a shell session (Phase 3 will enforce; in Phase 1 simply do not give it any such path).
- Wi-Fi/LAN only for the MVP. No Bluetooth/USB work.
- Frames are `(u8, u8, u32 BE)` with a hard 1 MiB bound; stream type is the first byte of each stream.

If you believe one of these is wrong, **do not change it**: document your evidence in the report under "Deviasi dari spesifikasi" and wait for the human.

---

## 7. WHAT TO DO WHEN BLOCKED

- A crate API is not what the docs say: read the source of the pinned version, adapt, and note it in the report.
- A test is flaky: do not retry-until-green. Find the race, fix it, or mark and explain it. Flaky security tests are a **MERAH** item.
- A platform gap (cannot run on macOS/Windows locally): write the CI job, mark **NOT EXECUTED**, move on.
- A requirement seems contradictory: choose the more conservative security behavior, document it, and continue.

---

## 8. TOKEN-BURNING GUIDANCE (spend effort where it pays)

Spend generously on: property tests and fuzzing of the parser/codec/ticket, `cargo-mutants` on security modules, the MITM and guessing harnesses, the namespace-based offline test, the S1 measurements (many runs, not one), and the independent review pass. Do **not** spend effort on polish outside the Phase 1 scope.

---

## 9. DEFINITION OF DONE (Phase 1)

Phase 1 is done only when **all** are true, each backed by command output in `Laporan-1.md`:

- [ ] Spike S1 finished with a measured decision (or a documented failure with Plan B proposed).
- [ ] `splice pair` / `pair --join` work over LAN **without internet and without relay** (offline test passed, or NOT EXECUTED with the exact CI command and the reason).
- [ ] Ticket mode and `--addr` work.
- [ ] Wrong code ×3 burns the code; MITM harness fails as required; guessing simulation shows 0 successes.
- [ ] A trusted device appears via presence and answers `Ping` within the Brief §9 targets in the measured environment (state which).
- [ ] Foreign NodeId is rejected; removed device is rejected; one-sided consent stores nothing.
- [ ] I1–I4, I9 (codec), I11–I13, I16–I18 each have tests and a status in the report.
- [ ] `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, `cargo audit` pass.
- [ ] Fuzz smoke (≥ 60 s per target) and `cargo-mutants` results recorded.
- [ ] CI workflows (`ci.yml`, `offline.yml`) exist and are syntactically valid.
- [ ] **`Laporan-1.md` is complete, honest, and in Indonesian.**

When done, print a 10-line summary and the path `Laporan-1.md`. Do not start Phase 2.

---

# BEGIN

Start with Step 0 now. First message to the human: one sentence saying you are starting Phase 1 and creating `Laporan-1.md`. Then execute the steps in order.
