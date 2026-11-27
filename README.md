# Fair-Play Protocol (FPP v1)

**A fairness-maximalist, cryptographically enforced authority & trust protocol for video games and MMOs.**

Every authority claim, device attestation, match/shard admission, input commit, checkpoint, and enforcement revocation is encoded in **owned strict deterministic CBOR / COSE_Sign1** (`crates/fpp`), carried over **owned `Noise_IK_25519_ChaChaPoly_SHA256` transport** (UDP game sessions and framed TCP control links pinned directly to static X25519 keys — zero X.509 PKI ceremony, zero `bincode`/`serde` on the wire), and anchored in a **hybrid Ed25519 + ML-DSA-65 C2SP Transparency Log** with independent witness cosigning.

---

## Owned 5-Crate Architecture

| Crate | Purpose |
|---|---|
| [`crates/fpp`](crates/fpp) | Complete `#![forbid(unsafe_code)]` FPP v1 protocol crate: deterministic CBOR/COSE, Ed25519/ES256/ML-DSA-65 + SHA-256/HMAC/ChaCha20-Poly1305 primitives, RFC 9162 Merkle trees, AR/SAT/SAR tokens, Noise IK UDP game sessions (`fpp::session`), Noise IK framed TCP control transport (`fpp::transport`), unified `GsLink` client, C2SP Transparency Log + Witness (`log` feature), evidence auditor, and TPM 2.0 collector. |
| [`crates/fpp-attest`](crates/fpp-attest) | Feature-gated hardware attestation appraisal (`default = ["tpm"]`, optional `mobile`): TPM 2.0 quotes/PCRs/WBCL/IMA/credential activation + Android KeyMint/Play Integrity + Apple App Attest. Core protocol stays 100% vendor-independent. |
| [`crates/fpp-ffi`](crates/fpp-ffi) | Pure-Rust C/C++ SDK (`libfpp.a` + `include/fpp.h`) including `gs-link` with zero `tokio`/`quinn`/`rustls`/`aws-lc` — cross-compiles cleanly to 32-bit `i686` and `aarch64`. Exports `fpp_sha256`, `fpp_hmac_sha256`, `fpp_aead_seal`, and `fpp_aead_open` so game titles never hand-roll crypto. |
| [`crates/fppd`](crates/fppd) | Unified authority daemon & operator CLI (`fppd init`, `fppd serve`, `fppd role witness`, `fppd enforce`, `fppd evidence`, `fppd audit`, `fppd ticket`). Consolidates all trust-plane roles into one binary while preserving strictly isolated per-role signing keys (`KeyRole` allowlists), publisher-keyed unlinkable Device IDs (`ID-02`), multi-shard slot balancing, and standalone independent witnesses. |
| [`crates/fpp-sim`](crates/fpp-sim) | Headless reference client, reference game server (sharing `fpp::gs_link::GsLink`), and all 5 end-to-end adversarial exit test suites (`smoke`, `revocation_load`, `split_view`, `attestation_exit`, `verified_exit`). |

---

## Extending FPP to Any MMO or Multiplayer Game

`mmo` contains **zero game-specific code**: the protocol treats per-tick input frames, match/zone events, state roots, and roster leaves as opaque title-defined byte payloads. Any MMO, RPG, shooter, or engine can adopt the stack in three steps:

### 1. Define a Title & Region Policy (`fppd`)

Configure your publisher domain, region, custom queues/shards and their device-tier floors (`D0`–`D3`), per-shard slot capacity (Broker automatically balances across live shards), and IMA-measured server binary path in a plain key-value policy file:

```ini
# game.conf
domain = realm.example
region = us-east
policy_ver = 1
max_slots = 500
gs_program = /opt/realm/zone-server
queues.clear = true
queue.world-shard = D0
queue.ranked-arena = D2
queue.tournament = D3
```

```bash
fppd serve --policy game.conf --dir cell --bundle keys/fpp_key_bundle.json --bind 0.0.0.0:4444
```

Each cell generates its own isolated per-role signing keys plus a private publisher HMAC key (`verifier/did.seed`), ensuring hardware Device IDs stay stable for bans within your game while remaining cryptographically unlinkable across games (`ID-02`).

### 2. Link the Protocol SDK into Your Engine

- **Rust servers & clients:** depend directly on [`crates/fpp`](crates/fpp) (`fpp::session`, `fpp::gs_link::GsLink`, `fpp::tokens`, `fpp::wire`, `fpp::crypto`).
- **C / C++ / Unreal / Unity / Godot / custom engines:** link [`crates/fpp-ffi`](crates/fpp-ffi) (`libfpp.a` / `fpp.lib` + [`include/fpp.h`](crates/fpp-ffi/include/fpp.h)) for Noise IK peer sessions (`fpp_p2p_*`), Server Liveness blessing (`fpp_gs_link_*`), SAT/AR admission & revocations (`fpp_admission_*`), SAR chain checks (`fpp_sar_chain_*`), epoch `InputCommit`/`Checkpoint` signing, and shared crypto primitives.

### 3. Attach the Game-Side Fairness Hooks

To get the full fairness guarantees demonstrated by our reference title (**[Halo: CE fork (`halo-ce-pi`)](https://github.com/tmart234/halo-ce-pi)**, see [`docs/anticheat/08-reference-title-halo.md`](docs/anticheat/08-reference-title-halo.md)):

1. **Server authority:** simulate movement, combat, and economy strictly from client *intents* (`InputFrame`), validate line-of-sight/rates/bounds server-side, and emit structured Signals on violations.
2. **Information minimization:** send clients only entities inside their server-computed perceivable/relevance set (anti-ESP).
3. **Cryptographic transport & admission:** run gameplay over `fpp::session` (`fpp_p2p_*`), enforce Verifier/Broker `AR` + `SAT` admission (device tier, measured client build, Device ID bans), and verify the server's continuous `SAR` chain on the client.
4. **Accountable evidence:** sign per-epoch `InputCommit`s on clients and hash-chained `Checkpoint`s on servers, anchored into the Transparency Log and auditable offline with `fppd audit`.

---

## Cryptographic Enforcement Flow

1. **GS Join & Blessing** (`Noise_IK` TCP pinned to `bundle.transport_pub` + CBOR): Server Liveness challenges the game server/shard, verifies its long-term key + TPM 2.0 EK/AK/PCR/IMA evidence & credential activation, and streams hash-chained **Server Attestation Results (SARs)** every `sar_interval_s` (default 2 s, `exp = iat + 10 s`). Missing or invalid epoch **Checkpoints** stop SARs immediately.
2. **Client Attestation & Admission**: Verifier appraises hardware evidence (TPM 2.0 / Android / Apple) bound to the client's session key (Ed25519 or hardware-resident ES256) and signs an **Attestation Result (AR)**. Broker checks the AR, enforces the queue's configured tier floor and active revocations, reserves a slot on the least-loaded live server/shard, and signs a **Session Admission Token (SAT)**.
3. **Game Session (`fpp::session`)**: Noise IK over UDP to the GS static key named by the Broker. Client verifies the server's SAR chain binds that exact static key and match audience before presenting `Admit{SAT, AR}`. Every epoch, the client signs an `InputCommit` and checks server `CheckpointHead`s against the Transparency Log (Ed25519 + ML-DSA-65 + witness cosignature + Merkle inclusion proof).
4. **Revocation & Split-View Protection**: Enforcement revocations are logged in the Transparency Log first, relayed to Broker & live game servers (p99 kick < 1 s), and if a rogue GS ignores its revocation or equivocates on a Checkpoint, clients drop it on their own within one SAR lifetime.

> **Design and spec:** [`docs/anticheat/`](docs/anticheat/README.md)

---

## Quick Start

```bash
# Run unified regional authority daemon (writes keys/fpp_key_bundle.json)
cargo run -p fppd -- serve

# Or run with a custom game policy
cargo run -p fppd -- serve --domain realm.example --region us-east --max-slots 500 --queue ranked:2

# Or run authority + independent witness in containers (2 services)
docker compose -f deploy/cell/docker-compose.yml up -d --build

# Run full CI (fmt, clippy, unit/integration tests, all 5 adversarial exit suites,
# Python golden-vector interop, Go sumdb interop, C SDK conformance)
FPP_REQUIRE_SWTPM=1 FPP_REQUIRE_GO=1 make ci

# Dependency policy (zero ignored advisories)
cargo deny check

# C SDK conformance (64-bit x86_64 and 32-bit i686 ABI)
make ffi-c-test
make ffi-c-test-i686

# Raspberry Pi (aarch64) single-binary authority + emulation smoke
make pi-cell pi-cell-smoke ffi-c-test-aarch64
```

Nothing in `keys/` or `cell/` is committed to git. Every client and game server trusts only the public role keys and pinned Noise X25519 `transport_pub` in `keys/fpp_key_bundle.json`.