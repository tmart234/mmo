# Fair-Play Protocol (FPP v1)

**A fairness-maximalist, cryptographically enforced authority & trust protocol for video games.**

Every authority claim, device attestation, match admission, input commit, checkpoint, and enforcement revocation is encoded in **owned strict deterministic CBOR / COSE_Sign1** (`crates/fpp`), carried over **owned `Noise_IK_25519_ChaChaPoly_SHA256` transport** (UDP game sessions and framed TCP control links pinned directly to static X25519 keys — zero X.509 PKI ceremony, zero `bincode`/`serde` on the wire), and anchored in a **hybrid Ed25519 + ML-DSA-65 C2SP Transparency Log** with independent witness cosigning.

---

## Owned 5-Crate Architecture

| Crate | Purpose |
|---|---|
| [`crates/fpp`](crates/fpp) | Complete `#![forbid(unsafe_code)]` FPP v1 protocol crate: deterministic CBOR/COSE, Ed25519/ES256/ML-DSA-65 + SHA-256/HMAC/ChaCha20-Poly1305 primitives, RFC 9162 Merkle trees, AR/SAT/SAR tokens, Noise IK UDP game sessions (`fpp::session`), Noise IK framed TCP control transport (`fpp::transport`), unified `GsLink` client, C2SP Transparency Log + Witness (`log` feature), evidence auditor, and TPM 2.0 collector. |
| [`crates/fpp-attest`](crates/fpp-attest) | Feature-gated hardware attestation appraisal (`default = ["tpm"]`, optional `mobile`): TPM 2.0 quotes/PCRs/WBCL/IMA/credential activation + Android KeyMint/Play Integrity + Apple App Attest. Core protocol stays 100% vendor-independent. |
| [`crates/fpp-ffi`](crates/fpp-ffi) | Pure-Rust C/C++ SDK (`libfpp.a` + `include/fpp.h`) including `gs-link` with zero `tokio`/`quinn`/`rustls`/`aws-lc` — cross-compiles cleanly to 32-bit `i686` (Halo: CE ABI) and `aarch64` (Raspberry Pi). Exports `fpp_sha256`, `fpp_hmac_sha256`, `fpp_aead_seal`, and `fpp_aead_open` so game titles never hand-roll crypto. |
| [`crates/fppd`](crates/fppd) | Unified authority daemon & operator CLI (`fppd init`, `fppd serve`, `fppd role witness`, `fppd enforce`, `fppd evidence`, `fppd audit`, `fppd ticket`). Consolidates all trust-plane roles into one binary while preserving strictly isolated per-role signing keys (`KeyRole` allowlists) and supporting standalone independent witnesses. |
| [`crates/fpp-sim`](crates/fpp-sim) | Headless reference client, reference game server (sharing `fpp::gs_link::GsLink`), and all 5 end-to-end adversarial exit test suites (`smoke`, `revocation_load`, `split_view`, `attestation_exit`, `verified_exit`). |

---

## Cryptographic Enforcement Flow

1. **GS Join & Blessing** (`Noise_IK` TCP pinned to `bundle.transport_pub` + CBOR): Server Liveness challenges the game server, verifies its long-term key + TPM 2.0 EK/AK/PCR/IMA evidence & credential activation, and streams hash-chained **Server Attestation Results (SARs)** every 2 s (`exp = iat + 10 s`). Missing or invalid epoch **Checkpoints** stop SARs immediately.
2. **Client Attestation & Admission**: Verifier appraises hardware evidence (TPM 2.0 / Android / Apple) bound to the client's session key (Ed25519 or hardware-resident ES256) and signs an **Attestation Result (AR)**. Broker checks the AR, enforces queue tier floors (`open`, `verified` D2, `hardened` D3) and active revocations, reserves a slot on a live GS, and signs a **Session Admission Token (SAT)**.
3. **Game Session (`fpp::session`)**: Noise IK over UDP to the GS static key named by the Broker. Client verifies the server's SAR chain binds that exact static key and match audience before presenting `Admit{SAT, AR}`. Every epoch, the client signs an `InputCommit` and checks server `CheckpointHead`s against the Transparency Log (Ed25519 + ML-DSA-65 + witness cosignature + Merkle inclusion proof).
4. **Revocation & Split-View Protection**: Enforcement revocations are logged in the Transparency Log first, relayed to Broker & live game servers (p99 kick < 1 s), and if a rogue GS ignores its revocation or equivocates on a Checkpoint, clients drop it on their own within one SAR lifetime (10 s).

> **Design and spec:** [`docs/anticheat/`](docs/anticheat/README.md)

---

## Quick Start

```bash
# Run unified regional authority daemon (writes keys/fpp_key_bundle.json)
cargo run -p fppd -- serve

# Or run authority + independent witness in containers (2 services)
docker compose -f deploy/cell/docker-compose.yml up -d --build

# Run full CI (fmt, clippy, unit/integration tests, all 5 adversarial exit suites,
# Python golden-vector interop, Go sumdb interop, C SDK conformance)
FPP_REQUIRE_SWTPM=1 FPP_REQUIRE_GO=1 make ci

# Dependency policy (zero ignored advisories)
cargo deny check

# C SDK conformance (64-bit x86_64 and 32-bit i686 Halo ABI)
make ffi-c-test
make ffi-c-test-i686

# Raspberry Pi (aarch64) single-binary authority + emulation smoke
make pi-cell pi-cell-smoke ffi-c-test-aarch64
```

Nothing in `keys/` or `cell/` is committed to git. Every client and game server trusts only the public role keys and pinned Noise X25519 `transport_pub` in `keys/fpp_key_bundle.json`.