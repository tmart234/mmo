# mmo

## High-level Idea
Client <-> GS <-> VS, speaking the Fair-Play Protocol (FPP v1).

- **VS** – the trust plane (split into services in roadmap P2). It admits
  game servers, keeps each one "blessed" with a short-lived, hash-chained
  **Server Attestation Result (SAR)**, verifies one signed **Checkpoint** per
  epoch from each, and revokes by simply stopping SARs. For clients it acts
  as (stub) **Verifier** and **Broker**: it issues an **Attestation Result
  (AR)** with a device trust tier and a **Session Admission Token (SAT)** for
  a match, both bound to the client's session key.
- **GS** – runs the match. Clients join over **fpp-session** (Noise over UDP,
  ADR-002): the GS shows its current SAR, checks `Admit{SAT, AR}`, applies
  clients' *intent* (never positions), and signs a Checkpoint per epoch.
- **Client** – refuses to play unless the GS's SAR chain certifies the exact
  key it connected to, and stops the moment that chain lapses. It commits to
  its inputs every epoch with a signed **InputCommit**.

Flow:
1. **GS join** (QUIC control link, TLS 1.3 with X25519MLKEM768): VS challenge →
   `JoinRequest` signed by the GS long-term key, binding its instance key,
   game-port key and address → `JoinAccept`. With a TPM 2.0 (`gs-sim
   --tpm2`) it also carries a quote over the challenge, the boot and IMA
   logs and the EK certificate, and the VS runs credential activation and
   checks the build the kernel measured (`TPM_GUIDE.md`).
2. **Liveness**: VS → GS a new SAR every 2 s (`exp = iat + 10 s`); GS → VS a
   signed Checkpoint every epoch. No Checkpoint, or a bad one, revokes the
   GS: SARs stop.
3. **Client admission** (QUIC control link): VS challenge → session-key proof →
   AR (tier D0 until platform evidence is appraised, P3) + SAT for the match,
   refused where the queue's tier floor is higher (e.g. `verified`).
4. **Join the GS** (fpp-session): Noise IK to the GS key the Broker named →
   `SarUpdate` → client checks it → `Admit{SAT, AR}` → `Admitted{slot}`.
5. **Play**: InputFrames (unreliable, redundant) per tick; InputCommit per
   epoch and SarUpdate / CheckpointHead messages on the reliable channel.
6. **Revocation**: when SARs stop, the GS kicks everyone and clients drop
   within 3 issue intervals, on their own.

> **Design and spec:** [`docs/anticheat/`](docs/anticheat/README.md): threat
> model, requirements, architecture, protocol spec (FPP v1), ADRs and roadmap.

---

### Quick Start

```bash
# generate dev keys: VS signing key + a dev CA with VS/GS TLS certificates (keys/)
cargo run -p tools --bin gen_keys

# run full CI-lite (fmt, clippy, tests, smoke)
make ci

# dependency policy (advisories, licenses, sources), as in CI
cargo deny check

# C SDK for C/C++ games (include/fpp.h + libfpp.a): conformance, 64-bit and Halo's 32-bit ABI
make ffi-c-test
make ffi-c-test-i686

# Raspberry Pi: VS for a Pi Zero 2 W, SDK for the Pi 5 host (deploy/pi/README.md)
make pi-vs pi-vs-smoke ffi-c-test-aarch64

# fuzz the wire decoders and verifiers (nightly + cargo-fuzz)
cargo +nightly fuzz run wire_decode -- -max_total_time=60
cargo +nightly fuzz run verify_untrusted -- -max_total_time=60
```

Every QUIC control link verifies certificates against `keys/dev_ca.der` and
negotiates X25519MLKEM768. Game servers pin `keys/vs_ed25519.pub` for
JoinAccept; everyone trusts the role keys in `keys/fpp_key_bundle.json`
(Verifier, Broker, Server Liveness). Clients drop a GS as soon as its SAR
chain breaks or goes stale. Nothing in `keys/` is committed.