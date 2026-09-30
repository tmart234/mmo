# mmo

## High-level Idea
Client <-> GS <-> trust plane, speaking the Fair-Play Protocol (FPP v1).

- **Trust plane** – a regional *cell* of separate services, each its own
  process with its own key, so one failing or compromised takes neither the
  others' keys nor their availability (docs/anticheat/03 §3):
  - **Server Liveness** (`svc-liveness`) admits game servers on their TPM
    2.0 evidence, keeps each one "blessed" with a short-lived, hash-chained
    **Server Attestation Result (SAR)**, verifies one signed **Checkpoint**
    per epoch from each, and revokes by simply stopping SARs.
  - **Verifier** (`svc-verifier`) appraises a client's platform evidence
    and signs an **Attestation Result (AR)** with its device trust tier.
  - **Broker** (`svc-broker`) takes an AR, applies the queue's tier floor,
    has Server Liveness reserve a slot on a live GS (over the cell's mutual
    TLS), and signs a **Session Admission Token (SAT)** for that match.
  - **Revocation Feed** (`svc-revocation`) carries Enforcement's signed
    revocation events (`fpp-enforce`) to the Broker and Server Liveness,
    which relays them to game servers; every event is in the Transparency
    Log first.
  - **Evidence Store** (`svc-evidence`) keeps the Checkpoints Server
    Liveness verified, content addressed, for auditors (`fpp-evidence`).
  - **Transparency Log** and its **witness** (`svc-log`, `svc-witness`).
- **GS** – runs the match. Clients join over **fpp-session** (Noise over UDP,
  ADR-002): the GS shows its current SAR, checks `Admit{SAT, AR}`, applies
  clients' *intent* (never positions), and signs a Checkpoint per epoch.
- **Client** – refuses to play unless the GS's SAR chain certifies the exact
  key it connected to, and stops the moment that chain lapses. It commits to
  its inputs every epoch with a signed **InputCommit**.

Flow:
1. **GS join** (QUIC, TLS 1.3 with X25519MLKEM768, to Server Liveness):
   challenge → `JoinRequest` signed by the GS long-term key, binding its
   instance key, game-port key and address → `JoinAccept`. With a TPM 2.0
   (`gs-sim --tpm2`) it also carries a quote over the challenge, the boot
   and IMA logs and the EK certificate, and Server Liveness runs credential
   activation and checks the build the kernel measured (`TPM_GUIDE.md`).
2. **Liveness**: Server Liveness → GS a new SAR every 2 s (`exp = iat + 10
   s`); GS → Server Liveness a signed Checkpoint every epoch. No Checkpoint,
   or a bad one, revokes the GS: SARs stop.
3. **Client admission**: Verifier challenge → session-key proof and
   evidence → AR (tier D0 until platform evidence is appraised, P3); then
   Broker challenge → the AR, used by its session key → SAT for a slot,
   refused where the queue's tier floor is higher (e.g. `verified`).
4. **Join the GS** (fpp-session): Noise IK to the GS key the Broker named →
   `SarUpdate` → client checks it → `Admit{SAT, AR}` → `Admitted{slot}`.
5. **Play**: InputFrames (unreliable, redundant) per tick; InputCommit per
   epoch and SarUpdate / CheckpointHead messages on the reliable channel.
6. **Revocation**: Enforcement's event reaches the GS through the feed and
   Server Liveness, and the GS removes the players it names (p99 well under
   5 s, `make ci`). A revoked GS gets no more SARs: it kicks everyone, and
   if it ignores that too its clients drop within 3 issue intervals, on
   their own.

> **Design and spec:** [`docs/anticheat/`](docs/anticheat/README.md): threat
> model, requirements, architecture, protocol spec (FPP v1), ADRs and roadmap.

---

### Quick Start

```bash
# dev keys: a dev CA and public TLS certificates (keys/), and a cell with
# each service's identity (cell/); services make their signing keys on first start
cargo run -p tools --bin gen_keys

# a cell in containers (Server Liveness, Verifier, Broker): deploy/cell/README.md
docker compose -f deploy/cell/docker-compose.yml up --build

# run full CI-lite (fmt, clippy, tests, smoke)
make ci

# dependency policy (advisories, licenses, sources), as in CI
cargo deny check

# C SDK for C/C++ games (include/fpp.h + libfpp.a): conformance, 64-bit and Halo's 32-bit ABI
make ffi-c-test
make ffi-c-test-i686

# Raspberry Pi: the cell on a Pi Zero 2 W, SDK for the Pi 5 host (deploy/pi/README.md)
make pi-cell pi-cell-smoke ffi-c-test-aarch64

# fuzz the wire decoders and verifiers (nightly + cargo-fuzz)
cargo +nightly fuzz run wire_decode -- -max_total_time=60
cargo +nightly fuzz run verify_untrusted -- -max_total_time=60
```

Every QUIC link to a service verifies its certificate against
`keys/dev_ca.der` (and its name, `liveness.dev`, `verifier.dev`,
`broker.dev`) and negotiates X25519MLKEM768; services call each other over
mutual TLS with the cell's own CA. Everyone trusts the role keys in
`keys/fpp_key_bundle.json` (Verifier, Broker, Server Liveness), which
`tools::cell` or `fpp-cell bundle cell` gathers from what each service
publishes in `cell/public/`. Clients drop a GS as soon as its SAR
chain breaks or goes stale. Nothing in `keys/` or `cell/` is committed.