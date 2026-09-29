# mmo

## High-level Idea
Client <-> GS <-> VS

- **VS (Validation Server)** – Root of truth. Hands out short-lived proofs that a given Game Server is legit. Audits the Game Server’s behavior and can revoke it in seconds.
- **GS (Game Server)** – Runs the actual simulation / match. Talks to VS to stay “blessed.” Talks to clients.
- **Client** – Only talks to GS, but refuses to trust GS unless GS can prove VS is still blessing it.

Flow:
1. **JoinRequest**: GS → VS, signed by GS long-term key; binds:
   - `gs_id`, ephemeral session public key, `sw_hash` (binary hash), time + nonce.
2. **JoinAccept**: VS → GS, returns `session_id` and signs it (pinning VS identity).
3. **PlayTickets**: VS → GS issues short-lived, hash-chained tickets `{counter, nb/na, prev_ticket_hash}`.
4. **Client inputs**: Client → GS includes:
   - current `PlayTicket` (VS sig), `client_nonce` (monotone), `client_sig` over canonical bytes.
5. **GS verifies** ticket freshness & chain, client sig/nonce, clamps movement, updates world, and advances a rolling **receipt_tip**.
6. **Heartbeats**: GS → VS with `{session_id, gs_counter, gs_time_ms, receipt_tip, sw_hash}` signed by GS *ephemeral* session key.
7. **ProtectedReceipt**: VS returns a short signature over `{session_id, gs_counter, receipt_tip}` to notarize the transcript so far.
8. **Revocation**: If VS stops blessing (stops tickets / rejects heartbeat) → clients are kicked via ticket starvation + revoke broadcast.

Goal: anti-cheat + anti-rogue-host + audit trail, built into the protocol.

> **Production design:** see [`docs/anticheat/`](docs/anticheat/README.md) for the
> threat model, requirements, architecture, protocol spec (FPP v1), ontology
> review, language decision (ADR-001) and roadmap that supersede the prototype
> design below.

---

## Crypto (so far)
Continuous attestation (GS→VS heartbeats):
- VS verifies a per-session ephemeral key and pins the GS sw_hash observed at join. Heartbeats carry:
  - session_id, gs_counter (strictly monotonic), gs_time_ms, receipt_tip (rolling digest), sw_hash, sig_gs.
  - VS enforces: valid signature, monotonic counter, pinned sw_hash. On mismatch → revoke.

Transcript notarization (VS receipts):
- GS periodically sends TranscriptDigest { session_id, gs_counter, receipt_tip, positions }.
- VS returns ProtectedReceipt (signed) echoing { session_id, gs_counter, receipt_tip }.
- This creates a signed audit trail so GS can’t later deny what it claimed happened at counter N.

Short-lived tickets (VS→GS→Client):
- PlayTicket includes { session_id, client_binding (placeholder=0s for now), counter, not_before_ms, not_after_ms, prev_ticket_hash } and VS signature.
- Tickets are rotated ~every 2s with a hash chain (prev_ticket_hash) to prevent reordering. Clients/GS check freshness windows.

Ephemeral session keys:
- Each GS session uses a fresh ephemeral keypair bound inside JoinRequest. VS uses it to verify heartbeats for that session only.

World/physics enforcement (on VS):
- VS measures movement between notarized snapshots (time from heartbeat, positions from digest) and revokes on speed violations.


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

# fuzz the wire decoders and verifiers (nightly + cargo-fuzz)
cargo +nightly fuzz run wire_decode -- -max_total_time=60
cargo +nightly fuzz run verify_untrusted -- -max_total_time=60
```

Every QUIC link verifies certificates: clients and game servers pin
`keys/dev_ca.der`, the GS pins the VS signing key `keys/vs_ed25519.pub`, and
clients drop a GS as soon as its VS ticket chain breaks or expires. Nothing in
`keys/` is committed.