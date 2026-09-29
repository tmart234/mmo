# ADR-002 — Transport per plane: encrypted UDP for game data, QUIC where it earns its place

- **Status:** Accepted
- **Date:** 2026-09-29
- **Question:** *"Is QUIC the most efficient transport for the game?"*

## Decision

| Plane | Transport | Used by |
|-------|-----------|---------|
| **Game data, native clients**: player-hosted *and* dedicated servers | `fpp-session` (04 §7.7): Noise IK over plain UDP, unreliable latest-wins datagrams plus a small reliable ordered channel | PC, consoles, mobile, classic C/C++ titles through `fpp_p2p_*` |
| **Game data, browsers** | QUIC / WebTransport, `DATAGRAM` frames for inputs and snapshots (04 §7.1, §7.3) | Browser clients (they cannot send raw UDP) |
| **Control plane**: accounts, attestation, matchmaking, key bundles, evidence upload | QUIC or HTTPS over TLS 1.3 with `X25519MLKEM768` | Everyone |

Game data never goes over a reliable QUIC stream; the prototype's
stream-based client input (`client-core`) is legacy and moves to `fpp-session`.

## Why

The goal is the least latency and CPU per game packet without giving up
security. "Raw UDP" is not an option: an unencrypted, unauthenticated game
plane lets any player read and forge others' traffic (the Halo port's H03).
So the comparison is **encrypted UDP (fpp-session) vs QUIC**:

| | fpp-session | QUIC 1-RTT + DATAGRAM |
|--|-------------|-----------------------|
| Bytes around a payload | 30 | ≈ 28–30 (header with 8-byte connection ID, packet number, frame type, tag) |
| Per-packet crypto | ChaCha20-Poly1305 | AEAD + header protection |
| Other per-packet work | replay window | ACK frames and processing, congestion and loss state, stream machinery |
| Measured seal + open, 100 B payload | **4.1 µs** (x86-64, release) | not measured here |
| Reliability | chosen per message: unreliable by default, reliable ordered channel | streams (ordered, head-of-line per stream) or DATAGRAM (unreliable) |
| Engine integration | sans-I/O, the game's own socket, C ABI | a full stack inside the game loop |
| Post-quantum key exchange | no (no standard PQ Noise yet) | yes (`X25519MLKEM768`) |
| Browsers | no | yes (WebTransport) |

Byte overhead is a wash; the wins are less work per packet, selective
reliability, and integration with the game's existing socket. What QUIC
keeps is browser reach and post-quantum confidentiality, which matter where
personal data flows (control plane), not for per-tick inputs that are worth
nothing a few seconds later.

Claims we checked and rejected while deciding: that QUIC carries a mandatory
60 bytes per packet (it is about 28–30), that its safe datagram MTU is 1140
bytes (QUIC's floor is 1200 and it discovers more), and a 4× latency gap
measured against an *unencrypted* library (not a like-for-like comparison).

## Consequences

- `fpp-session` is the native data plane. It gained a reliable ordered channel
  (`reliable.rs`: cumulative + 64-bit selective acks, RTO from measured RTT,
  64-message window with backpressure) and stateless join cookies for public
  servers (04 §7.7).
- **Still needed for dedicated servers:** the server's static key and SAR
  binding from the Session Admission Token instead of an invite (with
  `fpp-tokens`), and send pacing. Until then dedicated servers use the invite
  form, which is fine for staging.
- 04 §7.3's `InputFrame` layout (redundant newest-first frames) is carried as
  the payload of unreliable `fpp-session` datagrams; `InputCommit`s and
  `CheckpointHead`s use the reliable channel.
- The browser path keeps QUIC and must implement the same messages; conformance
  tests cover both transports.
- Revisit PQ when a standardized hybrid Noise pattern exists.
