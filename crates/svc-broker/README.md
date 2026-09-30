# svc-broker

The Broker, one service of a cell (docs/anticheat/04 §5.2). A client
presents its Attestation Result and a queue, signed by the session key the
AR names over the Broker's challenge. The Broker checks the AR against the
Verifier's key, applies the queue's tier floor (`open`: any; `verified`:
D2+), asks Server Liveness (cell mutual TLS) for a slot on a live game
server, and signs a Session Admission Token for it with its own key
(`cell/broker/ed25519.seed`).

It never sees device evidence and cannot bless a server. With Server
Liveness unreachable it refuses (`ServerDraining`) within two seconds and
reconnects on the next request.

```bash
svc-broker --cell cell --bind 0.0.0.0:4446 --liveness 127.0.0.1:4454
```

`tests/cell.rs` runs a cell in one process: a client admitted through all
three services, and each one's refusals (an AR signed by another service's
key, an AR used by another key, a caller other than the Broker asking
Server Liveness for a slot, a revoked server).
