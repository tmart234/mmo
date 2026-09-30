# svc-evidence

The Evidence Store, one service of a cell (docs/anticheat/03 §3).

- **Content addressed:** an object is stored under the SHA-256 of its
  bytes, and re-checked against that name on every read, by the store and
  by `Client` (a corrupted disk is reported, not served). A reader asks for
  a digest it learned elsewhere (a Checkpoint chain, a player's bundle, the
  Transparency Log), so the store cannot substitute evidence.
- **Indexed by match:** the digests stored for a match, in order.
- **Access:** only writers store (default: Server Liveness), only readers
  read (default: `audit`, `enforcement`), by cell certificate.

Server Liveness sends every Checkpoint it verified (`svc-liveness
--evidence`), queued and retried, so a store that is down delays evidence
without holding up SARs. `fpp-evidence` reads it:

```bash
svc-evidence --cell cell --bind 127.0.0.1:4470
fpp-evidence --cell cell list <match hex>
fpp-evidence --cell cell get <digest hex> checkpoint.cose
```

Tests: `tests/store.rs` (access, content addressing, the index, a
corrupted object, a restart); the smoke test reads a match's Checkpoints
back as `audit` and checks they form one chain.

Open: replication across a region, retention, and encryption at rest
(03 §3 lists the store as "durable, regional, encrypted").
