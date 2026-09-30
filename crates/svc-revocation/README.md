# svc-revocation

The Revocation Feed, one service of a cell (docs/anticheat/04 §9), and
`fpp-enforce`, the Enforcement tool.

- **Enforcement** (`fpp-enforce`, `enforce.rs`) writes an enforcement
  record (who, what, why) to the Transparency Log, then signs a
  `RevocationEvent` naming the record's hash with the Enforcement key
  (`cell/enforcement/`, used nowhere else) and publishes it.
- **The feed** (`svc-revocation`) accepts events from Enforcement only,
  checks the signature, appends each to the Transparency Log before
  accepting it (with `--log`), keeps them on disk, and serves them by
  sequence number to the Broker and Server Liveness, holding each request
  open until there is something new. It is idempotent by event id and has
  no signing key: it can delay an event, not forge one.
- **Subscribers** (`fpp_svc::follow`): the Broker refuses accounts,
  devices, session keys and builds that are denied admission (or
  suspended, or banned). Server Liveness stops the SARs of a revoked game
  server instance, and relays every event to its game servers, which check
  the Enforcement signature and remove the players it names.

```bash
fpp-enforce --cell cell init
svc-revocation --cell cell --bind 127.0.0.1:4460 --log 127.0.0.1:7201
fpp-enforce --cell cell --log 127.0.0.1:7201 kick session:<hex> --note "why"
fpp-enforce --cell cell --log 127.0.0.1:7201 deny-admission account:<hex> --for 86400
fpp-enforce --cell cell --log 127.0.0.1:7201 kick gs:<instance hex>
```

Tests: `tests/feed.rs` (who may publish and follow, forged and repeated
events, the log entries, a restart); `client-core/tests/session_attacks.rs`
(a GS removes exactly the player an event names, and refuses it after);
`tools/src/revocation_load.rs`, in `make ci` (the P2 exit tests below).

## Measured (`revocation_load`, a dev cell on one 4-core machine)

| Test | Result |
|------|--------|
| revocation → kick, 32 players, debug build | p50 40–45 ms, p99 111–222 ms over three runs (bound: 5 s) |
| revocation → kick, 60 players, release build | p50 6 ms, p99 42 ms |
| an account denied admission | refused by the Broker (`Revoked`) |
| a rogue GS that ignores its revocation | all its players lapse in 5–6.2 s over three runs (bound: one SAR lifetime, 10 s) |
