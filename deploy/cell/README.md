# A cell in containers

One regional cell of the trust plane (docs/anticheat/03 §3): the
**Transparency Log** and a **witness**, the **Revocation Feed**, the **Evidence Store**,
**Server Liveness**, the **Verifier** and the **Broker**, each in its own
container with its own keys and its own cell identity (mutual TLS between
services); the public ones with their own TLS certificates. Enforcement
and auditors are tool containers.

```bash
docker compose -f deploy/cell/docker-compose.yml up --build
```

Needs Docker Engine 26 or later (volume subpaths). CI runs this
(`cell-containers` job).

| Container | Port (UDP, QUIC) | Mounts (from the `state` volume) |
|-----------|------------------|----------------------------------|
| `log` | 7201 (cell); 4447: players (checks of Checkpoints) | `cell/log/` (keys and tiles), `cell/public/`, the cell CA |
| `witness` | | `cell/witness/`, `cell/public/`, the cell CA |
| `revocation` | 4460 (cell) | `cell/revocation/`, `cell/public/`, the cell CA |
| `evidence` | 4470 (cell) | `cell/evidence/` (identity and objects), the cell CA |
| `liveness` | 4444: game servers; 4454: cell API for the Broker | `cell/liveness/`, `cell/public/`, the cell CA |
| `verifier` | 4445: clients | `cell/verifier/`, `cell/public/`, the cell CA |
| `broker`   | 4446: clients | `cell/broker/`, `cell/public/`, the cell CA |
| `enforcement-init` (once), `enforce` (tool) | | `cell/enforcement/`, `cell/public/`, the cell CA |
| `audit` (tool) | | `cell/audit/` (read only), the cell CA |
| `init` (once) | | everything: makes the dev PKI and the cell, then moves each service's public TLS identity into that service's directory |
| `bundle` (once) | | `cell/public/` (read only), `keys/`: writes `keys/fpp_key_bundle.json` |

A service's directory holds its signing seed (`ed25519.seed`, made on first
start), its cell identity and its public TLS identity. No other container
mounts it: a compromised Broker cannot sign SARs or ARs. Each service
publishes its public key in `cell/public/<service>`; that directory is
shared (for development; in production relying parties get a key bundle
signed by the Publisher Root chain, and a service's key comes from its
HSM).

## Playing against it

Copy the CA and the key bundle out, then run a game server and a client
from the repository (`--game-addr` is the address the Broker hands clients:
use the machine's LAN address to play from elsewhere):

```bash
docker compose -f deploy/cell/docker-compose.yml cp bundle:/var/lib/fpp/keys ./keys
cargo run -p gs-sim -- --liveness 127.0.0.1:4444
cargo run -p client-core --bin client-sim -- --verifier 127.0.0.1:4445 --broker 127.0.0.1:4446 \
  --log 127.0.0.1:4447 --liveness 127.0.0.1:4444 --smoke-test --check-log 30
```

Stop Server Liveness (`docker compose -f deploy/cell/docker-compose.yml
stop liveness`) and the game server loses its SARs and its players, while
the Verifier keeps issuing ARs and the Broker refuses new players
(`ServerDraining`) instead of failing.

Act as Enforcement, and read evidence as an auditor:

```bash
docker compose -f deploy/cell/docker-compose.yml run --rm enforce kick session:<hex> --note "why"
docker compose -f deploy/cell/docker-compose.yml run --rm audit list <match hex>
```

`docker compose -f deploy/cell/docker-compose.yml down -v` removes the cell
and its keys.
