# Regional FPP Authority Cell (Containers)

Runs one regional Fair-Play Protocol authority cell with two long-lived containers built from the single `fppd` binary:

- **`authority`** (`fppd serve --no-witness`): serves Server Liveness, Verifier, Broker, Revocation Feed, Evidence Store, and Transparency Log on `4444/tcp` over our owned `Noise_IK_25519_ChaChaPoly_SHA256` + deterministic CBOR protocol. Every trust role holds its own isolated signing keypair.
- **`witness`** (`fppd role witness`): independent container cosigning Transparency Log checkpoints (Ed25519 + ML-DSA-65 verified before cosigning).

## Quick Start

```bash
docker compose -f deploy/cell/docker-compose.yml up -d --build
```

## Operator Commands

```bash
# Publish a signed revocation (logged in Transparency Log first)
docker compose -f deploy/cell/docker-compose.yml run --rm enforce \
  kick session:0707070707070707070707070707070707070707070707070707070707070707 --note "example"

# List verified Checkpoints for a match in the Evidence Store
docker compose -f deploy/cell/docker-compose.yml run --rm audit list <match-hex>
```
