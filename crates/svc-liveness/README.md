# svc-liveness

Server Liveness, one service of a cell (docs/anticheat/03 §3, 04 §6.3):

- **GS admission** (`admission.rs`): challenge, `JoinRequest`, TPM 2.0
  evidence (`tpm2.rs`: EK chain, quote, measured-boot and IMA logs, Build
  Registry, credential activation; see `TPM_GUIDE.md`).
- **The SAR chain** per game server (`liveness.rs`), signed with this
  service's own key (`cell/liveness/ed25519.seed`, made on first start).
- **Checkpoints** (`checkpoints.rs`) and the **watchdog** (`watchdog.rs`):
  a bad or missing Checkpoint revokes the GS, and its SARs stop.
- **Placement** (`placement.rs`): the cell API (mutual TLS) on which the
  Broker, and only the Broker, reserves a slot on a live GS.

```bash
svc-liveness --cell cell --bind 0.0.0.0:4444 --rpc 127.0.0.1:4454 \
  --tpm-ek-roots tpm-manufacturers.pem --build-registry build-registry.txt
```

With `--feed`, it follows the Revocation Feed (`revocation.rs`): a revoked
instance gets no more SARs, and every event is relayed to the game servers
here. With `--evidence`, every verified Checkpoint goes to the Evidence
Store (`evidence.rs`).

TBD: re-attestation during a session.
