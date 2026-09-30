# svc-verifier

The Verifier, one service of a cell (docs/anticheat/04 §5.1). A client
proves a fresh session key against the Verifier's challenge and sends its
device's platform evidence; the Verifier appraises it (`appraisal.rs`:
Android key attestation, Apple App Attest) and signs an Attestation Result
bound to that key, with its own key (`cell/verifier/ed25519.seed`). Evidence
that fails appraisal still gets an AR, at tier D0.

The Verifier cannot admit anyone to a match or bless a server: those are
the Broker's and Server Liveness's keys, in their own processes.

```bash
svc-verifier --cell cell --bind 0.0.0.0:4445 \
  --android-app com.example.game:<sha256 of the signing cert> --apple-app-id TEAMID.com.example.game
```
