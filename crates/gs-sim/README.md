# gs-sim

The reference game server. It joins the VS, keeps its SAR chain, serves one
match to clients over `fpp-session`, and signs one Checkpoint per epoch.

- **Admission:** a challenge, then a `JoinRequest`. With `--tpm2`, the
  request carries TPM 2.0 evidence: the EK certificate, a quote over the
  challenge, and the boot and IMA logs. The VS then checks the build as the
  kernel measured it, and runs credential activation (`src/tpm2.rs`,
  `TPM_GUIDE.md`).
- **Match (`src/game.rs`):** §7.2 admission of clients (SAT, AR, AdmitPop),
  InputFrames and InputCommits, host-side movement clamps, CheckpointHeads
  and SarUpdates to clients, and the match ledger (`ledger/`, JSON lines).
- **Blessing:** the match stops when the SAR chain lapses.
