# vs

The prototype Validation Server. For now it runs the trust-plane roles in
one process: GS admission (`admission.rs`, with TPM 2.0 evidence in
`tpm2.rs`), Server Liveness (the SAR chain, `liveness.rs`), Checkpoint
intake (`checkpoints.rs`, `watchdog.rs`), and a stub Verifier and Broker
for clients (`broker.rs`, `appraisal.rs`). Roadmap P2 splits these into
separate services (docs/anticheat/07 §4).
