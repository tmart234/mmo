# TPM Guide: Admitting a Game Server by Its Hardware and Its Build

A game server (GS) is admitted by Server Liveness (`svc-liveness`) with evidence
from its TPM 2.0. The GS never vouches for itself: the TPM manufacturer
vouches for the TPM, the TPM vouches for what was measured, and the kernel
measured the GS binary before it ran. Server Liveness checks all of it
(`crates/attest-tpm`, `crates/svc-liveness/src/tpm2.rs`); the design is in
[docs/anticheat/10-attestation-and-secure-boot.md](docs/anticheat/10-attestation-and-secure-boot.md)
§5, the findings it closes (F05, F06, F21) in
[docs/anticheat/07-gap-analysis-and-roadmap.md](docs/anticheat/07-gap-analysis-and-roadmap.md).

## What Server Liveness checks at admission

```text
GS (gs-sim --tpm2, tpm2-tools)                         Server Liveness
  ChallengeRequest ─────────────────────────────────►
                   ◄──────────────────────────────── AttestChallenge (fresh nonce)
  JoinRequest + Tpm2Evidence ───────────────────────► 1. EK certificate → manufacturer root (--tpm-ek-roots)
    EK public + certificate chain                        2. quote: AK is a restricted TPM signing key; signature;
    AK public                                               nonce = H(challenge, this JoinRequest); PCR digest
    quote (TPMS_ATTEST + signature)                      3. boot log replays to the quoted PCRs; Secure Boot
    PCR values                                              (--require-secure-boot)
    boot log, IMA log                                    4. IMA log replays to PCR 10; the binary the kernel
                                                            measured at --gs-program is in --build-registry,
                                                            and the GS's own sw_hash names the same build
                   ◄──────────────────────────────── CredentialChallenge (secret sealed to the EK, for the AK's Name)
  TPM2_ActivateCredential
  CredentialResponse (secret) ──────────────────────► 5. only the TPM holding that EK and that AK opens it
                   ◄──────────────────────────────── JoinAccept, then SARs
```

Step 5 is what makes step 2 mean anything: without it, anyone could make a
key with the right attributes in software and "quote" whatever they like.

## Running it

**The GS machine** needs a TPM 2.0, tpm2-tools 5, and an IMA policy that
measures executables with SHA-256 (kernel command line
`ima_policy=tcb ima_hash=sha256`, or a custom policy with
`measure func=BPRM_CHECK`). Install the GS binary from a CI release (below)
at `/opt/fpp/gs-sim`, then:

```bash
gs-sim --tpm2 --liveness 203.0.113.10:4444
#   --tpm2-pcrs 0,1,2,3,4,5,6,7,10   (default)
#   --tpm2-ek-intermediates ca.pem   (if the TPM's NV does not hold them)
#   TPM2TOOLS_TCTI=device:/dev/tpmrm0 (the default)
```

**Server Liveness**:

```bash
svc-liveness --tpm-ek-roots tpm-manufacturers.pem \
   --build-registry build-registry.txt \
   --gs-program /opt/fpp/gs-sim \
   --require-secure-boot
```

- `--tpm-ek-roots`: the root certificates of the TPM manufacturers you
  accept (Infineon, STMicroelectronics, Nuvoton, Intel PTT, AMD fTPM
  publish theirs), as one PEM bundle. Fetch them from the manufacturers,
  not from a machine you are appraising.
- `--build-registry`: `sha256sum` lines of the GS builds you accept. Each
  CI release (`.github/workflows/gs-release.yml`) publishes the binary, its
  signed SLSA build provenance, and its line (`build-registry.txt`). Check
  the provenance before adding a line:
  `gh attestation verify gs-sim-x86_64-linux --repo tmart234/mmo`.
- With a Build Registry, a GS without TPM 2.0 evidence is refused: its own
  `sw_hash` proves nothing.

## Development without a TPM

- `swtpm` gives a real TPM 2.0 (libtpms) in software. `gs_sim::tpm2::swtpm`
  starts one with an EK certificate from a CA of its own, as the tests do
  (`crates/attest-tpm/tests/swtpm.rs`, the admission test in
  `crates/svc-liveness/src/tpm2.rs`). CI installs swtpm and tpm2-tools and requires
  those tests (`FPP_REQUIRE_SWTPM=1`).

## Limits

- TBD: re-attestation during a session. A GS is appraised at join;
  periodic re-quotes with the growing IMA log are next.
- Secure Boot's `dbx` (revoked boot components) is not appraised yet.
- IMA measures a binary when it starts, not what a running process does
  to itself; runtime integrity for servers is the confidential-VM step
  (P5), and every GS is still held to account by its Checkpoints
  (`fpp-audit`).
- A Raspberry Pi 5 has no measured boot; with a TPM HAT it can still give
  a quote and an IMA log (no Secure Boot claim).
