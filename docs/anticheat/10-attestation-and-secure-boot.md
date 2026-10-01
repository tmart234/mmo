# 10 — Platform Attestation and Secure Boot

Status: Draft v1 (2026-09-29). Roadmap P3, first slice: mobile clients.
Builds on [02](02-requirements.md) ATT-01..06, [03](03-architecture.md) §4
(Device Trust Tiers) and [04](04-protocol.md) §4–§6.

## 1. Secure boot is in the design; it was not in the code

The design already requires boot state. Threat T09 (bootkits, Secure Boot
bypass) is in [01](01-threat-model.md). ATT-04 requires replaying the TCG
measured-boot log, ATT-05 requires Secure Boot `dbx` currency, and tier D2
requires "measured boot + Secure Boot" on PCs ([03](03-architecture.md)
§4.2). What was missing is the implementation. Until this slice, the VS
appraised no client evidence (every client was D0), and its TPM path for
game servers checks quotes from enrolled keys but not what booted (F05).

A precise statement of the principle: **measured boot** makes attestation
meaningful, and **secure boot** is one of the things it reports. A quote
proves "this TPM holds these PCR values". The PCRs mean something only if
every boot stage measured the next one before running it. Secure Boot
enforces signatures at boot, and PCR 7 records whether it was on and which
keys it trusted. The Verifier needs both the measurements (what ran) and a
policy (what is acceptable).

## 2. What each platform can prove

| Platform | Evidence | Boot claim it carries | Key location claim | Stable device identity |
|----------|----------|-----------------------|--------------------|------------------------|
| **Android** | Keystore key attestation (KeyMint), chain to Google's roots | `RootOfTrust`: `verifiedBootState` (Verified / SelfSigned / Unverified / Failed), `deviceLocked`, `verifiedBootKey`, `verifiedBootHash` (hardware-enforced) | `attestationSecurityLevel`, `keyMintSecurityLevel`: Software, TEE, StrongBox | None, by design (privacy); Play Integrity device recall is the ban lever |
| **iOS** | App Attest attestation, chain to Apple's App Attestation root; then assertions | **None.** The Secure Enclave has its own secure boot, but App Attest exposes no boot measurements, no OS version and no jailbreak verdict | Secure Enclave (implied by a valid attestation) | The App Attest key id, stable per app install |
| **Windows PC** | TPM 2.0 quote + TCG event log; `GetRuntimeAttestationReport` (25H2+) | PCRs 0–7 (firmware, boot manager, Secure Boot policy in PCR 7), replayed from the event log | TPM (EK certificate chain to the manufacturer) | EK public key |
| **Linux PC** | TPM quote where available | Same PCRs, but distributions vary, and Secure Boot is often off | TPM | EK |
| **Raspberry Pi 5** (our GS) | TPM quote only with a TPM HAT | **None usable.** The Pi's boot ROM and bootloader do not measure into a TPM, so PCRs 0–7 stay empty. Raspberry Pi "secure boot" (a signed `boot.img` with a key in OTP) enforces, but reports nothing remotely | TPM HAT (for example Infineon SLB 9672) | EK |

### 2.1 Corrections to the analysis that prompted this slice

| Claim | Assessment |
|-------|------------|
| "App Attest includes hashes of the software components calculated during boot" | ✗ **Wrong.** An App Attest attestation contains the Apple certificate chain, the nonce, the RP ID hash (team + bundle id), a counter, the AAGUID and the key id, plus a receipt. There are no boot measurements. Apple uses the Secure Enclave's boot state internally, but does not export it. An iOS AR therefore reports `secure_boot` as *unknown*, not *true*. |
| "An iOS client's AR can prove it booted a genuine, unmodified Apple OS" | ✗ It proves a genuine Apple device and our genuine app. Jailbroken devices can still produce valid attestations. Server-side detection stays necessary. |
| Android: `verifiedBootState`, `verifiedBootHash`, `attestationSecurityLevel`; require TEE, prefer StrongBox | ✓ Correct, and implemented. Also needed, and implemented: `deviceLocked`, key `origin == GENERATED`, the root of trust from the **hardware-enforced** list only, `attestationApplicationId` (package + signing-certificate digest), the patch level, and Google's **revocation list**. Leaked TEE attestation keys ("keyboxes") are sold to cheaters, and the status list is how they get revoked. |
| "Check `verifiedBootHash` against known-good firmware images" | ◐ Not practical across thousands of OEM builds. Rely on `Verified` + `deviceLocked` + patch level, and on Play Integrity's `MEETS_STRONG_INTEGRITY` (a separate adapter). |
| TPM: "AIK certificate chains to a trusted TPM vendor" | ◐ The chain is on the **EK**. An AK is tied to it by credential activation (`TPM2_MakeCredential` / `ActivateCredential`). A quote signed by an uncertified AK proves nothing (finding F21). |
| TPM: "PCR[0–6] match the allowlist" | ◐ Brittle: every firmware update changes them. Replay the TCG **event log** against the quoted PCRs, then appraise events (Secure Boot variables, `dbx`, boot manager hashes). That is ATT-04. |
| "TPM quote + PCR 7 = highest trust (GS)" | ◐ Game servers are not ranked by device tier. They have a server class (S-Community, S-FirstParty, S-FirstParty-CVM; 03 §4.3). Measured boot helps a first-party GS, but the stronger guarantees for servers are confidential VMs (SEV-SNP / TDX) and Checkpoint audits. |
| Tier table: StrongBox = High, TEE = Medium | ◐ Both reach **D2**. The AR carries a `strongbox` feature claim, so a queue can require it. What decides D1 vs D2 is whether the **session key** is in hardware (04 §4.1: "software fallback ⇒ tier ≤ D1"). Otherwise one genuine phone could endorse a cheater's session key on a PC. |

## 3. What is implemented (this slice)

```text
device (Kotlin / Swift adapter)                 C SDK (fpp-ffi)                  Verifier (vs)
  keygen / attestKey with challenge  ◄── fpp_attest_challenge(vs_nonce, session_pub)
  chain / attestation object         ──► fpp_evidence_android_key / _apple_attest / _apple_assert
                                                   │ ClientAdmissionRequest.evidence (PoP-signed)
                                                   ▼
                                            attest-android / attest-apple → Claims → tier, features, DID
```

- **Binding.** `attest_challenge = SHA-256("fpp/1/attest-challenge" || 0x00
  || verifier_challenge || session_pub)`. Android puts it in
  `setAttestationChallenge`, and App Attest uses it as `clientDataHash`. So
  evidence is bound to one single-use VS challenge *and* to the session key the
  AR is issued for (`cnf`).
- **`attest-core`**: X.509 chains to pinned roots (aws-lc-rs signatures,
  names, validity, revocation), a strict DER reader, `Claims`, and the tier
  rule.
- **`attest-android`**: Google's two published roots are vendored (2022 RSA
  and "Key Attestation CA1"), and the status list is loaded with
  `svc-verifier --android-status`. Checks 1–7 in the crate docs. An **Ed25519** attested
  key (KeyMint on Android 13+, TEE) can *be* the session key, which earns D2.
- **`attest-apple`**: Apple's App Attestation root is vendored. Attestations
  are checked as Apple documents (chain, nonce extension, key id, App ID, a
  counter of 0, and a production AAGUID unless `--apple-allow-development`).
  Assertions are checked by the stored key with a strictly increasing counter.
- **VS**: `--android-app package:sha256`, `--apple-app-id TEAM.bundle`. Failed
  or missing evidence gives D0 with a warning, and the queue floor decides.
  The AR carries `secure_boot`, `key_in_hw`, `app_attested`, `strongbox` and
  `os_patch_age_days`.
- **Tests**: 16 Android and 9 Apple attack tests (replay, wrong session key,
  software keystore, unlocked bootloader, root of trust only in the software
  list, imported key, wrong app or signer, stale patch, untrusted root,
  revoked batch key, tampered leaf; wrong App ID, development key, credential
  id mismatch, a non-zero counter, assertion replay, a foreign key). The C
  conformance program checks the challenge against an independent SHA-256 on
  x86-64, i686 and aarch64.
- **Adapters**: `sdk/android/FppKeyAttestation.kt`, `sdk/apple/FppAppAttest.swift`
  (reference code, not built in CI).

Not verified here: evidence from a real device. The synthetic chains follow
Google's and Apple's documented formats. The first real Pixel and iPhone
runs are the next check, and DER strictness may need to relax for OEM
quirks.

## 4. Tiers after this slice

| Device | Evidence | Tier | Claims |
|--------|----------|------|--------|
| Android 13+, locked, verified boot, Ed25519 session key in the TEE | key attestation | **D2** | `secure_boot`, `key_in_hw`, `app_attested` |
| Android, locked, verified boot, P-256 (ES256) session key in the TEE or StrongBox | key attestation | **D2** | as above; `strongbox` if so |
| Android, locked, verified boot, a P-256 key endorsing a software session key | key attestation | **D1** | as above, `key_in_hw: false` |
| Android, unlocked bootloader or custom OS | key attestation | **D0** | `secure_boot: false` |
| iPhone / iPad | App Attest | **D1** | `app_attested`; `secure_boot` absent |
| anything else, or failed evidence | none | **D0** | warning names why |

## 5. Next steps (P3, in order)

1. ✅ **External signers in the SDK.** `fpp_signer_external(public_key,
   callback, ctx)`: an `FppSigner` whose key stays in the Android Keystore
   (the Kotlin adapter's `sign`). The SDK verifies each signature the
   callback returns, and returns `FPP_STATUS_SIGNER_FAILED` with no object
   when the hardware fails or signs with another key. Tests: an external
   key produces the same bytes as a local key with the same seed (Ed25519 is
   deterministic), and it signs InputCommits, Checkpoints and the P2P
   AdmitPop. D2 is reachable on Android 13+ devices (with the binding fixed
   in step 2).
2. ✅ **P-256 session keys (suite S1, ES256)**: a `SessionKey` is Ed25519 or
   P-256 everywhere a session key goes: `cnf` of ARs and SATs (an EC2
   `COSE_Key`), the AdmitPop and InputCommits (`fpp-session`, the GS), the
   Verifier's and Broker's proofs of possession, revocations
   (`session_key_id`). ES256 signatures are `r ‖ s` with low `s`; ES256 is
   accepted only from session keys. The C SDK adds
   `fpp_signer_external_p256` (the hardware may return either `s`; the SDK
   emits the low one and checks it), `fpp_signer_session_key` and `_key`
   variants of the challenge, InputCommit and AR checks, without changing
   the 32-byte calls the Halo port uses. Golden vectors carry an ES256
   InputCommit, an AR with a P-256 `cnf`, a high-`s` twin and an ES256 key
   under an EdDSA header; the Python verifier checks them with its own P-256
   (checked against RFC 6979 A.2.5). The smoke client plays with a P-256 key.
   StrongBox now reaches D2.
   **Fixed with it:** a Keystore key that *is* the session key is attested
   when it is made, so its own public key cannot be in its challenge, and
   the D2 path above could not work on a real device. Such a key now binds
   `attest_challenge_hw_key(verifier_challenge)` (no session key), and the
   Verifier requires the attested key to equal the session key; a key that
   endorses a separate session key still binds that key.
   iOS stays D1: an App Attest key signs only assertions, so the session
   key is a separate key, and App Attest cannot prove it is in the Secure
   Enclave.
3. **Play Integrity** (Android): a server-side decrypted verdict for
   `MEETS_STRONG_INTEGRITY` and device recall, for bans that survive
   reinstalls.
4. ◐ **`attest-tpm`** (game servers and Windows clients). Done, in
   `crates/attest-tpm`:
   - `TPMS_ATTEST` quotes, verified with the AK's `TPMT_PUBLIC` (RSA-SSA,
     RSA-PSS, ECDSA P-256/P-384): the AK must be a restricted signing key
     made in the TPM; the nonce; the PCR values against the signed digest;
   - EK certificates to a pinned manufacturer root (attest-core's chains),
     and that the certificate's key is the EK's;
   - credential activation: `TPM2_MakeCredential` in software (RSA-OAEP
     with the "IDENTITY" label, or ECDH with KDFe), which only the TPM
     holding the EK opens, and only for the AK with that Name;
   - the measured-boot log replayed against the quote, and Secure Boot's
     state from PCR 7 (the event's data checked against its digest);
   - the IMA log replayed against PCR 10, and a **Build Registry**: the
     program a server runs, as the kernel measured it before running it,
     must be a registered build (F06);
   - tests against a real TPM 2.0 (swtpm, libtpms) with tpm2-tools in CI:
     the TPM activates the credentials the crate makes, RSA and ECDSA quotes
     verify, and forged quotes, nonces, PCR values, boot logs (Secure Boot
     off, claimed on) and IMA logs (a modified server, or a log naming the
     registered build when another ran) fail. A fuzz target covers every
     parser.

   ✅ Wired in: Server Liveness admits a GS with a real TPM (`svc-liveness --tpm-ek-roots
   --build-registry --gs-program --require-secure-boot`); the GS gathers the
   evidence with tpm2-tools (`gs-sim --tpm2`), and credential activation
   runs at every join, before `JoinAccept`. CI builds the GS with signed
   SLSA provenance and publishes each build's registry line
   (`.github/workflows/gs-release.yml`). An end-to-end test joins a GS on
   swtpm over QUIC and refuses: a GS claiming another build, a GS with no
   TPM evidence, a guessed credential, an unregistered build, a TPM from an
   untrusted manufacturer, and a modified GS that really ran. Operator
   steps: `TPM_GUIDE.md`. Open: TPM 2.0 re-attestation during a session,
   and `dbx` currency.
5. **Persistent App Attest keys** in the Verifier (today in memory: a
   restarted Verifier asks each app to attest a new key).

For the home-lab **Pi 5 GS**, nothing on the board can prove its boot
remotely. It stays S-Community: it is admitted with an enrolled key, and it
is held accountable by Checkpoints and replay. A GS that must prove its boot
state needs a UEFI machine with a TPM (step 4) or a confidential VM (P5).
