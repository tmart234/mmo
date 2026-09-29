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
  || vs_challenge || session_pub)`. Android puts it in
  `setAttestationChallenge`, and App Attest uses it as `clientDataHash`. So
  evidence is bound to one single-use VS challenge *and* to the session key the
  AR is issued for (`cnf`).
- **`attest-core`**: X.509 chains to pinned roots (aws-lc-rs signatures,
  names, validity, revocation), a strict DER reader, `Claims`, and the tier
  rule.
- **`attest-android`**: Google's two published roots are vendored (2022 RSA
  and "Key Attestation CA1"), and the status list is loaded with
  `vs --android-status`. Checks 1–7 in the crate docs. An **Ed25519** attested
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
| Android, locked, verified boot, P-256 key (TEE or StrongBox) | key attestation | **D1** | as above, `key_in_hw: false`; `strongbox` if so |
| Android, unlocked bootloader or custom OS | key attestation | **D0** | `secure_boot: false` |
| iPhone / iPad | App Attest | **D1** | `app_attested`; `secure_boot` absent |
| anything else, or failed evidence | none | **D0** | warning names why |

## 5. Next steps (P3, in order)

1. **External signers in the SDK.** An `FppSigner` backed by a callback, so
   the Android Ed25519 Keystore key signs AdmitPops and InputCommits. That
   makes D2 reachable on real Android devices.
2. **P-256 session keys (suite S1, ES256)** in `fpp-crypto`, the tokens and
   `fpp-session`. Secure Enclave and StrongBox keys are P-256 only. An App
   Attest assertion then endorses a Secure Enclave session key, and iOS and
   StrongBox reach D2.
3. **Play Integrity** (Android): a server-side decrypted verdict for
   `MEETS_STRONG_INTEGRITY` and device recall, for bans that survive
   reinstalls.
4. **`attest-tpm`** (game servers and Windows clients): `TPMS_ATTEST`
   parsing, EK certificate chains, credential activation, and TCG event log
   replay with a Secure Boot and `dbx` policy. This replaces the prototype
   path (F05, F21).
5. **Persistent App Attest keys** in the VS (today in memory: a restarted VS
   asks each app to attest a new key).

For the home-lab **Pi 5 GS**, nothing on the board can prove its boot
remotely. It stays S-Community: it is admitted with an enrolled key, and it
is held accountable by Checkpoints and replay. A GS that must prove its boot
state needs a UEFI machine with a TPM (step 4) or a confidential VM (P5).
