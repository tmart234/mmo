# Platform adapters (reference)

Device-side code that produces the platform evidence the Verifier appraises
(roadmap P3; ADR-001: adapters are Kotlin and Swift, everything else goes
through the C SDK in `crates/fpp-ffi`).

| File | Platform | Evidence | Verifier crate | Best tier today |
|------|----------|----------|----------------|-----------------|
| `android/FppKeyAttestation.kt` | Android 9+ | Keystore key attestation (TEE or StrongBox), chain to Google's roots | `attest-android` | D2 when the attested key is the session key (`attestSessionKey` with `fpp_attest_challenge_hw_key`): Ed25519 in the TEE (Android 13+, `fpp_signer_external`) or P-256 in the TEE or StrongBox (`fpp_signer_external_p256`), signing through `FppKeyAttestation.sign`; D1 with a P-256 key endorsing a software session key (`attestEndorsement`) |
| `apple/FppAppAttest.swift` | iOS 14+ | App Attest attestation once, then assertions | `attest-apple` | D1 (App Attest endorses a separate session key and cannot prove where it lives) |

Evidence is bound to `fpp_attest_challenge(verifier_challenge, session_pub)`,
or, for a Keystore key that is itself the session key (its public key does
not exist before it is made), to `fpp_attest_challenge_hw_key(verifier_challenge)`
with the attested key required to equal the session key. Either way it
cannot be replayed into another admission or used for another session key. Wrap the result with `fpp_evidence_android_key`,
`fpp_evidence_apple_attest` or `fpp_evidence_apple_assert`, and send it as
`EvidenceRequest.evidence` to the Verifier.

The Verifier needs the app's identity to accept the evidence:

```bash
svc-verifier --android-app com.halo.decomp:<sha256 of the signing certificate> \
             --android-status attestation_status.json \
             --apple-app-id TEAMID.com.halo.decomp
# refresh the revocation list daily:
curl -sSo attestation_status.json https://android.googleapis.com/attestation/status
```

These files are not compiled in this repository's CI (no Android SDK or
Xcode here). They are short on purpose, so they are easy to review before
you copy them into an app.
