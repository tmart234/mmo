// Reference iOS adapter for FPP client evidence (roadmap P3; ADR-001:
// platform adapters are Swift). Not built in this repo's CI: copy it into the
// game's iOS target and enable the App Attest capability
// (com.apple.developer.devicecheck.appattest-environment = production).
//
// Flow:
//   first admission on this install:
//     challenge = fpp_attest_challenge(vs_challenge, session_pub)   (C SDK)
//     (keyId, attestation) = try await FppAppAttest.attest(challenge)
//     evidence = fpp_evidence_apple_attest(attestation)
//   later admissions:
//     evidence = fpp_evidence_apple_assert(keyId, try await FppAppAttest.assert(keyId, challenge))
//   The Verifier (crates/attest-apple) keeps the key after the attestation;
//   if it answers "unknown App Attest key", attest a new key.
//
// App Attest proves a genuine Apple device's Secure Enclave holds the key
// and that it belongs to this app. It says nothing about the OS (no boot
// measurements, no jailbreak verdict). The session key stays in software, so
// the Verifier grants tier D1 until P-256 session keys land (04 §4.1).
import DeviceCheck
import Foundation

enum FppAppAttestError: Error {
    case unsupported
    case badChallenge
}

enum FppAppAttest {
    /// Make an App Attest key and have Apple attest it with `challenge`
    /// (32 bytes from fpp_attest_challenge, used as the client data hash).
    /// Keep the returned key id (base64-decoded, 32 bytes) for assertions.
    static func attest(challenge: Data) async throws -> (keyId: Data, attestation: Data) {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw FppAppAttestError.unsupported }
        guard challenge.count == 32 else { throw FppAppAttestError.badChallenge }
        let keyId = try await service.generateKey()
        let attestation = try await service.attestKey(keyId, clientDataHash: challenge)
        guard let raw = Data(base64Encoded: keyId) else { throw FppAppAttestError.unsupported }
        return (raw, attestation)
    }

    /// An assertion by the attested key over `challenge` (a fresh
    /// fpp_attest_challenge for this admission).
    static func assert(keyId: Data, challenge: Data) async throws -> Data {
        guard challenge.count == 32 else { throw FppAppAttestError.badChallenge }
        return try await DCAppAttestService.shared.generateAssertion(
            keyId.base64EncodedString(), clientDataHash: challenge)
    }
}
