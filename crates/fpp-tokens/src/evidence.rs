//! Client platform evidence as carried to the Verifier (04 §5.1, roadmap P3):
//! the challenge a device binds its evidence to, and the envelope in
//! `ClientAdmissionRequest.evidence`. Appraisal is Verifier-side
//! (`attest-core`, `attest-android`, `attest-apple`); this module is what a
//! client SDK needs, without X.509 or vendor code.

use fpp_wire::cbor::{self, Value};
use sha2::{Digest, Sha256};

/// Domain separation for [`attest_challenge`].
pub const ATTEST_CHALLENGE_CTX: &str = "fpp/1/attest-challenge";

/// Largest evidence envelope accepted (a certificate chain of a few KiB, or an
/// App Attest object with its receipt).
pub const MAX_EVIDENCE: usize = 16 * 1024;
/// Most certificates in a chain.
pub const MAX_CHAIN: usize = 8;

/// `SHA-256(ctx || 0x00 || verifier_challenge || session_pub)` (`session_pub`
/// as `SessionKey::to_bytes`: 32 bytes for Ed25519, 65 for P-256): what the device's
/// platform evidence must carry (the Android attestation challenge, the App
/// Attest client data hash). Evidence made for another challenge or another
/// session key does not verify.
pub fn attest_challenge(verifier_challenge: &[u8; 32], session_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ATTEST_CHALLENGE_CTX.as_bytes());
    h.update([0]);
    h.update(verifier_challenge);
    h.update(session_pub);
    h.finalize().into()
}

/// The challenge for a key that will *be* the session key (an Android
/// Keystore key, attested when it is made): its public key does not exist
/// yet, so the challenge binds the Verifier's challenge only, and the
/// Verifier requires the attested key to equal the session key.
/// `attest_challenge(verifier_challenge, &[])`.
pub fn attest_challenge_hw_key(verifier_challenge: &[u8; 32]) -> [u8; 32] {
    attest_challenge(verifier_challenge, &[])
}

/// A malformed evidence envelope (which field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceError(pub &'static str);

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// The envelope in `ClientAdmissionRequest.evidence`: a CBOR map with `fmt`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Android Keystore key attestation: the certificate chain of a key made
    /// with the attestation challenge, leaf first (`x5c`).
    AndroidKey { chain: Vec<Vec<u8>> },
    /// Apple App Attest: the attestation object from `attestKey` (`att`),
    /// sent once per app key.
    AppleAppAttest { attestation: Vec<u8> },
    /// Apple App Attest: an assertion from `generateAssertion` by a key the
    /// Verifier has already appraised (`key_id`, `assertion`).
    AppleAppAssert { key_id: Vec<u8>, assertion: Vec<u8> },
}

impl Evidence {
    pub const FMT_ANDROID_KEY: &'static str = "android-key";
    pub const FMT_APPLE_ATTEST: &'static str = "apple-appattest";
    pub const FMT_APPLE_ASSERT: &'static str = "apple-appassert";

    pub fn encode(&self) -> Vec<u8> {
        let v = match self {
            Evidence::AndroidKey { chain } => cbor::text_map([
                ("fmt", Value::text(Self::FMT_ANDROID_KEY)),
                (
                    "x5c",
                    Value::Array(chain.iter().map(|c| Value::bytes(c.clone())).collect()),
                ),
            ]),
            Evidence::AppleAppAttest { attestation } => cbor::text_map([
                ("att", Value::bytes(attestation.clone())),
                ("fmt", Value::text(Self::FMT_APPLE_ATTEST)),
            ]),
            Evidence::AppleAppAssert { key_id, assertion } => cbor::text_map([
                ("fmt", Value::text(Self::FMT_APPLE_ASSERT)),
                ("key_id", Value::bytes(key_id.clone())),
                ("assertion", Value::bytes(assertion.clone())),
            ]),
        };
        cbor::encode(&v).expect("evidence envelope encodes")
    }

    /// `Ok(None)` for empty evidence (no platform evidence: tier D0).
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, EvidenceError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() > MAX_EVIDENCE {
            return Err(EvidenceError("too large"));
        }
        let v = cbor::decode(bytes).map_err(|_| EvidenceError("not deterministic CBOR"))?;
        let m = cbor::MapView::new(&v, "evidence").map_err(|_| EvidenceError("not a map"))?;
        let fmt = m
            .field("fmt")
            .ok()
            .and_then(Value::as_text)
            .ok_or(EvidenceError("fmt"))?;
        let bytes_of = |name| {
            m.bytes(name)
                .map(<[u8]>::to_vec)
                .map_err(|_| EvidenceError(name))
        };
        match fmt {
            Self::FMT_ANDROID_KEY => {
                let items = m
                    .field("x5c")
                    .ok()
                    .and_then(Value::as_array)
                    .ok_or(EvidenceError("x5c"))?;
                if items.is_empty() || items.len() > MAX_CHAIN {
                    return Err(EvidenceError("x5c length"));
                }
                let chain = items
                    .iter()
                    .map(|c| c.as_bytes().map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(EvidenceError("x5c entry"))?;
                Ok(Some(Evidence::AndroidKey { chain }))
            }
            Self::FMT_APPLE_ATTEST => Ok(Some(Evidence::AppleAppAttest {
                attestation: bytes_of("att")?,
            })),
            Self::FMT_APPLE_ASSERT => Ok(Some(Evidence::AppleAppAssert {
                key_id: bytes_of("key_id")?,
                assertion: bytes_of("assertion")?,
            })),
            _ => Err(EvidenceError("unknown fmt")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_binds_both_inputs() {
        let a = attest_challenge(&[1; 32], &[2; 32]);
        assert_ne!(a, attest_challenge(&[1; 32], &[3; 32]));
        assert_ne!(a, attest_challenge(&[4; 32], &[2; 32]));
    }
}
