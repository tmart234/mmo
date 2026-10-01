//! Play Integrity verdicts (ATT-03; 03 §4.2: Android D2 is "Play Integrity
//! `MEETS_STRONG_INTEGRITY` + key attestation"), decrypted and verified by
//! the Verifier itself with the app's keys from the Play Console ("manage
//! response encryption"), not through Google's decode endpoint.
//!
//! The app requests a token with `nonce = base64url(attest_challenge(...))`
//! (the same value its key attestation binds), so a verdict is good for one
//! admission and one session key. The token is a JWE (`A256KW`,
//! `A256GCM`) around a JWS (`ES256`) whose payload is the verdict.
//!
//! What it adds to key attestation: Google's judgement of the device
//! (`MEETS_STRONG_INTEGRITY`: a recent, locked, hardware-backed Android
//! that Google recognises) and of the app (`PLAY_RECOGNIZED`: installed
//! from Play, unmodified), at the time of the request.

use attest_core::AttestError;
use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_lc_rs::key_wrap::{AesKek, KeyWrap, AES_256};
use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde_json::Value;

use crate::AllowedApp;

/// The app's response keys from the Play Console.
#[derive(Clone, Debug)]
pub struct IntegrityKeys {
    /// The AES-256 decryption key.
    pub decryption: [u8; 32],
    /// The ECDSA P-256 verification key, as an uncompressed SEC1 point
    /// (the Console gives an X.509 SubjectPublicKeyInfo: see
    /// [`IntegrityKeys::from_console`]).
    pub verification: Vec<u8>,
}

impl IntegrityKeys {
    /// From the two base64 strings the Play Console shows.
    pub fn from_console(decryption_b64: &str, verification_b64: &str) -> Result<Self, AttestError> {
        let decryption: [u8; 32] = b64(decryption_b64.trim())
            .and_then(|k| k.try_into().ok())
            .ok_or(AttestError::Policy("Play Integrity decryption key"))?;
        let spki = b64(verification_b64.trim())
            .ok_or(AttestError::Policy("Play Integrity verification key"))?;
        // SubjectPublicKeyInfo for an EC P-256 key: a 26-byte header, then
        // the 65-byte uncompressed point.
        const HEADER: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let point = spki
            .strip_prefix(&HEADER[..])
            .filter(|p| p.len() == 65 && p[0] == 4)
            .ok_or(AttestError::Policy(
                "Play Integrity verification key is not EC P-256",
            ))?;
        Ok(IntegrityKeys {
            decryption,
            verification: point.to_vec(),
        })
    }
}

/// What a valid verdict says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// `MEETS_DEVICE_INTEGRITY`: a genuine, certified Android device.
    pub device: bool,
    /// `MEETS_STRONG_INTEGRITY`: and a recent, hardware-backed, locked one.
    pub strong: bool,
    pub package: String,
    pub version_code: Option<u64>,
}

/// base64 or base64url, padded or not.
pub fn b64(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    // (leftover bits must be zero padding)
    (n < 6 && bits & ((1 << n) - 1) == 0).then_some(out)
}

/// base64url without padding (what the app passes as the nonce).
pub fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let v = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(A[((v >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn bad(what: &'static str) -> AttestError {
    AttestError::Malformed(what)
}

fn json(part: &str, what: &'static str) -> Result<Value, AttestError> {
    serde_json::from_slice(&b64(part).ok_or(bad(what))?).map_err(|_| bad(what))
}

/// Decrypt the JWE: the JWS inside.
fn decrypt(token: &str, key: &[u8; 32]) -> Result<String, AttestError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    let [header, encrypted_key, iv, ciphertext, tag] = parts.as_slice() else {
        return Err(bad("Play Integrity token is not a JWE"));
    };
    let h = json(header, "JWE header")?;
    if h["alg"] != "A256KW" || h["enc"] != "A256GCM" {
        return Err(AttestError::Policy(
            "Play Integrity token: not A256KW/A256GCM",
        ));
    }
    let wrapped = b64(encrypted_key).ok_or(bad("JWE key"))?;
    let mut cek = [0u8; 32];
    let unwrapped = AesKek::new(&AES_256, key)
        .map_err(|_| bad("decryption key"))?
        .unwrap(&wrapped, &mut cek)
        .map_err(|_| AttestError::BadSignature("Play Integrity token: not for this app's key"))?;
    if unwrapped.len() != 32 {
        return Err(bad("JWE content key"));
    }
    let iv: [u8; 12] = b64(iv)
        .and_then(|v| v.try_into().ok())
        .ok_or(bad("JWE iv"))?;
    let mut data = b64(ciphertext).ok_or(bad("JWE ciphertext"))?;
    data.extend(b64(tag).ok_or(bad("JWE tag"))?);
    let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &cek).map_err(|_| bad("JWE key"))?);
    let plain = aead
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(header.as_bytes()),
            &mut data,
        )
        .map_err(|_| AttestError::BadSignature("Play Integrity token: decryption failed"))?;
    String::from_utf8(plain.to_vec()).map_err(|_| bad("JWS"))
}

/// Verify a token: decrypt, check Google's signature, then the verdict
/// against this admission (`expected_nonce`, the attest challenge), the
/// allowed apps, and freshness (`max_age_ms`).
pub fn verify(
    token: &str,
    keys: &IntegrityKeys,
    expected_nonce: &[u8; 32],
    apps: &[AllowedApp],
    now_ms: u64,
    max_age_ms: u64,
) -> Result<Verdict, AttestError> {
    let jws = decrypt(token, &keys.decryption)?;
    let parts: Vec<&str> = jws.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return Err(bad("JWS"));
    };
    if json(header, "JWS header")?["alg"] != "ES256" {
        return Err(AttestError::Policy("Play Integrity verdict: not ES256"));
    }
    let signature = b64(signature).ok_or(bad("JWS signature"))?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &keys.verification)
        .verify(format!("{header}.{payload}").as_bytes(), &signature)
        .map_err(|_| AttestError::BadSignature("Play Integrity verdict"))?;
    let v = json(payload, "verdict")?;

    let request = &v["requestDetails"];
    // (classic requests echo `nonce`; standard ones `requestHash`)
    let nonce = request["nonce"]
        .as_str()
        .or(request["requestHash"].as_str())
        .and_then(b64)
        .ok_or(bad("verdict nonce"))?;
    if nonce != expected_nonce {
        return Err(AttestError::ChallengeMismatch);
    }
    let issued: u64 = request["timestampMillis"]
        .as_str()
        .and_then(|t| t.parse().ok())
        .ok_or(bad("verdict timestamp"))?;
    if now_ms.saturating_sub(issued) > max_age_ms || issued > now_ms + 60_000 {
        return Err(AttestError::Policy("Play Integrity verdict is stale"));
    }

    let app = &v["appIntegrity"];
    if app["appRecognitionVerdict"] != "PLAY_RECOGNIZED" {
        return Err(AttestError::Policy("app not recognised by Play"));
    }
    let package = app["packageName"].as_str().ok_or(bad("packageName"))?;
    if request["requestPackageName"].as_str() != Some(package) {
        return Err(AttestError::Policy("verdict for another package"));
    }
    let digests: Vec<Vec<u8>> = app["certificateSha256Digest"]
        .as_array()
        .ok_or(bad("certificateSha256Digest"))?
        .iter()
        .filter_map(|d| d.as_str().and_then(b64))
        .collect();
    let allowed = apps.iter().any(|a| {
        a.package == package
            && digests
                .iter()
                .any(|d| a.signer_sha256.iter().any(|s| d[..] == s[..]))
    });
    if !allowed {
        return Err(AttestError::Policy(
            "verdict for an app not on the allowlist",
        ));
    }
    let labels: Vec<&str> = v["deviceIntegrity"]["deviceRecognitionVerdict"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    Ok(Verdict {
        device: labels.contains(&"MEETS_DEVICE_INTEGRITY"),
        strong: labels.contains(&"MEETS_STRONG_INTEGRITY"),
        package: package.to_string(),
        version_code: app["versionCode"].as_str().and_then(|c| c.parse().ok()),
    })
}

/// Google's side, for tests: mint verdicts with a pair of response keys.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{b64url, IntegrityKeys};
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    use aws_lc_rs::key_wrap::{AesKek, KeyWrap, AES_256};
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    use serde_json::Value;

    /// Google's side: the app's response keys.
    pub struct Google {
        pub signing: EcdsaKeyPair,
        pub encryption: [u8; 32],
    }

    impl Default for Google {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Google {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let mut encryption = [0u8; 32];
            rng.fill(&mut encryption).unwrap();
            Google {
                signing: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
                encryption,
            }
        }

        pub fn keys(&self) -> IntegrityKeys {
            IntegrityKeys {
                decryption: self.encryption,
                verification: self.signing.public_key().as_ref().to_vec(),
            }
        }

        pub fn token(&self, verdict: &Value) -> String {
            let rng = SystemRandom::new();
            let header = b64url(br#"{"alg":"ES256"}"#);
            let payload = b64url(verdict.to_string().as_bytes());
            let signed = format!("{header}.{payload}");
            let sig = self.signing.sign(&rng, signed.as_bytes()).unwrap();
            let jws = format!("{signed}.{}", b64url(sig.as_ref()));

            let jwe_header = b64url(br#"{"alg":"A256KW","enc":"A256GCM"}"#);
            let mut cek = [0u8; 32];
            rng.fill(&mut cek).unwrap();
            let mut wrapped = [0u8; 40];
            let wrapped = AesKek::new(&AES_256, &self.encryption)
                .unwrap()
                .wrap(&cek, &mut wrapped)
                .unwrap()
                .to_vec();
            let mut iv = [0u8; 12];
            rng.fill(&mut iv).unwrap();
            let mut data = jws.into_bytes();
            let tag = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &cek).unwrap())
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(iv),
                    Aad::from(jwe_header.as_bytes()),
                    &mut data,
                )
                .unwrap();
            format!(
                "{jwe_header}.{}.{}.{}.{}",
                b64url(&wrapped),
                b64url(&iv),
                b64url(&data),
                b64url(tag.as_ref())
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0xff; 33],
        ] {
            assert_eq!(b64(&b64url(data)).unwrap(), data);
        }
        assert_eq!(b64("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(b64("Zm9vYmFy").unwrap(), b"foobar");
        assert!(b64("Zm9vY?").is_none());
        assert!(b64("Zm9vYh").is_none()); // non-zero padding bits
    }
}
