//! Shared low-level cryptographic primitives and time utilities:
//! SHA-256, HMAC-SHA256, RFC 8439 ChaCha20-Poly1305 AEAD, constant-time
//! comparison, and Unix timestamps.
//!
//! Exposed through `fpp-ffi` so C/C++ games (e.g. Halo: CE signalling) use
//! the same vetted pure-Rust primitives instead of hand-rolling crypto.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Overhead added by [`aead_seal`]: 12-byte random nonce + 16-byte Poly1305 tag.
pub const AEAD_OVERHEAD: usize = 12 + 16;

/// Current Unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current Unix timestamp in seconds.
pub fn now_s() -> u64 {
    now_ms() / 1000
}

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 over the concatenation of `parts`.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Domain-separated SHA-256: `SHA-256(tag || 0x00 || data)`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    sha256_parts(&[tag.as_bytes(), &[0], data])
}

/// Streaming SHA-256 of a file on disk.
pub fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Seal `plaintext` with RFC 8439 ChaCha20-Poly1305 (empty AAD) and a fresh
/// random 12-byte nonce. Output layout: `nonce (12 B) || ciphertext || tag (16 B)`.
pub fn aead_seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    aead_seal_with_nonce(key, &nonce, plaintext)
}

/// Deterministic variant of [`aead_seal`] with an explicit 12-byte nonce
/// (for RFC 8439 vector testing).
pub fn aead_seal_with_nonce(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .expect("ChaCha20-Poly1305 encryption");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a message sealed by [`aead_seal`], verifying the Poly1305 tag in
/// constant time. Returns `None` if truncated or unauthentic.
pub fn aead_open(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < AEAD_OVERHEAD {
        return None;
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce_bytes.try_into().expect("12 bytes");
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(&Nonce::from(nonce), ct).ok()
}

/// Constant-time byte-slice equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Raw Ed25519 sign (for domain-separated admission PoP messages).
pub fn ed25519_sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg).to_bytes()
}

/// Raw Ed25519 verify.
pub fn ed25519_verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    pk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_hmac_vectors() {
        // FIPS 180-4 empty & "abc"
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 test case 2: key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn aead_round_trip_and_tamper() {
        let key = [0x42u8; 32];
        let pt = b"fairness maximalist";
        let mut sealed = aead_seal(&key, pt);
        assert_eq!(sealed.len(), pt.len() + AEAD_OVERHEAD);
        assert_eq!(aead_open(&key, &sealed).unwrap(), pt);

        // Tampering ciphertext or tag fails authentication.
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(aead_open(&key, &sealed).is_none());
        // Truncated input fails cleanly.
        assert!(aead_open(&key, &sealed[..AEAD_OVERHEAD - 1]).is_none());
    }
}
