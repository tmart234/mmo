use bincode::{DefaultOptions, Options};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256 as Sha2};

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn rand_u128() -> u128 {
    rand::random::<u128>()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new();
    h.update(data);
    h.finalize().into()
}

pub fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha2::new();
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

pub fn gen_ed25519() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key(); // compute before moving sk
    (sk, vk)
}

pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg).to_bytes()
}

// ed25519-dalek v2: from_bytes returns a Signature (not a Result)
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    pk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

/// Bytes the GS long-term key signs in a JoinRequest. Binds the instance
/// key, the game-port static key and address to this GS identity and build.
pub fn join_request_sign_bytes(
    gs_id: &str,
    sw_hash: &[u8; 32],
    t_unix_ms: u64,
    nonce: &[u8; 16],
    ephemeral_pub: &[u8; 32],
    noise_static: &[u8; 32],
    game_addr: &str,
) -> Vec<u8> {
    bincode::serialize(&(
        "mmo/join-request/v2",
        gs_id,
        sw_hash,
        t_unix_ms,
        nonce,
        ephemeral_pub,
        noise_static,
        game_addr,
    ))
    .expect("serialize join request")
}

/// Bytes a client's session key signs to prove possession at admission,
/// bound to the VS challenge and everything the tokens will say.
pub fn client_admission_sign_bytes(
    challenge: &[u8; 32],
    session_pub: &[u8; 32],
    platform: &str,
    client_build: &[u8; 32],
    queue: &str,
    evidence: &[u8],
) -> Vec<u8> {
    bincode::serialize(&(
        "mmo/client-admission/v1",
        challenge,
        session_pub,
        platform,
        client_build,
        queue,
        evidence,
    ))
    .expect("serialize client admission")
}

/// Turn a runtime signature Vec<u8> (should be 64 bytes) into a fixed
/// [u8; 64]. Returns None if it's the wrong length.
pub fn sigvec_to_array64(sig: &crate::proto::Sig) -> Option<[u8; 64]> {
    sig.as_slice().try_into().ok()
}

pub fn rolling_hash_update(prev: [u8; 32], event_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new();
    h.update(prev);
    h.update(event_bytes);
    h.finalize().into()
}

pub fn canonical_serialize<T: Serialize>(t: &T) -> Vec<u8> {
    DefaultOptions::new()
        .with_fixint_encoding() // stable integer encoding
        .reject_trailing_bytes() // disallow extras
        .serialize(t)
        .expect("canonical serialize")
}

/// Load a pinned Ed25519 public key (32 raw bytes) from `path`.
pub fn load_verifying_key(path: impl AsRef<std::path::Path>) -> anyhow::Result<VerifyingKey> {
    use anyhow::Context;
    let path = path.as_ref();
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!("{}: expected 32 bytes, got {}", path.display(), bytes.len())
    })?;
    VerifyingKey::from_bytes(&arr)
        .with_context(|| format!("{}: invalid Ed25519 key", path.display()))
}
