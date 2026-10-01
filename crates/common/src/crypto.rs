use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256 as Sha2};

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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

/// Bytes a client's session key signs for the Verifier, bound to its
/// challenge and everything the AR will say.
pub fn evidence_request_sign_bytes(
    challenge: &[u8; 32],
    session_pub: &[u8],
    platform: &str,
    client_build: &[u8; 32],
    evidence: &[u8],
) -> Vec<u8> {
    bincode::serialize(&(
        "mmo/evidence-request/v1",
        challenge,
        session_pub,
        platform,
        client_build,
        evidence,
    ))
    .expect("serialize evidence request")
}

/// Bytes a client's session key signs for the Broker: this AR, for this
/// queue, bound to the Broker's challenge.
pub fn match_request_sign_bytes(challenge: &[u8; 32], ar: &[u8], queue: &str) -> Vec<u8> {
    bincode::serialize(&("mmo/match-request/v1", challenge, ar, queue))
        .expect("serialize match request")
}
