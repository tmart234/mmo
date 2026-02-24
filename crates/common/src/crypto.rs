use crate::proto::{ClientCmd, PlayTicket};
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

/// VS will verify this signature using gs_pub, and then trust that
/// `ephemeral_pub` belongs to this GS session. After that, all heartbeats
/// are expected to be signed with the ephemeral key, not the long-term key.
pub fn join_request_sign_bytes(
    gs_id: &str,
    sw_hash: &[u8; 32],
    t_unix_ms: u64,
    nonce: &[u8; 16],
    ephemeral_pub: &[u8; 32],
) -> Vec<u8> {
    bincode::serialize(&(gs_id, sw_hash, t_unix_ms, nonce, ephemeral_pub)).unwrap()
}

pub fn heartbeat_sign_bytes(
    session_id: &[u8; 16],
    gs_counter: u64,
    gs_time_ms: u64,
    receipt_tip: &[u8; 32],
    sw_hash: &[u8; 32],
    snapshot_root: &[u8; 32],
) -> Vec<u8> {
    bincode::serialize(&(
        session_id,
        gs_counter,
        gs_time_ms,
        receipt_tip,
        sw_hash,
        snapshot_root,
    ))
    .unwrap()
}

pub fn rolling_hash_update(prev: [u8; 32], event_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new();
    h.update(prev);
    h.update(event_bytes);
    h.finalize().into()
}

/// Turn a runtime signature Vec<u8> (should be 64 bytes)
/// into a fixed [u8; 64]. Returns None if it's the wrong length.
pub fn sigvec_to_array64(sig: &crate::proto::Sig) -> Option<[u8; 64]> {
    if sig.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(sig);
    Some(out)
}

/// Canonical bytes the client signs for ClientInput.
/// MUST match on both client and GS.
pub fn client_input_sign_bytes(
    session_id: &[u8; 16],
    ticket_counter: u64,
    ticket_sig_vs: &[u8; 64],
    client_nonce: u64,
    cmd: &crate::proto::ClientCmd,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 8 + 64 + 8 + 1 + 8);

    // session_id
    out.extend_from_slice(session_id);

    // ticket_counter
    out.extend_from_slice(&ticket_counter.to_le_bytes());

    // VS signature stapled to this input
    out.extend_from_slice(ticket_sig_vs);

    // client_nonce
    out.extend_from_slice(&client_nonce.to_le_bytes());

    // command tag + payload
    match cmd {
        ClientCmd::Move { dx, dy } => {
            out.push(0u8); // tag: Move
            out.extend_from_slice(&dx.to_le_bytes());
            out.extend_from_slice(&dy.to_le_bytes());
        }
        ClientCmd::SpendCoins(sc) => {
            out.push(1u8); // tag: SpendCoins
                           // op_id: [u8; 16], amount: u64
            out.extend_from_slice(&sc.op_id);
            out.extend_from_slice(&sc.amount.to_le_bytes());
        }
    }

    out
}

/* -------------------------
Shared ticket helpers
------------------------- */

/// Default ticket lifetime used by VS in dev.
pub const DEFAULT_TICKET_LIFETIME_MS: u64 = 2_000;

/// Canonical body tuple for PlayTicket signing/verification.
#[inline]
pub fn ticket_body_tuple(
    session_id: &[u8; 16],
    client_binding: &[u8; 32],
    counter: u64,
    not_before_ms: u64,
    not_after_ms: u64,
    prev_ticket_hash: &[u8; 32],
) -> ([u8; 16], [u8; 32], u64, u64, u64, [u8; 32]) {
    (
        *session_id,
        *client_binding,
        counter,
        not_before_ms,
        not_after_ms,
        *prev_ticket_hash,
    )
}

/// Canonical body bytes for PlayTicket signing/verification.
#[inline]
pub fn ticket_body_bytes(
    session_id: &[u8; 16],
    client_binding: &[u8; 32],
    counter: u64,
    not_before_ms: u64,
    not_after_ms: u64,
    prev_ticket_hash: &[u8; 32],
) -> Vec<u8> {
    let t = ticket_body_tuple(
        session_id,
        client_binding,
        counter,
        not_before_ms,
        not_after_ms,
        prev_ticket_hash,
    );
    bincode::serialize(&t).expect("ticket_body_bytes serialize")
}

/// Compute next prev_ticket_hash from the *body bytes* we just signed.
#[inline]
pub fn ticket_hash_next(body_bytes: &[u8]) -> [u8; 32] {
    sha256(body_bytes)
}

/// Verify the VS signature on a PlayTicket using the given VS public key.
#[inline]
pub fn verify_ticket_sig(vs_pub: &VerifyingKey, pt: &PlayTicket) -> bool {
    let body = ticket_body_bytes(
        &pt.session_id,
        &pt.client_binding,
        pt.counter,
        pt.not_before_ms,
        pt.not_after_ms,
        &pt.prev_ticket_hash,
    );
    verify(vs_pub, &body, &pt.sig_vs)
}

/// Canonical update for the rolling transcript receipt tip:
/// new_tip = sha256(prev_tip || client_input_bytes || authoritative_event_bytes)
pub fn receipt_tip_update(prev_tip: &[u8; 32], ci_bytes: &[u8], ev_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(prev_tip.len() + ci_bytes.len() + ev_bytes.len());
    buf.extend_from_slice(prev_tip);
    buf.extend_from_slice(ci_bytes);
    buf.extend_from_slice(ev_bytes);
    sha256(&buf)
}

pub fn canonical_serialize<T: Serialize>(t: &T) -> Vec<u8> {
    DefaultOptions::new()
        .with_fixint_encoding() // stable integer encoding
        .reject_trailing_bytes() // disallow extras
        .serialize(t)
        .expect("canonical serialize")
}
