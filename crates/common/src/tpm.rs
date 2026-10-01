//! What a game server's TPM quotes at admission. The TPM 2.0 evidence
//! itself is gathered by `common::tpm2` and appraised by `attest-tpm` in the
//! VS (`vs/src/tpm2.rs`).

use sha2::{Digest as _, Sha256};

/// Qualifying data for the join quote: the VS's single-use challenge and the
/// exact signed JoinRequest body (which includes the session's ephemeral key),
/// so a quote is good for one admission only (finding F04).
pub fn join_quote_nonce(challenge: &[u8; 32], join_sign_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"mmo/tpm/join-quote/v1\0");
    h.update(challenge);
    h.update(join_sign_bytes);
    h.finalize().into()
}
