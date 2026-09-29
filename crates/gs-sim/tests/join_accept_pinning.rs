//! F02: the GS accepts a JoinAccept only from the pinned VS key.

use common::{crypto::sign, proto::JoinAccept};
use ed25519_dalek::SigningKey;
use gs_sim::admission::verify_join_accept;

const SESSION: [u8; 16] = [0x5E; 16];

fn join_accept(signer: &SigningKey, claimed_pub: [u8; 32]) -> JoinAccept {
    JoinAccept {
        session_id: SESSION,
        sig_vs: sign(signer, &SESSION).to_vec(),
        vs_pub: claimed_pub,
    }
}

#[test]
fn accepts_pinned_vs() {
    let vs = SigningKey::from_bytes(&[1; 32]);
    let ja = join_accept(&vs, vs.verifying_key().to_bytes());
    verify_join_accept(&vs.verifying_key(), &ja).unwrap();
}

#[test]
fn rejects_fake_vs_with_its_own_key() {
    // A fake VS (or MITM) signs with its own key and advertises it. The old
    // code verified against the advertised key and accepted this.
    let pinned = SigningKey::from_bytes(&[1; 32]);
    let fake = SigningKey::from_bytes(&[2; 32]);
    let ja = join_accept(&fake, fake.verifying_key().to_bytes());
    let e = verify_join_accept(&pinned.verifying_key(), &ja).unwrap_err();
    assert!(format!("{e:#}").contains("untrusted VS key"), "{e:#}");
}

#[test]
fn rejects_pinned_key_claim_with_wrong_signature() {
    let pinned = SigningKey::from_bytes(&[1; 32]);
    let fake = SigningKey::from_bytes(&[2; 32]);
    let ja = join_accept(&fake, pinned.verifying_key().to_bytes());
    let e = verify_join_accept(&pinned.verifying_key(), &ja).unwrap_err();
    assert!(format!("{e:#}").contains("signature invalid"), "{e:#}");
}

#[test]
fn rejects_malformed_signature() {
    let pinned = SigningKey::from_bytes(&[1; 32]);
    let mut ja = join_accept(&pinned, pinned.verifying_key().to_bytes());
    ja.sig_vs.truncate(10);
    assert!(verify_join_accept(&pinned.verifying_key(), &ja).is_err());
}
