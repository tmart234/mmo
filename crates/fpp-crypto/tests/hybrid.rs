//! FPP-S1H: both signatures must verify, from one registered hybrid key,
//! of a role that requires it.
#![cfg(feature = "s1h")]

use fpp_crypto::hybrid::{sign_hybrid, verify_hybrid, HybridSigner};
use fpp_crypto::{KeyRole, KeySet, VerifyError};
use fpp_types::Digest;
use fpp_wire::cose::SignMulti;
use fpp_wire::LogReceipt;

fn receipt() -> LogReceipt {
    LogReceipt {
        log_id: Digest([1; 32]),
        leaf_hash: Digest([2; 32]),
        timestamp: 3,
        mmd_s: 4,
    }
}

fn keys(k: &HybridSigner, role: KeyRole) -> KeySet {
    let mut ks = KeySet::default();
    ks.insert_hybrid(role, k.ed25519_public(), k.ml_dsa_public().to_vec());
    ks
}

#[test]
fn both_signatures_must_verify() {
    let k = HybridSigner::from_seeds(&[1; 32], &[2; 32]).unwrap();
    let signed = sign_hybrid(&k, &receipt());
    let ks = keys(&k, KeyRole::Log);
    assert_eq!(
        verify_hybrid::<LogReceipt>(&signed, &ks).unwrap().payload,
        receipt()
    );

    // deterministic key generation from the seeds
    let again = HybridSigner::from_seeds(&[1; 32], &[2; 32]).unwrap();
    assert_eq!(again.ml_dsa_public(), k.ml_dsa_public());

    let object = SignMulti::decode(&signed).unwrap();
    // either signature changed
    for i in 0..2 {
        let mut bad = object.clone();
        bad.signatures[i].signature[5] ^= 1;
        assert_eq!(
            verify_hybrid::<LogReceipt>(&bad.encode(), &ks).unwrap_err(),
            VerifyError::Signature
        );
    }
    // one signature dropped
    let mut one = object.clone();
    one.signatures.pop();
    assert!(verify_hybrid::<LogReceipt>(&one.encode(), &ks).is_err());
    // the ML-DSA half of another key
    let other = HybridSigner::from_seeds(&[1; 32], &[3; 32]).unwrap();
    let mut mixed = object.clone();
    mixed.signatures[1] = SignMulti::decode(&sign_hybrid(&other, &receipt()))
        .unwrap()
        .signatures[1]
        .clone();
    assert!(matches!(
        verify_hybrid::<LogReceipt>(&mixed.encode(), &ks),
        Err(VerifyError::UnknownKey(_))
    ));
    // payload changed
    let mut changed = object.clone();
    changed.payload[3] ^= 1;
    assert!(verify_hybrid::<LogReceipt>(&changed.encode(), &ks).is_err());
    // a role that does not sign receipts, and a short-lived role registered as hybrid
    assert!(matches!(
        verify_hybrid::<LogReceipt>(&signed, &keys(&k, KeyRole::BuildSigning)),
        Err(VerifyError::RoleNotAllowed { .. })
    ));
    // unknown keys
    assert!(matches!(
        verify_hybrid::<LogReceipt>(&signed, &KeySet::default()),
        Err(VerifyError::UnknownKey(_))
    ));
    // not a COSE_Sign at all
    assert!(matches!(
        verify_hybrid::<LogReceipt>(b"\x80", &ks),
        Err(VerifyError::Encoding(_))
    ));
}
