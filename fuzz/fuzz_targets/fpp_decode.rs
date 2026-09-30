//! FPP v1 decoders and verification on untrusted bytes.
#![no_main]

use ed25519_dalek::SigningKey;
use fpp_crypto::{verify, Ed25519Signer, KeyRole, KeySet};
use fpp_wire::{cbor, cose::Sign1, AdmitPop, Checkpoint, InputCommit, Payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exactly one accepted encoding: whatever decodes re-encodes identically.
    if let Ok(v) = cbor::decode(data) {
        assert_eq!(
            cbor::encode(&v).expect("decoded maps have unique keys"),
            data
        );
    }
    let _ = Sign1::decode(data);
    let _ = InputCommit::from_cbor(data);
    let _ = Checkpoint::from_cbor(data);
    let _ = AdmitPop::from_cbor(data);
    let _ = fpp_tokens::AttestationResult::from_cbor(data);
    let _ = fpp_tokens::SessionAdmissionToken::from_cbor(data);
    let _ = fpp_tokens::ServerAttestationResult::from_cbor(data);
    let _ = fpp_tokens::control::Control::decode(data);
    let _ = fpp_wire::InputFrame::decode(data);

    let mut keys = KeySet::default();
    for (seed, role) in [
        (0x51, KeyRole::Session),
        (0x52, KeyRole::Session),
        (0x61, KeyRole::GsInstance),
        (0x71, KeyRole::Log),
    ] {
        keys.insert_ed25519(
            role,
            Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32])).verifying_key(),
        );
    }
    let _ = verify::<InputCommit>(data, &keys);
    let _ = verify::<Checkpoint>(data, &keys);
    let _ = verify::<AdmitPop>(data, &keys);
});
