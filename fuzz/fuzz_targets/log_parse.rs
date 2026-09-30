//! Transparency Log inputs from the network or storage (notes, checkpoints,
//! entry bundles, hybrid COSE_Sign receipts): never panic.
#![no_main]

use fpp_crypto::{KeyRole, KeySet};
use fpp_log::{b64, log::decode_bundle, Checkpoint, Note};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => {
            if let Ok(text) = std::str::from_utf8(body) {
                if let Ok(note) = Note::parse(text) {
                    let _ = note.verify("fpp.test/log", &[7; 32]);
                    let _ = note.verify_cosignature("w", &[7; 32]);
                    let _ = Checkpoint::parse(&note.text);
                    let _ = note.encode();
                }
                let _ = b64::decode(text);
            }
        }
        1 => {
            let _ = decode_bundle(body);
        }
        2 => {
            let _ = fpp_wire::cose::SignMulti::decode(body);
        }
        _ => {
            let mut keys = KeySet::default();
            keys.insert_hybrid(
                KeyRole::Log,
                ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key(),
                vec![0; 1952],
            );
            let _ = fpp_crypto::hybrid::verify_hybrid::<fpp_wire::LogReceipt>(body, &keys);
        }
    }
});
