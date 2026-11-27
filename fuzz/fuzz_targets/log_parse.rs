//! Transparency Log inputs from the network or storage: never panic.
#![no_main]

use fpp::b64;
use fpp::crypto::{hybrid, KeyRole, KeySet};
use fpp::log::{leaf, log::decode_bundle, Checkpoint, Note};
use fpp::wire::{cose::SignMulti, LogReceipt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 5 {
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
            let _ = SignMulti::decode(body);
        }
        3 => {
            let _ = leaf::parse_checkpoint(body);
        }
        _ => {
            let mut keys = KeySet::default();
            keys.insert_hybrid(
                KeyRole::Log,
                ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key(),
                vec![0; 1952],
            );
            let _ = hybrid::verify_hybrid::<LogReceipt>(body, &keys);
        }
    }
});
