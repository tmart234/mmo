//! Verifiers that consume attacker-controlled messages must never panic.
#![no_main]

use common::crypto::{client_input_sign_bytes, verify_ticket_sig};
use common::proto::{ClientInput, JoinAccept, PlayTicket};
use common::tickets::TicketChain;
use common::tpm::{verify_quote, TpmQuote};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let vs = SigningKey::from_bytes(&[7; 32]).verifying_key();
    match selector % 4 {
        0 => {
            if let Ok(t) = bincode::deserialize::<PlayTicket>(body) {
                let _ = verify_ticket_sig(&vs, &t);
                if let Ok(mut chain) = TicketChain::start(vs, t.session_id, [0; 32], t.clone(), t.not_before_ms) {
                    let _ = chain.advance(t.clone(), t.not_after_ms);
                    let _ = chain.ensure_fresh(u64::MAX);
                }
            }
        }
        1 => {
            if let Ok(ja) = bincode::deserialize::<JoinAccept>(body) {
                let _ = gs_sim::admission::verify_join_accept(&vs, &ja);
            }
        }
        2 => {
            if let Ok(q) = bincode::deserialize::<TpmQuote>(body) {
                let _ = verify_quote(&q, &q.nonce, None);
                let _ = verify_quote(&q, &[0; 32], Some(&q.pcr_values));
            }
        }
        _ => {
            if let Ok(ci) = bincode::deserialize::<ClientInput>(body) {
                let bytes = client_input_sign_bytes(
                    &ci.session_id,
                    ci.ticket_counter,
                    &ci.ticket_sig_vs,
                    ci.client_nonce,
                    &ci.cmd,
                );
                if let Ok(vk) = VerifyingKey::from_bytes(&ci.client_pub) {
                    let _ = vk.verify_strict(&bytes, &Signature::from_bytes(&ci.client_sig));
                }
            }
        }
    }
});
