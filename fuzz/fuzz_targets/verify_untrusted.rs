//! Verifiers that consume attacker-controlled messages must never panic.
#![no_main]

use ed25519_dalek::SigningKey;
use fpp::crypto::{self, Ed25519Signer, KeyRole, KeySet};
use fpp::tokens::admission::{admit, AdmissionPolicy, Revocations};
use fpp::tokens::{verify_ar, verify_sat, SarChain};
use fpp::types::{BuildId, DeviceTier, GsInstanceId, MatchId, SessionKey};
use fpp::wire::{InputCommit, Payload as _};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let mut keys = KeySet::default();
    for (seed, role) in [
        (0x11, KeyRole::VerifierAr),
        (0x12, KeyRole::BrokerSat),
        (0x13, KeyRole::ServerLiveness),
    ] {
        keys.insert_ed25519(
            role,
            Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32])).verifying_key(),
        );
    }
    let now = 1_790_000_000;
    match selector % 4 {
        0 => {
            let _ = verify_ar(body, &keys, now);
            let _ = verify_sat(body, &keys, now);
            if let Ok(mut chain) = SarChain::start(body, &keys, now) {
                let _ = chain.update(body, &keys, now);
                let _ = chain.live(u64::MAX);
            }
        }
        2 => {
            let (key, object) = body.split_at(body.len().min(65));
            if let Some(key) = SessionKey::from_bytes(key) {
                let mut session = KeySet::default();
                if session.insert_session(&key).is_some() {
                    let _ = crypto::verify::<InputCommit>(object, &session);
                    let _ = crypto::verify_session_raw(&key, b"msg", object);
                }
            }
        }
        3 => {
            let _ = fpp::tokens::AttestationResult::from_cbor(body);
            let _ = fpp::tokens::SessionAdmissionToken::from_cbor(body);
            if let Ok(token) = std::str::from_utf8(body) {
                let ikeys = fpp_attest::android::integrity::IntegrityKeys {
                    decryption: [7; 32],
                    verification: vec![4; 65],
                };
                let _ = fpp::b64::decode(token);
                let _ = fpp_attest::android::integrity::verify(token, &ikeys, &[0; 32], &[], 0, 1);
            }
        }
        _ => {
            let mid = body.len() / 2;
            let policy = AdmissionPolicy {
                gs_instance_id: GsInstanceId([0; 32]),
                matches: vec![MatchId([0; 16])],
                min_tier: DeviceTier::D0Unknown,
                client_builds: vec![BuildId([0; 32])],
            };
            let _ = admit(
                &body[..mid],
                &body[mid..],
                &SessionKey::Ed25519([0; 32]),
                &keys,
                &policy,
                &Revocations::default(),
                now,
            );
        }
    }
});
