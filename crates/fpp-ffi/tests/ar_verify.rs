//! `fpp_ar_verify`: a host (a game server, or a player host with a trust
//! policy) appraises a joiner's Attestation Result before admitting it.

use ed25519_dalek::SigningKey;
use fpp::*;
use fpp_crypto::{sign, Ed25519Signer};
use fpp_tokens::{AttestationResult, Features};
use fpp_types::{BuildId, DeviceTier, Did};
use std::ptr;

const NOW: u64 = 1_790_000_000;

fn key(seed: u8) -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32]))
}

fn public(k: &Ed25519Signer) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn ar(session: [u8; 32], tier: DeviceTier, iat: u64) -> AttestationResult {
    AttestationResult {
        iss: "ver.dev".into(),
        iat,
        exp: iat + 1800,
        cti: [1; 16],
        cnf: fpp_types::SessionKey::Ed25519(session),
        nonce: [2; 32],
        did: Did([3; 32]),
        tier,
        features: Features {
            secure_boot: Some(true),
            key_in_hw: Some(true),
            hvci: Some(false),
            ..Features::default()
        },
        client_build: BuildId([4; 32]),
        platform: "windows".into(),
        policy_ver: 7,
        warnings: vec![],
    }
}

fn verify(
    token: &[u8],
    keys: &[[u8; 32]],
    session: &[u8; 32],
    now: u64,
    minimum: u8,
) -> (FppStatus, FppArInfo) {
    let flat: Vec<u8> = keys.iter().flatten().copied().collect();
    let mut info = unsafe { std::mem::zeroed::<FppArInfo>() };
    let status = unsafe {
        fpp_ar_verify(
            token.as_ptr(),
            token.len(),
            flat.as_ptr(),
            keys.len(),
            session.as_ptr(),
            now,
            minimum,
            &mut info,
        )
    };
    (status, info)
}

#[test]
fn admits_a_good_result_and_reports_it() {
    let (verifier, session) = (key(0x11), key(0x51));
    let token = sign(
        &verifier,
        &ar(public(&session), DeviceTier::D2Hardware, NOW),
    );
    // (the right key among others, as a regional bundle holds several)
    let (status, info) = verify(
        &token,
        &[public(&key(0x12)), public(&verifier)],
        &public(&session),
        NOW + 60,
        2,
    );
    assert_eq!(status, FppStatus::Ok);
    assert_eq!(info.tier, 2);
    assert_eq!(
        info.features,
        FPP_FEATURE_SECURE_BOOT | FPP_FEATURE_KEY_IN_HW
    );
    assert_eq!(info.exp, NOW + 1800);
    assert_eq!(&info.platform[..8], b"windows\0");
    assert_eq!(info.did, [3; 32]);
}

#[test]
fn refuses_a_tier_below_the_minimum_but_says_which() {
    let (verifier, session) = (key(0x11), key(0x51));
    let token = sign(
        &verifier,
        &ar(public(&session), DeviceTier::D1Software, NOW),
    );
    let (status, info) = verify(&token, &[public(&verifier)], &public(&session), NOW, 2);
    assert_eq!(status, FppStatus::TokenTier);
    assert_eq!(info.tier, 1);
    assert_eq!(
        verify(&token, &[public(&verifier)], &public(&session), NOW, 1).0,
        FppStatus::Ok
    );
}

#[test]
fn refuses_a_result_for_another_session_key() {
    // a genuine device's result, presented by someone else
    let (verifier, session, thief) = (key(0x11), key(0x51), key(0x52));
    let token = sign(
        &verifier,
        &ar(public(&session), DeviceTier::D2Hardware, NOW),
    );
    assert_eq!(
        verify(&token, &[public(&verifier)], &public(&thief), NOW, 0).0,
        FppStatus::TokenBinding
    );
}

#[test]
fn refuses_expired_future_unknown_and_tampered_results() {
    let (verifier, session) = (key(0x11), key(0x51));
    let keys = [public(&verifier)];
    let token = sign(
        &verifier,
        &ar(public(&session), DeviceTier::D2Hardware, NOW),
    );
    assert_eq!(
        verify(&token, &keys, &public(&session), NOW + 1800 + 61, 0).0,
        FppStatus::TokenExpired
    );
    assert_eq!(
        verify(&token, &keys, &public(&session), NOW - 61, 0).0,
        FppStatus::TokenNotYetValid
    );
    // signed by a key the host does not trust (a self-made "Verifier")
    let forged = sign(
        &key(0x66),
        &ar(public(&session), DeviceTier::D3Hardened, NOW),
    );
    assert_eq!(
        verify(&forged, &keys, &public(&session), NOW, 0).0,
        FppStatus::UnknownKey
    );
    // any byte changed
    let mut tampered = token.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_ne!(
        verify(&tampered, &keys, &public(&session), NOW, 0).0,
        FppStatus::Ok
    );
}

#[test]
fn rejects_bad_arguments() {
    let session = [0u8; 32];
    let keys = [0u8; 32];
    let status = unsafe {
        fpp_ar_verify(
            ptr::null(),
            0,
            keys.as_ptr(),
            1,
            session.as_ptr(),
            NOW,
            0,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, FppStatus::InvalidArgument);
    let token = [0xA0u8];
    let status = unsafe {
        fpp_ar_verify(
            token.as_ptr(),
            1,
            keys.as_ptr(),
            1,
            session.as_ptr(),
            NOW,
            4,
            ptr::null_mut(),
        )
    };
    assert_eq!(status, FppStatus::InvalidArgument);
}
