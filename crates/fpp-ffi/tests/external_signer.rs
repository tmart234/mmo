//! `fpp_signer_external`: a session key held outside the SDK (an Android
//! Keystore key) signs through a callback, and the SDK checks every signature.

use ed25519_dalek::{Signer as _, SigningKey};
use fpp::*;
use std::ffi::{c_int, c_void};
use std::ptr;

const SEED: [u8; 32] = [42; 32];

/// The "hardware": signs with the key at `ctx`.
unsafe extern "C" fn good_sign(
    ctx: *mut c_void,
    msg: *const u8,
    len: usize,
    sig: *mut u8,
) -> c_int {
    let key = unsafe { &*(ctx as *const SigningKey) };
    let msg = unsafe { std::slice::from_raw_parts(msg, len) };
    let s = key.sign(msg).to_bytes();
    unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, 64) };
    0
}

/// Hardware that reports an error (the user cancelled, the key is gone).
unsafe extern "C" fn failing_sign(_: *mut c_void, _: *const u8, _: usize, _: *mut u8) -> c_int {
    -1
}

/// Hardware that claims success but signs with another key.
unsafe extern "C" fn wrong_key_sign(
    _: *mut c_void,
    msg: *const u8,
    len: usize,
    sig: *mut u8,
) -> c_int {
    let other = SigningKey::from_bytes(&[7; 32]);
    let msg = unsafe { std::slice::from_raw_parts(msg, len) };
    let s = other.sign(msg).to_bytes();
    unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, 64) };
    0
}

fn external(callback: FppSignCallback, key: &SigningKey) -> *mut FppSigner {
    let mut out = ptr::null_mut();
    let public = key.verifying_key().to_bytes();
    let st = unsafe {
        fpp_signer_external(
            public.as_ptr(),
            callback,
            key as *const _ as *mut c_void,
            &mut out,
        )
    };
    assert_eq!(st, FppStatus::Ok);
    out
}

/// One epoch's InputCommit signed by `signer`, or the failing status.
fn commit(signer: *const FppSigner) -> Result<Vec<u8>, FppStatus> {
    let mut b = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_input_commit_begin([1; 16].as_ptr(), 0, 0, 0, 29, ptr::null(), &mut b),
            FppStatus::Ok
        );
        for t in 0..30u32 {
            let payload = t.to_le_bytes();
            assert_eq!(
                fpp_input_commit_add_frame(b, t, payload.as_ptr(), 4),
                FppStatus::Ok
            );
        }
        let mut out = vec![0u8; 4096];
        let mut len = 0usize;
        let st = fpp_input_commit_sign(b, signer, out.as_mut_ptr(), out.len(), &mut len);
        fpp_input_commit_free(b);
        if st != FppStatus::Ok {
            return Err(st);
        }
        out.truncate(len);
        Ok(out)
    }
}

#[test]
fn external_key_signs_like_a_local_one() {
    let key = SigningKey::from_bytes(&SEED);
    let ext = external(Some(good_sign), &key);
    let mut local = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_signer_from_seed(SEED.as_ptr(), &mut local),
            FppStatus::Ok
        )
    };
    // Ed25519 is deterministic: the same object, byte for byte.
    let a = commit(ext).unwrap();
    assert_eq!(a, commit(local).unwrap());
    let public = key.verifying_key().to_bytes();
    unsafe {
        assert_eq!(
            fpp_verify_input_commit(a.as_ptr(), a.len(), public.as_ptr(), ptr::null_mut()),
            FppStatus::Ok
        );
        let mut got = [0u8; 32];
        assert_eq!(fpp_signer_public_key(ext, got.as_mut_ptr()), FppStatus::Ok);
        assert_eq!(got, public);
        fpp_signer_free(ext);
        fpp_signer_free(local);
    }
}

#[test]
fn failing_or_lying_hardware_emits_nothing() {
    let key = SigningKey::from_bytes(&SEED);
    for cb in [
        failing_sign as unsafe extern "C" fn(_, _, _, _) -> _,
        wrong_key_sign,
    ] {
        let ext = external(Some(cb), &key);
        assert_eq!(commit(ext).unwrap_err(), FppStatus::SignerFailed);
        // The failure does not stick: a later call is judged on its own.
        assert_eq!(commit(ext).unwrap_err(), FppStatus::SignerFailed);
        unsafe { fpp_signer_free(ext) };
    }
}

#[test]
fn external_key_joins_a_p2p_host() {
    let key = SigningKey::from_bytes(&SEED);
    let ext = external(Some(good_sign), &key);
    let host_static = [9u8; 32];
    let addr = b"127.0.0.1:50000";
    let mut j = ptr::null_mut();
    let st = unsafe {
        fpp_p2p_joiner_new(
            host_static.as_ptr(),
            ptr::null(),
            ext,
            ptr::null(),
            0,
            ptr::null(),
            0,
            addr.as_ptr(),
            addr.len(),
            &mut j,
        )
    };
    assert_eq!(st, FppStatus::Ok);
    unsafe { fpp_p2p_joiner_free(j) };
    // The AdmitPop is signed at join: failing hardware fails the join.
    let bad = external(Some(failing_sign), &key);
    let mut j = ptr::null_mut();
    let st = unsafe {
        fpp_p2p_joiner_new(
            host_static.as_ptr(),
            ptr::null(),
            bad,
            ptr::null(),
            0,
            ptr::null(),
            0,
            addr.as_ptr(),
            addr.len(),
            &mut j,
        )
    };
    assert_eq!(st, FppStatus::SignerFailed);
    assert!(j.is_null());
    unsafe {
        fpp_signer_free(ext);
        fpp_signer_free(bad);
    }
}

#[test]
fn bad_arguments() {
    let mut out = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_signer_external([1; 32].as_ptr(), None, ptr::null_mut(), &mut out),
            FppStatus::NullPointer
        );
        assert_eq!(
            fpp_signer_external(ptr::null(), Some(good_sign), ptr::null_mut(), &mut out),
            FppStatus::NullPointer
        );
    }
}

// ---- ES256: a P-256 key in a TPM, the Secure Enclave or StrongBox.

/// P-256 "hardware": signs with the key at `ctx`, returning `r ‖ s` with
/// whichever `s` it likes (here always the high one, as hardware may).
unsafe extern "C" fn p256_sign_high_s(
    ctx: *mut c_void,
    msg: *const u8,
    len: usize,
    sig: *mut u8,
) -> c_int {
    use p256::ecdsa::signature::Signer as _;
    let key = unsafe { &*(ctx as *const p256::ecdsa::SigningKey) };
    let msg = unsafe { std::slice::from_raw_parts(msg, len) };
    let s: p256::ecdsa::Signature = key.sign(msg);
    let s = s.normalize_s().unwrap_or(s);
    let (r, low) = s.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -low).unwrap();
    unsafe { ptr::copy_nonoverlapping(high.to_bytes().as_ptr(), sig, 64) };
    0
}

fn p256_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes(&[0x53; 32].into()).unwrap()
}

fn sec1(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

#[test]
fn an_external_p256_key_signs_session_objects_with_low_s() {
    let key = p256_key();
    let public = sec1(&key);
    let mut ext = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_signer_external_p256(
                public.as_ptr(),
                Some(p256_sign_high_s),
                &key as *const _ as *mut c_void,
                &mut ext,
            ),
            FppStatus::Ok
        );
        // the session key, 65 bytes; no 32-byte Ed25519 key
        let mut got = [0u8; FPP_SESSION_KEY_MAX];
        let mut got_len = 0usize;
        assert_eq!(
            fpp_signer_session_key(ext, got.as_mut_ptr(), &mut got_len),
            FppStatus::Ok
        );
        assert_eq!(&got[..got_len], &public[..]);
        let mut ed = [0u8; 32];
        assert_eq!(
            fpp_signer_public_key(ext, ed.as_mut_ptr()),
            FppStatus::InvalidArgument
        );
    }
    let c = commit(ext).unwrap();
    // ES256 and low s, whatever the hardware returned
    let s = fpp_wire::cose::Sign1::decode(&c).unwrap();
    assert_eq!(s.protected.alg, fpp_wire::cose::alg::ES256);
    let sig = p256::ecdsa::Signature::from_slice(&s.signature).unwrap();
    assert!(sig.normalize_s().is_none(), "high s emitted");
    unsafe {
        assert_eq!(
            fpp_verify_input_commit_key(
                c.as_ptr(),
                c.len(),
                public.as_ptr(),
                public.len(),
                ptr::null_mut()
            ),
            FppStatus::Ok
        );
        // the 32-byte entry point cannot name this key
        assert_ne!(
            fpp_verify_input_commit(c.as_ptr(), c.len(), public[1..33].as_ptr(), ptr::null_mut()),
            FppStatus::Ok
        );
        // the challenge binds the 65-byte key, as the Verifier computes it
        let mut ch = [0u8; 32];
        assert_eq!(
            fpp_attest_challenge_key(
                [9; 32].as_ptr(),
                public.as_ptr(),
                public.len(),
                ch.as_mut_ptr()
            ),
            FppStatus::Ok
        );
        assert_eq!(
            ch,
            fpp_tokens::evidence::attest_challenge(&[9; 32], &public)
        );
        // a P-256 key cannot sign as a host
        let mut b = ptr::null_mut();
        assert_eq!(
            fpp_checkpoint_begin(
                [1; 16].as_ptr(),
                [2; 32].as_ptr(),
                1,
                0,
                0,
                63,
                ptr::null(),
                &mut b
            ),
            FppStatus::Ok
        );
        let mut out = vec![0u8; 4096];
        let mut len = 0usize;
        assert_eq!(
            fpp_checkpoint_sign(b, ext, out.as_mut_ptr(), out.len(), &mut len),
            FppStatus::InvalidArgument
        );
        fpp_checkpoint_free(b);
        fpp_signer_free(ext);
    }
}

#[test]
fn a_p256_key_that_is_not_on_the_curve_is_refused() {
    let mut public = sec1(&p256_key());
    public[64] ^= 1;
    let mut out = ptr::null_mut();
    unsafe {
        assert_eq!(
            fpp_signer_external_p256(
                public.as_ptr(),
                Some(p256_sign_high_s),
                ptr::null_mut(),
                &mut out
            ),
            FppStatus::InvalidArgument
        );
    }
}
