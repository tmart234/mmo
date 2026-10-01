//! Fair-Play Protocol v1 SDK for C/C++ games (docs/anticheat/06-adr-001-language.md,
//! exception E1: the C ABI is the product boundary for classic games).
//!
//! Conventions for every function:
//! - returns `FppStatus` (0 = `FPP_STATUS_OK`); never panics or unwinds into C;
//! - fixed-size inputs are pointers to exactly that many bytes (documented per
//!   parameter); variable-size inputs are `(ptr, len)` and `ptr` may be NULL
//!   only when `len` is 0;
//! - signed objects are written to a caller buffer `(out, cap)`, and the
//!   required size is always stored in `*out_len`, so passing `out = NULL` or a
//!   short buffer returns `FPP_STATUS_BUFFER_TOO_SMALL` with the size to use;
//! - handles (`FppSigner`, builders) are created by `*_new`/`*_begin` and must be
//!   released with the matching `*_free`; no other memory crosses the boundary.
//!
//! This is the only crate in the workspace that uses `unsafe`, confined to
//! reading caller pointers (ADR-001 rule 1).

#![deny(unsafe_op_in_unsafe_fn)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use fpp_crypto::{self as crypto, Ed25519Signer, KeyRole, KeySet, VerifyError};
use fpp_tokens::evidence::{attest_challenge, Evidence, MAX_CHAIN, MAX_EVIDENCE};
use fpp_types::{BuildId, Digest, GsInstanceId, MatchId, SessionKey};
use fpp_wire::msg::frame_leaf_data;
use fpp_wire::{Checkpoint, InputCommit, InputLeaf};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};

mod p2p;
pub use p2p::*;

/// Result of every SDK call. Verification failures map one-to-one onto the
/// rejection categories of 04-protocol.md §2.1.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppStatus {
    Ok = 0,
    /// A required pointer was NULL.
    NullPointer = 1,
    /// An argument is out of range or breaks an ordering rule.
    InvalidArgument = 2,
    /// `*out_len` holds the required size.
    BufferTooSmall = 3,
    /// Nothing queued (poll functions).
    Empty = 4,
    Encoding = 10,
    Header = 11,
    Version = 12,
    Context = 13,
    UnknownKey = 14,
    Role = 15,
    Algorithm = 16,
    Signature = 17,
    Schema = 18,
    /// An external signer's callback failed, or returned a signature that
    /// does not verify under its public key (`fpp_signer_external`).
    SignerFailed = 19,
    /// Tokens (`fpp_ar_verify`): past `exp` (with the §13 skew).
    TokenExpired = 20,
    /// `iat` in the future (with the §13 skew).
    TokenNotYetValid = 21,
    /// Bound (`cnf`) to another session key than the one proven.
    TokenBinding = 22,
    /// Valid, but the device tier is below the minimum asked for.
    TokenTier = 23,
    /// P2P sessions (`fpp_p2p_*`): why a datagram was dropped or a call
    /// refused. Drop the datagram and carry on; none of these is fatal.
    /// Not a packet of this protocol, or too large.
    P2pMalformed = 30,
    /// No session with that receiver index (stale, or never existed).
    P2pUnknownSession = 31,
    /// Packet counter already seen or older than the replay window.
    P2pReplay = 32,
    /// Authentication failed (wrong keys, or tampered).
    P2pDecrypt = 33,
    /// Noise handshake failed (e.g. the joiner used another host key).
    P2pHandshake = 34,
    /// The join did not carry the host's invite secret.
    P2pInvite = 35,
    /// The joiner's session-key proof (AdmitPop) is invalid.
    P2pBinding = 36,
    /// The host has no free player slot.
    P2pFull = 37,
    /// Not valid in the current state (e.g. sending before connected).
    P2pState = 38,
    /// Packet counter limit reached; join again.
    P2pExhausted = 39,
    /// Payload, hello or attestation above its limit.
    P2pTooLarge = 40,
    /// No such peer.
    P2pUnknownPeer = 41,
    /// Reliable channel full (64 unacknowledged messages); retry after a tick.
    P2pCongested = 42,
    /// Host under load and the join's cookie is missing or wrong (dropped).
    P2pCookie = 43,
    /// A bug in the SDK (a caught panic). Please report it.
    Internal = 99,
}

impl From<VerifyError> for FppStatus {
    fn from(e: VerifyError) -> Self {
        match e.category() {
            "encoding" => FppStatus::Encoding,
            "header" => FppStatus::Header,
            "version" => FppStatus::Version,
            "ctx" => FppStatus::Context,
            "kid" => FppStatus::UnknownKey,
            "role" => FppStatus::Role,
            "alg" => FppStatus::Algorithm,
            "signature" => FppStatus::Signature,
            _ => FppStatus::Schema,
        }
    }
}

type Res = Result<(), FppStatus>;

fn guard(f: impl FnOnce() -> Res) -> FppStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => FppStatus::Ok,
        Ok(Err(s)) => s,
        Err(_) => FppStatus::Internal,
    }
}

/// # Safety
/// `ptr` must be NULL with `len == 0`, or valid for `len` reads.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], FppStatus> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(FppStatus::NullPointer);
    }
    if len > isize::MAX as usize {
        return Err(FppStatus::InvalidArgument);
    }
    // SAFETY: non-null and, per the caller contract, valid for `len` bytes.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// `ptr` must be NULL or valid for `N` reads.
unsafe fn fixed<const N: usize>(ptr: *const u8) -> Result<[u8; N], FppStatus> {
    if ptr.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: non-null and valid for N bytes; [u8; N] has alignment 1.
    Ok(unsafe { std::ptr::read(ptr as *const [u8; N]) })
}

/// Like `fixed`, but NULL means all zeros (e.g. `prev` at epoch 0).
unsafe fn fixed_or_zero<const N: usize>(ptr: *const u8) -> Result<[u8; N], FppStatus> {
    if ptr.is_null() {
        Ok([0; N])
    } else {
        // SAFETY: forwarded caller contract.
        unsafe { fixed(ptr) }
    }
}

/// # Safety
/// `out` must be NULL or valid for `N` writes.
unsafe fn write_fixed<const N: usize>(out: *mut u8, value: &[u8; N]) -> Res {
    if out.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: non-null and valid for N bytes per the caller contract.
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), out, N) };
    Ok(())
}

/// # Safety
/// `out_len` must be valid for a write; `out` must be NULL or valid for `cap` writes.
unsafe fn write_object(object: &[u8], out: *mut u8, cap: usize, out_len: *mut usize) -> Res {
    if out_len.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: non-null per the check above.
    unsafe { *out_len = object.len() };
    if out.is_null() || cap < object.len() {
        return Err(FppStatus::BufferTooSmall);
    }
    // SAFETY: `out` is valid for `cap >= object.len()` bytes.
    unsafe { std::ptr::copy_nonoverlapping(object.as_ptr(), out, object.len()) };
    Ok(())
}

/// # Safety
/// `handle` must be NULL or a live handle of type `T` from this SDK.
unsafe fn handle<'a, T>(handle: *const T) -> Result<&'a T, FppStatus> {
    // SAFETY: per the caller contract.
    unsafe { handle.as_ref() }.ok_or(FppStatus::NullPointer)
}

/// # Safety
/// `handle` must be NULL or a live, not concurrently used handle of type `T`.
unsafe fn handle_mut<'a, T>(handle: *mut T) -> Result<&'a mut T, FppStatus> {
    // SAFETY: per the caller contract.
    unsafe { handle.as_mut() }.ok_or(FppStatus::NullPointer)
}

/// # Safety
/// `out` must be valid for a pointer write.
unsafe fn emit<T>(out: *mut *mut T, value: T) -> Res {
    if out.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: non-null per the check above.
    unsafe { *out = Box::into_raw(Box::new(value)) };
    Ok(())
}

/// # Safety
/// `ptr` must be NULL or a handle of type `T` created by this SDK and not yet freed.
unsafe fn free<T>(ptr: *mut T) {
    if !ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: created by Box::into_raw in `emit`, freed once.
            drop(unsafe { Box::from_raw(ptr) })
        }));
    }
}

// ------------------------------------------------------------------ misc

/// ABI version of this header. Increments on any incompatible change.
#[no_mangle]
pub extern "C" fn fpp_abi_version() -> u32 {
    1
}

/// Static, human-readable name of a status code (never NULL).
#[no_mangle]
pub extern "C" fn fpp_status_str(status: c_int) -> *const c_char {
    let s: &'static [u8] = match status {
        0 => b"ok\0",
        1 => b"null pointer\0",
        2 => b"invalid argument\0",
        3 => b"buffer too small\0",
        4 => b"empty: nothing queued\0",
        10 => b"encoding: not deterministic CBOR\0",
        11 => b"header: malformed COSE_Sign1 or protected header\0",
        12 => b"version: unsupported protocol version\0",
        13 => b"ctx: wrong object type or domain\0",
        14 => b"kid: unknown signing key\0",
        15 => b"role: key may not sign this object\0",
        16 => b"alg: algorithm does not match key\0",
        17 => b"signature: verification failed\0",
        18 => b"schema: payload fields invalid\0",
        19 => b"signer: the external key did not sign\0",
        20 => b"token: expired\0",
        21 => b"token: not yet valid\0",
        22 => b"token: bound to another session key\0",
        23 => b"token: device tier below the minimum\0",
        30 => b"p2p: malformed or oversized packet\0",
        31 => b"p2p: unknown session\0",
        32 => b"p2p: replayed or too old\0",
        33 => b"p2p: authentication failed\0",
        34 => b"p2p: handshake failed\0",
        35 => b"p2p: invite secret missing or wrong\0",
        36 => b"p2p: session key proof invalid\0",
        37 => b"p2p: host full\0",
        38 => b"p2p: not valid in this state\0",
        39 => b"p2p: packet counter exhausted\0",
        40 => b"p2p: too large\0",
        41 => b"p2p: unknown peer\0",
        42 => b"p2p: reliable channel congested\0",
        43 => b"p2p: join cookie invalid\0",
        99 => b"internal SDK error\0",
        _ => b"unknown status\0",
    };
    s.as_ptr() as *const c_char
}

/// SHA-256 of `data`.
///
/// # Safety
/// `data` valid for `len` bytes (or NULL with `len` 0); `out` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_sha256(data: *const u8, len: usize, out: *mut u8) -> FppStatus {
    guard(|| {
        let data = unsafe { input(data, len) }?;
        unsafe { write_fixed(out, &Sha256::digest(data).into()) }
    })
}

/// Digest of a signed object (its exact bytes): the value for `prev` links and
/// for InputLeaf commit references.
///
/// # Safety
/// `object` valid for `len` bytes; `out` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_object_digest(
    object: *const u8,
    len: usize,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let object = unsafe { input(object, len) }?;
        unsafe { write_fixed(out, &crypto::object_digest(object).0) }
    })
}

// ------------------------------------------------------------------ platform evidence

/// The challenge a device binds its platform evidence to (roadmap P3):
/// `SHA-256("fpp/1/attest-challenge" || 0x00 || verifier_challenge || session_pub)`.
/// Pass it to Android `KeyGenParameterSpec.Builder.setAttestationChallenge`
/// or as the App Attest `clientDataHash`. Evidence made for another admission
/// challenge or another session key does not verify.
///
/// # Safety
/// `verifier_challenge`, `session_pub` and `out` valid for 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn fpp_attest_challenge(
    verifier_challenge: *const u8,
    session_pub: *const u8,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let challenge = unsafe { fixed::<32>(verifier_challenge) }?;
        let session = unsafe { fixed::<32>(session_pub) }?;
        unsafe { write_fixed(out, &attest_challenge(&challenge, &session)) }
    })
}

/// The challenge for a key that will itself be the session key (an Android
/// Keystore key, Ed25519 in the TEE or P-256 in the TEE or StrongBox): it
/// is attested when it is made, so its public key cannot be in the
/// challenge. The Verifier then requires the attested key to be the
/// session key. `SHA-256("fpp/1/attest-challenge" || 0x00 || verifier_challenge)`.
///
/// # Safety
/// `verifier_challenge` and `out` valid for 32 bytes each.
#[no_mangle]
pub unsafe extern "C" fn fpp_attest_challenge_hw_key(
    verifier_challenge: *const u8,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let challenge = unsafe { fixed::<32>(verifier_challenge) }?;
        unsafe {
            write_fixed(
                out,
                &fpp_tokens::evidence::attest_challenge_hw_key(&challenge),
            )
        }
    })
}

/// [`fpp_attest_challenge`] for a session key of either kind
/// (`fpp_signer_session_key`: 32 or 65 bytes).
///
/// # Safety
/// `verifier_challenge` and `out` valid for 32 bytes; `session_key` valid
/// for `session_key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_attest_challenge_key(
    verifier_challenge: *const u8,
    session_key: *const u8,
    session_key_len: usize,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let challenge = unsafe { fixed::<32>(verifier_challenge) }?;
        let session = unsafe { session_key_in(session_key, session_key_len) }?;
        unsafe { write_fixed(out, &attest_challenge(&challenge, &session.to_bytes())) }
    })
}

fn write_evidence(evidence: Evidence, out: *mut u8, cap: usize, out_len: *mut usize) -> Res {
    let bytes = evidence.encode();
    if bytes.len() > MAX_EVIDENCE {
        return Err(FppStatus::InvalidArgument);
    }
    // SAFETY: forwarded caller contract.
    unsafe { write_object(&bytes, out, cap, out_len) }
}

/// The evidence envelope for an Android Keystore key attestation: the
/// attested key's certificate chain, leaf first
/// (`KeyStore.getCertificateChain`, each `Certificate.getEncoded()`), for
/// `ClientAdmissionRequest.evidence`.
///
/// # Safety
/// `certs` and `lens` valid for `count` entries; each `certs[i]` valid for
/// `lens[i]` bytes. `out_len` valid for a write; `out` NULL or valid for `cap`.
#[no_mangle]
pub unsafe extern "C" fn fpp_evidence_android_key(
    certs: *const *const u8,
    lens: *const usize,
    count: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| unsafe { android_key(certs, lens, count, None, out, cap, out_len) })
}

/// [`fpp_evidence_android_key`] with a Play Integrity token (the string
/// `IntegrityTokenResponse.token()` gives), requested with
/// `nonce = base64url(fpp_attest_challenge_key(verifier_challenge,
/// session_key))` (no padding). A Verifier with the app's response keys
/// needs a `MEETS_STRONG_INTEGRITY` verdict for tier D2.
///
/// # Safety
/// As [`fpp_evidence_android_key`]; `token` valid for `token_len` bytes of
/// UTF-8.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn fpp_evidence_android_key_integrity(
    certs: *const *const u8,
    lens: *const usize,
    count: usize,
    token: *const u8,
    token_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let token = std::str::from_utf8(unsafe { input(token, token_len) }?)
            .map_err(|_| FppStatus::InvalidArgument)?;
        if token.is_empty() || token.len() > 8 * 1024 {
            return Err(FppStatus::InvalidArgument);
        }
        unsafe {
            android_key(
                certs,
                lens,
                count,
                Some(token.to_string()),
                out,
                cap,
                out_len,
            )
        }
    })
}

/// # Safety
/// As [`fpp_evidence_android_key`].
unsafe fn android_key(
    certs: *const *const u8,
    lens: *const usize,
    count: usize,
    integrity: Option<String>,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> Res {
    if count == 0 || count > MAX_CHAIN {
        return Err(FppStatus::InvalidArgument);
    }
    if certs.is_null() || lens.is_null() {
        return Err(FppStatus::NullPointer);
    }
    let mut chain = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: both arrays are valid for `count` entries.
        let (ptr, len) = unsafe { (*certs.add(i), *lens.add(i)) };
        if len == 0 {
            return Err(FppStatus::InvalidArgument);
        }
        chain.push(unsafe { input(ptr, len) }?.to_vec());
    }
    write_evidence(Evidence::AndroidKey { chain, integrity }, out, cap, out_len)
}

/// The evidence envelope for an Apple App Attest attestation object (from
/// `DCAppAttestService.attestKey`, made with `fpp_attest_challenge` as the
/// client data hash). Send it once per app key; later admissions send
/// assertions (`fpp_evidence_apple_assert`).
///
/// # Safety
/// `attestation` valid for `len` bytes; `out_len` valid for a write; `out`
/// NULL or valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_evidence_apple_attest(
    attestation: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let attestation = unsafe { input(attestation, len) }?.to_vec();
        if attestation.is_empty() {
            return Err(FppStatus::InvalidArgument);
        }
        write_evidence(Evidence::AppleAppAttest { attestation }, out, cap, out_len)
    })
}

/// The evidence envelope for an Apple App Attest assertion (from
/// `DCAppAttestService.generateAssertion`, with `fpp_attest_challenge` as the
/// client data hash) by the attested key `key_id` (32 bytes, base64-decoded).
///
/// # Safety
/// `key_id` valid for 32 bytes; `assertion` valid for `len` bytes; `out_len`
/// valid for a write; `out` NULL or valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_evidence_apple_assert(
    key_id: *const u8,
    assertion: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let key_id = unsafe { fixed::<32>(key_id) }?.to_vec();
        let assertion = unsafe { input(assertion, len) }?.to_vec();
        if assertion.is_empty() {
            return Err(FppStatus::InvalidArgument);
        }
        write_evidence(
            Evidence::AppleAppAssert { key_id, assertion },
            out,
            cap,
            out_len,
        )
    })
}

// ------------------------------------------------------------------ keys

/// An Ed25519 signing key (a player's session key or a host's instance key),
/// held here or outside the SDK (`fpp_signer_external`).
pub struct FppSigner {
    inner: Key,
}

/// Signs `len` bytes at `msg` with an Ed25519 key held outside the SDK (an
/// Android Keystore key, a TPM), writing the 64-byte signature to `sig_out`.
/// Returns 0 on success. Called synchronously on the thread that called the
/// SDK function; it may block (secure hardware can take tens of ms).
pub type FppSignCallback = Option<
    unsafe extern "C" fn(ctx: *mut c_void, msg: *const u8, len: usize, sig_out: *mut u8) -> c_int,
>;

/// A key held outside the SDK: the SDK checks every signature it returns.
struct ExternalSigner {
    session: SessionKey,
    public: crypto::PublicKey,
    kid: fpp_types::Kid,
    callback: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8) -> c_int,
    ctx: *mut c_void,
    /// Set when a signature could not be made; read by `Key::check`.
    failed: Cell<bool>,
}

enum Key {
    Local(Ed25519Signer),
    External(ExternalSigner),
}

impl Key {
    fn session_key(&self) -> SessionKey {
        match self {
            Key::Local(s) => SessionKey::Ed25519(s.verifying_key().to_bytes()),
            Key::External(e) => e.session,
        }
    }

    /// The Ed25519 public key. A P-256 key is a session key only: it cannot
    /// sign as a host (Checkpoints) or be passed where 32 bytes are expected.
    fn ed25519(&self) -> Result<VerifyingKey, FppStatus> {
        match self.session_key() {
            SessionKey::Ed25519(k) => verifying_key(k),
            SessionKey::P256 { .. } => Err(FppStatus::InvalidArgument),
        }
    }

    /// After signing: whether every signature was made. An external key that
    /// failed produced a placeholder the caller must not emit.
    fn check(&self) -> Res {
        match self {
            Key::External(e) if e.failed.replace(false) => Err(FppStatus::SignerFailed),
            _ => Ok(()),
        }
    }
}

impl crypto::Signer for Key {
    fn alg(&self) -> i64 {
        self.session_key().alg()
    }

    fn kid(&self) -> fpp_types::Kid {
        match self {
            Key::Local(s) => s.kid(),
            Key::External(e) => e.kid,
        }
    }

    fn sign(&self, to_be_signed: &[u8]) -> Vec<u8> {
        match self {
            Key::Local(s) => s.sign(to_be_signed),
            Key::External(e) => {
                let mut sig = [0u8; 64];
                // SAFETY: the caller of fpp_signer_external promised a callback
                // that reads `len` bytes at `msg` and writes 64 at `sig_out`.
                let rc = unsafe {
                    (e.callback)(
                        e.ctx,
                        to_be_signed.as_ptr(),
                        to_be_signed.len(),
                        sig.as_mut_ptr(),
                    )
                };
                // ES256: either valid `s` is accepted from the hardware; the
                // SDK emits the low one, the only one verifiers accept.
                if matches!(e.session, SessionKey::P256 { .. }) {
                    if let Some(low) = crypto::es256_normalize(&sig) {
                        sig = low;
                    }
                }
                if rc != 0 || !e.public.verify(to_be_signed, &sig) {
                    e.failed.set(true);
                }
                sig.to_vec()
            }
        }
    }
}

impl crypto::SessionSigner for Key {
    fn session_key(&self) -> SessionKey {
        Key::session_key(self)
    }
}

/// Generate a fresh key from the OS random number generator.
///
/// # Safety
/// `out` valid for a pointer write. Free the result with `fpp_signer_free`.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_generate(out: *mut *mut FppSigner) -> FppStatus {
    guard(|| {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        unsafe {
            emit(
                out,
                FppSigner {
                    inner: Key::Local(Ed25519Signer::new(sk)),
                },
            )
        }
    })
}

/// Recreate a key from a 32-byte seed (deterministic; for tests and for keys
/// the game persists itself).
///
/// # Safety
/// `seed` valid for 32 bytes; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_from_seed(
    seed: *const u8,
    out: *mut *mut FppSigner,
) -> FppStatus {
    guard(|| {
        let seed: [u8; 32] = unsafe { fixed(seed) }?;
        let signer = Ed25519Signer::new(SigningKey::from_bytes(&seed));
        unsafe {
            emit(
                out,
                FppSigner {
                    inner: Key::Local(signer),
                },
            )
        }
    })
}

/// A key held outside the SDK: its 32-byte Ed25519 public key and a callback
/// that signs with it (an Android 13+ Keystore Ed25519 key, attested in the
/// TEE, is then the session key itself: tier D2, docs 10 §4). Every signature
/// the callback returns is verified; one that fails, or a non-zero return,
/// makes the signing call return `FPP_STATUS_SIGNER_FAILED` and emit nothing.
/// `ctx` is passed back to the callback unchanged and must outlive the handle.
///
/// # Safety
/// `public_key` valid for 32 bytes; `callback` safe to call as documented at
/// `FppSignCallback`; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_external(
    public_key: *const u8,
    callback: FppSignCallback,
    ctx: *mut c_void,
    out: *mut *mut FppSigner,
) -> FppStatus {
    guard(|| {
        let session = SessionKey::Ed25519(unsafe { fixed::<32>(public_key) }?);
        unsafe { external(session, callback, ctx, out) }
    })
}

/// [`fpp_signer_external`] for an ECDSA P-256 session key (ES256): a key in
/// a TPM, the Secure Enclave or StrongBox, which have no Ed25519.
/// `public_key` is the uncompressed SEC1 point (`0x04 ‖ x ‖ y`, 65 bytes);
/// the callback writes the signature as `r ‖ s` (64 bytes, big-endian; not
/// DER), over SHA-256 of the message as ES256 defines. Either `s` is
/// accepted; the SDK emits the low one.
///
/// # Safety
/// `public_key` valid for 65 bytes; `callback` safe to call as documented at
/// `FppSignCallback`; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_external_p256(
    public_key: *const u8,
    callback: FppSignCallback,
    ctx: *mut c_void,
    out: *mut *mut FppSigner,
) -> FppStatus {
    guard(|| {
        let bytes = unsafe { fixed::<65>(public_key) }?;
        let session = SessionKey::from_bytes(&bytes).ok_or(FppStatus::InvalidArgument)?;
        unsafe { external(session, callback, ctx, out) }
    })
}

/// # Safety
/// As [`fpp_signer_external`].
unsafe fn external(
    session: SessionKey,
    callback: FppSignCallback,
    ctx: *mut c_void,
    out: *mut *mut FppSigner,
) -> Res {
    let public = crypto::PublicKey::session(&session).ok_or(FppStatus::InvalidArgument)?;
    let callback = callback.ok_or(FppStatus::NullPointer)?;
    let signer = ExternalSigner {
        kid: crypto::session_kid(&session),
        session,
        public,
        callback,
        ctx,
        failed: Cell::new(false),
    };
    unsafe {
        emit(
            out,
            FppSigner {
                inner: Key::External(signer),
            },
        )
    }
}

/// # Safety
/// `signer` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_free(signer: *mut FppSigner) {
    unsafe { free(signer) }
}

/// The key's 32-byte Ed25519 public key (what peers need to verify it).
/// `FPP_STATUS_INVALID_ARGUMENT` for a P-256 key: use
/// [`fpp_signer_session_key`].
///
/// # Safety
/// `signer` a live handle; `out` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_public_key(
    signer: *const FppSigner,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let s = unsafe { handle(signer) }?;
        unsafe { write_fixed(out, &s.inner.ed25519()?.to_bytes()) }
    })
}

/// Longest session key encoding ([`fpp_signer_session_key`]): a P-256 point.
pub const FPP_SESSION_KEY_MAX: usize = 65;

/// The key as a session key: 32 bytes for Ed25519, 65 (`0x04 ‖ x ‖ y`) for
/// P-256. This is what `fpp_attest_challenge_key`, `fpp_verify_input_commit_key`
/// and `fpp_ar_verify_key` take, and what the Verifier binds the AR to.
///
/// # Safety
/// `signer` a live handle; `out` valid for `FPP_SESSION_KEY_MAX` bytes;
/// `out_len` valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_session_key(
    signer: *const FppSigner,
    out: *mut u8,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let s = unsafe { handle(signer) }?;
        unsafe { write_session_key(&s.inner.session_key(), out, out_len) }
    })
}

/// # Safety
/// `out` valid for `FPP_SESSION_KEY_MAX` bytes; `out_len` valid for a write.
unsafe fn write_session_key(key: &SessionKey, out: *mut u8, out_len: *mut usize) -> Res {
    let bytes = key.to_bytes();
    if out.is_null() || out_len.is_null() {
        return Err(FppStatus::NullPointer);
    }
    // SAFETY: caller contract above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }
    Ok(())
}

/// A session key from C: 32 bytes (Ed25519) or 65 (P-256), a valid key.
///
/// # Safety
/// `key` valid for `len` bytes.
unsafe fn session_key_in(key: *const u8, len: usize) -> Result<SessionKey, FppStatus> {
    let bytes = unsafe { input(key, len) }?;
    let key = SessionKey::from_bytes(bytes).ok_or(FppStatus::InvalidArgument)?;
    crypto::PublicKey::session(&key).ok_or(FppStatus::InvalidArgument)?;
    Ok(key)
}

/// SHA-256 of a public key's COSE_Key: the `gs_instance_id` of a host key.
/// The first 16 bytes are the key's `kid`.
///
/// # Safety
/// `public_key` valid for 32 bytes; `out` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_key_digest(public_key: *const u8, out: *mut u8) -> FppStatus {
    guard(|| {
        let key = verifying_key(unsafe { fixed(public_key) }?)?;
        unsafe { write_fixed(out, &crypto::key_digest(&key).0) }
    })
}

fn verifying_key(bytes: [u8; 32]) -> Result<ed25519_dalek::VerifyingKey, FppStatus> {
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| FppStatus::InvalidArgument)
}

// ------------------------------------------------------------------ InputCommit

/// Accumulates one player's input frames for one epoch (04-protocol.md §7.4).
pub struct FppInputCommitBuilder {
    commit: InputCommit,
    frames: Vec<Vec<u8>>,
    last_tick: Option<u32>,
}

impl FppInputCommitBuilder {
    fn finish(&self) -> InputCommit {
        let mut c = self.commit.clone();
        c.n = self.frames.len() as u32;
        c.frames_root = fpp_merkle::root(&self.frames);
        c
    }
}

/// Start an epoch's commitment. `match_id`: 16 bytes. `prev`: 32 bytes, the
/// digest of this player's previous signed InputCommit, or NULL at epoch 0.
/// Requires `first_tick <= last_tick`.
///
/// # Safety
/// Pointers valid as documented; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_input_commit_begin(
    match_id: *const u8,
    slot: u16,
    epoch: u32,
    first_tick: u32,
    last_tick: u32,
    prev: *const u8,
    out: *mut *mut FppInputCommitBuilder,
) -> FppStatus {
    guard(|| {
        if first_tick > last_tick {
            return Err(FppStatus::InvalidArgument);
        }
        let commit = InputCommit {
            match_id: MatchId(unsafe { fixed(match_id) }?),
            slot,
            epoch,
            first_tick,
            last_tick,
            n: 0,
            frames_root: Digest::default(),
            prev: Digest(unsafe { fixed_or_zero(prev) }?),
        };
        unsafe {
            emit(
                out,
                FppInputCommitBuilder {
                    commit,
                    frames: Vec::new(),
                    last_tick: None,
                },
            )
        }
    })
}

/// Add the frame (title-defined intent bytes) sent for `tick`. Ticks must be
/// strictly ascending and inside the epoch's range.
///
/// # Safety
/// `builder` a live handle; `payload` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_input_commit_add_frame(
    builder: *mut FppInputCommitBuilder,
    tick: u32,
    payload: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle_mut(builder) }?;
        let payload = unsafe { input(payload, len) }?;
        let in_range = (b.commit.first_tick..=b.commit.last_tick).contains(&tick);
        if !in_range || b.last_tick.is_some_and(|t| tick <= t) {
            return Err(FppStatus::InvalidArgument);
        }
        b.frames.push(frame_leaf_data(tick, payload));
        b.last_tick = Some(tick);
        Ok(())
    })
}

/// Merkle root of the frames added so far. A host builds one from the frames
/// it received and compares it with the player's signed `frames_root`.
///
/// # Safety
/// `builder` a live handle; `out` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_input_commit_frames_root(
    builder: *const FppInputCommitBuilder,
    out: *mut u8,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle(builder) }?;
        unsafe { write_fixed(out, &b.finish().frames_root.0) }
    })
}

/// Sign the commitment with the player's session key. Does not consume the
/// builder; signing is deterministic, so a size query followed by a second
/// call yields the same bytes.
///
/// # Safety
/// Handles live; `out` valid for `cap` bytes or NULL; `out_len` valid.
#[no_mangle]
pub unsafe extern "C" fn fpp_input_commit_sign(
    builder: *const FppInputCommitBuilder,
    session_key: *const FppSigner,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle(builder) }?;
        let key = unsafe { handle(session_key) }?;
        let signed = crypto::sign(&key.inner, &b.finish());
        key.inner.check()?;
        unsafe { write_object(&signed, out, cap, out_len) }
    })
}

/// # Safety
/// `builder` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_input_commit_free(builder: *mut FppInputCommitBuilder) {
    unsafe { free(builder) }
}

// ------------------------------------------------------------------ Checkpoint

/// Accumulates a host's commitment for one match epoch (04-protocol.md §8.1).
pub struct FppCheckpointBuilder {
    checkpoint: Checkpoint,
    inputs: Vec<Vec<u8>>,
    last_slot: Option<u16>,
    events: Vec<Vec<u8>>,
    rng: Vec<Vec<u8>>,
    roster: Vec<Vec<u8>>,
}

/// Start a checkpoint. `match_id`: 16 bytes; `build_id`: 32 bytes; `prev`: 32
/// bytes (digest of the previous signed Checkpoint) or NULL at epoch 0.
///
/// # Safety
/// Pointers valid as documented; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_begin(
    match_id: *const u8,
    build_id: *const u8,
    policy_ver: u64,
    epoch: u32,
    first_tick: u32,
    last_tick: u32,
    prev: *const u8,
    out: *mut *mut FppCheckpointBuilder,
) -> FppStatus {
    guard(|| {
        if first_tick > last_tick {
            return Err(FppStatus::InvalidArgument);
        }
        let checkpoint = Checkpoint {
            match_id: MatchId(unsafe { fixed(match_id) }?),
            gs_instance_id: GsInstanceId::default(),
            build_id: BuildId(unsafe { fixed(build_id) }?),
            policy_ver,
            epoch,
            ticks: (first_tick, last_tick),
            prev: Digest(unsafe { fixed_or_zero(prev) }?),
            inputs_root: Digest::default(),
            inputs_n: 0,
            events_root: Digest::default(),
            events_n: 0,
            state_root: Digest::default(),
            rng_root: Digest::default(),
            rng_n: 0,
            roster_root: Digest::default(),
            roster_n: 0,
        };
        unsafe {
            emit(
                out,
                FppCheckpointBuilder {
                    checkpoint,
                    inputs: Vec::new(),
                    last_slot: None,
                    events: Vec::new(),
                    rng: Vec::new(),
                    roster: Vec::new(),
                },
            )
        }
    })
}

/// Add one player slot's input record, in strictly ascending slot order.
/// `commit_digest`: 32 bytes (`fpp_object_digest` of the player's signed
/// InputCommit) or NULL if none arrived. `applied`: bitset over the epoch's
/// ticks, bit i (LSB-first per byte) set when the frame for `first_tick + i`
/// was applied in time; exactly `ceil(ticks / 8)` bytes.
///
/// # Safety
/// `builder` a live handle; pointers valid as documented.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_add_input(
    builder: *mut FppCheckpointBuilder,
    slot: u16,
    commit_digest: *const u8,
    applied: *const u8,
    applied_len: usize,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle_mut(builder) }?;
        let applied = unsafe { input(applied, applied_len) }?;
        let (first, last) = b.checkpoint.ticks;
        let expected = ((u64::from(last - first) + 1).div_ceil(8)) as usize;
        if applied.len() != expected || b.last_slot.is_some_and(|s| slot <= s) {
            return Err(FppStatus::InvalidArgument);
        }
        let commit = if commit_digest.is_null() {
            None
        } else {
            Some(Digest(unsafe { fixed(commit_digest) }?))
        };
        let leaf = InputLeaf {
            slot,
            commit,
            applied: applied.to_vec(),
        };
        b.inputs.push(leaf.leaf_data());
        b.last_slot = Some(slot);
        Ok(())
    })
}

/// # Safety
/// `builder` a live handle or NULL; `data` valid for `len` bytes.
unsafe fn push_leaf(
    builder: *mut FppCheckpointBuilder,
    data: *const u8,
    len: usize,
    list: fn(&mut FppCheckpointBuilder) -> &mut Vec<Vec<u8>>,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle_mut(builder) }?;
        let data = unsafe { input(data, len) }?;
        list(b).push(data.to_vec());
        Ok(())
    })
}

/// Append an authoritative event (title-defined bytes), in simulation order.
///
/// # Safety
/// `builder` a live handle; `data` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_add_event(
    builder: *mut FppCheckpointBuilder,
    data: *const u8,
    len: usize,
) -> FppStatus {
    unsafe { push_leaf(builder, data, len, |b| &mut b.events) }
}

/// Append a VRF proof for an outcome roll made this epoch.
///
/// # Safety
/// `builder` a live handle; `data` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_add_rng(
    builder: *mut FppCheckpointBuilder,
    data: *const u8,
    len: usize,
) -> FppStatus {
    unsafe { push_leaf(builder, data, len, |b| &mut b.rng) }
}

/// Append a roster entry (slot, admission token id, device id) for an admitted player.
///
/// # Safety
/// `builder` a live handle; `data` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_add_roster(
    builder: *mut FppCheckpointBuilder,
    data: *const u8,
    len: usize,
) -> FppStatus {
    unsafe { push_leaf(builder, data, len, |b| &mut b.roster) }
}

/// Set the digest of the canonical audit-projection state at `last_tick`
/// (32 bytes). Defaults to all zeros for titles without an audit projection yet.
///
/// # Safety
/// `builder` a live handle; `root` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_set_state_root(
    builder: *mut FppCheckpointBuilder,
    root: *const u8,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle_mut(builder) }?;
        b.checkpoint.state_root = Digest(unsafe { fixed(root) }?);
        Ok(())
    })
}

/// Sign the checkpoint with the host's instance key. `gs_instance_id` is
/// derived from that key. Does not consume the builder.
///
/// # Safety
/// Handles live; `out` valid for `cap` bytes or NULL; `out_len` valid.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_sign(
    builder: *const FppCheckpointBuilder,
    instance_key: *const FppSigner,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let b = unsafe { handle(builder) }?;
        let key = unsafe { handle(instance_key) }?;
        let mut cp = b.checkpoint.clone();
        cp.gs_instance_id = GsInstanceId(crypto::key_digest(&key.inner.ed25519()?).0);
        cp.inputs_root = fpp_merkle::root(&b.inputs);
        cp.inputs_n = b.inputs.len() as u32;
        cp.events_root = fpp_merkle::root(&b.events);
        cp.events_n = b.events.len() as u32;
        cp.rng_root = fpp_merkle::root(&b.rng);
        cp.rng_n = b.rng.len() as u32;
        cp.roster_root = fpp_merkle::root(&b.roster);
        cp.roster_n = b.roster.len() as u32;
        let signed = crypto::sign(&key.inner, &cp);
        key.inner.check()?;
        unsafe { write_object(&signed, out, cap, out_len) }
    })
}

/// # Safety
/// `builder` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_checkpoint_free(builder: *mut FppCheckpointBuilder) {
    unsafe { free(builder) }
}

// ------------------------------------------------------------------ verification

/// Fields of a verified InputCommit, plus its object digest.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FppInputCommitInfo {
    pub match_id: [u8; 16],
    pub slot: u16,
    pub epoch: u32,
    pub first_tick: u32,
    pub last_tick: u32,
    pub n: u32,
    pub frames_root: [u8; 32],
    pub prev: [u8; 32],
    pub digest: [u8; 32],
}

/// Fields of a verified Checkpoint, plus its object digest.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FppCheckpointInfo {
    pub match_id: [u8; 16],
    pub gs_instance_id: [u8; 32],
    pub build_id: [u8; 32],
    pub policy_ver: u64,
    pub epoch: u32,
    pub first_tick: u32,
    pub last_tick: u32,
    pub prev: [u8; 32],
    pub inputs_root: [u8; 32],
    pub inputs_n: u32,
    pub events_root: [u8; 32],
    pub events_n: u32,
    pub state_root: [u8; 32],
    pub rng_root: [u8; 32],
    pub rng_n: u32,
    pub roster_root: [u8; 32],
    pub roster_n: u32,
    pub digest: [u8; 32],
}

fn keyset(role: KeyRole, public_key: [u8; 32]) -> Result<KeySet, FppStatus> {
    let mut keys = KeySet::default();
    keys.insert_ed25519(role, verifying_key(public_key)?);
    Ok(keys)
}

/// Verify a signed InputCommit against a player's 32-byte session public key.
/// On success fills `*info` if it is not NULL.
///
/// # Safety
/// `object` valid for `len` bytes; `session_public_key` valid for 32 bytes;
/// `info` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_verify_input_commit(
    object: *const u8,
    len: usize,
    session_public_key: *const u8,
    info: *mut FppInputCommitInfo,
) -> FppStatus {
    guard(|| {
        let key = SessionKey::Ed25519(unsafe { fixed(session_public_key) }?);
        unsafe { verify_input_commit(object, len, &key, info) }
    })
}

/// [`fpp_verify_input_commit`] for a session key of either kind (32 bytes
/// Ed25519, or 65 bytes P-256: `fpp_p2p_host_peer_session_key`).
///
/// # Safety
/// `object` valid for `len` bytes; `session_key` valid for
/// `session_key_len` bytes; `info` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_verify_input_commit_key(
    object: *const u8,
    len: usize,
    session_key: *const u8,
    session_key_len: usize,
    info: *mut FppInputCommitInfo,
) -> FppStatus {
    guard(|| {
        let key = unsafe { session_key_in(session_key, session_key_len) }?;
        unsafe { verify_input_commit(object, len, &key, info) }
    })
}

/// # Safety
/// As [`fpp_verify_input_commit`].
unsafe fn verify_input_commit(
    object: *const u8,
    len: usize,
    key: &SessionKey,
    info: *mut FppInputCommitInfo,
) -> Res {
    {
        let object = unsafe { input(object, len) }?;
        let mut keys = KeySet::default();
        keys.insert_session(key).ok_or(FppStatus::InvalidArgument)?;
        let v = crypto::verify::<InputCommit>(object, &keys)?;
        if let Some(info) = unsafe { info.as_mut() } {
            let c = v.payload;
            *info = FppInputCommitInfo {
                match_id: c.match_id.0,
                slot: c.slot,
                epoch: c.epoch,
                first_tick: c.first_tick,
                last_tick: c.last_tick,
                n: c.n,
                frames_root: c.frames_root.0,
                prev: c.prev.0,
                digest: v.digest.0,
            };
        }
        Ok(())
    }
}

/// Verify a signed Checkpoint against a host's 32-byte instance public key,
/// and check that `gs_instance_id` names that key. On success fills `*info`
/// if it is not NULL.
///
/// # Safety
/// `object` valid for `len` bytes; `instance_public_key` valid for 32 bytes;
/// `info` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_verify_checkpoint(
    object: *const u8,
    len: usize,
    instance_public_key: *const u8,
    info: *mut FppCheckpointInfo,
) -> FppStatus {
    guard(|| {
        let object = unsafe { input(object, len) }?;
        let public = unsafe { fixed(instance_public_key) }?;
        let keys = keyset(KeyRole::GsInstance, public)?;
        let v = crypto::verify::<Checkpoint>(object, &keys)?;
        let c = v.payload;
        if c.gs_instance_id.0 != crypto::key_digest(&verifying_key(public)?).0 {
            return Err(FppStatus::Schema);
        }
        if let Some(info) = unsafe { info.as_mut() } {
            *info = FppCheckpointInfo {
                match_id: c.match_id.0,
                gs_instance_id: c.gs_instance_id.0,
                build_id: c.build_id.0,
                policy_ver: c.policy_ver,
                epoch: c.epoch,
                first_tick: c.ticks.0,
                last_tick: c.ticks.1,
                prev: c.prev.0,
                inputs_root: c.inputs_root.0,
                inputs_n: c.inputs_n,
                events_root: c.events_root.0,
                events_n: c.events_n,
                state_root: c.state_root.0,
                rng_root: c.rng_root.0,
                rng_n: c.rng_n,
                roster_root: c.roster_root.0,
                roster_n: c.roster_n,
                digest: v.digest.0,
            };
        }
        Ok(())
    })
}

// ------------------------------------------------------------------ Attestation Results

/// `FppArInfo.features` bits: a feature the Verifier reported true.
pub const FPP_FEATURE_SECURE_BOOT: u32 = 1 << 0;
pub const FPP_FEATURE_MEASURED_BOOT: u32 = 1 << 1;
pub const FPP_FEATURE_HVCI: u32 = 1 << 2;
pub const FPP_FEATURE_VBS: u32 = 1 << 3;
pub const FPP_FEATURE_IOMMU: u32 = 1 << 4;
pub const FPP_FEATURE_RUNTIME_REPORT: u32 = 1 << 5;
pub const FPP_FEATURE_KEY_IN_HW: u32 = 1 << 6;
pub const FPP_FEATURE_STRONG_INTEGRITY: u32 = 1 << 7;
pub const FPP_FEATURE_APP_ATTESTED: u32 = 1 << 8;
pub const FPP_FEATURE_STRONGBOX: u32 = 1 << 9;

/// Fields of a verified Attestation Result (04-protocol.md §6.1).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppArInfo {
    /// Device tier, 0..3 (D0..D3).
    pub tier: u8,
    /// `FPP_FEATURE_*` bits.
    pub features: u32,
    pub iat: u64,
    pub exp: u64,
    pub policy_ver: u64,
    pub did: [u8; 32],
    pub client_build: [u8; 32],
    pub cti: [u8; 16],
    /// NUL-terminated, e.g. "windows", "android", "ios".
    pub platform: [u8; 33],
}

fn feature_bits(f: &fpp_tokens::Features) -> u32 {
    [
        (f.secure_boot, FPP_FEATURE_SECURE_BOOT),
        (f.measured_boot, FPP_FEATURE_MEASURED_BOOT),
        (f.hvci, FPP_FEATURE_HVCI),
        (f.vbs, FPP_FEATURE_VBS),
        (f.iommu, FPP_FEATURE_IOMMU),
        (f.runtime_report, FPP_FEATURE_RUNTIME_REPORT),
        (f.key_in_hw, FPP_FEATURE_KEY_IN_HW),
        (f.strong_integrity, FPP_FEATURE_STRONG_INTEGRITY),
        (f.app_attested, FPP_FEATURE_APP_ATTESTED),
        (f.strongbox, FPP_FEATURE_STRONGBOX),
    ]
    .iter()
    .filter(|(on, _)| *on == Some(true))
    .fold(0, |bits, (_, bit)| bits | bit)
}

/// Appraise a joiner's Attestation Result where it is admitted (a game
/// server, or a player host with a trust policy): signed by one of
/// `verifier_key_count` 32-byte Verifier public keys at `verifier_keys`,
/// valid at `now_s` (Unix seconds, ±60 s), bound to `session_public_key`
/// (the key the joiner proved in the handshake: `FppP2pEvent.key`), and of
/// tier `minimum_tier` or above. Fills `*info` (if not NULL) whenever the
/// token verifies, so a caller refusing on `FPP_STATUS_TOKEN_TIER` can say
/// which tier it had.
///
/// # Safety
/// `ar` valid for `len` bytes; `verifier_keys` valid for
/// `32 * verifier_key_count` bytes; `session_public_key` valid for 32 bytes;
/// `info` NULL or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_ar_verify(
    ar: *const u8,
    len: usize,
    verifier_keys: *const u8,
    verifier_key_count: usize,
    session_public_key: *const u8,
    now_s: u64,
    minimum_tier: u8,
    info: *mut FppArInfo,
) -> FppStatus {
    guard(|| {
        let session = SessionKey::Ed25519(unsafe { fixed(session_public_key) }?);
        unsafe {
            ar_verify(
                ar,
                len,
                verifier_keys,
                verifier_key_count,
                &session,
                now_s,
                minimum_tier,
                info,
            )
        }
    })
}

/// [`fpp_ar_verify`] for a session key of either kind (32 bytes Ed25519,
/// or 65 bytes P-256: `fpp_p2p_host_peer_session_key`).
///
/// # Safety
/// As [`fpp_ar_verify`], with `session_key` valid for `session_key_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_ar_verify_key(
    ar: *const u8,
    len: usize,
    verifier_keys: *const u8,
    verifier_key_count: usize,
    session_key: *const u8,
    session_key_len: usize,
    now_s: u64,
    minimum_tier: u8,
    info: *mut FppArInfo,
) -> FppStatus {
    guard(|| {
        let session = unsafe { session_key_in(session_key, session_key_len) }?;
        unsafe {
            ar_verify(
                ar,
                len,
                verifier_keys,
                verifier_key_count,
                &session,
                now_s,
                minimum_tier,
                info,
            )
        }
    })
}

/// # Safety
/// As [`fpp_ar_verify`].
#[allow(clippy::too_many_arguments)]
unsafe fn ar_verify(
    ar: *const u8,
    len: usize,
    verifier_keys: *const u8,
    verifier_key_count: usize,
    session: &SessionKey,
    now_s: u64,
    minimum_tier: u8,
    info: *mut FppArInfo,
) -> Res {
    let ar = unsafe { input(ar, len) }?;
    if ar.is_empty() || verifier_key_count == 0 || verifier_key_count > 64 || minimum_tier > 3 {
        return Err(FppStatus::InvalidArgument);
    }
    let raw = unsafe { input(verifier_keys, 32 * verifier_key_count) }?;
    let mut keys = KeySet::default();
    for key in raw.as_chunks::<32>().0 {
        keys.insert_ed25519(KeyRole::VerifierAr, verifying_key(*key)?);
    }
    let result = fpp_tokens::verify_ar(ar, &keys, now_s).map_err(|e| match e {
        fpp_tokens::TokenError::Verify(v) => FppStatus::from(v),
        fpp_tokens::TokenError::Expired => FppStatus::TokenExpired,
        fpp_tokens::TokenError::NotYetValid => FppStatus::TokenNotYetValid,
        _ => FppStatus::Schema,
    })?;
    if result.cnf != *session {
        return Err(FppStatus::TokenBinding);
    }
    if let Some(info) = unsafe { info.as_mut() } {
        let mut platform = [0u8; 33];
        let name = result.platform.as_bytes();
        let n = name.len().min(32);
        platform[..n].copy_from_slice(&name[..n]);
        *info = FppArInfo {
            tier: result.tier as u8,
            features: feature_bits(&result.features),
            iat: result.iat,
            exp: result.exp,
            policy_ver: result.policy_ver,
            did: result.did.0,
            client_build: result.client_build.0,
            cti: result.cti,
            platform,
        };
    }
    if (result.tier as u8) < minimum_tier {
        return Err(FppStatus::TokenTier);
    }
    Ok(())
}

impl From<fpp_wire::WireError> for FppStatus {
    fn from(e: fpp_wire::WireError) -> Self {
        if e.is_encoding() {
            FppStatus::Encoding
        } else {
            FppStatus::Schema
        }
    }
}
