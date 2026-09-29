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

use ed25519_dalek::SigningKey;
use fpp_crypto::{self as crypto, Ed25519Signer, KeyRole, KeySet, VerifyError};
use fpp_types::{BuildId, Digest, GsInstanceId, MatchId};
use fpp_wire::msg::frame_leaf_data;
use fpp_wire::{Checkpoint, InputCommit, InputLeaf};
use sha2::{Digest as _, Sha256};
use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

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
    Encoding = 10,
    Header = 11,
    Version = 12,
    Context = 13,
    UnknownKey = 14,
    Role = 15,
    Algorithm = 16,
    Signature = 17,
    Schema = 18,
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
        10 => b"encoding: not deterministic CBOR\0",
        11 => b"header: malformed COSE_Sign1 or protected header\0",
        12 => b"version: unsupported protocol version\0",
        13 => b"ctx: wrong object type or domain\0",
        14 => b"kid: unknown signing key\0",
        15 => b"role: key may not sign this object\0",
        16 => b"alg: algorithm does not match key\0",
        17 => b"signature: verification failed\0",
        18 => b"schema: payload fields invalid\0",
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

// ------------------------------------------------------------------ keys

/// An Ed25519 signing key (a player's session key or a host's instance key).
pub struct FppSigner {
    inner: Ed25519Signer,
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
                    inner: Ed25519Signer::new(sk),
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
        unsafe { emit(out, FppSigner { inner: signer }) }
    })
}

/// # Safety
/// `signer` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_signer_free(signer: *mut FppSigner) {
    unsafe { free(signer) }
}

/// The key's 32-byte Ed25519 public key (what peers need to verify it).
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
        unsafe { write_fixed(out, &s.inner.verifying_key().to_bytes()) }
    })
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
        cp.gs_instance_id = GsInstanceId(crypto::key_digest(&key.inner.verifying_key()).0);
        cp.inputs_root = fpp_merkle::root(&b.inputs);
        cp.inputs_n = b.inputs.len() as u32;
        cp.events_root = fpp_merkle::root(&b.events);
        cp.events_n = b.events.len() as u32;
        cp.rng_root = fpp_merkle::root(&b.rng);
        cp.rng_n = b.rng.len() as u32;
        cp.roster_root = fpp_merkle::root(&b.roster);
        cp.roster_n = b.roster.len() as u32;
        let signed = crypto::sign(&key.inner, &cp);
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
        let object = unsafe { input(object, len) }?;
        let keys = keyset(KeyRole::Session, unsafe { fixed(session_public_key) }?)?;
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
    })
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

impl From<fpp_wire::WireError> for FppStatus {
    fn from(e: fpp_wire::WireError) -> Self {
        if e.is_encoding() {
            FppStatus::Encoding
        } else {
            FppStatus::Schema
        }
    }
}
