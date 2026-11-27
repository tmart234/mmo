//! A dedicated game server's control link to Server Liveness (feature
//! `gs-link`; stage H5 of docs/anticheat/08): thin C ABI over `fpp_core::gs_link`
//! (owned `Noise_IK` TCP + deterministic CBOR, pure `std` — zero `tokio`,
//! zero `quinn`, zero `rustls`, zero `bincode`).

use super::{emit, fixed, free, guard, handle, handle_mut, input, FppKeys, FppStatus};
use ed25519_dalek::SigningKey;
use fpp_core::bundle::KeyBundle;
use fpp_core::gs_link::{default_gs_tpm2_options, GsLink, GsLinkConfig, GsLinkEvent};
use std::ffi::{c_char, CStr};
use std::net::SocketAddr;
use std::time::Duration;

/// Load a regional key bundle (`keys/fpp_key_bundle.json`) into a key set for
/// the rest of the SDK.
///
/// # Safety
/// `path` a NUL-terminated string; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_keys_load_bundle(
    path: *const c_char,
    out: *mut *mut FppKeys,
) -> FppStatus {
    guard(|| {
        let path = unsafe { text(path) }?;
        let bundle = KeyBundle::load(path).map_err(|_| FppStatus::InvalidArgument)?;
        unsafe {
            emit(
                out,
                FppKeys {
                    inner: bundle.keyset(),
                },
            )
        }
    })
}

/// # Safety
/// `ptr` NULL or a NUL-terminated string.
unsafe fn text<'a>(ptr: *const c_char) -> Result<&'a str, FppStatus> {
    if ptr.is_null() {
        return Err(FppStatus::NullPointer);
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| FppStatus::InvalidArgument)
}

/// What the server joins with.
#[repr(C)]
pub struct FppGsLinkConfig {
    /// Server Liveness, "ip:port".
    pub liveness: *const c_char,
    /// Legacy optional CA path (retained for C ABI compatibility; Noise IK
    /// pins `transport_pub` directly from `bundle`).
    pub ca_cert: *const c_char,
    /// The regional key bundle (JSON or CBOR file): carries Server Liveness's
    /// signing key, Enforcement's key, and the pinned Noise `transport_pub`.
    pub bundle: *const c_char,
    /// A label for this server.
    pub gs_id: *const c_char,
    /// The address players dial, "ip:port" (the Broker hands it out).
    pub game_addr: *const c_char,
    /// 32-byte seed of the server's long-term Ed25519 key.
    pub gs_key_seed: *const u8,
    /// 32-byte Ed25519 key that signs this run's Checkpoints.
    pub instance_public_key: *const u8,
    /// 32-byte static X25519 key of the server's `fpp_p2p_host`.
    pub noise_public_key: *const u8,
    /// 32-byte SHA-256 of the server's executable, or NULL to hash the
    /// running one. With `tpm2`, Server Liveness uses the kernel's
    /// measurement instead.
    pub sw_hash: *const u8,
    /// 1: prove the server's boot and build with a TPM 2.0 through
    /// tpm2-tools.
    pub tpm2: u8,
    /// Give up joining after this long (0: 10 s).
    pub timeout_ms: u32,
}

/// `FppGsEvent.kind`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppGsEventKind {
    /// data = the next SAR, already checked.
    Sar = 1,
    /// data = a signed RevocationEvent (`fpp_admission_revocation`).
    Revocation = 2,
    /// The link is gone (`reason`): the server is no longer blessed.
    Closed = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppGsEvent {
    pub kind: FppGsEventKind,
    /// `fpp_core::types::Reason` code (Closed).
    pub reason: u16,
    pub data_len: usize,
}

/// A server's link to Server Liveness.
pub struct FppGsLink {
    inner: GsLink,
}

fn link_error(what: &str, e: impl std::fmt::Display) -> FppStatus {
    eprintln!("[fpp gs-link] {what}: {e}");
    FppStatus::GsLink
}

/// Join Server Liveness and start the link. Blocks until joined (or
/// `timeout_ms`). `FPP_STATUS_GS_LINK` if it cannot reach or join Server
/// Liveness.
///
/// # Safety
/// `config` valid, its strings NUL-terminated and its keys valid for 32
/// bytes; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_connect(
    config: *const FppGsLinkConfig,
    out: *mut *mut FppGsLink,
) -> FppStatus {
    guard(|| {
        let c = unsafe { handle(config) }?;
        let liveness: SocketAddr = unsafe { text(c.liveness) }?
            .parse()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let game_addr = unsafe { text(c.game_addr) }?.to_string();
        game_addr
            .parse::<SocketAddr>()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let bundle =
            KeyBundle::load(unsafe { text(c.bundle) }?).map_err(|e| link_error("key bundle", e))?;
        let sw_hash = if c.sw_hash.is_null() {
            let exe = std::env::current_exe().map_err(|_| FppStatus::GsLink)?;
            fpp_core::crypto::file_sha256(&exe).map_err(|_| FppStatus::GsLink)?
        } else {
            unsafe { fixed(c.sw_hash) }?
        };
        let timeout = Duration::from_millis(match c.timeout_ms {
            0 => 10_000,
            t => t.into(),
        });
        let cfg = GsLinkConfig {
            liveness,
            bundle,
            gs_id: unsafe { text(c.gs_id) }?.to_string(),
            game_addr,
            gs_key: SigningKey::from_bytes(&unsafe { fixed(c.gs_key_seed) }?),
            instance_pub: unsafe { fixed(c.instance_public_key) }?,
            noise_pub: unsafe { fixed(c.noise_public_key) }?,
            sw_hash,
            tpm2: (c.tpm2 != 0).then(default_gs_tpm2_options),
            timeout,
        };
        let inner = GsLink::connect(cfg).map_err(|e| link_error("join", e))?;
        unsafe { emit(out, FppGsLink { inner }) }
    })
}

/// The match Server Liveness gave this server.
///
/// # Safety
/// `link` a live handle; `out` valid for 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_match_id(link: *const FppGsLink, out: *mut u8) -> FppStatus {
    guard(|| {
        let l = unsafe { handle(link) }?;
        unsafe { super::write_fixed(out, &l.inner.match_id()) }
    })
}

/// Next event, or `FPP_STATUS_EMPTY`.
///
/// # Safety
/// `link` a live handle; `event` valid for a write; `data` NULL or valid
/// for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_poll(
    link: *mut FppGsLink,
    event: *mut FppGsEvent,
    data: *mut u8,
    cap: usize,
) -> FppStatus {
    guard(|| {
        let l = unsafe { handle_mut(link) }?;
        let event = unsafe { event.as_mut() }.ok_or(FppStatus::NullPointer)?;
        l.inner.with_front(|front| {
            let Some(front) = front else {
                return (Err(FppStatus::Empty), false);
            };
            let (kind, reason, bytes): (_, u16, &[u8]) = match front {
                GsLinkEvent::Sar(b) => (FppGsEventKind::Sar, 0, b),
                GsLinkEvent::Revocation(b) => (FppGsEventKind::Revocation, 0, b),
                GsLinkEvent::Closed(r) => (FppGsEventKind::Closed, *r as u16, &[]),
            };
            *event = FppGsEvent {
                kind,
                reason,
                data_len: bytes.len(),
            };
            if !bytes.is_empty() {
                if data.is_null() || cap < bytes.len() {
                    return (Err(FppStatus::BufferTooSmall), false);
                }
                // SAFETY: `data` is valid for `cap >= bytes.len()` bytes.
                unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
            }
            (Ok(()), true)
        })
    })
}

/// Submit a signed Checkpoint for the current epoch.
///
/// # Safety
/// `link` a live handle; `checkpoint` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_submit_checkpoint(
    link: *mut FppGsLink,
    checkpoint: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let l = unsafe { handle_mut(link) }?;
        let checkpoint = unsafe { input(checkpoint, len) }?.to_vec();
        l.inner
            .submit_checkpoint(checkpoint)
            .map_err(|_| FppStatus::GsLink)
    })
}

/// Close the link and free it.
///
/// # Safety
/// `link` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_gs_link_free(link: *mut FppGsLink) {
    unsafe { free(link) }
}
