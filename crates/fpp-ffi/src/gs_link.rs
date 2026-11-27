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

// ============================================================================
// Client control-plane admission & Transparency Log split-view audit (EVD-02/03)
// ============================================================================

/// Maximum token size stored inside [`FppAdmittedTicket`].
pub const FPP_MAX_TICKET_TOKEN: usize = 4096;

/// Parameters for direct client admission against `fppd` (`fpp_client_admit`).
#[repr(C)]
pub struct FppClientAdmitConfig {
    /// Regional authority (`fppd`) address, `"ip:port"`.
    pub authority: *const c_char,
    /// Path to `fpp_key_bundle.json` (carries Verifier/Broker/Liveness keys and
    /// pinned Noise transport keys).
    pub bundle: *const c_char,
    /// Queue/playlist/shard name (NULL or empty defaults to `"open"`).
    pub queue: *const c_char,
    /// 32-byte SHA-256 client build digest, or NULL to hash the running binary.
    pub client_build: *const u8,
    /// Optional 32-byte Ed25519 session seed, or NULL to generate a fresh key.
    pub session_seed: *const u8,
    /// Total admission timeout in milliseconds (`0` defaults to 15,000 ms).
    pub timeout_ms: u32,
}

/// Verified admission ticket returned by [`fpp_client_admit`].
#[repr(C)]
pub struct FppAdmittedTicket {
    pub session_seed: [u8; 32],
    pub gs_noise_static: [u8; 32],
    pub liveness_key: [u8; 32],
    pub match_id: [u8; 16],
    pub did: [u8; 32],
    /// NUL-terminated `"ip:port"` of the assigned game server / shard.
    pub gs_addr: [c_char; 64],
    pub ar: [u8; 4096],
    pub ar_len: usize,
    pub sat: [u8; 4096],
    pub sat_len: usize,
    pub slot: u16,
    /// Assigned device tier (`0..3`).
    pub tier: u8,
    /// If refused by Verifier or Broker, the FPP `Reason` code (`0` on success).
    pub reason: u16,
}

/// Outcome of auditing a game server's Checkpoint against the Transparency Log.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppTlogStatus {
    /// Not yet indexed in the log; retry after the next witness round.
    Pending = 0,
    /// Proven included under a witness-cosigned Transparency Log checkpoint.
    Included = 1,
    /// Proven split view: the log holds a different Checkpoint digest for this
    /// `(match_id, epoch)`. Report it via [`fpp_tlog_report_equivocation`].
    SplitView = 2,
}

/// Request an Attestation Result from Verifier and a Session Admission Token
/// from Broker directly over `Noise_IK` TCP, filling `out` with verified ticket
/// material ready for `fpp_p2p_joiner_new` and `fpp_control_admit`.
///
/// # Safety
/// `config` valid with NUL-terminated strings; `out` valid for writing an
/// [`FppAdmittedTicket`].
#[no_mangle]
pub unsafe extern "C" fn fpp_client_admit(
    config: *const FppClientAdmitConfig,
    out: *mut FppAdmittedTicket,
) -> FppStatus {
    guard(|| {
        let c = unsafe { handle(config) }?;
        let out_ref = unsafe { out.as_mut() }.ok_or(FppStatus::NullPointer)?;
        out_ref.reason = 0;

        let authority: SocketAddr = unsafe { text(c.authority) }?
            .parse()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let bundle =
            KeyBundle::load(unsafe { text(c.bundle) }?).map_err(|e| link_error("key bundle", e))?;
        let queue = if c.queue.is_null() {
            "open".to_string()
        } else {
            let q = unsafe { text(c.queue) }?;
            if q.is_empty() {
                "open".to_string()
            } else {
                q.to_string()
            }
        };
        let client_build = if c.client_build.is_null() {
            let exe = std::env::current_exe().map_err(|_| FppStatus::GsLink)?;
            fpp_core::crypto::file_sha256(&exe).map_err(|_| FppStatus::GsLink)?
        } else {
            unsafe { fixed(c.client_build) }?
        };
        let session_seed = if c.session_seed.is_null() {
            None
        } else {
            Some(unsafe { fixed(c.session_seed) }?)
        };
        let timeout = Duration::from_millis(match c.timeout_ms {
            0 => 15_000,
            t => t.into(),
        });

        let ticket = fpp_core::client::admit(&fpp_core::client::AdmitConfig {
            authority,
            bundle,
            queue,
            client_build,
            session_seed,
            timeout,
        })
        .map_err(|e| {
            if let Some(code) = e.reason {
                out_ref.reason = code;
            }
            link_error("client admit", e)
        })?;

        if ticket.ar.len() > FPP_MAX_TICKET_TOKEN
            || ticket.sat.len() > FPP_MAX_TICKET_TOKEN
            || ticket.gs_addr.len() >= out_ref.gs_addr.len()
        {
            return Err(FppStatus::BufferTooSmall);
        }

        out_ref.session_seed = ticket.session_seed;
        out_ref.gs_noise_static = ticket.gs_noise_static;
        out_ref.liveness_key = ticket.liveness_key;
        out_ref.match_id = ticket.match_id;
        out_ref.did = ticket.did;
        out_ref.gs_addr.fill(0);
        for (i, b) in ticket.gs_addr.as_bytes().iter().enumerate() {
            out_ref.gs_addr[i] = *b as c_char;
        }
        out_ref.ar[..ticket.ar.len()].copy_from_slice(&ticket.ar);
        out_ref.ar_len = ticket.ar.len();
        out_ref.sat[..ticket.sat.len()].copy_from_slice(&ticket.sat);
        out_ref.sat_len = ticket.sat.len();
        out_ref.slot = ticket.slot;
        out_ref.tier = ticket.tier as u8;
        out_ref.reason = 0;
        Ok(())
    })
}

/// Audit a game server's Checkpoint `(match_id, epoch, digest)` against the
/// Transparency Log at `log_addr`, verifying the C2SP log signature, witness
/// cosignature, and RFC 9162 Merkle inclusion proof (EVD-02 / EVD-03).
///
/// # Safety
/// `log_addr` and `bundle` are NUL-terminated; `match_id` valid for 16 bytes;
/// `digest` valid for 32 bytes; `out_status` non-NULL; `out_logged_digest`
/// NULL or valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_tlog_check_checkpoint(
    log_addr: *const c_char,
    bundle: *const c_char,
    match_id: *const u8,
    epoch: u32,
    digest: *const u8,
    timeout_ms: u32,
    out_status: *mut FppTlogStatus,
    out_logged_digest: *mut u8,
) -> FppStatus {
    guard(|| {
        let addr: SocketAddr = unsafe { text(log_addr) }?
            .parse()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let bundle =
            KeyBundle::load(unsafe { text(bundle) }?).map_err(|e| link_error("key bundle", e))?;
        let match_id: [u8; 16] = unsafe { fixed(match_id) }?;
        let digest: [u8; 32] = unsafe { fixed(digest) }?;
        let status_out = unsafe { out_status.as_mut() }.ok_or(FppStatus::NullPointer)?;
        let timeout = Duration::from_millis(match timeout_ms {
            0 => 5_000,
            t => t.into(),
        });

        let audit =
            fpp_core::client::check_checkpoint(addr, &bundle, &match_id, epoch, &digest, timeout)
                .map_err(|e| link_error("tlog check", e))?;
        match audit {
            fpp_core::client::CheckpointAudit::Pending => {
                *status_out = FppTlogStatus::Pending;
            }
            fpp_core::client::CheckpointAudit::Included { .. } => {
                *status_out = FppTlogStatus::Included;
            }
            fpp_core::client::CheckpointAudit::SplitView { logged } => {
                *status_out = FppTlogStatus::SplitView;
                if !out_logged_digest.is_null() {
                    unsafe { super::write_fixed(out_logged_digest, &logged) }?;
                }
            }
        }
        Ok(())
    })
}

/// Report a conflicting signed Checkpoint to Server Liveness (`liveness_addr`)
/// so the equivocating game server is revoked immediately. Sets `*out_revoked`
/// to `1` if Server Liveness confirmed revocation, `0` otherwise.
///
/// # Safety
/// `liveness_addr` and `bundle` are NUL-terminated; `signed_checkpoint` valid
/// for `signed_checkpoint_len` bytes; `out_revoked` NULL or valid for 1 byte.
#[no_mangle]
pub unsafe extern "C" fn fpp_tlog_report_equivocation(
    liveness_addr: *const c_char,
    bundle: *const c_char,
    signed_checkpoint: *const u8,
    signed_checkpoint_len: usize,
    timeout_ms: u32,
    out_revoked: *mut u8,
) -> FppStatus {
    guard(|| {
        let addr: SocketAddr = unsafe { text(liveness_addr) }?
            .parse()
            .map_err(|_| FppStatus::InvalidArgument)?;
        let bundle =
            KeyBundle::load(unsafe { text(bundle) }?).map_err(|e| link_error("key bundle", e))?;
        let checkpoint = unsafe { input(signed_checkpoint, signed_checkpoint_len) }?;
        let timeout = Duration::from_millis(match timeout_ms {
            0 => 5_000,
            t => t.into(),
        });

        let ans = fpp_core::client::report_equivocation(addr, &bundle, checkpoint, timeout)
            .map_err(|e| link_error("tlog report", e))?;
        if !out_revoked.is_null() {
            let revoked = matches!(ans, fpp_core::control::ReportAnswer::Revoked);
            unsafe { *out_revoked = u8::from(revoked) };
        }
        Ok(())
    })
}
