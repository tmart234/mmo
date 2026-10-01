//! Verified playlists (stage H5 of docs/anticheat/08): what a dedicated game
//! server and its players need beyond the player-hosted profile, all
//! sans-I/O.
//!
//! - `FppKeys`: the regional key bundle (Verifier, Broker, Server Liveness,
//!   Enforcement public keys) every check below runs against.
//! - `FppSarChain`: a server's Server Attestation Results (04 §6.3). A player
//!   starts one from the first `SarUpdate` and extends it with every later
//!   one; a gap, fork, foreign instance or expiry means the server lost its
//!   blessing (`SAR_LAPSED`). A server checks its own chain the same way.
//! - `FppAdmission`: the server's §7.2 admission checks over a joiner's SAT
//!   and AR, its roster of admitted slots, and its revocation cache (the
//!   Revocation Feed's events, and the title's own device bans).
//! - `fpp_control_*`: the session-plane control messages (04 §7.2), in the
//!   bytes the reliable channel of `fpp_p2p_*` carries.

use super::{
    emit, fixed, free, guard, handle, handle_mut, input, session_key_in, verifying_key, FppStatus,
    Res,
};
use fpp_crypto::{KeyRole, KeySet};
use fpp_tokens::admission::{admit, AdmissionPolicy, Admitted, Revocations};
use fpp_tokens::control::Control;
use fpp_tokens::{SarChain, TokenError};
use fpp_types::{BuildId, DeviceTier, Did, MatchId, Reason, SessionKey};
use fpp_wire::{RevocationEvent, SubjectKind};
use std::collections::BTreeMap;
use std::ffi::c_char;

pub(crate) fn token_status(e: TokenError) -> FppStatus {
    match e {
        TokenError::Verify(v) => FppStatus::from(v),
        TokenError::Expired => FppStatus::TokenExpired,
        TokenError::NotYetValid => FppStatus::TokenNotYetValid,
        TokenError::Audience => FppStatus::TokenAudience,
        TokenError::Binding => FppStatus::TokenBinding,
        TokenError::ArLink => FppStatus::TokenArLink,
        TokenError::Tier => FppStatus::TokenTier,
        TokenError::Chain => FppStatus::TokenChain,
        TokenError::Revoked => FppStatus::TokenRevoked,
        TokenError::Build => FppStatus::TokenBuild,
    }
}

/// Copy `text` into a NUL-terminated fixed buffer, cut to fit.
fn c_text<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let n = text.len().min(N - 1);
    out[..n].copy_from_slice(&text.as_bytes()[..n]);
    out
}

// ------------------------------------------------------------------ keys

/// `fpp_keys_add` roles: the regional key bundle's keys.
pub const FPP_KEY_VERIFIER: u32 = 1;
pub const FPP_KEY_BROKER: u32 = 2;
pub const FPP_KEY_LIVENESS: u32 = 3;
pub const FPP_KEY_ENFORCEMENT: u32 = 4;

/// The keys tokens and revocation events are checked against.
pub struct FppKeys {
    pub(crate) inner: KeySet,
}

/// An empty key set. Free it with `fpp_keys_free`.
///
/// # Safety
/// `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_keys_new(out: *mut *mut FppKeys) -> FppStatus {
    guard(|| unsafe {
        emit(
            out,
            FppKeys {
                inner: KeySet::default(),
            },
        )
    })
}

/// Add a 32-byte Ed25519 public key in `role` (`FPP_KEY_*`). A role may hold
/// several keys (rotation).
///
/// # Safety
/// `keys` a live handle; `public_key` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_keys_add(
    keys: *mut FppKeys,
    role: u32,
    public_key: *const u8,
) -> FppStatus {
    guard(|| {
        let keys = unsafe { handle_mut(keys) }?;
        let role = match role {
            FPP_KEY_VERIFIER => KeyRole::VerifierAr,
            FPP_KEY_BROKER => KeyRole::BrokerSat,
            FPP_KEY_LIVENESS => KeyRole::ServerLiveness,
            FPP_KEY_ENFORCEMENT => KeyRole::Enforcement,
            _ => return Err(FppStatus::InvalidArgument),
        };
        let key = verifying_key(unsafe { fixed(public_key) }?)?;
        keys.inner.insert_ed25519(role, key);
        Ok(())
    })
}

/// # Safety
/// `keys` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_keys_free(keys: *mut FppKeys) {
    unsafe { free(keys) }
}

// ------------------------------------------------------------------ SAR chain

/// `FppSarInfo.server_class` (04 §6.3).
pub const FPP_SERVER_COMMUNITY: u8 = 0;
pub const FPP_SERVER_PARTNER: u8 = 1;
pub const FPP_SERVER_FIRST_PARTY: u8 = 2;
pub const FPP_SERVER_FIRST_PARTY_CVM: u8 = 3;

/// The current SAR of a chain.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppSarInfo {
    /// `gs_instance_id`: the SAT's `aud` must name it.
    pub sub: [u8; 32],
    /// The instance key: the server's Checkpoints verify under it
    /// (`fpp_verify_checkpoint`).
    pub cnf: [u8; 32],
    /// 1 if the SAR binds an `fpp_p2p_*` endpoint: its static X25519 key,
    /// which must be the key the player dialled.
    pub has_noise_static: u8,
    pub noise_static: [u8; 32],
    /// The server's build, as Server Liveness measured it.
    pub build_id: [u8; 32],
    pub server_class: u8,
    pub iat: u64,
    pub exp: u64,
    pub seq: u64,
    /// NUL-terminated.
    pub region: [u8; 33],
}

/// A server's SAR chain.
pub struct FppSarChain {
    chain: SarChain,
    keys: KeySet,
}

fn sar_info(chain: &SarChain) -> FppSarInfo {
    let s = chain.current();
    FppSarInfo {
        sub: s.sub.0,
        cnf: s.cnf,
        has_noise_static: s.noise_static.is_some() as u8,
        noise_static: s.noise_static.unwrap_or_default(),
        build_id: s.build_id.0,
        server_class: s.server_class as u8,
        iat: s.iat,
        exp: s.exp,
        seq: s.seq,
        region: c_text(&s.region),
    }
}

/// Start a chain from a server's first SAR, checked under `keys`' Server
/// Liveness keys at `now_s` (Unix seconds). The caller then checks that it
/// is for the server it meant (`fpp_sar_chain_info`: `noise_static` is the
/// key it dialled, `sub` its SAT's audience).
///
/// # Safety
/// `keys` a live handle; `sar` valid for `len` bytes; `out` valid for a
/// pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_sar_chain_start(
    keys: *const FppKeys,
    sar: *const u8,
    len: usize,
    now_s: u64,
    out: *mut *mut FppSarChain,
) -> FppStatus {
    guard(|| {
        let keys = unsafe { handle(keys) }?.inner.clone();
        let sar = unsafe { input(sar, len) }?;
        let chain = SarChain::start(sar, &keys, now_s).map_err(token_status)?;
        unsafe { emit(out, FppSarChain { chain, keys }) }
    })
}

/// Extend the chain with the server's next SAR. Any error means the
/// server lost its blessing: end the session (`SAR_LAPSED`, 7). The chain
/// is unchanged on error.
///
/// # Safety
/// `chain` a live handle; `sar` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_sar_chain_update(
    chain: *mut FppSarChain,
    sar: *const u8,
    len: usize,
    now_s: u64,
) -> FppStatus {
    guard(|| {
        let c = unsafe { handle_mut(chain) }?;
        let sar = unsafe { input(sar, len) }?;
        c.chain.update(sar, &c.keys, now_s).map_err(token_status)
    })
}

/// `FPP_STATUS_OK` while the current SAR is valid at `now_s`, else
/// `FPP_STATUS_TOKEN_EXPIRED`. (Also count time since the last SAR on your
/// own clock: no update for three issue intervals is a lapse, 04 §6.3.)
///
/// # Safety
/// `chain` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_sar_chain_live(chain: *const FppSarChain, now_s: u64) -> FppStatus {
    guard(|| {
        let c = unsafe { handle(chain) }?;
        if c.chain.live(now_s) {
            Ok(())
        } else {
            Err(FppStatus::TokenExpired)
        }
    })
}

/// The chain's current SAR.
///
/// # Safety
/// `chain` a live handle; `info` valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_sar_chain_info(
    chain: *const FppSarChain,
    info: *mut FppSarInfo,
) -> FppStatus {
    guard(|| {
        let c = unsafe { handle(chain) }?;
        let info = unsafe { info.as_mut() }.ok_or(FppStatus::NullPointer)?;
        *info = sar_info(&c.chain);
        Ok(())
    })
}

/// # Safety
/// `chain` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_sar_chain_free(chain: *mut FppSarChain) {
    unsafe { free(chain) }
}

// ------------------------------------------------------------------ admission

/// A joiner the server admitted, or (`reason` set) why it did not.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppAdmitted {
    /// `fpp_types::Reason` code to send in `Reject` and close the session
    /// with; 0 when admitted.
    pub reason: u16,
    /// The SAT's slot (the Broker placed the player there).
    pub slot: u16,
    /// Device tier of the AR, 0..3.
    pub tier: u8,
    /// Device ID (stable per device: what a ban names, finding H08).
    pub did: [u8; 32],
    /// The SAT's account (`sub`).
    pub account: [u8; 32],
    /// The AR's measured client build (finding H07).
    pub client_build: [u8; 32],
    pub sat_cti: [u8; 16],
    pub sat_exp: u64,
    /// NUL-terminated.
    pub platform: [u8; 33],
    /// NUL-terminated.
    pub queue: [u8; 65],
}

impl FppAdmitted {
    fn refused(reason: Reason) -> Self {
        Self {
            reason: reason as u16,
            slot: 0,
            tier: 0,
            did: [0; 32],
            account: [0; 32],
            client_build: [0; 32],
            sat_cti: [0; 16],
            sat_exp: 0,
            platform: [0; 33],
            queue: [0; 65],
        }
    }

    fn of(a: &Admitted) -> Self {
        Self {
            reason: 0,
            slot: a.sat.slot,
            tier: a.ar.tier as u8,
            did: a.sat.did.0,
            account: a.sat.sub,
            client_build: a.ar.client_build.0,
            sat_cti: a.sat.cti,
            sat_exp: a.sat.exp,
            platform: c_text(&a.ar.platform),
            queue: c_text(&a.sat.queue),
        }
    }
}

/// What `fpp_admission_revocation` did with an event.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppRevocationOutcome {
    /// Expired, or an action that neither refuses nor removes players.
    Ignored = 0,
    /// Refused from now on; players already admitted stay.
    Recorded = 1,
    /// Recorded, and any admitted players it names are queued for removal
    /// (`fpp_admission_poll_removed`).
    Removing = 2,
    /// Not in force yet: applied by `fpp_admission_tick` when it is.
    Scheduled = 3,
    /// It revokes this server instance: end the match.
    InstanceRevoked = 4,
}

/// A server's admission state for one match.
pub struct FppAdmission {
    keys: KeySet,
    policy: AdmissionPolicy,
    revocations: Revocations,
    roster: BTreeMap<u16, Admitted>,
    scheduled: Vec<RevocationEvent>,
    /// (slot, reason) of admitted players a revocation removed.
    removed: Vec<(u16, u16)>,
}

/// Admission for match `match_id` on the server whose instance key is
/// `instance_public_key` (the SAT's `aud` must name it), against `keys`'
/// Broker and Verifier keys (copied), refusing ARs below `minimum_tier`.
///
/// # Safety
/// `keys` a live handle; `instance_public_key` valid for 32 bytes;
/// `match_id` valid for 16 bytes; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_new(
    keys: *const FppKeys,
    instance_public_key: *const u8,
    match_id: *const u8,
    minimum_tier: u8,
    out: *mut *mut FppAdmission,
) -> FppStatus {
    guard(|| {
        let keys = unsafe { handle(keys) }?.inner.clone();
        let instance: [u8; 32] = unsafe { fixed(instance_public_key) }?;
        verifying_key(instance)?;
        let match_id = MatchId(unsafe { fixed(match_id) }?);
        let min_tier = match minimum_tier {
            0 => DeviceTier::D0Unknown,
            1 => DeviceTier::D1Software,
            2 => DeviceTier::D2Hardware,
            3 => DeviceTier::D3Hardened,
            _ => return Err(FppStatus::InvalidArgument),
        };
        unsafe {
            emit(
                out,
                FppAdmission {
                    keys,
                    policy: AdmissionPolicy {
                        gs_instance_id: fpp_tokens::instance_id(&instance),
                        matches: vec![match_id],
                        min_tier,
                        client_builds: Vec::new(),
                    },
                    revocations: Revocations::default(),
                    roster: BTreeMap::new(),
                    scheduled: Vec::new(),
                    removed: Vec::new(),
                },
            )
        }
    })
}

/// Admit only ARs whose measured client build is one of those added
/// (finding H07: a modified client cannot claim a release build where the
/// platform measures it). None added: any build.
///
/// # Safety
/// `admission` a live handle; `build_id` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_add_client_build(
    admission: *mut FppAdmission,
    build_id: *const u8,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        let build = BuildId(unsafe { fixed(build_id) }?);
        if !a.policy.client_builds.contains(&build) {
            a.policy.client_builds.push(build);
        }
        Ok(())
    })
}

/// Refuse a device by its Device ID (a title's own ban list; finding H08:
/// the ID comes from the AR, which the Verifier derives from hardware where
/// the platform has it). An admitted player on that device is queued for
/// removal.
///
/// # Safety
/// `admission` a live handle; `did` valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_ban_device(
    admission: *mut FppAdmission,
    did: *const u8,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        let did = Did(unsafe { fixed(did) }?);
        a.revocations.devices.insert(did);
        let named: Vec<u16> = a
            .roster
            .iter()
            .filter(|(_, p)| p.sat.did == did)
            .map(|(slot, _)| *slot)
            .collect();
        for slot in named {
            a.roster.remove(&slot);
            a.removed.push((slot, Reason::Revoked as u16));
        }
        Ok(())
    })
}

/// §7.2 admission of a joiner that proved `session_key` in its handshake
/// (`fpp_p2p_host_peer_session_key`), presenting `sat` and `ar` in `Admit`,
/// at `now_s`. On success the player holds the SAT's slot until
/// `fpp_admission_remove`, and the SAT cannot be used again in this match.
/// `*out` is always filled: `reason` says what to send in `Reject` when the
/// status is not OK (a taken slot is `SAT_INVALID`).
///
/// # Safety
/// `admission` a live handle; `sat`, `ar` and `session_key` valid for their
/// lengths; `out` valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_admit(
    admission: *mut FppAdmission,
    sat: *const u8,
    sat_len: usize,
    ar: *const u8,
    ar_len: usize,
    session_key: *const u8,
    session_key_len: usize,
    now_s: u64,
    out: *mut FppAdmitted,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        let out = unsafe { out.as_mut() }.ok_or(FppStatus::NullPointer)?;
        *out = FppAdmitted::refused(Reason::SatInvalid);
        let sat = unsafe { input(sat, sat_len) }?;
        let ar = unsafe { input(ar, ar_len) }?;
        let key: SessionKey = unsafe { session_key_in(session_key, session_key_len) }?;
        a.apply_due(now_s);
        let admitted = match admit(sat, ar, &key, &a.keys, &a.policy, &a.revocations, now_s) {
            Ok(v) => v,
            Err((token, e)) => {
                *out = FppAdmitted::refused(e.reason(token));
                return Err(token_status(e));
            }
        };
        if a.roster.contains_key(&admitted.sat.slot) {
            *out = FppAdmitted::refused(Reason::SatInvalid);
            return Err(FppStatus::TokenAudience);
        }
        // A SAT is single-use per match (04 §7.2).
        a.revocations.token_ctis.insert(admitted.sat.cti);
        *out = FppAdmitted::of(&admitted);
        a.roster.insert(admitted.sat.slot, admitted);
        Ok(())
    })
}

/// The player in `slot` left: the slot is free (its SAT stays used).
///
/// # Safety
/// `admission` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_remove(
    admission: *mut FppAdmission,
    slot: u16,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        a.roster
            .remove(&slot)
            .map(|_| ())
            .ok_or(FppStatus::InvalidArgument)
    })
}

impl FppAdmission {
    fn apply(&mut self, event: RevocationEvent, now_s: u64) -> FppRevocationOutcome {
        if event.expires_at.is_some_and(|e| e <= now_s) {
            return FppRevocationOutcome::Ignored;
        }
        if event.effective_at > now_s + fpp_tokens::SKEW_S {
            self.scheduled.push(event);
            return FppRevocationOutcome::Scheduled;
        }
        if !(event.action.removes_players() || event.action.denies_admission()) {
            return FppRevocationOutcome::Ignored;
        }
        if event.subject_kind == SubjectKind::GsInstance {
            return if event.subject_id == self.policy.gs_instance_id.0 {
                FppRevocationOutcome::InstanceRevoked
            } else {
                FppRevocationOutcome::Ignored
            };
        }
        let mut one = Revocations::default();
        one.add(&event);
        self.revocations.add(&event);
        if !event.action.removes_players() {
            return FppRevocationOutcome::Recorded;
        }
        let named: Vec<u16> = self
            .roster
            .iter()
            .filter(|(_, p)| one.covers(&p.sat, &p.ar))
            .map(|(slot, _)| *slot)
            .collect();
        for slot in named {
            self.roster.remove(&slot);
            self.removed.push((slot, event.reason));
        }
        FppRevocationOutcome::Removing
    }

    fn apply_due(&mut self, now_s: u64) -> bool {
        if self.scheduled.is_empty() {
            return false;
        }
        let due: Vec<RevocationEvent>;
        (due, self.scheduled) = std::mem::take(&mut self.scheduled)
            .into_iter()
            .partition(|e| e.effective_at <= now_s + fpp_tokens::SKEW_S);
        // (every due event applies, even after one that ends the match)
        let mut instance = false;
        for e in due {
            instance |= self.apply(e, now_s) == FppRevocationOutcome::InstanceRevoked;
        }
        instance
    }
}

/// A signed RevocationEvent from the Revocation Feed (Server Liveness
/// relays them to its game servers: `fpp_gs_link_poll`), checked under
/// `keys`' Enforcement keys and applied at `now_s`. `*outcome` (if not
/// NULL) says what to do next.
///
/// # Safety
/// `admission` a live handle; `event` valid for `len` bytes; `outcome` NULL
/// or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_revocation(
    admission: *mut FppAdmission,
    event: *const u8,
    len: usize,
    now_s: u64,
    outcome: *mut FppRevocationOutcome,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        let event = unsafe { input(event, len) }?;
        let v = fpp_crypto::verify::<RevocationEvent>(event, &a.keys)?;
        let o = a.apply(v.payload, now_s);
        if let Some(out) = unsafe { outcome.as_mut() } {
            *out = o;
        }
        Ok(())
    })
}

/// Apply scheduled revocation events now in force. Call about once a
/// second. Returns `FPP_STATUS_TOKEN_REVOKED` if one revoked this server
/// instance (end the match); players removed are queued as with
/// `fpp_admission_revocation`.
///
/// # Safety
/// `admission` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_tick(admission: *mut FppAdmission, now_s: u64) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        if a.apply_due(now_s) {
            Err(FppStatus::TokenRevoked)
        } else {
            Ok(())
        }
    })
}

/// Next admitted player a revocation (or a device ban) removed: its slot
/// and the reason code to kick it with. `FPP_STATUS_EMPTY` when none.
///
/// # Safety
/// `admission` a live handle; `slot` and `reason` valid for writes.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_poll_removed(
    admission: *mut FppAdmission,
    slot: *mut u16,
    reason: *mut u16,
) -> FppStatus {
    guard(|| {
        let a = unsafe { handle_mut(admission) }?;
        if slot.is_null() || reason.is_null() {
            return Err(FppStatus::NullPointer);
        }
        if a.removed.is_empty() {
            return Err(FppStatus::Empty);
        }
        let (s, r) = a.removed.remove(0);
        // SAFETY: non-null per the check above, valid per the caller contract.
        unsafe {
            *slot = s;
            *reason = r;
        }
        Ok(())
    })
}

/// # Safety
/// `admission` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_admission_free(admission: *mut FppAdmission) {
    unsafe { free(admission) }
}

// ------------------------------------------------------------------ control messages

/// `FppControl.kind`: the §7.2 message types the fpp-session profile uses.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppControlKind {
    /// data = SAT ‖ AR (`first_len`, `second_len`); the PoP is the handshake.
    Admit = 3,
    /// `slot`, `start_tick`.
    Admitted = 4,
    /// `code`.
    Reject = 5,
    /// data = the SAR.
    SarUpdate = 6,
    /// `code`.
    Kick = 10,
    Bye = 11,
    /// data = the signed Checkpoint.
    CheckpointHead = 12,
    /// data = the signed InputCommit.
    InputCommit = 13,
}

/// A decoded control message. Byte fields go to the caller's data buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppControl {
    pub kind: FppControlKind,
    pub code: u16,
    pub slot: u16,
    pub start_tick: u32,
    pub first_len: usize,
    pub second_len: usize,
}

/// Largest control message.
pub const FPP_CONTROL_MAX: usize = fpp_tokens::control::MAX_CONTROL;

/// Decode one control message from the reliable channel. Byte fields are
/// copied to `(data, cap)` back to back (`first_len`, then `second_len`);
/// `FPP_STATUS_BUFFER_TOO_SMALL` if they do not fit (`*out` holds the
/// lengths). A message type the fpp-session profile does not use is
/// `FPP_STATUS_SCHEMA`.
///
/// # Safety
/// `message` valid for `len` bytes; `out` valid for a write; `data` NULL or
/// valid for `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_decode(
    message: *const u8,
    len: usize,
    out: *mut FppControl,
    data: *mut u8,
    cap: usize,
) -> FppStatus {
    guard(|| {
        let message = unsafe { input(message, len) }?;
        let out = unsafe { out.as_mut() }.ok_or(FppStatus::NullPointer)?;
        let mut c = FppControl {
            kind: FppControlKind::Bye,
            code: 0,
            slot: 0,
            start_tick: 0,
            first_len: 0,
            second_len: 0,
        };
        let (first, second): (Vec<u8>, Vec<u8>) = match Control::decode(message)? {
            Control::Admit { sat, ar, .. } => {
                c.kind = FppControlKind::Admit;
                (sat, ar)
            }
            Control::Admitted { slot, start_tick } => {
                c.kind = FppControlKind::Admitted;
                c.slot = slot;
                c.start_tick = start_tick;
                Default::default()
            }
            Control::Reject { code } => {
                c.kind = FppControlKind::Reject;
                c.code = code;
                Default::default()
            }
            Control::SarUpdate { sar } => {
                c.kind = FppControlKind::SarUpdate;
                (sar, Vec::new())
            }
            Control::Kick { code } => {
                c.kind = FppControlKind::Kick;
                c.code = code;
                Default::default()
            }
            Control::Bye => Default::default(),
            Control::CheckpointHead { checkpoint } => {
                c.kind = FppControlKind::CheckpointHead;
                (checkpoint, Vec::new())
            }
            Control::InputCommit { commit } => {
                c.kind = FppControlKind::InputCommit;
                (commit, Vec::new())
            }
            Control::Hello { .. } | Control::HelloAck { .. } => {
                return Err(FppStatus::Schema);
            }
        };
        c.first_len = first.len();
        c.second_len = second.len();
        *out = c;
        let total = first.len() + second.len();
        if total == 0 {
            return Ok(());
        }
        if data.is_null() || cap < total {
            return Err(FppStatus::BufferTooSmall);
        }
        // SAFETY: `data` is valid for `cap >= total` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(first.as_ptr(), data, first.len());
            std::ptr::copy_nonoverlapping(second.as_ptr(), data.add(first.len()), second.len());
        }
        Ok(())
    })
}

/// Encode `msg` into `(out, cap)` per the SDK's output convention.
unsafe fn control_out(msg: Control, out: *mut u8, cap: usize, out_len: *mut usize) -> Res {
    unsafe { super::write_object(&msg.encode(), out, cap, out_len) }
}

/// `SarUpdate{sar}`: the server sends it first to every joiner, and every
/// new SAR to every player.
///
/// # Safety
/// `sar` valid for `len` bytes; output per the SDK's convention.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_sar_update(
    sar: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let sar = unsafe { input(sar, len) }?.to_vec();
        unsafe { control_out(Control::SarUpdate { sar }, out, cap, out_len) }
    })
}

/// `Admit{sat, ar}` (empty PoP: the fpp-session handshake proved the key).
///
/// # Safety
/// `sat`, `ar` valid for their lengths; output per the SDK's convention.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_admit(
    sat: *const u8,
    sat_len: usize,
    ar: *const u8,
    ar_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let sat = unsafe { input(sat, sat_len) }?.to_vec();
        let ar = unsafe { input(ar, ar_len) }?.to_vec();
        let msg = Control::Admit {
            sat,
            ar,
            pop: Vec::new(),
        };
        unsafe { control_out(msg, out, cap, out_len) }
    })
}

/// `Admitted{slot, start_tick}`.
///
/// # Safety
/// Output per the SDK's convention.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_admitted(
    slot: u16,
    start_tick: u32,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| unsafe { control_out(Control::Admitted { slot, start_tick }, out, cap, out_len) })
}

/// `Reject{code}` (`kick` 0) or `Kick{code}` (`kick` 1).
///
/// # Safety
/// Output per the SDK's convention.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_refuse(
    code: u16,
    kick: u8,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let msg = if kick != 0 {
            Control::Kick { code }
        } else {
            Control::Reject { code }
        };
        unsafe { control_out(msg, out, cap, out_len) }
    })
}

/// `CheckpointHead{checkpoint}`: the Checkpoint the server just signed,
/// for every player.
///
/// # Safety
/// `checkpoint` valid for `len` bytes; output per the SDK's convention.
#[no_mangle]
pub unsafe extern "C" fn fpp_control_checkpoint_head(
    checkpoint: *const u8,
    len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> FppStatus {
    guard(|| {
        let checkpoint = unsafe { input(checkpoint, len) }?.to_vec();
        unsafe { control_out(Control::CheckpointHead { checkpoint }, out, cap, out_len) }
    })
}

/// Name of a `fpp_types::Reason` code (never NULL).
#[no_mangle]
pub extern "C" fn fpp_reason_str(code: u16) -> *const c_char {
    let s: &'static [u8] = match code {
        0 => b"none\0",
        1 => b"version unsupported\0",
        2 => b"SAT invalid\0",
        3 => b"AR invalid\0",
        4 => b"proof of possession invalid\0",
        5 => b"device tier insufficient\0",
        6 => b"revoked\0",
        7 => b"SAR lapsed\0",
        8 => b"integrity failed\0",
        9 => b"commit mismatch\0",
        10 => b"input equivocation\0",
        11 => b"policy kick\0",
        12 => b"server draining\0",
        13 => b"server full\0",
        14 => b"client build not admitted\0",
        _ => b"unknown reason\0",
    };
    s.as_ptr() as *const c_char
}
