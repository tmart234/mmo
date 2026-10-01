//! Game-server admission checks (04-protocol.md §7.2), transport-agnostic:
//! the caller has already proven that the peer holds `session_key` (the
//! fpp-session AdmitPop, or the QUIC Admit PoP in [`crate::control`]).

use crate::{verify_ar, verify_sat, AttestationResult, SessionAdmissionToken, Token, TokenError};
use fpp_crypto::KeyResolver;
use fpp_types::{BuildId, DeviceTier, Did, GsInstanceId, MatchId, SessionKey};
use fpp_wire::{RevocationEvent, SubjectKind};
use std::collections::HashSet;

/// What this server accepts.
#[derive(Clone, Debug)]
pub struct AdmissionPolicy {
    pub gs_instance_id: GsInstanceId,
    /// Matches hosted here.
    pub matches: Vec<MatchId>,
    /// Queue minimum, re-checked here as defense in depth (the Broker applied it first).
    pub min_tier: DeviceTier,
}

/// Revocation cache, fed by the Revocation Feed (04 §9).
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    pub token_ctis: HashSet<[u8; 16]>,
    pub devices: HashSet<Did>,
    pub accounts: HashSet<[u8; 32]>,
    pub builds: HashSet<BuildId>,
    /// Session keys (`cnf`), by `fpp_crypto::session_key_id`.
    pub sessions: HashSet<[u8; 32]>,
}

impl Revocations {
    /// Record an event's subject. Returns false for a subject kind this
    /// cache does not hold (a game server instance).
    pub fn add(&mut self, event: &RevocationEvent) -> bool {
        let id = &event.subject_id;
        let fixed32 = || <[u8; 32]>::try_from(id.as_slice()).ok();
        match event.subject_kind {
            SubjectKind::Account => fixed32().map(|a| self.accounts.insert(a)),
            SubjectKind::Device => fixed32().map(|d| self.devices.insert(Did(d))),
            SubjectKind::Session => fixed32().map(|k| self.sessions.insert(k)),
            SubjectKind::Build => fixed32().map(|b| self.builds.insert(BuildId(b))),
            SubjectKind::Sat => <[u8; 16]>::try_from(id.as_slice())
                .ok()
                .map(|c| self.token_ctis.insert(c)),
            SubjectKind::GsInstance => None,
        }
        .is_some()
    }

    /// Whether a player admitted with these tokens is revoked.
    pub fn covers(&self, sat: &SessionAdmissionToken, ar: &AttestationResult) -> bool {
        self.token_ctis.contains(&sat.cti)
            || self.token_ctis.contains(&ar.cti)
            || self.devices.contains(&sat.did)
            || self.accounts.contains(&sat.sub)
            || self
                .sessions
                .contains(&fpp_crypto::session_key_id(&sat.cnf))
            || self.builds.contains(&ar.client_build)
    }
}

#[derive(Clone, Debug)]
pub struct Admitted {
    pub sat: SessionAdmissionToken,
    pub ar: AttestationResult,
}

/// §7.2 checks in order: SAT, then AR, then the session-key binding, then
/// revocation. `keys` must hold the Broker SAT and Verifier AR keys (the
/// regional key bundle). On failure returns which token failed and why, for
/// `Reject{code}` via [`TokenError::reason`].
pub fn admit(
    sat: &[u8],
    ar: &[u8],
    session_key: &SessionKey,
    keys: &impl KeyResolver,
    policy: &AdmissionPolicy,
    revoked: &Revocations,
    now: u64,
) -> Result<Admitted, (Token, TokenError)> {
    let sat = verify_sat(sat, keys, now).map_err(|e| (Token::Sat, e))?;
    if sat.aud != policy.gs_instance_id || !policy.matches.contains(&sat.match_id) {
        return Err((Token::Sat, TokenError::Audience));
    }
    let ar = verify_ar(ar, keys, now).map_err(|e| (Token::Ar, e))?;
    if ar.cnf != sat.cnf {
        return Err((Token::Ar, TokenError::Binding));
    }
    if ar.cti != sat.ar_cti {
        return Err((Token::Ar, TokenError::ArLink));
    }
    if ar.tier < policy.min_tier || sat.tier > ar.tier {
        return Err((Token::Ar, TokenError::Tier));
    }
    if sat.cnf != *session_key {
        return Err((Token::Sat, TokenError::Binding));
    }
    if revoked.covers(&sat, &ar) {
        return Err((Token::Sat, TokenError::Revoked));
    }
    Ok(Admitted { sat, ar })
}
