//! Game-server admission checks (04-protocol.md §7.2), transport-agnostic:
//! the caller has already proven that the peer holds `session_key` (the
//! fpp-session AdmitPop, or the QUIC Admit PoP in [`crate::control`]).

use crate::{verify_ar, verify_sat, AttestationResult, SessionAdmissionToken, Token, TokenError};
use fpp_crypto::KeyResolver;
use fpp_types::{BuildId, DeviceTier, Did, GsInstanceId, MatchId};
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

/// Revocation cache, fed by the revocation feed (P2).
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    pub token_ctis: HashSet<[u8; 16]>,
    pub devices: HashSet<Did>,
    pub accounts: HashSet<[u8; 32]>,
    pub builds: HashSet<BuildId>,
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
    session_key: &[u8; 32],
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
    if revoked.token_ctis.contains(&sat.cti)
        || revoked.token_ctis.contains(&ar.cti)
        || revoked.devices.contains(&sat.did)
        || revoked.accounts.contains(&sat.sub)
        || revoked.builds.contains(&ar.client_build)
    {
        return Err((Token::Sat, TokenError::Revoked));
    }
    Ok(Admitted { sat, ar })
}
