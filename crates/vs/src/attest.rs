// crates/vs/src/attest.rs
//! Appraisal of the prototype's TPM quotes (findings F04 and F05 in
//! docs/anticheat/07-gap-analysis-and-roadmap.md). Pure functions, so every
//! rule is tested without a network.
//!
//! What this fixes: the VS, not the GS, now chooses quote freshness (a
//! single-use challenge at join, an unpredictable ticket signature for
//! re-attestation), and quotes must come from an enrolled or session-pinned
//! attestation key instead of whatever key the quote carries. What remains
//! for the Verifier (roadmap P3): EK certificate chains, credential
//! activation, TPMS_ATTEST parsing and event-log replay for real TPMs.

use anyhow::{anyhow, bail, Result};
use common::config::VsConfig;
use common::tpm::{join_quote_nonce, reattest_quote_nonce, verify_quote, TpmQuote};
use std::collections::VecDeque;

/// Re-attestation quotes may be seeded by any of this many latest tickets
/// (at one ticket per 2 s: the last 16 s).
pub const RECENT_TICKETS: usize = 8;

fn check_ak(cfg: &VsConfig, quote: &TpmQuote) -> Result<()> {
    if cfg.trusted_ak_keys.is_empty()
        || cfg
            .trusted_ak_keys
            .iter()
            .any(|k| k.as_slice() == quote.ak_pub)
    {
        Ok(())
    } else {
        bail!("TPM attestation key is not enrolled")
    }
}

fn baselines(cfg: &VsConfig) -> Option<&std::collections::BTreeMap<u8, [u8; 32]>> {
    (!cfg.required_pcr_baselines.is_empty()).then_some(&cfg.required_pcr_baselines)
}

/// Appraise the quote in a JoinRequest against the challenge this VS issued
/// on this connection. Returns the attestation key to pin for the session.
pub fn appraise_join_quote(
    cfg: &VsConfig,
    challenge: &[u8; 32],
    join_sign_bytes: &[u8],
    quote: Option<&TpmQuote>,
) -> Result<Option<Vec<u8>>> {
    let Some(quote) = quote else {
        if cfg.require_tpm_quote {
            bail!("TPM quote required");
        }
        return Ok(None);
    };
    check_ak(cfg, quote)?;
    verify_quote(
        quote,
        &join_quote_nonce(challenge, join_sign_bytes),
        baselines(cfg),
    )?;
    Ok(Some(quote.ak_pub.clone()))
}

/// Appraise a re-attestation quote from a Heartbeat. It must come from the key
/// pinned at join, be seeded by a ticket this VS issued recently, and match
/// the PCR baseline (configured, or else the session's first re-attestation).
#[allow(clippy::too_many_arguments)]
pub fn appraise_reattest_quote(
    cfg: &VsConfig,
    session_id: &[u8; 16],
    gs_counter: u64,
    quote: &TpmQuote,
    quote_ticket: u64,
    pinned_ak: Option<&[u8]>,
    recent_tickets: &VecDeque<(u64, Vec<u8>)>,
    session_baseline: Option<&std::collections::BTreeMap<u8, [u8; 32]>>,
) -> Result<()> {
    let pinned = pinned_ak.ok_or_else(|| anyhow!("no attestation key was pinned at join"))?;
    if quote.ak_pub != pinned {
        bail!("re-attestation quote is signed by a different attestation key");
    }
    let (_, sig) = recent_tickets
        .iter()
        .find(|(counter, _)| *counter == quote_ticket)
        .ok_or_else(|| anyhow!("quote is not seeded by a recent ticket (#{quote_ticket})"))?;
    verify_quote(
        quote,
        &reattest_quote_nonce(session_id, gs_counter, sig),
        baselines(cfg).or(session_baseline),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::tpm::{SimulatedTpm, TpmProvider};

    const SESSION: [u8; 16] = [9; 16];

    fn tpm(seed: u8) -> SimulatedTpm {
        let mut t = SimulatedTpm::new_deterministic(&[seed; 32]);
        t.extend_pcr(0, b"gs-binary").unwrap();
        t
    }

    fn ak(t: &SimulatedTpm) -> [u8; 32] {
        t.quote(&[0], &[0; 32]).unwrap().ak_pub.try_into().unwrap()
    }

    fn join_quote(t: &SimulatedTpm, challenge: &[u8; 32], join: &[u8]) -> TpmQuote {
        t.quote(&[0, 1], &join_quote_nonce(challenge, join))
            .unwrap()
    }

    #[test]
    fn join_quote_is_single_use() {
        let cfg = VsConfig::default();
        let t = tpm(1);
        let q = join_quote(&t, &[1; 32], b"join-a");
        assert!(appraise_join_quote(&cfg, &[1; 32], b"join-a", Some(&q)).is_ok());
        // Replayed on a later connection (new challenge): rejected.
        assert!(appraise_join_quote(&cfg, &[2; 32], b"join-a", Some(&q)).is_err());
        // Same challenge, another JoinRequest (e.g. another ephemeral key): rejected.
        assert!(appraise_join_quote(&cfg, &[1; 32], b"join-b", Some(&q)).is_err());
    }

    #[test]
    fn self_made_attestation_keys_are_rejected_once_keys_are_enrolled() {
        let honest = tpm(1);
        let forger = tpm(2); // any key can sign a "quote" for any PCR values
        let cfg = VsConfig {
            trusted_ak_keys: vec![ak(&honest)],
            ..VsConfig::default()
        };
        let forged = join_quote(&forger, &[1; 32], b"join");
        assert!(appraise_join_quote(&cfg, &[1; 32], b"join", Some(&forged)).is_err());
        let real = join_quote(&honest, &[1; 32], b"join");
        let pinned = appraise_join_quote(&cfg, &[1; 32], b"join", Some(&real)).unwrap();
        assert_eq!(pinned.as_deref(), Some(&ak(&honest)[..]));
    }

    #[test]
    fn quote_can_be_required() {
        let cfg = VsConfig {
            require_tpm_quote: true,
            ..VsConfig::default()
        };
        assert!(appraise_join_quote(&cfg, &[1; 32], b"join", None).is_err());
        assert!(
            appraise_join_quote(&VsConfig::default(), &[1; 32], b"join", None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reattestation_needs_the_pinned_key_and_a_recent_ticket() {
        let cfg = VsConfig::default();
        let t = tpm(1);
        let pinned = ak(&t);
        let tickets: VecDeque<(u64, Vec<u8>)> = (10..=12).map(|c| (c, vec![c as u8; 64])).collect();
        let quote_for = |t: &SimulatedTpm, ticket: u64, counter: u64| {
            t.quote(
                &[0, 1],
                &reattest_quote_nonce(&SESSION, counter, &[ticket as u8; 64]),
            )
            .unwrap()
        };
        let check = |q: &TpmQuote, ticket: u64, counter: u64, pinned: Option<&[u8]>| {
            appraise_reattest_quote(&cfg, &SESSION, counter, q, ticket, pinned, &tickets, None)
        };

        let ok = quote_for(&t, 12, 100);
        assert!(check(&ok, 12, 100, Some(&pinned)).is_ok());
        // Nothing pinned at join: a heartbeat cannot introduce a key.
        assert!(check(&ok, 12, 100, None).is_err());
        // Another TPM (or a software key) cannot take over mid-session.
        let other = quote_for(&tpm(2), 12, 100);
        assert!(check(&other, 12, 100, Some(&pinned)).is_err());
        // Seeded by a ticket the VS has not issued (made ahead of time), or by
        // one that has aged out of the window.
        assert!(check(&quote_for(&t, 13, 100), 13, 100, Some(&pinned)).is_err());
        assert!(check(&quote_for(&t, 3, 100), 3, 100, Some(&pinned)).is_err());
        // Bound to its heartbeat counter.
        assert!(check(&ok, 12, 101, Some(&pinned)).is_err());
    }
}
