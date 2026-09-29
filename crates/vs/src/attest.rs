// crates/vs/src/attest.rs
//! Appraisal of the prototype's TPM quotes (findings F04, F05 and F21 in
//! docs/anticheat/07-gap-analysis-and-roadmap.md). Pure functions, so every
//! rule is tested without a network.
//!
//! What this fixes: the VS, not the GS, chooses quote freshness (a
//! single-use challenge at join; a recent SAR, whose signature the GS cannot
//! predict, for re-attestation), and quotes must come from an enrolled or
//! session-pinned attestation key instead of whatever key the quote carries.
//! Re-attestation PCRs must equal the ones measured at join (or the
//! configured baseline). What remains for the Verifier (roadmap P3): EK
//! certificate chains, credential activation, TPMS_ATTEST parsing and
//! event-log replay for real TPMs.

use anyhow::{anyhow, bail, Result};
use common::config::VsConfig;
use common::tpm::{join_quote_nonce, reattest_quote_nonce, verify_quote, TpmQuote};
use std::collections::{BTreeMap, VecDeque};

/// Re-attestation quotes may be seeded by any of this many latest SARs
/// (at one SAR per 2 s: the last 16 s).
pub const RECENT_SARS: usize = 8;

/// What the join quote established for the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedTpm {
    pub ak: Vec<u8>,
    pub pcrs: BTreeMap<u8, [u8; 32]>,
}

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

fn baselines(cfg: &VsConfig) -> Option<&BTreeMap<u8, [u8; 32]>> {
    (!cfg.required_pcr_baselines.is_empty()).then_some(&cfg.required_pcr_baselines)
}

/// Appraise the quote in a JoinRequest against the challenge this VS issued
/// on this connection. Returns what to pin for the session.
pub fn appraise_join_quote(
    cfg: &VsConfig,
    challenge: &[u8; 32],
    join_sign_bytes: &[u8],
    quote: Option<&TpmQuote>,
) -> Result<Option<PinnedTpm>> {
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
    Ok(Some(PinnedTpm {
        ak: quote.ak_pub.clone(),
        pcrs: quote.pcr_values.clone(),
    }))
}

/// Appraise a re-attestation quote sent with the Checkpoint for `epoch`. It
/// must come from the key pinned at join, be seeded by a SAR this VS issued
/// recently, and show the PCR values measured at join (or the configured
/// baseline).
pub fn appraise_reattest_quote(
    cfg: &VsConfig,
    session_id: &[u8; 16],
    epoch: u64,
    quote: &TpmQuote,
    quote_sar_seq: u64,
    pinned: Option<&PinnedTpm>,
    recent_sars: &VecDeque<(u64, Vec<u8>)>,
) -> Result<()> {
    let pinned = pinned.ok_or_else(|| anyhow!("no attestation key was pinned at join"))?;
    if quote.ak_pub != pinned.ak {
        bail!("re-attestation quote is signed by a different attestation key");
    }
    let (_, sar) = recent_sars
        .iter()
        .find(|(seq, _)| *seq == quote_sar_seq)
        .ok_or_else(|| anyhow!("quote is not seeded by a recent SAR (#{quote_sar_seq})"))?;
    verify_quote(
        quote,
        &reattest_quote_nonce(session_id, epoch, sar),
        Some(baselines(cfg).unwrap_or(&pinned.pcrs)),
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
        // Same challenge, another JoinRequest (e.g. another instance key): rejected.
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
        assert_eq!(pinned.unwrap().ak, ak(&honest).to_vec());
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
    fn reattestation_needs_the_pinned_key_a_recent_sar_and_unchanged_pcrs() {
        let cfg = VsConfig::default();
        let t = tpm(1);
        let pinned =
            appraise_join_quote(&cfg, &[1; 32], b"j", Some(&join_quote(&t, &[1; 32], b"j")))
                .unwrap()
                .unwrap();
        let sars: VecDeque<(u64, Vec<u8>)> = (10..=12).map(|s| (s, vec![s as u8; 300])).collect();
        let quote_for = |t: &SimulatedTpm, seq: u64, epoch: u64| {
            t.quote(
                &[0, 1],
                &reattest_quote_nonce(&SESSION, epoch, &[seq as u8; 300]),
            )
            .unwrap()
        };
        let check = |q: &TpmQuote, seq: u64, epoch: u64, p: Option<&PinnedTpm>| {
            appraise_reattest_quote(&cfg, &SESSION, epoch, q, seq, p, &sars)
        };

        let ok = quote_for(&t, 12, 100);
        assert!(check(&ok, 12, 100, Some(&pinned)).is_ok());
        // Nothing pinned at join: a checkpoint cannot introduce a key.
        assert!(check(&ok, 12, 100, None).is_err());
        // Another TPM (or a software key) cannot take over mid-session.
        assert!(check(&quote_for(&tpm(2), 12, 100), 12, 100, Some(&pinned)).is_err());
        // Seeded by a SAR the VS has not issued (made ahead of time), or by
        // one that has aged out of the window.
        assert!(check(&quote_for(&t, 13, 100), 13, 100, Some(&pinned)).is_err());
        assert!(check(&quote_for(&t, 3, 100), 3, 100, Some(&pinned)).is_err());
        // Bound to its epoch.
        assert!(check(&ok, 12, 101, Some(&pinned)).is_err());
        // Code changed after join (PCR 0 extended again): refused.
        let mut patched = tpm(1);
        patched.extend_pcr(0, b"hot patch").unwrap();
        assert!(check(&quote_for(&patched, 12, 100), 12, 100, Some(&pinned)).is_err());
    }
}
