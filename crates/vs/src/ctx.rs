// crates/vs/src/ctx.rs
use common::config::VsConfig;
use common::keys::ServiceKeys;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use fpp_types::Digest;
use std::collections::VecDeque;
use std::sync::Arc;

#[derive(Clone)]
pub struct VsCtx {
    /// Signs JoinAccepts (GS admission).
    pub vs_sk: Arc<SigningKey>,
    /// Verifier, Broker and Server Liveness role keys (04 §4).
    pub keys: Arc<ServiceKeys>,
    pub sessions: Arc<DashMap<[u8; 16], Session>>,
    pub config: VsConfig,
    /// Client evidence policy and App Attest keys (P3).
    pub attestation: Arc<crate::appraisal::ClientAttestation>,
}

/// One admitted game server instance; its session id is also the id of the
/// match it hosts.
#[derive(Clone)]
pub struct Session {
    /// Instance key: signs Checkpoints; certified by every SAR.
    pub instance_pub: [u8; 32],
    /// fpp-session static key and address of the game port.
    pub noise_static: [u8; 32],
    pub game_addr: String,
    pub sw_hash: [u8; 32],
    pub last_seen_ms: u64,
    pub revoked: bool,
    /// Epoch and digest of the last verified Checkpoint (the `prev` chain).
    pub last_checkpoint: Option<(u32, Digest)>,
    /// TPM attestation key and PCRs pinned at join; re-attestation must match.
    pub tpm: Option<crate::attest::PinnedTpm>,
    /// (seq, exact bytes) of the latest SARs issued, newest last (at most
    /// `attest::RECENT_SARS`). Re-attestation quotes are seeded by one.
    pub recent_sars: VecDeque<(u64, Vec<u8>)>,
    /// Next player slot the Broker hands out for this match.
    pub next_slot: u16,
}

impl VsCtx {
    pub fn new(vs_sk: Arc<SigningKey>) -> Self {
        Self::new_with_config(vs_sk, VsConfig::default())
    }

    pub fn new_with_config(vs_sk: Arc<SigningKey>, config: VsConfig) -> Self {
        let keys = Arc::new(ServiceKeys::derive(&vs_sk.to_bytes()));
        Self {
            vs_sk,
            keys,
            sessions: Arc::new(DashMap::new()),
            config,
            attestation: Arc::new(crate::appraisal::ClientAttestation::default()),
        }
    }

    pub fn revoke(&self, session_id: &[u8; 16], why: &str) {
        if let Some(mut s) = self.sessions.get_mut(session_id) {
            if !s.revoked {
                s.revoked = true;
                crate::metrics::REVOCATIONS_TOTAL.inc();
                eprintln!(
                    "[VS] REVOKED session {}.. ({why}); no further SARs",
                    hex::encode(&session_id[..4])
                );
            }
        }
    }
}
