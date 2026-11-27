//! Pure-`std` client control-plane helpers for FPP v1 (zero `tokio`, zero `quinn`,
//! zero `rustls`, zero C crypto deps):
//!
//! - [`admit`]: connects directly to `fppd` Verifier and Broker over our owned
//!   `Noise_IK` TCP transport to obtain a verified `AR`, `SAT`, matched server
//!   address, and pinned server Noise key — usable directly from any Rust or
//!   C/C++ game client without shelling out to `fppd ticket`.
//! - [`check_checkpoint`]: queries `fppd`'s Transparency Log (`Purpose::Gossip`)
//!   for a game server's `CheckpointHead`, verifying the C2SP `tlog-checkpoint`
//!   signature (Ed25519 + ML-DSA-65 when `s1h` is enabled), witness
//!   `cosignature/v1`, and RFC 9162 Merkle inclusion proof (EVD-02 / EVD-03).
//! - [`report_equivocation`]: reports a proven split-view Checkpoint to Server
//!   Liveness (`Purpose::Report`), causing immediate revocation of the rogue server.

use crate::bundle::{KeyBundle, LogKeys};
use crate::control::{
    evidence_request_sign_bytes, match_request_sign_bytes, AttestChallenge, ChallengeRequest,
    EquivocationReport, EvidenceAnswer, EvidenceRequest, GossipAnswer, GossipRequest, MatchAnswer,
    MatchRequest, Purpose, ReportAnswer, CONTROL_VERSION,
};
use crate::crypto::{now_s, Ed25519Signer, SessionSigner, Signer};
use crate::log::{self, Checkpoint, Note};
use crate::merkle;
use crate::tokens::{verify_ar, verify_sat};
use crate::transport::sync::NoiseStream;
use crate::types::{DeviceTier, Digest, Reason};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ClientError {
    pub message: String,
    /// Optional FPP protocol refusal reason code (`fpp::types::Reason`).
    pub reason: Option<u16>,
}

impl ClientError {
    fn msg(m: impl Into<String>) -> Self {
        Self {
            message: m.into(),
            reason: None,
        }
    }

    fn refused(what: &str, code: u16) -> Self {
        Self {
            message: format!("{what} refused ({code})"),
            reason: Some(code),
        }
    }
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClientError {}

/// Parameters for direct client admission against `fppd` (Verifier + Broker).
pub struct AdmitConfig {
    pub authority: SocketAddr,
    pub bundle: KeyBundle,
    pub queue: String,
    pub client_build: [u8; 32],
    /// Optional caller-supplied 32-byte Ed25519 session seed (`None` generates a fresh key).
    pub session_seed: Option<[u8; 32]>,
    pub timeout: Duration,
}

/// Verified admission material returned by [`admit`].
#[derive(Clone, Debug)]
pub struct AdmittedTicket {
    pub session_seed: [u8; 32],
    pub ar: Vec<u8>,
    pub sat: Vec<u8>,
    pub gs_addr: String,
    pub gs_noise_static: [u8; 32],
    pub liveness_key: [u8; 32],
    pub match_id: [u8; 16],
    pub slot: u16,
    pub tier: DeviceTier,
    pub did: [u8; 32],
}

/// Outcome of auditing a game server's Checkpoint against the Transparency Log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointAudit {
    /// Proven included under a witness-cosigned Transparency Log checkpoint.
    Included { index: u64, tree_size: u64 },
    /// Not yet indexed in the log; retry after the next witness round.
    Pending,
    /// Proven split view: the log holds a different Checkpoint digest for the same
    /// `(match_id, epoch)`. Report the conflicting signed Checkpoint via
    /// [`report_equivocation`].
    SplitView { logged: [u8; 32] },
}

fn open_control_sync(
    addr: SocketAddr,
    server_pub: &[u8; 32],
    purpose: Purpose,
    timeout: Duration,
) -> Result<(NoiseStream, [u8; 32]), ClientError> {
    let mut stream = NoiseStream::connect(addr, server_pub, None, timeout)
        .map_err(|e| ClientError::msg(format!("connect {addr}: {e}")))?;
    stream
        .send(&ChallengeRequest {
            version: CONTROL_VERSION,
            purpose,
        })
        .map_err(|e| ClientError::msg(format!("ChallengeRequest: {e}")))?;
    let challenge: AttestChallenge = stream
        .recv()
        .map_err(|e| ClientError::msg(format!("AttestChallenge: {e}")))?;
    Ok((stream, challenge.nonce))
}

/// Request an Attestation Result from Verifier and a Session Admission Token
/// from Broker directly over `Noise_IK` TCP, retrying while the region has no
/// live server (`Reason::ServerDraining`) until `cfg.timeout` expires.
pub fn admit(cfg: &AdmitConfig) -> Result<AdmittedTicket, ClientError> {
    let verifier_pub = cfg
        .bundle
        .transport_key("verifier")
        .map_err(|e| ClientError::msg(format!("key bundle verifier transport: {e}")))?;
    let broker_pub = cfg
        .bundle
        .transport_key("broker")
        .map_err(|e| ClientError::msg(format!("key bundle broker transport: {e}")))?;
    let keys = cfg.bundle.keyset();

    let session_seed = match cfg.session_seed {
        Some(s) => s,
        None => {
            let mut s = [0u8; 32];
            OsRng.fill_bytes(&mut s);
            s
        }
    };
    let signer = Ed25519Signer::new(SigningKey::from_bytes(&session_seed));
    let session_key = signer.session_key();
    let session_pub = session_key.to_bytes();
    let platform = std::env::consts::OS.to_string();

    let deadline = Instant::now() + cfg.timeout;
    let io_timeout = cfg.timeout.min(Duration::from_secs(10));

    loop {
        // 1) Verifier -> AR
        let (mut vs, vchal) =
            open_control_sync(cfg.authority, &verifier_pub, Purpose::Evidence, io_timeout)?;
        let emsg =
            evidence_request_sign_bytes(&vchal, &session_pub, &platform, &cfg.client_build, &[]);
        let pop_sig: [u8; 64] = signer.sign(&emsg).try_into().expect("64-byte sig");
        vs.send(&EvidenceRequest {
            session_pub: session_pub.clone(),
            pop_sig,
            platform: platform.clone(),
            client_build: cfg.client_build,
            evidence: Vec::new(),
        })
        .map_err(|e| ClientError::msg(format!("EvidenceRequest: {e}")))?;
        let ar = match vs
            .recv::<EvidenceAnswer>()
            .map_err(|e| ClientError::msg(format!("EvidenceAnswer: {e}")))?
        {
            EvidenceAnswer::Ar(ar) => ar,
            EvidenceAnswer::Refused { code } => return Err(ClientError::refused("verifier", code)),
            EvidenceAnswer::Activate(_) => {
                return Err(ClientError::msg("unexpected TPM activation challenge"))
            }
        };
        let ar_claims = verify_ar(&ar, &keys, now_s())
            .map_err(|e| ClientError::msg(format!("verify AR: {e}")))?;
        if ar_claims.cnf != session_key || ar_claims.nonce != vchal {
            return Err(ClientError::msg("AR binding mismatch"));
        }

        // 2) Broker -> SAT
        let (mut bs, bchal) =
            open_control_sync(cfg.authority, &broker_pub, Purpose::Match, io_timeout)?;
        let mmsg = match_request_sign_bytes(&bchal, &ar, &cfg.queue);
        let mpop: [u8; 64] = signer.sign(&mmsg).try_into().expect("64-byte sig");
        bs.send(&MatchRequest {
            ar: ar.clone(),
            queue: cfg.queue.clone(),
            pop_sig: mpop,
        })
        .map_err(|e| ClientError::msg(format!("MatchRequest: {e}")))?;

        match bs
            .recv::<MatchAnswer>()
            .map_err(|e| ClientError::msg(format!("MatchAnswer: {e}")))?
        {
            MatchAnswer::Granted {
                sat,
                gs_addr,
                gs_noise_static,
            } => {
                let sat_claims = verify_sat(&sat, &keys, now_s())
                    .map_err(|e| ClientError::msg(format!("verify SAT: {e}")))?;
                if sat_claims.cnf != session_key {
                    return Err(ClientError::msg("SAT session-key binding mismatch"));
                }
                return Ok(AdmittedTicket {
                    session_seed,
                    ar,
                    sat,
                    gs_addr,
                    gs_noise_static,
                    liveness_key: cfg.bundle.server_liveness.to_bytes(),
                    match_id: sat_claims.match_id.0,
                    slot: sat_claims.slot,
                    tier: sat_claims.tier,
                    did: sat_claims.did.0,
                });
            }
            MatchAnswer::Refused { code }
                if code == Reason::ServerDraining as u16 && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(250));
            }
            MatchAnswer::Refused { code } => return Err(ClientError::refused("broker", code)),
        }
    }
}

/// Verify a C2SP Transparency Log checkpoint note under the log key (Ed25519,
/// plus ML-DSA-65 when built with `s1h`) and at least one known witness cosignature.
pub fn verify_tlog_checkpoint(
    log_keys: &LogKeys,
    note: &str,
) -> Result<(u64, Digest), ClientError> {
    let parsed = Note::parse(note).map_err(|e| ClientError::msg(format!("tlog note: {e}")))?;
    #[cfg(feature = "s1h")]
    {
        parsed
            .verify_hybrid(&log_keys.origin, &log_keys.ed25519, &log_keys.ml_dsa)
            .map_err(|e| ClientError::msg(format!("tlog hybrid signature: {e}")))?;
    }
    #[cfg(not(feature = "s1h"))]
    {
        parsed
            .verify(&log_keys.origin, &log_keys.ed25519)
            .map_err(|e| ClientError::msg(format!("tlog ed25519 signature: {e}")))?;
    }
    if !log_keys
        .witnesses
        .iter()
        .any(|(name, key)| parsed.verify_cosignature(name, key).is_ok())
    {
        return Err(ClientError::msg(
            "tlog checkpoint not cosigned by a known witness",
        ));
    }
    let cp = Checkpoint::parse(&parsed.text)
        .map_err(|e| ClientError::msg(format!("tlog checkpoint body: {e}")))?;
    if cp.origin != log_keys.origin {
        return Err(ClientError::msg("tlog checkpoint origin mismatch"));
    }
    Ok((cp.size, Digest(cp.root)))
}

fn verify_inclusion_proof(
    log_keys: &LogKeys,
    note: &str,
    leaf: &[u8],
    index: u64,
    proof: &[[u8; 32]],
) -> Result<u64, ClientError> {
    let (size, root) = verify_tlog_checkpoint(log_keys, note)?;
    let proof: Vec<Digest> = proof.iter().copied().map(Digest).collect();
    if !merkle::verify_inclusion(&merkle::leaf_hash(leaf), index, size, &proof, &root) {
        return Err(ClientError::msg("tlog Merkle inclusion proof invalid"));
    }
    Ok(size)
}

/// Audit a game server's Checkpoint `(match_id, epoch, digest)` against the
/// region's Transparency Log (`Purpose::Gossip`).
pub fn check_checkpoint(
    log_addr: SocketAddr,
    bundle: &KeyBundle,
    match_id: &[u8; 16],
    epoch: u32,
    digest: &[u8; 32],
    timeout: Duration,
) -> Result<CheckpointAudit, ClientError> {
    let log_keys = bundle
        .log
        .as_ref()
        .ok_or_else(|| ClientError::msg("key bundle names no Transparency Log"))?;
    let server_pub = bundle
        .transport_key("log")
        .map_err(|e| ClientError::msg(format!("key bundle log transport: {e}")))?;
    let (mut stream, _) = open_control_sync(log_addr, &server_pub, Purpose::Gossip, timeout)?;
    stream
        .send(&GossipRequest {
            match_id: *match_id,
            epoch,
            digest: *digest,
        })
        .map_err(|e| ClientError::msg(format!("GossipRequest: {e}")))?;
    let answer: GossipAnswer = stream
        .recv()
        .map_err(|e| ClientError::msg(format!("GossipAnswer: {e}")))?;
    match answer {
        GossipAnswer::Pending => Ok(CheckpointAudit::Pending),
        GossipAnswer::Included {
            checkpoint,
            index,
            proof,
        } => {
            let leaf = log::leaf::checkpoint(match_id, epoch, digest);
            let tree_size = verify_inclusion_proof(log_keys, &checkpoint, &leaf, index, &proof)?;
            Ok(CheckpointAudit::Included { index, tree_size })
        }
        GossipAnswer::Conflict {
            checkpoint,
            index,
            logged,
            proof,
        } => {
            if logged == *digest {
                return Err(ClientError::msg("log reported own digest as conflict"));
            }
            let leaf = log::leaf::checkpoint(match_id, epoch, &logged);
            verify_inclusion_proof(log_keys, &checkpoint, &leaf, index, &proof)?;
            Ok(CheckpointAudit::SplitView { logged })
        }
    }
}

/// Report a conflicting signed Checkpoint to Server Liveness (`Purpose::Report`)
/// so the equivocating game server is immediately revoked.
pub fn report_equivocation(
    liveness_addr: SocketAddr,
    bundle: &KeyBundle,
    signed_checkpoint: &[u8],
    timeout: Duration,
) -> Result<ReportAnswer, ClientError> {
    let server_pub = bundle
        .transport_key("liveness")
        .map_err(|e| ClientError::msg(format!("key bundle liveness transport: {e}")))?;
    let (mut stream, _) = open_control_sync(liveness_addr, &server_pub, Purpose::Report, timeout)?;
    stream
        .send(&EquivocationReport {
            checkpoint: signed_checkpoint.to_vec(),
        })
        .map_err(|e| ClientError::msg(format!("EquivocationReport: {e}")))?;
    stream
        .recv()
        .map_err(|e| ClientError::msg(format!("ReportAnswer: {e}")))
}
