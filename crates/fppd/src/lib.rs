//! Unified Fair-Play Protocol authority & trust-plane daemon (`fppd`).
//!
//! Replaces 7 separate daemon processes (`svc-liveness`, `svc-verifier`,
//! `svc-broker`, `svc-revocation`, `svc-evidence`, `svc-log`, `svc-witness`)
//! and their mTLS/QUIC/bincode ceremony with ONE lean Rust node speaking our
//! owned `Noise_IK_25519_ChaChaPoly_SHA256` TCP + deterministic CBOR protocol.
//!
//! Security model is preserved intact:
//! - Every trust role holds its own independent signing keypair with strict
//!   `fpp::crypto::KeyRole` context allowlists.
//! - Every connection authenticates the authority via its pinned 32-byte X25519
//!   `transport_pub` from `keys/fpp_key_bundle.json` (F01).
//! - Privileged operations (Enforcement, Auditor, Witness, Broker→Liveness)
//!   authenticate callers by their Noise IK initiator static key.
//! - Can run all-in-one (`fppd serve`) OR per-role (`fppd role <role>`),
//!   including an independent external witness (`fppd role witness`).

pub mod broker;
pub mod evidence;
pub mod keys;
pub mod liveness;
pub mod revocation;
pub mod tlog;
pub mod verifier;

use anyhow::{anyhow, Context, Result};
use broker::{BrokerRole, Placer};
use evidence::EvidenceStore;
use fpp::bundle::KeyBundle;
use fpp::control::{
    AttestChallenge, ChallengeRequest, CredentialResponse, EquivocationReport, EvidenceAnswer,
    EvidenceRequest, EvidenceStoreRequest, EvidenceStoreResponse, GossipRequest, LogRequest,
    LogResponse, MatchRequest, PlaceResponse, Purpose, ReportAnswer, RevocationRequest,
    RevocationResponse, CONTROL_VERSION, MAX_CONTROL_FRAME, MAX_JOIN_FRAME,
};
use fpp::crypto::now_s;
use fpp::log::{Checkpoint, Log, Note, Witness};
use fpp::session::StaticKeypair;
use fpp::transport::async_io::AsyncNoiseStream;
use fpp::transport::DEFAULT_DEADLINE;
use keys::{CellKeys, LOG_ORIGIN, WITNESS_NAME};
use liveness::{LivenessConfig, LivenessRole};
use rand::{rngs::OsRng, RngCore};
use revocation::RevocationFeed;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tlog::{spawn_internal_witness, LogEngine};
use tokio::net::TcpListener;
use verifier::{ClientAttestation, VerifierRole, VerifierStep};

/// One regional authority node (all-in-one or single-role subset).
pub struct Authority {
    pub transport: StaticKeypair,
    /// Noise static X25519 public keys authorized for admin / inter-role RPCs.
    pub admin_keys: Vec<[u8; 32]>,
    pub deadline: Duration,
    pub liveness: Option<Arc<LivenessRole>>,
    pub verifier: Option<Arc<VerifierRole>>,
    pub broker: Option<Arc<BrokerRole>>,
    pub revocation: Option<Arc<RevocationFeed>>,
    pub evidence: Option<Arc<EvidenceStore>>,
    pub log: Option<Arc<LogEngine>>,
}

/// Running handle for an all-in-one authority (stops background witness on drop).
pub struct RunningAuthority {
    pub authority: Arc<Authority>,
    pub bundle: KeyBundle,
    pub keys: CellKeys,
    witness_task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for RunningAuthority {
    fn drop(&mut self) {
        if let Some(t) = self.witness_task.take() {
            t.abort();
        }
    }
}

impl Authority {
    /// Open a complete regional authority cell in `dir`, write `bundle_path`,
    /// and optionally spawn the internal Witness cosigner.
    pub fn open_all(
        dir: &Path,
        bundle_path: Option<&Path>,
        liveness_cfg: LivenessConfig,
        attestation: ClientAttestation,
        witness_interval: Option<Duration>,
    ) -> Result<RunningAuthority> {
        let cell_keys = CellKeys::open(dir)?;
        let bundle = cell_keys.bundle();
        if let Some(p) = bundle_path {
            bundle
                .save(p)
                .map_err(|e| anyhow!("save bundle {}: {e}", p.display()))?;
        }

        let log_key = keys::load_log_hybrid(dir)?;
        let raw_log = Log::open(dir.join("log/data"), LOG_ORIGIN, log_key, 60)
            .map_err(|e| anyhow!("open Transparency Log: {e}"))?;
        let witnesses = vec![(
            WITNESS_NAME.to_string(),
            cell_keys.witness.verifying_key().to_bytes(),
        )];
        let log = Arc::new(LogEngine::open(raw_log, witnesses)?);

        let witness_task = match witness_interval {
            Some(interval) => {
                let w = Witness::open(
                    WITNESS_NAME,
                    cell_keys.witness.clone(),
                    LOG_ORIGIN,
                    cell_keys.log.ed25519_public().to_bytes(),
                    cell_keys.log.ml_dsa_public().to_vec(),
                    dir.join("witness/state"),
                )
                .map_err(|e| anyhow!("open Witness: {e}"))?;
                Some(spawn_internal_witness(log.clone(), w, interval))
            }
            None => None,
        };

        let evidence = Arc::new(EvidenceStore::open(dir.join("evidence"))?);
        let revocation = Arc::new(RevocationFeed::open(
            &dir.join("revocation/events.log"),
            cell_keys.enforcement.verifying_key(),
            Some(log.clone()),
        )?);
        let liveness_deadline = Duration::from_millis(liveness_cfg.admission_timeout_ms);
        let liveness = LivenessRole::new(
            fpp::crypto::Ed25519Signer::new(keys::load_ed25519(dir, "liveness")?),
            liveness_cfg,
            Some(evidence.clone()),
            Some(log.clone()),
            Some(revocation.clone()),
        );
        let verifier = Arc::new(VerifierRole {
            key: fpp::crypto::Ed25519Signer::new(keys::load_ed25519(dir, "verifier")?),
            attestation,
            deadline: liveness_deadline,
        });
        let broker = BrokerRole::new(
            fpp::crypto::Ed25519Signer::new(keys::load_ed25519(dir, "broker")?),
            cell_keys.verifier.verifying_key(),
            Placer::Local(liveness.clone()),
            Some(revocation.clone()),
        );

        let authority = Arc::new(Authority {
            transport: cell_keys.transport.clone(),
            admin_keys: vec![cell_keys.admin.public, cell_keys.transport.public],
            deadline: liveness_deadline,
            liveness: Some(liveness),
            verifier: Some(verifier),
            broker: Some(broker),
            revocation: Some(revocation),
            evidence: Some(evidence),
            log: Some(log),
        });

        Ok(RunningAuthority {
            authority,
            bundle,
            keys: cell_keys,
            witness_task,
        })
    }

    fn is_admin(&self, peer_static: &[u8; 32]) -> bool {
        self.admin_keys
            .iter()
            .any(|k| fpp::crypto::ct_eq(k, peer_static))
    }

    /// Accept Noise_IK TCP connections on `listener` until shutdown.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_connection(sock).await {
                    eprintln!("[fppd] connection closed: {e:#}");
                }
            });
        }
    }

    pub async fn handle_connection(self: Arc<Self>, sock: tokio::net::TcpStream) -> Result<()> {
        let mut stream = AsyncNoiseStream::accept(sock, &self.transport, self.deadline).await?;
        let peer_static = stream.peer_static;
        let req: ChallengeRequest = stream
            .recv_timeout(MAX_CONTROL_FRAME, self.deadline)
            .await
            .context("ChallengeRequest")?;
        if req.version != CONTROL_VERSION {
            anyhow::bail!(
                "protocol version mismatch: got {}, expected {CONTROL_VERSION}",
                req.version
            );
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        stream.send(&AttestChallenge { nonce: challenge }).await?;

        let admin = self.is_admin(&peer_static);

        match req.purpose {
            Purpose::GsJoin => {
                let Some(liveness) = self.liveness.clone() else {
                    anyhow::bail!("liveness role not enabled on this endpoint");
                };
                liveness.admit_and_serve(stream, challenge).await
            }
            Purpose::Report => {
                let Some(liveness) = self.liveness.as_ref() else {
                    stream
                        .send(&ReportAnswer::Rejected("liveness role not enabled".into()))
                        .await?;
                    return Ok(());
                };
                let report: EquivocationReport = stream
                    .recv_timeout(MAX_CONTROL_FRAME, self.deadline)
                    .await?;
                let answer = liveness.judge_report(&report).await;
                stream.send(&answer).await?;
                Ok(())
            }
            Purpose::Evidence => {
                let Some(verifier) = self.verifier.as_ref() else {
                    anyhow::bail!("verifier role not enabled on this endpoint");
                };
                let ev_req: EvidenceRequest = stream
                    .recv_timeout(MAX_JOIN_FRAME, verifier.deadline)
                    .await?;
                let answer = match verifier.answer(&challenge, &ev_req) {
                    VerifierStep::Answer(a) => a,
                    VerifierStep::Activate(cred, pending) => {
                        stream.send(&EvidenceAnswer::Activate(cred)).await?;
                        let resp: CredentialResponse = stream
                            .recv_timeout(MAX_CONTROL_FRAME, verifier.deadline)
                            .await?;
                        verifier.activated(*pending, &resp.secret)
                    }
                };
                stream.send(&answer).await?;
                Ok(())
            }
            Purpose::Match => {
                let Some(broker) = self.broker.as_ref() else {
                    anyhow::bail!("broker role not enabled on this endpoint");
                };
                let mreq: MatchRequest = stream
                    .recv_timeout(MAX_CONTROL_FRAME, self.deadline)
                    .await?;
                let answer = broker.answer(&challenge, &mreq).await;
                stream.send(&answer).await?;
                Ok(())
            }
            Purpose::Gossip => {
                let Some(log) = self.log.as_ref() else {
                    anyhow::bail!("log role not enabled on this endpoint");
                };
                // Allow multiple gossip queries on one connection.
                while let Ok(greq) = stream
                    .recv_timeout::<GossipRequest>(MAX_CONTROL_FRAME, self.deadline)
                    .await
                {
                    let ans = log.gossip(&greq).await;
                    stream.send(&ans).await?;
                }
                Ok(())
            }
            Purpose::Place => {
                let resp = if !admin {
                    PlaceResponse::Refused("unauthorized caller".into())
                } else if let Some(liveness) = self.liveness.as_ref() {
                    match liveness.place() {
                        Some(p) => PlaceResponse::Placed(p),
                        None => PlaceResponse::NoServer,
                    }
                } else {
                    PlaceResponse::Refused("liveness role not enabled".into())
                };
                stream.send(&resp).await?;
                Ok(())
            }
            Purpose::RevocationPublish | Purpose::RevocationSince => {
                let Some(feed) = self.revocation.as_ref() else {
                    stream
                        .send(&RevocationResponse::Refused(
                            "revocation role not enabled".into(),
                        ))
                        .await?;
                    return Ok(());
                };
                let rreq: RevocationRequest = stream
                    .recv_timeout(MAX_CONTROL_FRAME, self.deadline)
                    .await?;
                let resp = feed.handle_rpc(rreq, admin, admin).await;
                stream.send(&resp).await?;
                Ok(())
            }
            Purpose::EvidencePut | Purpose::EvidenceGet | Purpose::EvidenceList => {
                let Some(store) = self.evidence.as_ref() else {
                    stream
                        .send(&EvidenceStoreResponse::Refused(
                            "evidence role not enabled".into(),
                        ))
                        .await?;
                    return Ok(());
                };
                let ereq: EvidenceStoreRequest =
                    stream.recv_timeout(MAX_JOIN_FRAME, self.deadline).await?;
                let resp = store.handle_rpc(ereq, admin, admin).await;
                stream.send(&resp).await?;
                Ok(())
            }
            Purpose::LogAdd
            | Purpose::LogCheckpoint
            | Purpose::LogInclusion
            | Purpose::LogConsistency
            | Purpose::LogCosign => {
                let Some(log) = self.log.as_ref() else {
                    stream
                        .send(&LogResponse::Refused("log role not enabled".into()))
                        .await?;
                    return Ok(());
                };
                let lreq: LogRequest = stream.recv_timeout(MAX_JOIN_FRAME, self.deadline).await?;
                let resp = log.handle_rpc(lreq, admin, admin).await;
                stream.send(&resp).await?;
                Ok(())
            }
        }
    }
}

// ------------------------------------------------------------------ Noise_IK RPC client helpers

/// Connect to an authority endpoint and complete `ChallengeRequest` → `AttestChallenge`.
pub async fn open_control(
    addr: SocketAddr,
    server_pub: &[u8; 32],
    local: Option<&StaticKeypair>,
    purpose: Purpose,
) -> Result<(AsyncNoiseStream, [u8; 32])> {
    let mut stream = AsyncNoiseStream::connect(addr, server_pub, local, DEFAULT_DEADLINE).await?;
    stream
        .send(&ChallengeRequest {
            version: CONTROL_VERSION,
            purpose,
        })
        .await?;
    let chal: AttestChallenge = stream
        .recv_timeout(MAX_CONTROL_FRAME, DEFAULT_DEADLINE)
        .await?;
    Ok((stream, chal.nonce))
}

/// Publish a signed `RevocationEvent` to `authority` as `admin`.
pub async fn rpc_publish_revocation(
    authority: SocketAddr,
    server_pub: &[u8; 32],
    admin: &StaticKeypair,
    cose: Vec<u8>,
) -> Result<(u64, Option<u64>)> {
    let (mut s, _) = open_control(
        authority,
        server_pub,
        Some(admin),
        Purpose::RevocationPublish,
    )
    .await?;
    s.send(&RevocationRequest::Publish(cose)).await?;
    match s.recv::<RevocationResponse>().await? {
        RevocationResponse::Published { seq, log_index } => Ok((seq, log_index)),
        RevocationResponse::Refused(why) => Err(anyhow!("revocation refused: {why}")),
        other => Err(anyhow!("unexpected response: {other:?}")),
    }
}

/// Log an enforcement record, sign the `RevocationEvent`, and publish it to
/// `authority` over `Noise_IK` TCP. Returns `(seq, record_log_idx, event_log_idx)`.
pub async fn rpc_enforce(
    authority: SocketAddr,
    server_pub: &[u8; 32],
    admin: &StaticKeypair,
    enf_key: &fpp::crypto::Ed25519Signer,
    order: &revocation::Order,
) -> Result<(u64, u64, Option<u64>)> {
    let now = now_s();
    let record = revocation::encode_enforcement_record(order, now);
    let rec_idx = rpc_log_add(authority, server_pub, admin, vec![record.clone()]).await?;
    let (_, signed) = revocation::sign_order(enf_key, order, &record, now)?;
    let (seq, ev_idx) = rpc_publish_revocation(authority, server_pub, admin, signed).await?;
    Ok((seq, rec_idx, ev_idx))
}

/// Append entries to the Transparency Log at `authority` as `admin`.
pub async fn rpc_log_add(
    authority: SocketAddr,
    server_pub: &[u8; 32],
    admin: &StaticKeypair,
    entries: Vec<Vec<u8>>,
) -> Result<u64> {
    let (mut s, _) = open_control(authority, server_pub, Some(admin), Purpose::LogAdd).await?;
    s.send(&LogRequest::Add(entries)).await?;
    match s.recv::<LogResponse>().await? {
        LogResponse::Added(v) if !v.is_empty() => Ok(v[0].0),
        LogResponse::Refused(why) => Err(anyhow!("log refused: {why}")),
        other => Err(anyhow!("unexpected log response: {other:?}")),
    }
}

/// Read evidence digests for `match_id` as an authorized auditor (`admin`).
pub async fn rpc_evidence_list(
    authority: SocketAddr,
    server_pub: &[u8; 32],
    admin: &StaticKeypair,
    match_id: [u8; 16],
) -> Result<Vec<[u8; 32]>> {
    let (mut s, _) =
        open_control(authority, server_pub, Some(admin), Purpose::EvidenceList).await?;
    s.send(&EvidenceStoreRequest::List(match_id)).await?;
    match s.recv_max::<EvidenceStoreResponse>(MAX_JOIN_FRAME).await? {
        EvidenceStoreResponse::Digests(d) => Ok(d),
        EvidenceStoreResponse::Refused(why) => Err(anyhow!("evidence refused: {why}")),
        other => Err(anyhow!("unexpected evidence response: {other:?}")),
    }
}

/// Fetch one content-addressed object from the Evidence Store and re-verify SHA-256 on the client.
pub async fn rpc_evidence_get(
    authority: SocketAddr,
    server_pub: &[u8; 32],
    admin: &StaticKeypair,
    digest: [u8; 32],
) -> Result<Option<Vec<u8>>> {
    let (mut s, _) = open_control(authority, server_pub, Some(admin), Purpose::EvidenceGet).await?;
    s.send(&EvidenceStoreRequest::Get(digest)).await?;
    match s.recv_max::<EvidenceStoreResponse>(MAX_JOIN_FRAME).await? {
        EvidenceStoreResponse::Object(Some(bytes)) => {
            if fpp::crypto::sha256(&bytes) != digest {
                anyhow::bail!("evidence digest mismatch on client read");
            }
            Ok(Some(bytes))
        }
        EvidenceStoreResponse::Object(None) => Ok(None),
        EvidenceStoreResponse::Refused(why) => Err(anyhow!("evidence refused: {why}")),
        other => Err(anyhow!("unexpected evidence response: {other:?}")),
    }
}

/// One external Witness round over `Noise_IK` TCP against a remote Transparency Log.
pub async fn external_witness_round(
    log_addr: SocketAddr,
    server_pub: &[u8; 32],
    witness_transport: &StaticKeypair,
    witness: &mut Witness,
) -> Result<Option<u64>> {
    let (mut s, _) = open_control(
        log_addr,
        server_pub,
        Some(witness_transport),
        Purpose::LogCheckpoint,
    )
    .await?;
    s.send(&LogRequest::Checkpoint).await?;
    let LogResponse::Checkpoint(note) = s.recv().await? else {
        return Err(anyhow!("expected checkpoint"));
    };
    let text = Note::parse(&note).map_err(|e| anyhow!("{e}"))?.text;
    let cp = Checkpoint::parse(&text).map_err(|e| anyhow!("{e}"))?;
    let last = witness.last_size();
    let proof = if cp.size > last && last > 0 {
        let (mut s, _) = open_control(
            log_addr,
            server_pub,
            Some(witness_transport),
            Purpose::LogConsistency,
        )
        .await?;
        s.send(&LogRequest::Consistency {
            old: last,
            new: cp.size,
        })
        .await?;
        match s.recv().await? {
            LogResponse::Proof(p) => p.into_iter().map(fpp::types::Digest).collect(),
            other => return Err(anyhow!("consistency proof: {other:?}")),
        }
    } else {
        Vec::new()
    };
    let line = witness
        .cosign(&note, &proof, now_s())
        .map_err(|e| anyhow!("{e}"))?;
    let (mut s, _) = open_control(
        log_addr,
        server_pub,
        Some(witness_transport),
        Purpose::LogCosign,
    )
    .await?;
    s.send(&LogRequest::Cosign { text, line }).await?;
    match s.recv().await? {
        LogResponse::Done => Ok(Some(cp.size)),
        LogResponse::Refused(why) if why.contains("changed") => Ok(None),
        other => Err(anyhow!("cosign refused: {other:?}")),
    }
}
