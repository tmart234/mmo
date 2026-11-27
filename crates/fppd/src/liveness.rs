//! Server Liveness role (04 §6.3): admits game servers (with TPM 2.0 + IMA
//! Build Registry appraisal via `fpp-attest::tpm::verify`), issues short-lived
//! hash-chained Server Attestation Results (SARs every 2 s, `exp = iat + 10 s`),
//! verifies one signed Checkpoint per epoch, writes verified Checkpoints to the
//! Evidence Store and Transparency Log, handles player EquivocationReports
//! (automatic revocation on split view), relays Enforcement revocations, and
//! reserves match slots for the Broker.
//!
//! Uses ONLY its isolated Server Liveness signing key (`KeyRole::ServerLiveness`).

use crate::evidence::EvidenceStore;
use crate::revocation::RevocationFeed;
use crate::tlog::LogEngine;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use fpp::control::{
    join_request_sign_bytes, CheckpointSubmit, CredentialResponse, EquivocationReport, JoinAccept,
    JoinRequest, Placement, ReportAnswer, ToGameServer, MAX_CONTROL_FRAME, MAX_JOIN_FRAME,
};
use fpp::crypto::{self, ed25519_verify, now_ms, now_s, Ed25519Signer, KeyRole, KeySet};
use fpp::log::leaf;
use fpp::tokens::{instance_id, sar_link, ServerAttestationResult};
use fpp::transport::async_io::{AsyncNoiseReceiver, AsyncNoiseSender, AsyncNoiseStream};
use fpp::types::{BuildId, Digest, MatchId, ServerClass};
use fpp::wire::{Checkpoint, RevocationEvent, SubjectKind};
use fpp_attest::tpm::verify::appraise_gs_join;
use fpp_attest::tpm::Registry;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

pub const DEFAULT_GS_PROGRAM_PATH: &str = crate::policy::DEFAULT_GS_PROGRAM_PATH;

#[derive(Clone, Debug)]
pub struct LivenessConfig {
    pub issuer: String,
    pub region: String,
    pub max_slots: u16,
    pub sar_interval_s: u64,
    pub sar_ttl_s: u64,
    pub admission_timeout_ms: u64,
    pub join_max_skew_ms: u64,
    pub checkpoint_timeout_ms: u64,
    pub tpm_ek_roots: Vec<Vec<u8>>,
    pub build_registry: HashMap<[u8; 32], String>,
    pub gs_program_path: String,
    pub require_secure_boot: bool,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        let p = crate::policy::AuthorityPolicy::default();
        Self {
            issuer: p.liveness_iss(),
            region: p.region,
            max_slots: p.max_slots,
            sar_interval_s: p.sar_interval_s,
            sar_ttl_s: p.sar_ttl_s,
            admission_timeout_ms: 10_000,
            join_max_skew_ms: 120_000,
            checkpoint_timeout_ms: 30_000,
            tpm_ek_roots: Vec::new(),
            build_registry: HashMap::new(),
            gs_program_path: p.gs_program_path,
            require_secure_boot: false,
        }
    }
}

#[derive(Clone, Debug)]
struct GsSession {
    instance_pub: [u8; 32],
    noise_static: [u8; 32],
    game_addr: String,
    sw_hash: [u8; 32],
    last_seen_ms: u64,
    revoked: bool,
    last_checkpoint: Option<(u32, Digest)>,
    verified: Vec<Digest>,
    next_slot: u16,
}

type GsSender = (
    mpsc::UnboundedSender<ToGameServer>,
    Arc<tokio::sync::Notify>,
);

pub struct LivenessRole {
    pub key: Ed25519Signer,
    pub config: LivenessConfig,
    sessions: RwLock<HashMap<[u8; 16], GsSession>>,
    senders: RwLock<HashMap<[u8; 16], GsSender>>,
    evidence: Option<Arc<EvidenceStore>>,
    log: Option<Arc<LogEngine>>,
    feed: Option<Arc<RevocationFeed>>,
}

impl LivenessRole {
    pub fn new(
        key: Ed25519Signer,
        config: LivenessConfig,
        evidence: Option<Arc<EvidenceStore>>,
        log: Option<Arc<LogEngine>>,
        feed: Option<Arc<RevocationFeed>>,
    ) -> Arc<Self> {
        let role = Arc::new(Self {
            key,
            config,
            sessions: RwLock::new(HashMap::new()),
            senders: RwLock::new(HashMap::new()),
            evidence,
            log,
            feed: feed.clone(),
        });
        if let Some(feed) = feed {
            let role_bg = role.clone();
            let mut rx = feed.subscribe();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok((ev, cose)) => role_bg.apply_revocation(&ev, cose),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }
        role
    }

    pub fn deadline(&self) -> Duration {
        Duration::from_millis(self.config.admission_timeout_ms)
    }

    /// Reserve a slot on the least-loaded live, blessed game server / shard
    /// below `config.max_slots`.
    pub fn place(&self) -> Option<Placement> {
        let mut sessions = self.sessions.write().expect("sessions lock");
        let (&match_id, s) = sessions
            .iter_mut()
            .filter(|(_, s)| !s.revoked && s.next_slot < self.config.max_slots)
            .min_by_key(|(_, s)| s.next_slot)?;
        let slot = s.next_slot;
        s.next_slot = s.next_slot.checked_add(1)?;
        Some(Placement {
            match_id,
            instance_pub: s.instance_pub,
            noise_static: s.noise_static,
            game_addr: s.game_addr.clone(),
            slot,
        })
    }

    pub fn revoke(&self, session_id: &[u8; 16], reason: &str) {
        let mut sessions = self.sessions.write().expect("sessions lock");
        if let Some(s) = sessions.get_mut(session_id) {
            if !s.revoked {
                s.revoked = true;
                println!(
                    "[liveness] REVOKED session {}..: {reason}",
                    hex::encode(&session_id[..4])
                );
            }
        }
        // Drop sender channel and wake SAR loop so TCP writer closes immediately.
        if let Some((_, notify)) = self
            .senders
            .write()
            .expect("senders lock")
            .remove(session_id)
        {
            notify.notify_waiters();
        }
    }

    fn apply_revocation(&self, event: &RevocationEvent, cose: Vec<u8>) {
        if !event.scope.covers(Some(&self.config.region), None) {
            return;
        }
        if event.subject_kind == SubjectKind::GsInstance {
            let to_revoke: Vec<[u8; 16]> = {
                let sessions = self.sessions.read().expect("sessions lock");
                sessions
                    .iter()
                    .filter(|(_, s)| instance_id(&s.instance_pub).0.as_slice() == event.subject_id)
                    .map(|(id, _)| *id)
                    .collect()
            };
            for id in to_revoke {
                self.revoke(&id, "Enforcement revoked GS instance");
            }
            return;
        }
        // Relay player/device/account/session/SAT/build revocations to all live GS links.
        let senders: Vec<mpsc::UnboundedSender<ToGameServer>> = self
            .senders
            .read()
            .expect("senders lock")
            .values()
            .map(|(tx, _)| tx.clone())
            .collect();
        for tx in senders {
            let _ = tx.send(ToGameServer::Revocation(cose.clone()));
        }
    }

    fn issue_sar(
        &self,
        instance_pub: &[u8; 32],
        noise_static: &[u8; 32],
        sw_hash: &[u8; 32],
        seq: u64,
        prev: Digest,
    ) -> Vec<u8> {
        let iat = now_s();
        let sar = ServerAttestationResult {
            iss: self.config.issuer.clone(),
            sub: instance_id(instance_pub),
            iat,
            exp: iat + self.config.sar_ttl_s,
            cnf: *instance_pub,
            tls_spki_sha256: None,
            server_class: ServerClass::FirstParty,
            build_id: BuildId(*sw_hash),
            region: self.config.region.clone(),
            seq,
            prev,
            vrf_pub: None,
            noise_static: Some(*noise_static),
        };
        crypto::sign(&self.key, &sar)
    }

    /// Admit a game server after `ChallengeRequest(GsJoin)` + `AttestChallenge` and serve it.
    pub async fn admit_and_serve(
        self: Arc<Self>,
        mut stream: AsyncNoiseStream,
        challenge: [u8; 32],
    ) -> Result<()> {
        let deadline = self.deadline();
        let jr: JoinRequest = stream
            .recv_timeout(MAX_JOIN_FRAME, deadline)
            .await
            .context("recv JoinRequest")?;

        let gs_identity = VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub")?;
        let join_bytes = join_request_sign_bytes(
            &jr.gs_id,
            &jr.sw_hash,
            jr.t_unix_ms,
            &jr.nonce,
            &jr.ephemeral_pub,
            &jr.noise_static,
            &jr.game_addr,
        );
        if !ed25519_verify(&gs_identity, &join_bytes, &jr.sig_gs) {
            bail!("JoinRequest sig_gs invalid");
        }
        VerifyingKey::from_bytes(&jr.ephemeral_pub)
            .context("instance key is not a valid Ed25519 key")?;

        let skew = now_ms().abs_diff(jr.t_unix_ms);
        if skew > self.config.join_max_skew_ms {
            bail!("JoinRequest timestamp skew too large: {skew} ms");
        }

        let tpm_adm = match &jr.tpm2 {
            Some(ev) => {
                let registry = Registry {
                    builds: self
                        .config
                        .build_registry
                        .iter()
                        .map(|(h, l)| (h.to_vec(), l.clone()))
                        .collect(),
                };
                let program = (!self.config.build_registry.is_empty())
                    .then_some(self.config.gs_program_path.as_str());
                Some(
                    appraise_gs_join(
                        &self.config.tpm_ek_roots,
                        &registry,
                        program,
                        self.config.require_secure_boot,
                        &challenge,
                        &join_bytes,
                        &jr.sw_hash,
                        ev,
                        now_s() as i64,
                    )
                    .map_err(|e| anyhow!("TPM 2.0 appraisal failed: {e}"))?,
                )
            }
            None if !self.config.build_registry.is_empty() => {
                bail!("TPM 2.0 evidence required: only registered builds are admitted")
            }
            None => None,
        };

        if let Some(adm) = &tpm_adm {
            stream
                .send(&adm.activation.challenge)
                .await
                .context("send CredentialChallenge")?;
            let answer: CredentialResponse = stream
                .recv_timeout(MAX_CONTROL_FRAME, deadline)
                .await
                .context("recv CredentialResponse")?;
            if !adm.activation.opened(&answer.secret) {
                bail!("credential activation failed: AK not in certified EK TPM");
            }
            println!(
                "[liveness] TPM 2.0: EK ..{} certified and activated; secure boot {:?}; build {}",
                hex::encode(&adm.ek_digest[28..]),
                adm.secure_boot,
                adm.build
                    .as_ref()
                    .map(|(h, l)| format!("{l} ({})", hex::encode(&h[..6])))
                    .unwrap_or_else(|| "not checked".into())
            );
        }

        let sw_hash = tpm_adm
            .as_ref()
            .and_then(|a| a.build.as_ref().map(|(h, _)| *h))
            .unwrap_or(jr.sw_hash);

        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);
        {
            self.sessions.write().expect("sessions lock").insert(
                session_id,
                GsSession {
                    instance_pub: jr.ephemeral_pub,
                    noise_static: jr.noise_static,
                    game_addr: jr.game_addr.clone(),
                    sw_hash,
                    last_seen_ms: now_ms(),
                    revoked: false,
                    last_checkpoint: None,
                    verified: Vec::new(),
                    next_slot: 0,
                },
            );
        }

        stream
            .send(&JoinAccept { session_id })
            .await
            .context("send JoinAccept")?;

        println!(
            "[liveness] admitted gs_id={} match={}.. game_addr={}",
            jr.gs_id,
            hex::encode(&session_id[..4]),
            jr.game_addr
        );

        let (sender, receiver, _) = stream.split();
        let (tx, rx) = mpsc::unbounded_channel::<ToGameServer>();
        let revoked_notify = Arc::new(tokio::sync::Notify::new());
        self.senders
            .write()
            .expect("senders lock")
            .insert(session_id, (tx.clone(), revoked_notify.clone()));

        // Replay existing revocations in force immediately.
        if let Some(feed) = &self.feed {
            for (ev, cose) in feed.all_events().await {
                if ev.scope.covers(Some(&self.config.region), None)
                    && ev.subject_kind != SubjectKind::GsInstance
                {
                    let _ = tx.send(ToGameServer::Revocation(cose));
                }
            }
        }

        let writer = tokio::spawn(gs_writer_task(sender, rx));
        let sar_task = tokio::spawn(sar_loop_task(self.clone(), session_id, tx, revoked_notify));
        let cp_task = tokio::spawn(checkpoint_reader_task(self.clone(), session_id, receiver));
        let wd_task = tokio::spawn(watchdog_task(self.clone(), session_id));

        // Once the writer exits (all senders dropped on revoke) or reader exits (GS disconnected),
        // clean up all remaining per-session tasks promptly.
        let _ = writer.await;
        sar_task.abort();
        cp_task.abort();
        wd_task.abort();
        self.senders
            .write()
            .expect("senders lock")
            .remove(&session_id);
        Ok(())
    }

    /// Judge a player's split-view report (EVD-03, P2.5): if the GS signed a
    /// valid Checkpoint for a match and epoch whose digest differs from the
    /// Checkpoint Server Liveness verified for that epoch, log an equivocation
    /// leaf and revoke the instance immediately.
    pub async fn judge_report(&self, report: &EquivocationReport) -> ReportAnswer {
        let sessions_snapshot: Vec<([u8; 16], GsSession)> = self
            .sessions
            .read()
            .expect("sessions lock")
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();

        // Try each live/known session's instance key until the Checkpoint verifies.
        for (session_id, sess) in sessions_snapshot {
            let Ok(vk) = VerifyingKey::from_bytes(&sess.instance_pub) else {
                continue;
            };
            let mut keys = KeySet::default();
            keys.insert_ed25519(KeyRole::GsInstance, vk);
            let Ok(v) = crypto::verify::<Checkpoint>(&report.checkpoint, &keys) else {
                continue;
            };
            if v.payload.match_id != MatchId(session_id)
                || v.payload.gs_instance_id != instance_id(&sess.instance_pub)
            {
                continue;
            }
            let epoch = v.payload.epoch as usize;
            let Some(&honest_digest) = sess.verified.get(epoch) else {
                return ReportAnswer::Rejected("epoch not verified by Server Liveness yet".into());
            };
            if honest_digest == v.digest {
                return ReportAnswer::Rejected("same Checkpoint as Server Liveness holds".into());
            }
            // Split view proven! Log equivocation and revoke.
            if let Some(log) = &self.log {
                let entry =
                    leaf::equivocation(&session_id, v.payload.epoch, &honest_digest.0, &v.digest.0);
                let _ = log.append(&[entry]).await;
            }
            self.revoke(
                &session_id,
                &format!("equivocation at epoch {}", v.payload.epoch),
            );
            return ReportAnswer::Revoked;
        }
        ReportAnswer::Rejected("checkpoint does not verify for any tracked match".into())
    }
}

/// Verify a single Checkpoint against its instance key, match id, and previous chain link.
pub fn verify_checkpoint(
    cose: &[u8],
    instance_pub: &[u8; 32],
    match_id: &[u8; 16],
    last: Option<(u32, Digest)>,
) -> Result<(u32, Digest)> {
    let key = VerifyingKey::from_bytes(instance_pub)?;
    let mut keys = KeySet::default();
    keys.insert_ed25519(KeyRole::GsInstance, key);
    let v = crypto::verify::<Checkpoint>(cose, &keys).map_err(|e| anyhow!("{e:?}"))?;
    let cp = v.payload;
    if cp.gs_instance_id != instance_id(instance_pub) {
        bail!("gs_instance_id does not name the instance key");
    }
    if cp.match_id != MatchId(*match_id) {
        bail!("checkpoint for another match");
    }
    let (want_epoch, want_prev) = match last {
        None => (0, Digest::default()),
        Some((e, d)) => (e + 1, d),
    };
    if cp.epoch != want_epoch || cp.prev != want_prev {
        bail!(
            "chain broken: epoch {} (want {want_epoch}) or prev mismatch",
            cp.epoch
        );
    }
    Ok((cp.epoch, v.digest))
}

async fn gs_writer_task(
    mut sender: AsyncNoiseSender,
    mut rx: mpsc::UnboundedReceiver<ToGameServer>,
) {
    while let Some(msg) = rx.recv().await {
        if timeout(Duration::from_secs(10), sender.send(&msg))
            .await
            .is_err()
        {
            break;
        }
    }
    sender.shutdown().await;
}

async fn sar_loop_task(
    role: Arc<LivenessRole>,
    session_id: [u8; 16],
    tx: mpsc::UnboundedSender<ToGameServer>,
    revoked: Arc<tokio::sync::Notify>,
) {
    let mut seq = 0u64;
    let mut prev = Digest::default();
    loop {
        let sess = {
            role.sessions
                .read()
                .expect("sessions")
                .get(&session_id)
                .cloned()
        };
        let Some(s) = sess else { break };
        if s.revoked {
            break;
        }
        let sar = role.issue_sar(&s.instance_pub, &s.noise_static, &s.sw_hash, seq, prev);
        prev = sar_link(&sar).expect("own SAR decodes");
        if tx.send(ToGameServer::Sar(sar)).is_err() {
            break;
        }
        seq += 1;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(role.config.sar_interval_s.max(1))) => {}
            _ = revoked.notified() => break,
        }
    }
}

async fn checkpoint_reader_task(
    role: Arc<LivenessRole>,
    session_id: [u8; 16],
    mut receiver: AsyncNoiseReceiver,
) {
    loop {
        let submit: CheckpointSubmit = match receiver.recv_max(MAX_CONTROL_FRAME).await {
            Ok(m) => m,
            Err(_) => {
                // GS disconnected cleanly or dropped: revoke so Broker stops placing players on it.
                role.revoke(&session_id, "game server disconnected");
                break;
            }
        };
        let sess = {
            role.sessions
                .read()
                .expect("sessions")
                .get(&session_id)
                .cloned()
        };
        let Some(s) = sess else { break };
        if s.revoked {
            break;
        }
        let (epoch, digest) = match verify_checkpoint(
            &submit.checkpoint,
            &s.instance_pub,
            &session_id,
            s.last_checkpoint,
        ) {
            Ok(ok) => ok,
            Err(e) => {
                role.revoke(&session_id, &format!("invalid checkpoint: {e:#}"));
                break;
            }
        };
        if let Some(ev) = &role.evidence {
            let _ = ev.put(session_id, &submit.checkpoint).await;
        }
        if let Some(log) = &role.log {
            let _ = log
                .append(&[leaf::checkpoint(&session_id, epoch, &digest.0)])
                .await;
        }
        let mut sessions = role.sessions.write().expect("sessions");
        if let Some(s) = sessions.get_mut(&session_id) {
            s.last_checkpoint = Some((epoch, digest));
            s.verified.push(digest);
            s.last_seen_ms = now_ms();
        }
    }
}

async fn watchdog_task(role: Arc<LivenessRole>, session_id: [u8; 16]) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let sess = {
            role.sessions
                .read()
                .expect("sessions")
                .get(&session_id)
                .cloned()
        };
        let Some(s) = sess else { break };
        if s.revoked {
            break;
        }
        let idle = now_ms().saturating_sub(s.last_seen_ms);
        if idle > role.config.checkpoint_timeout_ms {
            role.revoke(&session_id, &format!("no checkpoint for {idle} ms"));
            break;
        }
    }
}
