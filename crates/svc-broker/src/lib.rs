//! The Broker (04 §5.2): a client presents its Attestation Result and asks
//! for a queue; the Broker checks the AR (signed by the Verifier's key, for
//! the key that signs this request), applies the queue's tier floor, has
//! Server Liveness reserve a slot on a live game server, and signs a
//! Session Admission Token for it.
//!
//! It holds only its own key (Broker SAT role). It never sees device
//! evidence (the Verifier does) and cannot bless a server (Server Liveness
//! does). If Server Liveness is unreachable, clients are told the servers
//! are draining, and the Broker reconnects on the next request.
//!
//! Queues carry a tier floor (03 §4.4): `open` admits everyone; `verified`
//! requires D2. Accounts, devices, session keys and builds that Enforcement
//! denied admission (or suspended, or banned) are refused (`Revoked`),
//! from the Revocation Feed.

use anyhow::{anyhow, Context, Result};
use common::admission::accept_challenge;
use common::crypto::{match_request_sign_bytes, now_ms};
use common::framing::{recv_msg, send_msg};
use common::proto::{MatchAnswer, MatchRequest};
use ed25519_dalek::VerifyingKey;
use fpp_crypto::{session_key_id, Ed25519Signer, KeyRole, KeySet};
use fpp_svc::api::liveness::{Placement, Request, Response};
use fpp_tokens::{instance_id, verify_ar, SessionAdmissionToken};
use fpp_types::{DeviceTier, MatchId, Reason, SessionKey};
use fpp_wire::{RevocationEvent, SubjectKind};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

pub const BROKER_ISS: &str = "broker.dev";
/// The region this cell serves (revocation scopes name it).
pub const REGION: &str = "dev";
pub const POLICY_VER: u64 = 1;
pub const SAT_LIFETIME_S: u64 = 3600;
/// How long the Broker waits on Server Liveness, per attempt.
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(2);

/// Tier floor per queue (the example policy of 03 §4.4).
pub fn queue_min_tier(queue: &str) -> Option<DeviceTier> {
    match queue {
        "open" => Some(DeviceTier::D0Unknown),
        "verified" => Some(DeviceTier::D2Hardware),
        // runtime-attested platforms only (no evidence reaches it yet)
        "hardened" => Some(DeviceTier::D3Hardened),
        _ => None,
    }
}

/// The Broker's connection to Server Liveness, inside the cell.
pub struct LivenessLink {
    pub endpoint: quinn::Endpoint,
    pub addr: SocketAddr,
    conn: Mutex<Option<quinn::Connection>>,
}

impl LivenessLink {
    pub fn new(identity: &fpp_svc::Identity, addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            endpoint: fpp_svc::mtls::client_endpoint(identity)?,
            addr,
            conn: Mutex::new(None),
        })
    }

    /// Reserve a slot; `None` if no server can take a player or Server
    /// Liveness cannot be reached (within [`LIVENESS_TIMEOUT`] per attempt:
    /// a client waits for its answer).
    pub async fn place(&self) -> Option<Placement> {
        let mut guard = self.conn.lock().await;
        for _ in 0..2 {
            let conn = match guard.as_ref() {
                Some(c) if c.close_reason().is_none() => c.clone(),
                _ => {
                    let connect = fpp_svc::mtls::connect(&self.endpoint, self.addr, "liveness");
                    match timeout(LIVENESS_TIMEOUT, connect).await {
                        Ok(Ok(c)) => {
                            *guard = Some(c.clone());
                            c
                        }
                        Ok(Err(e)) => {
                            eprintln!("[broker] Server Liveness unreachable: {e:#}");
                            return None;
                        }
                        Err(_) => {
                            eprintln!("[broker] Server Liveness unreachable: timed out");
                            return None;
                        }
                    }
                }
            };
            match timeout(LIVENESS_TIMEOUT, fpp_svc::call(&conn, &Request::Place)).await {
                Ok(Ok(Response::Placed(p))) => return Some(p),
                Ok(Ok(Response::NoServer)) => return None,
                Ok(Ok(Response::Refused(why))) => {
                    eprintln!("[broker] Server Liveness refused: {why}");
                    return None;
                }
                // (a stale connection: reconnect once)
                Ok(Err(_)) | Err(_) => *guard = None,
            }
        }
        None
    }
}

pub struct Broker {
    pub key: Ed25519Signer,
    /// Where the Verifier publishes its key (read on first use).
    pub cell: PathBuf,
    verifier_key: Mutex<Option<VerifyingKey>>,
    pub liveness: LivenessLink,
    pub deadline: Duration,
    /// Events from the Revocation Feed that deny admission.
    denials: std::sync::Mutex<Vec<RevocationEvent>>,
}

/// The dev account id of a session key (the SAT's `sub`: there is no
/// account system yet).
pub fn account_of(session_key: &SessionKey) -> [u8; 32] {
    tagged_hash("mmo/dev-acct", &session_key.to_bytes())
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0]);
    h.update(data);
    h.finalize().into()
}

fn refuse(reason: Reason) -> MatchAnswer {
    MatchAnswer::Refused {
        code: reason as u16,
    }
}

impl Broker {
    pub fn new(key: Ed25519Signer, cell: PathBuf, liveness: LivenessLink) -> Self {
        Self {
            key,
            cell,
            verifier_key: Mutex::new(None),
            liveness,
            deadline: common::admission::DEFAULT_DEADLINE,
            denials: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Take one event from the Revocation Feed.
    pub fn on_revocation(&self, event: RevocationEvent) {
        if event.action.denies_admission() {
            self.denials.lock().expect("denials lock").push(event);
        }
    }

    /// Whether Enforcement denied this AR's subjects admission to `queue` now.
    fn denied(&self, ar: &fpp_tokens::AttestationResult, queue: &str, now: u64) -> bool {
        let account = account_of(&ar.cnf);
        let mut denials = self.denials.lock().expect("denials lock");
        denials.retain(|e| e.expires_at.is_none_or(|x| x > now));
        denials.iter().any(|e| {
            e.effective_at <= now + fpp_tokens::SKEW_S
                && e.scope.covers(Some(REGION), Some(queue))
                && match e.subject_kind {
                    SubjectKind::Account => e.subject_id == account,
                    SubjectKind::Device => e.subject_id == ar.did.0,
                    SubjectKind::Session => e.subject_id == session_key_id(&ar.cnf),
                    SubjectKind::Build => e.subject_id == ar.client_build.0,
                    SubjectKind::Sat | SubjectKind::GsInstance => false,
                }
        })
    }

    /// Follow the feed at `feed` as `identity`, once Enforcement's key is
    /// published in the cell.
    pub async fn follow(self: Arc<Self>, identity: fpp_svc::Identity, feed: std::net::SocketAddr) {
        let key = loop {
            match fpp_svc::PublicKeys::read(&self.cell, "enforcement")
                .ok()
                .and_then(|p| VerifyingKey::from_bytes(&p.ed25519).ok())
            {
                Some(k) => break k,
                None => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        };
        let mut keys = KeySet::default();
        keys.insert_ed25519(KeyRole::Enforcement, key);
        fpp_svc::follow::follow(identity, feed, keys, move |event, _| {
            self.on_revocation(event)
        })
        .await
    }

    async fn verifier_keys(&self) -> Result<KeySet> {
        let mut guard = self.verifier_key.lock().await;
        let key = match *guard {
            Some(k) => k,
            None => {
                let public = fpp_svc::PublicKeys::read(&self.cell, "verifier")?;
                let k = VerifyingKey::from_bytes(&public.ed25519)
                    .map_err(|_| anyhow!("the Verifier's published key is invalid"))?;
                *guard = Some(k);
                k
            }
        };
        let mut keys = KeySet::default();
        keys.insert_ed25519(KeyRole::VerifierAr, key);
        Ok(keys)
    }

    /// Answer one request made against `challenge`.
    pub async fn answer(&self, challenge: &[u8; 32], req: &MatchRequest) -> MatchAnswer {
        let keys = match self.verifier_keys().await {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[broker] {e:#}");
                return refuse(Reason::ServerDraining);
            }
        };
        let now = now_ms() / 1000;
        let Ok(ar) = verify_ar(&req.ar, &keys, now) else {
            return refuse(Reason::ArInvalid);
        };
        // The AR is used by the key it was issued to, for this request.
        let msg = match_request_sign_bytes(challenge, &req.ar, &req.queue);
        if !fpp_crypto::verify_session_raw(&ar.cnf, &msg, &req.pop_sig) {
            return refuse(Reason::PopInvalid);
        }

        let Some(min) = queue_min_tier(&req.queue) else {
            return refuse(Reason::PolicyKick);
        };
        if ar.tier < min {
            return refuse(Reason::TierInsufficient);
        }
        if self.denied(&ar, &req.queue, now) {
            return refuse(Reason::Revoked);
        }
        let Some(p) = self.liveness.place().await else {
            return refuse(Reason::ServerDraining);
        };
        let mut cti = [0u8; 16];
        OsRng.fill_bytes(&mut cti);
        let sat = SessionAdmissionToken {
            iss: BROKER_ISS.into(),
            // No account system yet: a per-key pseudonym.
            sub: account_of(&ar.cnf),
            aud: instance_id(&p.instance_pub),
            iat: now,
            exp: now + SAT_LIFETIME_S,
            cti,
            cnf: ar.cnf,
            did: ar.did,
            tier: ar.tier,
            match_id: MatchId(p.match_id),
            slot: p.slot,
            queue: req.queue.clone(),
            policy_ver: POLICY_VER,
            ar_cti: ar.cti,
        };
        println!(
            "[broker] admitted ..{} to match {}.. slot {} (tier D{})",
            hex::encode(&session_key_id(&ar.cnf)[..3]),
            hex::encode(&p.match_id[..4]),
            p.slot,
            ar.tier as u8
        );
        MatchAnswer::Granted {
            sat: fpp_crypto::sign(&self.key, &sat),
            gs_addr: p.game_addr,
            gs_noise_static: p.noise_static,
        }
    }

    /// Serve clients on `endpoint` until it closes.
    pub async fn serve(self: Arc<Self>, endpoint: quinn::Endpoint) {
        common::admission::serve(endpoint, "broker", move |incoming| {
            let broker = self.clone();
            async move {
                let mut o = accept_challenge(incoming, broker.deadline).await?;
                let req: MatchRequest = timeout(broker.deadline, recv_msg(&mut o.recv))
                    .await
                    .context("request timed out")?
                    .context("recv MatchRequest")?;
                let answer = broker.answer(&o.challenge, &req).await;
                send_msg(&mut o.send, &answer).await?;
                let _ = timeout(Duration::from_secs(2), o.conn.closed()).await;
                Ok::<_, anyhow::Error>(())
            }
        })
        .await
    }
}
