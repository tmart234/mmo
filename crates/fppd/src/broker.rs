//! The Broker role (04 §5.2): verifies a client's Attestation Result (signed
//! ONLY by the Verifier's key, bound to the session key proving possession of
//! this challenge), enforces the queue's device tier floor and Enforcement
//! revocations, reserves a slot on a live game server (directly in all-in-one
//! mode, or over Noise_IK TCP in per-role mode), and signs a Session Admission
//! Token (SAT).
//!
//! Uses ONLY its isolated Broker signing key (`KeyRole::BrokerSat`).

use crate::liveness::LivenessRole;
use crate::revocation::RevocationFeed;
use ed25519_dalek::VerifyingKey;
use fpp::control::{
    match_request_sign_bytes, AttestChallenge, ChallengeRequest, MatchAnswer, MatchRequest,
    PlaceResponse, Placement, Purpose, CONTROL_VERSION,
};
use fpp::crypto::{self, now_s, session_key_id, tagged_hash, Ed25519Signer, KeyRole, KeySet};
use fpp::session::StaticKeypair;
use fpp::tokens::{instance_id, verify_ar, SessionAdmissionToken, SKEW_S};
use fpp::transport::async_io::AsyncNoiseStream;
use fpp::types::{DeviceTier, MatchId, Reason, SessionKey};
use fpp::wire::{RevocationEvent, SubjectKind};
use rand::{rngs::OsRng, RngCore};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const BROKER_ISS: &str = "broker.dev";
pub const REGION: &str = "dev";
pub const POLICY_VER: u64 = 1;
pub const SAT_LIFETIME_S: u64 = 3600;
pub const LIVENESS_TIMEOUT: Duration = Duration::from_secs(2);

pub fn queue_min_tier(queue: &str) -> Option<DeviceTier> {
    match queue {
        "open" => Some(DeviceTier::D0Unknown),
        "verified" => Some(DeviceTier::D2Hardware),
        "hardened" => Some(DeviceTier::D3Hardened),
        _ => None,
    }
}

/// Dev account pseudonym derived from the session key.
pub fn account_of(session_key: &SessionKey) -> [u8; 32] {
    tagged_hash("mmo/dev-acct", &session_key.to_bytes())
}

pub enum Placer {
    /// Direct in-process call (all-in-one `fppd serve`).
    Local(Arc<LivenessRole>),
    /// Remote `Noise_IK` TCP call to a standalone `fppd role liveness` process.
    Remote {
        addr: SocketAddr,
        server_pub: [u8; 32],
        client_kp: StaticKeypair,
    },
}

impl Placer {
    pub async fn place(&self) -> Option<Placement> {
        match self {
            Placer::Local(liveness) => liveness.place(),
            Placer::Remote {
                addr,
                server_pub,
                client_kp,
            } => {
                let mut s =
                    AsyncNoiseStream::connect(*addr, server_pub, Some(client_kp), LIVENESS_TIMEOUT)
                        .await
                        .ok()?;
                s.send(&ChallengeRequest {
                    version: CONTROL_VERSION,
                    purpose: Purpose::Place,
                })
                .await
                .ok()?;
                let _challenge: AttestChallenge = s.recv().await.ok()?;
                match s.recv::<PlaceResponse>().await.ok()? {
                    PlaceResponse::Placed(p) => Some(p),
                    _ => None,
                }
            }
        }
    }
}

pub struct BrokerRole {
    pub key: Ed25519Signer,
    verifier_keys: KeySet,
    placer: Placer,
    denials: Mutex<Vec<RevocationEvent>>,
}

fn refuse(reason: Reason) -> MatchAnswer {
    MatchAnswer::Refused {
        code: reason as u16,
    }
}

impl BrokerRole {
    pub fn new(
        key: Ed25519Signer,
        verifier_pub: VerifyingKey,
        placer: Placer,
        feed: Option<Arc<RevocationFeed>>,
    ) -> Arc<Self> {
        let mut verifier_keys = KeySet::default();
        verifier_keys.insert_ed25519(KeyRole::VerifierAr, verifier_pub);
        let broker = Arc::new(Self {
            key,
            verifier_keys,
            placer,
            denials: Mutex::new(Vec::new()),
        });
        if let Some(feed) = feed {
            let b = broker.clone();
            let mut rx = feed.subscribe();
            tokio::spawn(async move {
                for (ev, _) in feed.all_events().await {
                    b.on_revocation(ev);
                }
                loop {
                    match rx.recv().await {
                        Ok((ev, _)) => b.on_revocation(ev),
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }
        broker
    }

    pub fn on_revocation(&self, event: RevocationEvent) {
        if event.action.denies_admission() {
            self.denials.lock().expect("denials").push(event);
        }
    }

    fn denied(&self, ar: &fpp::tokens::AttestationResult, queue: &str, now: u64) -> bool {
        let account = account_of(&ar.cnf);
        let mut denials = self.denials.lock().expect("denials");
        denials.retain(|e| e.expires_at.is_none_or(|x| x > now));
        denials.iter().any(|e| {
            e.effective_at <= now + SKEW_S
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

    pub async fn answer(&self, challenge: &[u8; 32], req: &MatchRequest) -> MatchAnswer {
        let Some(min_tier) = queue_min_tier(&req.queue) else {
            return refuse(Reason::TierInsufficient);
        };
        let now = now_s();
        let Ok(ar) = verify_ar(&req.ar, &self.verifier_keys, now) else {
            return refuse(Reason::ArInvalid);
        };
        let msg = match_request_sign_bytes(challenge, &req.ar, &req.queue);
        if !crypto::verify_session_raw(&ar.cnf, &msg, &req.pop_sig) {
            return refuse(Reason::PopInvalid);
        }
        if ar.tier < min_tier {
            return refuse(Reason::TierInsufficient);
        }
        if self.denied(&ar, &req.queue, now) {
            return refuse(Reason::Revoked);
        }
        let Some(place) = self.placer.place().await else {
            return refuse(Reason::ServerDraining);
        };
        let mut cti = [0u8; 16];
        OsRng.fill_bytes(&mut cti);
        let sat = SessionAdmissionToken {
            iss: BROKER_ISS.into(),
            sub: account_of(&ar.cnf),
            aud: instance_id(&place.instance_pub),
            iat: now,
            exp: now + SAT_LIFETIME_S,
            cti,
            cnf: ar.cnf,
            did: ar.did,
            tier: ar.tier,
            match_id: MatchId(place.match_id),
            slot: place.slot,
            queue: req.queue.clone(),
            policy_ver: POLICY_VER,
            ar_cti: ar.cti,
        };
        let signed = crypto::sign(&self.key, &sat);
        println!(
            "[broker] SAT for ..{}: queue={} tier=D{} slot={} gs={}",
            hex::encode(&session_key_id(&ar.cnf)[..3]),
            req.queue,
            ar.tier as u8,
            place.slot,
            place.game_addr
        );
        MatchAnswer::Granted {
            sat: signed,
            gs_addr: place.game_addr,
            gs_noise_static: place.noise_static,
        }
    }
}
