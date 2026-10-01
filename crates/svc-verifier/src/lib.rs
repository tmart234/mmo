//! The Verifier (04 §5.1): a client proves a fresh session key and
//! presents its device's platform evidence; the Verifier appraises it
//! (`appraisal`) and signs an Attestation Result bound to that key.
//!
//! It holds only its own key (Verifier AR role): it cannot admit anyone to
//! a match (the Broker does) or bless a server (Server Liveness does).

pub mod appraisal;
pub mod tpm;

use anyhow::{Context, Result};
use common::admission::accept_challenge;
use common::crypto::{evidence_request_sign_bytes, now_ms};
use common::framing::{recv_msg, send_msg, send_msg_continue};
use common::proto::{CredentialChallenge, CredentialResponse, EvidenceAnswer, EvidenceRequest};
use fpp_crypto::Ed25519Signer;
use fpp_tokens::AttestationResult;
use fpp_types::{BuildId, Did, Reason, SessionKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

pub const VERIFIER_ISS: &str = "ver.dev";
pub const POLICY_VER: u64 = 1;
pub const AR_LIFETIME_S: u64 = 1800;

pub struct Verifier {
    pub key: Ed25519Signer,
    pub attestation: appraisal::ClientAttestation,
    /// How long a peer has for the handshake and its request (F08).
    pub deadline: Duration,
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0]);
    h.update(data);
    h.finalize().into()
}

fn refuse(reason: Reason) -> EvidenceAnswer {
    EvidenceAnswer::Refused {
        code: reason as u16,
    }
}

/// What a request leads to.
pub enum Step {
    Answer(EvidenceAnswer),
    /// TPM evidence: the credential to send, and what to answer once the
    /// client's TPM returned the secret (or not).
    Activate(CredentialChallenge, Box<PendingAr>),
}

/// An AR waiting for credential activation.
pub struct PendingAr {
    challenge: [u8; 32],
    req: EvidenceRequest,
    session_key: SessionKey,
    appraised: appraisal::Appraised,
    activation: tpm::Activation,
}

impl Verifier {
    /// Appraise one request made against `challenge`.
    pub fn answer(&self, challenge: &[u8; 32], req: &EvidenceRequest) -> Step {
        // Proof of possession of the session key, bound to this challenge.
        let Some(session_key) = SessionKey::from_bytes(&req.session_pub) else {
            return Step::Answer(refuse(Reason::PopInvalid));
        };
        let msg = evidence_request_sign_bytes(
            challenge,
            &req.session_pub,
            &req.platform,
            &req.client_build,
            &req.evidence,
        );
        if !fpp_crypto::verify_session_raw(&session_key, &msg, &req.pop_sig) {
            return Step::Answer(refuse(Reason::PopInvalid));
        }
        if req.platform.is_empty() || req.platform.len() > 32 {
            return Step::Answer(refuse(Reason::ArInvalid));
        }

        // Platform evidence, bound to this challenge and session key.
        match appraisal::appraise(&self.attestation, challenge, &session_key, &req.evidence) {
            appraisal::Outcome::Done(appraised) => {
                Step::Answer(self.issue(challenge, req, session_key, appraised))
            }
            appraisal::Outcome::Activate(appraised, activation) => Step::Activate(
                CredentialChallenge {
                    id_object: activation.id_object.clone(),
                    encrypted_secret: activation.encrypted_secret.clone(),
                },
                Box::new(PendingAr {
                    challenge: *challenge,
                    req: req.clone(),
                    session_key,
                    appraised,
                    activation,
                }),
            ),
        }
    }

    /// The AR once the client answered the credential: as appraised if its
    /// TPM opened it, else D0.
    pub fn activated(&self, pending: PendingAr, secret: &[u8]) -> EvidenceAnswer {
        let appraised = if pending.activation.opened(secret) {
            pending.appraised
        } else {
            appraisal::activation_failed()
        };
        self.issue(
            &pending.challenge,
            &pending.req,
            pending.session_key,
            appraised,
        )
    }

    fn issue(
        &self,
        challenge: &[u8; 32],
        req: &EvidenceRequest,
        session_key: SessionKey,
        appraised: appraisal::Appraised,
    ) -> EvidenceAnswer {
        // A hardware-rooted identity where the platform gives one (dev
        // stand-in for HMAC(publisher_did_key, hardware_identity), 04 §5);
        // else a per-key pseudonym.
        let did = match &appraised.identity {
            Some(id) => Did(tagged_hash("mmo/dev-did-hw", id)),
            None => Did(tagged_hash("mmo/dev-did", &req.session_pub)),
        };
        let mut cti = [0u8; 16];
        OsRng.fill_bytes(&mut cti);
        let now = now_ms() / 1000;
        let ar = AttestationResult {
            iss: VERIFIER_ISS.into(),
            iat: now,
            exp: now + AR_LIFETIME_S,
            cti,
            cnf: session_key,
            nonce: *challenge,
            did,
            tier: appraised.tier,
            features: appraised.features,
            client_build: BuildId(req.client_build),
            platform: appraised
                .platform
                .map_or_else(|| req.platform.clone(), str::to_string),
            policy_ver: POLICY_VER,
            warnings: appraised.warnings,
        };
        println!(
            "[verifier] AR for ..{}: tier D{}",
            hex::encode(&fpp_crypto::session_key_id(&session_key)[..3]),
            ar.tier as u8
        );
        EvidenceAnswer::Ar(fpp_crypto::sign(&self.key, &ar))
    }

    /// Serve clients on `endpoint` until it closes.
    pub async fn serve(self: Arc<Self>, endpoint: quinn::Endpoint) {
        common::admission::serve(endpoint, "verifier", move |incoming| {
            let verifier = self.clone();
            async move {
                let mut o = accept_challenge(incoming, verifier.deadline).await?;
                let req: EvidenceRequest = timeout(verifier.deadline, recv_msg(&mut o.recv))
                    .await
                    .context("request timed out")?
                    .context("recv EvidenceRequest")?;
                let answer = match verifier.answer(&o.challenge, &req) {
                    Step::Answer(a) => a,
                    Step::Activate(credential, pending) => {
                        send_msg_continue(&mut o.send, &EvidenceAnswer::Activate(credential))
                            .await?;
                        let r: CredentialResponse =
                            timeout(verifier.deadline, recv_msg(&mut o.recv))
                                .await
                                .context("activation timed out")?
                                .context("recv CredentialResponse")?;
                        verifier.activated(*pending, &r.secret)
                    }
                };
                send_msg(&mut o.send, &answer).await?;
                // Let the reply drain before the connection is dropped.
                let _ = timeout(Duration::from_secs(2), o.conn.closed()).await;
                Ok::<_, anyhow::Error>(())
            }
        })
        .await
    }
}

/// Run a Verifier with the key in `cell` on `bind`.
pub fn start(
    cell: &std::path::Path,
    identity: &common::pki::ServerIdentity,
    bind: std::net::SocketAddr,
    attestation: appraisal::ClientAttestation,
) -> Result<(Arc<Verifier>, quinn::Endpoint)> {
    let key = fpp_svc::keys::ed25519(cell, "verifier", VERIFIER_ISS)?;
    let verifier = Arc::new(Verifier {
        key: Ed25519Signer::new(key),
        attestation,
        deadline: common::admission::DEFAULT_DEADLINE,
    });
    let endpoint = common::admission::server_endpoint(identity, bind)?;
    Ok((verifier, endpoint))
}
