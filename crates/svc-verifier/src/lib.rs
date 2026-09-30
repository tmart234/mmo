//! The Verifier (04 §5.1): a client proves a fresh session key and
//! presents its device's platform evidence; the Verifier appraises it
//! (`appraisal`) and signs an Attestation Result bound to that key.
//!
//! It holds only its own key (Verifier AR role): it cannot admit anyone to
//! a match (the Broker does) or bless a server (Server Liveness does).

pub mod appraisal;

use anyhow::{Context, Result};
use common::admission::accept_challenge;
use common::crypto::{evidence_request_sign_bytes, now_ms};
use common::framing::{recv_msg, send_msg};
use common::proto::{EvidenceAnswer, EvidenceRequest};
use ed25519_dalek::{Signature, VerifyingKey};
use fpp_crypto::Ed25519Signer;
use fpp_tokens::AttestationResult;
use fpp_types::{BuildId, Did, Reason};
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

impl Verifier {
    /// Appraise one request made against `challenge`.
    pub fn answer(&self, challenge: &[u8; 32], req: &EvidenceRequest) -> EvidenceAnswer {
        // Proof of possession of the session key, bound to this challenge.
        let Ok(key) = VerifyingKey::from_bytes(&req.session_pub) else {
            return refuse(Reason::PopInvalid);
        };
        let msg = evidence_request_sign_bytes(
            challenge,
            &req.session_pub,
            &req.platform,
            &req.client_build,
            &req.evidence,
        );
        if key
            .verify_strict(&msg, &Signature::from_bytes(&req.pop_sig))
            .is_err()
        {
            return refuse(Reason::PopInvalid);
        }
        if req.platform.is_empty() || req.platform.len() > 32 {
            return refuse(Reason::ArInvalid);
        }

        // Platform evidence, bound to this challenge and session key.
        let appraised = appraisal::appraise(
            &self.attestation,
            challenge,
            &req.session_pub,
            &req.evidence,
        );
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
            cnf: req.session_pub,
            nonce: *challenge,
            did,
            tier: appraised.tier,
            features: appraised.features,
            client_build: BuildId(req.client_build),
            platform: req.platform.clone(),
            policy_ver: POLICY_VER,
            warnings: appraised.warnings,
        };
        println!(
            "[verifier] AR for ..{}: tier D{}",
            hex::encode(&req.session_pub[..3]),
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
                send_msg(&mut o.send, &verifier.answer(&o.challenge, &req)).await?;
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
