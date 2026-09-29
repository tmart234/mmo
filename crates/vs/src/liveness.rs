// crates/vs/src/liveness.rs
//! Server Liveness role: issue the instance's SAR chain (04 §6.3), the
//! successor of the PlayTicket loop. A SAR lives [`SAR_LIFETIME_S`]; one is
//! issued every [`SAR_INTERVAL`]. Revocation is simply "stop issuing": the GS
//! and its clients lapse within a few intervals.

use common::framing::send_msg;
use common::proto::SarIssue;
use fpp_tokens::{instance_id, sar_link, ServerAttestationResult};
use fpp_types::{BuildId, Digest, ServerClass};
use quinn::Connection;
use std::time::Duration;
use tokio::time::sleep;

use crate::attest::RECENT_SARS;
use crate::ctx::VsCtx;
use crate::metrics::SARS_ISSUED_TOTAL;

pub const SAR_INTERVAL: Duration = Duration::from_secs(2);
pub const SAR_LIFETIME_S: u64 = 10;
pub const LIVENESS_ISS: &str = "live.dev";

pub fn now_s() -> u64 {
    common::crypto::now_ms() / 1000
}

/// Build and sign the next SAR for a session.
pub fn issue(
    ctx: &VsCtx,
    instance_pub: &[u8; 32],
    noise_static: &[u8; 32],
    sw_hash: &[u8; 32],
    seq: u64,
    prev: Digest,
) -> Vec<u8> {
    let iat = now_s();
    let sar = ServerAttestationResult {
        iss: LIVENESS_ISS.into(),
        sub: instance_id(instance_pub),
        iat,
        exp: iat + SAR_LIFETIME_S,
        cnf: *instance_pub,
        tls_spki_sha256: None,
        noise_static: Some(*noise_static),
        server_class: ServerClass::FirstParty,
        build_id: BuildId(*sw_hash),
        region: "dev".into(),
        seq,
        prev,
        vrf_pub: None,
    };
    fpp_crypto::sign(&ctx.keys.liveness, &sar)
}

pub fn spawn_sar_loop(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    tokio::spawn(async move {
        let mut seq = 0u64;
        let mut prev = Digest::default();
        // (the map guard is consumed by `map`: no lock is held in the body)
        while let Some(s) = ctx.sessions.get(&session_id).map(|s| s.clone()) {
            if s.revoked {
                eprintln!(
                    "[VS] SAR loop ending for session {}.. (revoked)",
                    hex::encode(&session_id[..4])
                );
                break;
            }
            let sar = issue(
                &ctx,
                &s.instance_pub,
                &s.noise_static,
                &s.sw_hash,
                seq,
                prev,
            );
            prev = sar_link(&sar).expect("own SAR decodes");
            // Remember it before sending: the GS may seed a TPM quote with it at once.
            if let Some(mut s) = ctx.sessions.get_mut(&session_id) {
                s.recent_sars.push_back((seq, sar.clone()));
                while s.recent_sars.len() > RECENT_SARS {
                    s.recent_sars.pop_front();
                }
            }
            let sent = async {
                let mut uni = conn.open_uni().await?;
                send_msg(&mut uni, &SarIssue { sar }).await
            };
            if let Err(e) = sent.await {
                eprintln!("[VS] send SAR failed: {e:#}");
                break;
            }
            SARS_ISSUED_TOTAL.inc();
            seq += 1;
            sleep(SAR_INTERVAL).await;
        }
    });
}
