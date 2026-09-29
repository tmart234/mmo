// crates/vs/src/admission.rs
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::ctx::{Session, VsCtx};
use crate::enforcer::enforcer;
use crate::streams::{spawn_bistream_dispatch, spawn_ticket_loop, spawn_uni_heartbeat_listener};
use crate::watchdog::spawn_watchdog;

use common::{
    crypto::{join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg, send_msg_continue},
    proto::{AttestChallenge, ChallengeRequest, JoinAccept, JoinRequest, Sig},
};

/// Version in `ChallengeRequest`; bump on any admission-flow change.
pub const ADMISSION_VERSION: u32 = 1;

/// Admit one GS (authenticate JoinRequest) then spawn loops for that session.
pub async fn admit_and_run(connecting: quinn::Incoming, ctx: VsCtx) -> Result<()> {
    // QUIC handshake, attestation challenge and JoinRequest under one
    // deadline, so a peer that connects and then goes quiet cannot hold a VS
    // task and connection forever.
    let deadline = Duration::from_millis(ctx.config.admission_timeout_ms);
    let (conn, mut vs_send, jr, challenge) = timeout(deadline, async {
        let conn: Connection = connecting.await.context("handshake accept")?;
        println!("[VS] new conn from {}", conn.remote_address());

        // First bi-stream: ChallengeRequest -> AttestChallenge -> JoinRequest.
        let (mut vs_send, mut vs_recv) = conn
            .accept_bi()
            .await
            .context("accept_bi for JoinRequest")?;
        let hello: ChallengeRequest = recv_msg(&mut vs_recv)
            .await
            .context("recv ChallengeRequest")?;
        if hello.version != ADMISSION_VERSION {
            bail!("unsupported admission version {}", hello.version);
        }
        // F04: the verifier chooses quote freshness. One nonce per
        // connection, used for exactly one JoinRequest.
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        send_msg_continue(&mut vs_send, &AttestChallenge { nonce: challenge })
            .await
            .context("send AttestChallenge")?;

        let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;
        Ok::<_, anyhow::Error>((conn, vs_send, jr, challenge))
    })
    .await
    .map_err(|_| anyhow!("admission timed out after {} ms", deadline.as_millis()))??;
    println!(
        "[VS] got JoinRequest from gs_id={} (ephemeral pub ..{:02x}{:02x})",
        jr.gs_id, jr.ephemeral_pub[0], jr.ephemeral_pub[1]
    );

    // 1) Verify JoinRequest signature (binds gs_pub + ephemeral_pub + nonce + time + sw_hash).
    let gs_identity_vk =
        VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub in JoinRequest")?;

    let join_bytes = join_request_sign_bytes(
        &jr.gs_id,
        &jr.sw_hash,
        jr.t_unix_ms,
        &jr.nonce,
        &jr.ephemeral_pub,
    );

    let sig_gs_arr: [u8; 64] = jr
        .sig_gs
        .clone()
        .try_into()
        .map_err(|_| anyhow!("JoinRequest sig_gs len != 64"))?;
    if !verify(&gs_identity_vk, &join_bytes, &sig_gs_arr) {
        bail!("JoinRequest sig_gs invalid");
    }

    // 2) Anti-replay time skew.
    let now = now_ms();
    let skew = now.abs_diff(jr.t_unix_ms);
    if skew > ctx.config.join_max_skew_ms {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 3) Priority 3 (TOFU/TPM supply chain fix): sw_hash allowlist.
    //
    // If the allowlist is non-empty, the GS binary hash MUST be in it.
    // An empty allowlist means "dev/TOFU mode — accept any binary", which is
    // the safe default for local development.  Production deployments MUST
    // populate VsConfig::sw_hash_allowlist with the sha256 hashes of every
    // approved GS release build so a compromised or tampered binary cannot
    // join the network even if it has valid TPM quotes.
    if !ctx.config.sw_hash_allowlist.is_empty()
        && !ctx.config.sw_hash_allowlist.contains(&jr.sw_hash)
    {
        bail!(
            "sw_hash {} is not in the VS allowlist — unapproved GS build rejected",
            hex::encode(jr.sw_hash)
        );
    }

    // 4) Appraise the TPM quote: it must cover this connection's challenge and
    //    this exact JoinRequest, and come from an enrolled attestation key
    //    (any key, pinned for the session, in dev mode). Baselines apply.
    let tpm_ak = crate::attest::appraise_join_quote(
        &ctx.config,
        &challenge,
        &join_bytes,
        jr.tpm_quote.as_ref(),
    )
    .context("TPM quote appraisal failed")?;
    if tpm_ak.is_some() {
        let enrolled = if ctx.config.trusted_ak_keys.is_empty() {
            "dev mode: attestation key not enrolled, pinned for this session"
        } else {
            "enrolled attestation key"
        };
        println!("[VS] TPM quote verified ({enrolled})");
    }

    // Mint session id.
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    // Insert per-session state into ctx.
    ctx.sessions.insert(
        session_id,
        Session {
            ephemeral_pub: jr.ephemeral_pub,
            last_counter: 0,
            last_seen_ms: now_ms(),
            revoked: false,
            last_pr_counter: None,
            last_pr_tip: [0u8; 32],
            staged_hbs: Arc::new(Mutex::new(HashMap::new())),
            hb_notify: Arc::new(Notify::new()),
            tpm_ak,
            recent_tickets: Default::default(),
        },
    );

    // Tell the enforcer the allowed sw_hash for this session.
    enforcer().lock().unwrap().note_join(session_id, jr.sw_hash);

    // Reply JoinAccept (signed by VS).
    let sig_vs: Sig = sign(ctx.vs_sk.as_ref(), &session_id).to_vec();
    let ja = JoinAccept {
        session_id,
        sig_vs,
        vs_pub: ctx.vs_sk.verifying_key().to_bytes(),
    };

    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    // Spawn runtime loops for this connection/session.
    spawn_ticket_loop(&conn, ctx.clone(), session_id);
    spawn_bistream_dispatch(&conn, ctx.clone(), session_id);
    spawn_uni_heartbeat_listener(&conn, ctx.clone(), session_id); // <-- add this
    spawn_watchdog(&conn, ctx, session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{config::VsConfig, pki};
    use ed25519_dalek::SigningKey;

    /// F08: a peer that completes the QUIC handshake but never sends a
    /// JoinRequest is dropped at the admission deadline.
    #[tokio::test]
    async fn idle_peer_is_dropped_at_admission_deadline() {
        let dev = pki::DevPki::generate().unwrap();
        let server = quinn::Endpoint::server(
            pki::quic_server_config(&dev.vs).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();

        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connecting = client
            .connect_with(
                pki::quic_client_config(&dev.ca_cert_der).unwrap(),
                addr,
                pki::VS_SERVER_NAME,
            )
            .unwrap();

        let incoming = server.accept().await.unwrap();
        let config = VsConfig {
            admission_timeout_ms: 200,
            ..VsConfig::default()
        };
        let ctx = VsCtx::new_with_config(Arc::new(SigningKey::from_bytes(&[3; 32])), config);

        // The client completes the handshake, then stays connected and silent.
        let client_task = tokio::spawn(async move {
            let conn = connecting.await.unwrap();
            conn.closed().await;
        });
        let started = std::time::Instant::now();
        let err = admit_and_run(incoming, ctx).await.unwrap_err();
        client_task.abort();
        assert!(
            format!("{err:#}").contains("admission timed out"),
            "{err:#}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
