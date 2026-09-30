//! Game server admission: `ChallengeRequest` → `AttestChallenge`
//! (single-use nonce, F04), then the GS's `JoinRequest` with its TPM 2.0
//! evidence, credential activation, and `JoinAccept`. The GS then stays
//! connected: SARs out, Checkpoints in.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};
use std::time::Duration;
use tokio::time::timeout;

use crate::checkpoints::spawn_checkpoint_listener;
use crate::ctx::{Ctx, Session};
use crate::liveness::spawn_sar_loop;
use crate::watchdog::spawn_watchdog;

use common::{
    admission::accept_challenge,
    crypto::{join_request_sign_bytes, now_ms, verify},
    framing::{recv_msg, recv_msg_max, send_msg, send_msg_continue, MAX_JOIN_FRAME},
    proto::{CredentialResponse, JoinAccept, JoinRequest},
};

/// Admit one game server and keep it connected.
pub async fn admit_and_run(incoming: quinn::Incoming, ctx: Ctx) -> Result<()> {
    let deadline = deadline_of(&ctx);
    let o = accept_challenge(incoming, deadline).await?;
    let (conn, send, mut recv) = (o.conn, o.send, o.recv);
    let jr: JoinRequest = timeout(deadline, recv_msg_max(&mut recv, MAX_JOIN_FRAME))
        .await
        .map_err(|_| anyhow!("admission timed out after {} ms", deadline.as_millis()))?
        .context("recv JoinRequest")?;
    admit_game_server(conn, send, recv, jr, o.challenge, ctx).await
}

async fn admit_game_server(
    conn: Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    jr: JoinRequest,
    challenge: [u8; 32],
    ctx: Ctx,
) -> Result<()> {
    println!(
        "[liveness] JoinRequest from gs_id={} (instance ..{:02x}{:02x}, game port {})",
        jr.gs_id, jr.ephemeral_pub[0], jr.ephemeral_pub[1], jr.game_addr
    );

    // 1) Signature by the GS long-term key over everything it claims.
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
    let sig: [u8; 64] = jr
        .sig_gs
        .clone()
        .try_into()
        .map_err(|_| anyhow!("JoinRequest sig_gs len != 64"))?;
    if !verify(&gs_identity, &join_bytes, &sig) {
        bail!("JoinRequest sig_gs invalid");
    }
    VerifyingKey::from_bytes(&jr.ephemeral_pub)
        .context("instance key is not a valid Ed25519 key")?;

    // 2) Clock skew.
    let skew = now_ms().abs_diff(jr.t_unix_ms);
    if skew > ctx.config.join_max_skew_ms {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 3) The build. With TPM 2.0 evidence it is what the kernel measured
    //    (a registered build, F06), not what the GS says; with a Build
    //    Registry nothing else is admitted (without one: development).
    let tpm2 = match &jr.tpm2 {
        Some(evidence) => Some(
            crate::tpm2::appraise_join(
                &ctx.config,
                &challenge,
                &join_bytes,
                &jr.sw_hash,
                evidence,
                (now_ms() / 1000) as i64,
            )
            .context("TPM 2.0 appraisal failed")?,
        ),
        None if !ctx.config.build_registry.is_empty() => {
            bail!("TPM 2.0 evidence required: only registered builds are admitted, as the kernel measured them")
        }
        None => None,
    };
    // 4) TPM 2.0: credential activation proves the AK that signed the quote
    //    is in the TPM whose EK the manufacturer certified.
    if let Some(admission) = &tpm2 {
        send_msg_continue(&mut send, &admission.challenge)
            .await
            .context("send CredentialChallenge")?;
        let answer: CredentialResponse = timeout(deadline_of(&ctx), recv_msg(&mut recv))
            .await
            .map_err(|_| anyhow!("credential activation timed out"))?
            .context("recv CredentialResponse")?;
        crate::tpm2::check_activation(admission, &answer.secret)?;
        println!(
            "[liveness] TPM 2.0: EK ..{} certified and its AK activated; secure boot {:?}; build {}",
            hex::encode(&admission.ek_digest[28..]),
            admission.secure_boot,
            admission
                .build
                .as_ref()
                .map(|(hash, label)| format!("{label} ({})", hex::encode(&hash[..6])))
                .unwrap_or_else(|| "not checked (no Build Registry)".into())
        );
    }
    let sw_hash = tpm2
        .as_ref()
        .and_then(|a| a.build.as_ref().map(|(hash, _)| *hash))
        .unwrap_or(jr.sw_hash);

    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);
    ctx.sessions.insert(
        session_id,
        Session {
            instance_pub: jr.ephemeral_pub,
            noise_static: jr.noise_static,
            game_addr: jr.game_addr.clone(),
            sw_hash,
            last_seen_ms: now_ms(),
            revoked: false,
            last_checkpoint: None,
            next_slot: 0,
        },
    );

    send_msg(&mut send, &JoinAccept { session_id })
        .await
        .context("send JoinAccept")?;

    spawn_sar_loop(&conn, ctx.clone(), session_id);
    spawn_checkpoint_listener(&conn, ctx.clone(), session_id);
    spawn_watchdog(&conn, ctx, session_id);
    Ok(())
}

fn deadline_of(ctx: &Ctx) -> Duration {
    Duration::from_millis(ctx.config.admission_timeout_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LivenessConfig;
    use common::pki;
    use ed25519_dalek::SigningKey;
    use fpp_crypto::Ed25519Signer;

    /// F08: a peer that completes the QUIC handshake but never sends a
    /// request is dropped at the admission deadline.
    #[tokio::test]
    async fn idle_peer_is_dropped_at_admission_deadline() {
        let dev = pki::DevPki::generate().unwrap();
        let server = quinn::Endpoint::server(
            pki::quic_server_config(dev.service("liveness")).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();

        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let connecting = client
            .connect_with(
                pki::quic_client_config(&dev.ca_cert_der).unwrap(),
                addr,
                &pki::server_name("liveness"),
            )
            .unwrap();

        let incoming = server.accept().await.unwrap();
        let config = LivenessConfig {
            admission_timeout_ms: 200,
            ..LivenessConfig::default()
        };
        let ctx = Ctx::new(Ed25519Signer::new(SigningKey::from_bytes(&[3; 32])), config);

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
