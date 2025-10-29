// crates/vs/src/admission.rs
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};

use crate::ctx::{Session, VsCtx, JOIN_MAX_SKEW_MS};
use crate::enforcer::enforcer;
use crate::streams::{spawn_bistream_dispatch, spawn_ticket_loop};
use crate::watchdog::spawn_watchdog;

use common::{
    crypto::{join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{JoinAccept, JoinRequest, Sig},
};

/// Admit one GS (authenticate JoinRequest) then spawn loops for that session.
pub async fn admit_and_run(connecting: quinn::Incoming, ctx: VsCtx) -> Result<()> {
    // QUIC handshake
    let conn: Connection = connecting.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // First bi-stream: receive JoinRequest
    let (mut vs_send, mut vs_recv) = conn
        .accept_bi()
        .await
        .context("accept_bi for JoinRequest")?;

    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;
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
    if skew > JOIN_MAX_SKEW_MS {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 3) TODO: sw_hash allowlist here (enforce approved GS builds)

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
    spawn_watchdog(&conn, ctx, session_id);

    Ok(())
}
