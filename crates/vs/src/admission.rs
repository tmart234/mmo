// crates/vs/src/admission.rs
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};

use crate::ctx::{Session, VsCtx};
use crate::enforcer::enforcer;
use crate::streams::{spawn_bistream_dispatch, spawn_ticket_loop, spawn_uni_heartbeat_listener};
use crate::watchdog::spawn_watchdog;

use common::{
    crypto::{join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{JoinAccept, JoinRequest, Sig},
    tpm::verify_quote,
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

    // 4) Verify TPM attestation quote if present.
    if let Some(quote) = &jr.tpm_quote {
        println!(
            "[VS] verifying TPM quote for GS (nonce: {:02x?}...)",
            &quote.nonce[..4]
        );

        // The TPM quote nonce should match the JoinRequest nonce
        // TPM uses 32-byte nonces, so we check if the JoinRequest nonce matches the first 16 bytes
        if &quote.nonce[..16] != jr.nonce.as_slice() {
            bail!("TPM quote nonce doesn't match JoinRequest nonce");
        }

        // Priority 3: enforce required PCR baselines if configured.
        //
        // When VsConfig::required_pcr_baselines is non-empty, verify_quote will
        // check that the quote's PCR values exactly match the configured baseline.
        // This prevents a compromised hypervisor or modified OS from passing
        // attestation — the attacker would need to produce a TPM-signed quote
        // with the correct PCR values, which requires the TPM's AK private key.
        //
        // When required_pcr_baselines is empty (default), we operate in TOFU mode:
        // the first quote establishes the baseline and continuous attestation
        // (in spawn_uni_heartbeat_listener) ensures it never drifts.
        let required = if ctx.config.required_pcr_baselines.is_empty() {
            None
        } else {
            Some(&ctx.config.required_pcr_baselines)
        };

        verify_quote(quote, &quote.nonce, required).context("TPM quote verification failed")?;

        println!("[VS] TPM quote verified successfully");
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
