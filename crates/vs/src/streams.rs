// crates/vs/src/streams.rs
use common::{
    crypto::{heartbeat_sign_bytes, now_ms, sha256, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, PlayTicket, ProtectedReceipt, Sig, TranscriptDigest},
    tpm::verify_quote,
};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use std::time::Duration;
use tokio::time::sleep;

use crate::ctx::VsCtx;
use crate::enforcer::enforcer;
use crate::metrics::{HEARTBEATS_TOTAL, TPM_VERIFICATIONS_TOTAL, TPM_VERIFICATION_LATENCY};

/// VS -> GS: issue `PlayTicket` every ~2s. Stops when session is revoked.
pub fn spawn_ticket_loop(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();
    let vs_sk = ctx.vs_sk.clone();

    tokio::spawn(async move {
        let mut counter: u64 = 0;
        let mut prev_hash: [u8; 32] = [0u8; 32];

        loop {
            // Stop when revoked (authoritative) or missing (session removed).
            if enforcer().lock().unwrap().is_revoked(session_id) {
                eprintln!(
                    "[VS] ticket loop ending for session {}.. (revoked)",
                    hex::encode(&session_id[..4])
                );
                break;
            }
            if ctx.sessions.get(&session_id).is_none() {
                break;
            }

            sleep(Duration::from_secs(2)).await;

            counter += 1;
            let now = now_ms();
            let not_before = now;
            let not_after = now + 2_000;

            // Body VS signs (GS/Client verify the same tuple).
            let body_tuple = (
                session_id, [0u8; 32], // client_binding placeholder
                counter, not_before, not_after, prev_hash,
            );
            let body_bytes = match bincode::serialize(&body_tuple) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[VS] ticket serialize failed: {e:?}");
                    break;
                }
            };

            let sig_vs_arr: [u8; 64] = sign(vs_sk.as_ref(), &body_bytes);

            let pt = PlayTicket {
                session_id,
                client_binding: [0u8; 32],
                counter,
                not_before_ms: not_before,
                not_after_ms: not_after,
                prev_ticket_hash: prev_hash,
                sig_vs: sig_vs_arr,
            };

            // update chain for next ticket
            prev_hash = sha256(&body_bytes);

            match conn.open_bi().await {
                Ok((mut send, _recv)) => {
                    if let Err(e) = send_msg(&mut send, &pt).await {
                        eprintln!("[VS] send PlayTicket failed: {e:?}");
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[VS] open_bi for PlayTicket failed: {e:?}");
                    break;
                }
            }
        }
    });
}

/// Accept bi-streams from GS and handle TranscriptDigest (reply PR) or Heartbeat (verify, liveness).
pub fn spawn_bistream_dispatch(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();
    let vs_sk = ctx.vs_sk.clone();

    tokio::spawn(async move {
        loop {
            let pair = conn.accept_bi().await;
            let (mut send, mut recv) = match pair {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[VS] accept_bi stream error: {e:?}");
                    break;
                }
            };

            // Read length-prefixed frame (polymorphic message type).
            let mut len_buf = [0u8; 4];
            if let Err(e) = recv.read_exact(&mut len_buf).await {
                eprintln!("[VS] stream read len failed: {e:?}");
                continue;
            }
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut buf = vec![0u8; len];
            if let Err(e) = recv.read_exact(&mut buf).await {
                eprintln!("[VS] stream read body failed: {e:?}");
                continue;
            }

            // Try TranscriptDigest first.
            if let Ok(td) = bincode::deserialize::<TranscriptDigest>(&buf) {
                // Enforce physics / invariants at this tick.
                if let Err(e) = enforcer().lock().unwrap().on_transcript(session_id, &td) {
                    eprintln!(
                        "[VS] enforcement (transcript) error on session {}..: {e}",
                        hex::encode(&session_id[..4])
                    );
                    if let Some(mut s) = ctx.sessions.get_mut(&session_id) {
                        s.revoked = true;
                    }
                }

                // Dedupe logging
                let is_dup = if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                    if sess
                        .last_pr_counter
                        .map(|c| c == td.gs_counter)
                        .unwrap_or(false)
                        && sess.last_pr_tip == td.receipt_tip
                    {
                        true
                    } else {
                        sess.last_pr_counter = Some(td.gs_counter);
                        sess.last_pr_tip = td.receipt_tip;
                        false
                    }
                } else {
                    false
                };

                // Build/send ProtectedReceipt
                let pr_body =
                    match bincode::serialize(&(td.session_id, td.gs_counter, td.receipt_tip)) {
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("[VS] ProtectedReceipt serialize body failed: {e:?}");
                            continue;
                        }
                    };
                let sig_vs: Sig = sign(vs_sk.as_ref(), &pr_body).to_vec();
                let pr = ProtectedReceipt {
                    session_id: td.session_id,
                    gs_counter: td.gs_counter,
                    receipt_tip: td.receipt_tip,
                    sig_vs,
                };

                if let Err(e) = send_msg(&mut send, &pr).await {
                    let msg = format!("{e:?}");
                    if !msg.contains("stopped by peer") && !msg.contains("ClosedStream") {
                        eprintln!("[VS] send ProtectedReceipt failed: {e:?}");
                    }
                } else if !is_dup {
                    println!(
                        "[VS] ProtectedReceipt issued for ctr {} (session {}..)",
                        td.gs_counter,
                        hex::encode(&td.session_id[..4])
                    );
                }

                continue;
            }

            // Then try Heartbeat.
            if let Ok(hb) = bincode::deserialize::<Heartbeat>(&buf) {
                let mut sess = match ctx.sessions.get_mut(&session_id) {
                    Some(s) => s,
                    None => {
                        eprintln!("[VS] heartbeat for unknown session");
                        continue;
                    }
                };

                if hb.session_id != session_id {
                    eprintln!("[VS] heartbeat session mismatch");
                    continue;
                }

                if hb.gs_counter <= sess.last_counter {
                    eprintln!(
                        "[VS] heartbeat non-monotonic (got {}, last {})",
                        hb.gs_counter, sess.last_counter
                    );
                    continue;
                }

                let eph_vk = match VerifyingKey::from_bytes(&sess.ephemeral_pub) {
                    Ok(vk) => vk,
                    Err(e) => {
                        eprintln!("[VS] stored ephemeral_pub invalid: {e:?}");
                        continue;
                    }
                };

                let hb_bytes = heartbeat_sign_bytes(
                    &hb.session_id,
                    hb.gs_counter,
                    hb.gs_time_ms,
                    &hb.receipt_tip,
                    &hb.sw_hash,
                );

                let hb_sig_arr: [u8; 64] = match hb.sig_gs.clone().try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("[VS] heartbeat sig_gs wrong length (expected 64)");
                        continue;
                    }
                };

                if !verify(&eph_vk, &hb_bytes, &hb_sig_arr) {
                    eprintln!("[VS] heartbeat sig BAD]");
                    continue;
                }

                // Enforcement: pin sw_hash and stage time for speed check
                if let Err(e) = enforcer().lock().unwrap().on_heartbeat(session_id, &hb) {
                    eprintln!(
                        "[VS] enforcement (heartbeat) error on session {}..: {e}",
                        hex::encode(&session_id[..4])
                    );
                    sess.revoked = true;
                    continue;
                }

                sess.last_counter = hb.gs_counter;
                sess.last_seen_ms = now_ms();

                continue;
            }

            eprintln!("[VS] unknown message type on bi-stream");
        }
    });
}

/// Listen for Heartbeat messages on **uni** streams.
/// Updates `last_seen_ms`, verifies sig, and informs the enforcer.
///
/// Stage 1.2: Now also verifies TPM re-attestation quotes when present.
pub fn spawn_uni_heartbeat_listener(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();

    tokio::spawn(async move {
        // Track expected PCR values from initial attestation
        // In production, these would be stored in ctx.sessions at JoinRequest time
        let mut baseline_pcrs: Option<std::collections::HashMap<u8, [u8; 32]>> = None;

        loop {
            let mut recv = match conn.accept_uni().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[VS] accept_uni (heartbeat) failed: {e:?}");
                    break;
                }
            };

            let hb: Heartbeat = match recv_msg(&mut recv).await {
                Ok(hb) => hb,
                Err(e) => {
                    eprintln!("[VS] recv Heartbeat failed: {e:?}");
                    continue;
                }
            };

            HEARTBEATS_TOTAL.inc();

            let (ephemeral_pub, revoked) = match ctx.sessions.get(&session_id) {
                Some(s) => (s.ephemeral_pub, s.revoked),
                None => {
                    eprintln!(
                        "[VS] heartbeat for unknown session {}..",
                        hex::encode(&session_id[..4])
                    );
                    continue;
                }
            };
            if revoked {
                eprintln!(
                    "[VS] heartbeat ignored for revoked session {}..",
                    hex::encode(&session_id[..4])
                );
                continue;
            }

            // Verify GS heartbeat signature
            let sig_arr: [u8; 64] = match hb.sig_gs.clone().try_into() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!(
                        "[VS] bad hb.sig_gs length for session {}..",
                        hex::encode(&session_id[..4])
                    );
                    continue;
                }
            };
            let vk = match VerifyingKey::from_bytes(&ephemeral_pub) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!(
                        "[VS] bad ephemeral_pub in session {}..: {e:?}",
                        hex::encode(&session_id[..4])
                    );
                    continue;
                }
            };

            let bytes = heartbeat_sign_bytes(
                &hb.session_id,
                hb.gs_counter,
                hb.gs_time_ms,
                &hb.receipt_tip,
                &hb.sw_hash,
            );
            if !verify(&vk, &bytes, &sig_arr) {
                eprintln!(
                    "[VS] heartbeat signature invalid (sid {}.., ctr {})",
                    hex::encode(&session_id[..4]),
                    hb.gs_counter
                );
                continue;
            }

            // =========================================================
            // Stage 1.2: Verify TPM Re-Attestation Quote
            //
            // If the heartbeat includes a TPM quote, verify:
            // 1. The nonce matches our expectation (derived from session state)
            // 2. The quote signature is valid
            // 3. PCR values match the baseline from JoinRequest
            //
            // This detects:
            // - Hot-patching (modifying GS memory after startup)
            // - Configuration changes
            // - Any code tampering since initial attestation
            // =========================================================
            if let Some(ref quote) = hb.tpm_quote {
                let timer = TPM_VERIFICATION_LATENCY.start_timer();

                // Derive expected nonce (must match GS derivation)
                let expected_nonce = {
                    let mut buf = Vec::with_capacity(16 + 8 + 32);
                    buf.extend_from_slice(&session_id);
                    buf.extend_from_slice(&hb.gs_counter.to_le_bytes());
                    buf.extend_from_slice(&hb.receipt_tip);
                    sha256(&buf)
                };

                // Verify quote nonce and signature
                match verify_quote(quote, &expected_nonce, baseline_pcrs.as_ref()) {
                    Ok(()) => {
                        println!(
                            "[VS] TPM re-attestation verified (session {}.., ctr {})",
                            hex::encode(&session_id[..4]),
                            hb.gs_counter
                        );
                        TPM_VERIFICATIONS_TOTAL
                            .with_label_values(&["success"])
                            .inc();

                        // If this is the first quote we've seen, establish baseline
                        if baseline_pcrs.is_none() {
                            baseline_pcrs = Some(quote.pcr_values.clone());
                            println!(
                                "[VS] TPM baseline established for session {}.. (PCRs: {:?})",
                                hex::encode(&session_id[..4]),
                                quote.pcr_values.keys().collect::<Vec<_>>()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[VS] TPM re-attestation FAILED (session {}.., ctr {}): {}",
                            hex::encode(&session_id[..4]),
                            hb.gs_counter,
                            e
                        );
                        TPM_VERIFICATIONS_TOTAL.with_label_values(&["failed"]).inc();

                        // CRITICAL: Mark session as revoked - GS integrity compromised
                        if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                            sess.revoked = true;
                            eprintln!(
                                "[VS] Session {}.. REVOKED due to TPM attestation failure",
                                hex::encode(&session_id[..4])
                            );
                        }
                        continue;
                    }
                }

                timer.observe_duration();
            }

            // Mark last-seen and let the enforcer pin time/hash
            if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                sess.last_seen_ms = now_ms();
            }
            if let Err(e) = enforcer().lock().unwrap().on_heartbeat(session_id, &hb) {
                eprintln!("[VS] enforcer.on_heartbeat failed: {e:#}");
            }
        }
    });
}
