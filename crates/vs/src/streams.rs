// crates/vs/src/streams.rs
use common::{
    crypto::{heartbeat_sign_bytes, now_ms, sha256, sign, verify},
    framing::send_msg,
    proto::{Heartbeat, PlayTicket, ProtectedReceipt, Sig, TranscriptDigest},
};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use std::time::Duration;
use tokio::time::sleep;

use crate::ctx::VsCtx;
use crate::enforcer::enforcer;

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
    let ctx = ctx.clone(); // own a clone inside the task
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

            // manual framing: 4-byte len + body
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
                        s.revoked = true; // ticket loop will stop
                    }
                }

                // Dedupe logging: we ACK duplicates but avoid duplicate log lines.
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

                // Always build/send a ProtectedReceipt (clients/GS rely on the ACK).
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
                    eprintln!("[VS] send ProtectedReceipt failed: {e:?}");
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

                // session id check
                if hb.session_id != session_id {
                    eprintln!("[VS] heartbeat session mismatch");
                    continue;
                }

                // monotonic counter
                if hb.gs_counter <= sess.last_counter {
                    eprintln!(
                        "[VS] heartbeat non-monotonic (got {}, last {})",
                        hb.gs_counter, sess.last_counter
                    );
                    continue;
                }

                // verify signature with stored ephemeral pub
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
                    sess.revoked = true; // ticket loop will stop
                    continue;
                }

                // record liveness
                sess.last_counter = hb.gs_counter;
                sess.last_seen_ms = now_ms();

                continue;
            }

            eprintln!("[VS] unknown message type on bi-stream");
        }
    });
}
