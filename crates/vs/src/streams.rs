// crates/vs/src/streams.rs
use common::{
    crypto::{heartbeat_sign_bytes, now_ms, sha256, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, PlayTicket, ProtectedReceipt, TranscriptDigest},
    tpm::verify_quote,
};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use std::time::Duration;
use tokio::time::sleep;

use crate::ctx::VsCtx;
use crate::enforcer::enforcer;
use crate::metrics::{HEARTBEATS_TOTAL, TPM_VERIFICATIONS_TOTAL, TPM_VERIFICATION_LATENCY};

/// How long the bi-stream handler waits for the matching Heartbeat to be staged
/// before giving up and refusing to issue the ProtectedReceipt.
const HB_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// VS -> GS: issue `PlayTicket` every ~2s. Stops when session is revoked.
pub fn spawn_ticket_loop(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();
    let vs_sk = ctx.vs_sk.clone();

    tokio::spawn(async move {
        let mut counter: u64 = 0;
        let mut prev_hash = [0u8; 32];

        loop {
            if enforcer().lock().unwrap().is_revoked(session_id) {
                eprintln!(
                    "[VS] ticket loop ending for session {}.. (revoked)",
                    hex4(&session_id)
                );
                break;
            }
            if ctx.sessions.get(&session_id).is_none() {
                break;
            }

            sleep(Duration::from_secs(2)).await;

            counter += 1;
            let now = now_ms();
            let body_tuple = (session_id, [0u8; 32], counter, now, now + 2_000, prev_hash);
            let body_bytes = match bincode::serialize(&body_tuple) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[VS] ticket serialize failed: {e:?}");
                    break;
                }
            };

            let pt = PlayTicket {
                session_id,
                client_binding: [0u8; 32],
                counter,
                not_before_ms: now,
                not_after_ms: now + 2_000,
                prev_ticket_hash: prev_hash,
                sig_vs: sign(vs_sk.as_ref(), &body_bytes),
            };
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

/// Accept bi-streams from GS and handle TranscriptDigest (then reply ProtectedReceipt).
///
/// Fix 2 (Tick Synchronization): waits for the matching signed Heartbeat to be
/// staged by `spawn_uni_heartbeat_listener` before calling the enforcer, so
/// `on_heartbeat()` + `on_transcript()` always run as a verified pair.  This
/// closes the Premature Notarization exploit where a rogue GS could obtain a
/// receipt for an unverified TranscriptDigest by dropping or delaying its HB.
pub fn spawn_bistream_dispatch(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();
    let vs_sk = ctx.vs_sk.clone();

    tokio::spawn(async move {
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[VS] accept_bi error: {e:?}");
                    break;
                }
            };

            let mut len_buf = [0u8; 4];
            if let Err(e) = recv.read_exact(&mut len_buf).await {
                eprintln!("[VS] stream read len failed: {e:?}");
                continue;
            }
            let mut buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
            if let Err(e) = recv.read_exact(&mut buf).await {
                eprintln!("[VS] stream read body failed: {e:?}");
                continue;
            }

            let td = match bincode::deserialize::<TranscriptDigest>(&buf) {
                Ok(td) => td,
                Err(_) => {
                    eprintln!("[VS] unrecognised message on bi-stream (expected TranscriptDigest)");
                    continue;
                }
            };

            // Obtain staging handles (Arc clones; does not hold the DashMap entry).
            let (staged_hbs, hb_notify) = match ctx.sessions.get(&session_id) {
                Some(s) => (s.staged_hbs.clone(), s.hb_notify.clone()),
                None => {
                    eprintln!("[VS] TranscriptDigest for unknown session");
                    continue;
                }
            };

            // Wait for the matching Heartbeat (verified by the uni-stream handler).
            // Creating `notified` BEFORE the map check guarantees we cannot miss a
            // notification that races with the check.
            let maybe_hb = tokio::time::timeout(HB_WAIT_TIMEOUT, async {
                loop {
                    let notified = hb_notify.notified();
                    if let Some(hb) = staged_hbs.lock().unwrap().remove(&td.gs_counter) {
                        return hb;
                    }
                    notified.await;
                }
            })
            .await
            .ok(); // Elapsed → None

            let hb = match maybe_hb {
                Some(hb) => hb,
                None => {
                    eprintln!(
                        "[VS] timeout waiting for Heartbeat ctr={} (session {}..) \
                         — ProtectedReceipt withheld",
                        td.gs_counter,
                        hex4(&session_id)
                    );
                    continue;
                }
            };

            // on_heartbeat first (stages receipt_tip + snapshot_root), then on_transcript.
            if let Err(e) = enforcer().lock().unwrap().on_heartbeat(session_id, &hb) {
                eprintln!(
                    "[VS] on_heartbeat error (session {}.., ctr {}): {e}",
                    hex4(&session_id),
                    hb.gs_counter,
                );
                if let Some(mut s) = ctx.sessions.get_mut(&session_id) {
                    s.revoked = true;
                }
                continue;
            }

            if let Err(e) = enforcer().lock().unwrap().on_transcript(session_id, &td) {
                eprintln!(
                    "[VS] on_transcript error (session {}.., ctr {}): {e}",
                    hex4(&session_id),
                    td.gs_counter,
                );
                if let Some(mut s) = ctx.sessions.get_mut(&session_id) {
                    s.revoked = true;
                }
                continue;
            }

            // De-dup check (log suppression only — receipt is always issued on first).
            let is_dup = if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                if sess.last_pr_counter == Some(td.gs_counter) && sess.last_pr_tip == td.receipt_tip
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

            // Priority 1: persist DA payload before signing the receipt.
            if !td.da_payload.is_empty() {
                if let Err(e) = write_da_log(&td.session_id, td.gs_counter, &td.da_payload) {
                    eprintln!(
                        "[VS] DA log FAILED (session {}.., ctr={}): {e:?} \
                         — ProtectedReceipt withheld",
                        hex4(&session_id),
                        td.gs_counter,
                    );
                    continue;
                }
                if !is_dup {
                    println!(
                        "[VS] DA log written ({} inputs) session {}.., ctr={}",
                        td.da_payload.len(),
                        hex4(&td.session_id),
                        td.gs_counter,
                    );
                }
            }

            let pr_body = match bincode::serialize(&(td.session_id, td.gs_counter, td.receipt_tip))
            {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[VS] ProtectedReceipt serialize failed: {e:?}");
                    continue;
                }
            };
            let pr = ProtectedReceipt {
                session_id: td.session_id,
                gs_counter: td.gs_counter,
                receipt_tip: td.receipt_tip,
                sig_vs: sign(vs_sk.as_ref(), &pr_body).to_vec(),
            };

            if let Err(e) = send_msg(&mut send, &pr).await {
                let msg = format!("{e:?}");
                if !msg.contains("stopped by peer") && !msg.contains("ClosedStream") {
                    eprintln!("[VS] send ProtectedReceipt failed: {e:?}");
                }
            } else if !is_dup {
                println!(
                    "[VS] ProtectedReceipt issued ctr={} (session {}..)",
                    td.gs_counter,
                    hex4(&td.session_id)
                );
            }
        }
    });
}

/// Listen for Heartbeat messages on **uni** streams.
///
/// After verifying the GS signature and optional TPM quote, this handler
/// stages the Heartbeat in `session.staged_hbs` and fires `hb_notify`.
/// `spawn_bistream_dispatch` waits on that notification before processing
/// the matching TranscriptDigest, ensuring the two always run as a pair.
///
/// Stage 1.2: TPM re-attestation quotes are verified here before staging.
pub fn spawn_uni_heartbeat_listener(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();

    tokio::spawn(async move {
        let mut baseline_pcrs: Option<std::collections::BTreeMap<u8, [u8; 32]>> = None;

        loop {
            let mut recv = match conn.accept_uni().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[VS] accept_uni failed: {e:?}");
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

            let (ephemeral_pub, revoked, last_counter) = match ctx.sessions.get(&session_id) {
                Some(s) => (s.ephemeral_pub, s.revoked, s.last_counter),
                None => continue,
            };
            if revoked {
                continue;
            }

            // Counter must advance.
            if hb.gs_counter <= last_counter {
                eprintln!(
                    "[VS] HB non-monotonic (got {}, last {}) session {}..",
                    hb.gs_counter,
                    last_counter,
                    hex4(&session_id)
                );
                continue;
            }

            // Verify signature — now covers snapshot_root (Fix 1).
            let sig_arr: [u8; 64] = match hb.sig_gs.clone().try_into() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("[VS] bad sig_gs length session {}..", hex4(&session_id));
                    continue;
                }
            };
            let vk = match VerifyingKey::from_bytes(&ephemeral_pub) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!(
                        "[VS] bad ephemeral_pub session {}..: {e:?}",
                        hex4(&session_id)
                    );
                    continue;
                }
            };
            let sign_bytes = heartbeat_sign_bytes(
                &hb.session_id,
                hb.gs_counter,
                hb.gs_time_ms,
                &hb.receipt_tip,
                &hb.sw_hash,
                &hb.snapshot_root,
            );
            if !verify(&vk, &sign_bytes, &sig_arr) {
                eprintln!(
                    "[VS] HB sig invalid (session {}.., ctr {})",
                    hex4(&session_id),
                    hb.gs_counter
                );
                continue;
            }

            // Stage 1.2: verify TPM quote when present.
            if let Some(ref quote) = hb.tpm_quote {
                let timer = TPM_VERIFICATION_LATENCY.start_timer();

                let expected_nonce = {
                    let mut buf = Vec::with_capacity(56);
                    buf.extend_from_slice(&session_id);
                    buf.extend_from_slice(&hb.gs_counter.to_le_bytes());
                    buf.extend_from_slice(&hb.receipt_tip);
                    sha256(&buf)
                };

                match verify_quote(quote, &expected_nonce, baseline_pcrs.as_ref()) {
                    Ok(()) => {
                        TPM_VERIFICATIONS_TOTAL
                            .with_label_values(&["success"])
                            .inc();
                        if baseline_pcrs.is_none() {
                            baseline_pcrs = Some(quote.pcr_values.clone());
                            println!("[VS] TPM baseline set for session {}..", hex4(&session_id));
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[VS] TPM FAILED (session {}.., ctr {}): {e}",
                            hex4(&session_id),
                            hb.gs_counter
                        );
                        TPM_VERIFICATIONS_TOTAL.with_label_values(&["failed"]).inc();
                        if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                            sess.revoked = true;
                        }
                        continue;
                    }
                }

                timer.observe_duration();
            }

            // Signature verified — update liveness counter and stage for bi-stream.
            if let Some(mut sess) = ctx.sessions.get_mut(&session_id) {
                sess.last_seen_ms = now_ms();
                sess.last_counter = hb.gs_counter;
            }

            if let Some(s) = ctx.sessions.get(&session_id) {
                s.staged_hbs.lock().unwrap().insert(hb.gs_counter, hb);
                s.hb_notify.notify_waiters();
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Priority 1 (DA Black Hole fix): durable DA log writer.
// Writes before the ProtectedReceipt is signed so auditors can always
// reconstruct the transcript even if the GS later deletes its ledger.
//
// Format: da_log/session_<hex8>_ctr_<decimal>.da
//         [u32 LE count] ([u32 LE len] [bytes])...
// ---------------------------------------------------------------------------
fn write_da_log(
    session_id: &[u8; 16],
    gs_counter: u64,
    da_payload: &[Vec<u8>],
) -> std::io::Result<()> {
    use std::io::Write as _;

    std::fs::create_dir_all("da_log")?;
    let path = format!(
        "da_log/session_{}_ctr_{:010}.da",
        hex::encode(&session_id[..8]),
        gs_counter,
    );
    let mut f = std::fs::File::create(&path)?;
    f.write_all(&(da_payload.len() as u32).to_le_bytes())?;
    for entry in da_payload {
        f.write_all(&(entry.len() as u32).to_le_bytes())?;
        f.write_all(entry)?;
    }
    f.flush()
}

fn hex4(id: &[u8; 16]) -> String {
    hex::encode(&id[..4])
}
