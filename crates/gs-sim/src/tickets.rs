use crate::state::Shared;
use anyhow::{bail, Context, Result};
use common::{
    crypto::{now_ms, sha256, verify},
    framing::recv_msg,
    proto::PlayTicket,
};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use tokio::{
    sync::watch,
    time::{sleep, Duration},
};

/// Pure verifier for a PlayTicket against the last (counter, hash) and vs_pub.
/// Returns the new hash to carry forward if OK.
pub fn verify_and_hash_ticket(
    prev_counter: u64,
    prev_hash: [u8; 32],
    pt: &PlayTicket,
    vs_pk: &VerifyingKey,
) -> Result<[u8; 32]> {
    if pt.counter != prev_counter + 1 {
        bail!(
            "counter mismatch: got {}, want {}",
            pt.counter,
            prev_counter + 1
        );
    }
    if pt.prev_ticket_hash != prev_hash {
        bail!("prev_ticket_hash mismatch");
    }

    let body_tuple = (
        pt.session_id,
        pt.client_binding,
        pt.counter,
        pt.not_before_ms,
        pt.not_after_ms,
        pt.prev_ticket_hash,
    );
    let body_bytes = bincode::serialize(&body_tuple).context("serialize ticket body")?;

    if !verify(vs_pk, &body_bytes, &pt.sig_vs) {
        bail!("VS signature invalid");
    }

    Ok(sha256(&body_bytes))
}

/// VS → GS ticket stream, plus revocation watchdog.
///
/// - Listens for PlayTicket bi-streams from VS.
/// - Verifies counters, hash chain, VS signature.
/// - Updates shared.latest_ticket (and shared.prev_ticket) and notifies listeners.
/// - Runs a watchdog: if no fresh ticket in ~2.5s, mark revoked and broadcast.
pub async fn ticket_listener(
    conn: Connection,
    shared: Shared,
    vs_pub: VerifyingKey,
    revoke_tx: watch::Sender<bool>,
    ticket_tx: watch::Sender<Option<PlayTicket>>,
) -> Result<()> {
    let mut last_counter: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];

    // Watchdog marks revoked if we stop getting fresh tickets.
    // ROBUSTNESS: Increased timeout from 2.5s to 10s for high-latency networks.
    {
        use common::config::GsConfig;

        let shared_for_watchdog = shared.clone();
        let revoke_tx = revoke_tx.clone();
        let config = GsConfig::default();

        tokio::spawn(async move {
            let liveness_budget_ms = config.ticket_starvation_timeout_ms;
            loop {
                sleep(Duration::from_millis(250)).await;
                let (should_revoke, idle_ms) = {
                    let guard = shared_for_watchdog.lock().unwrap();
                    let last = guard.last_ticket_ms;
                    let now = now_ms();
                    let idle = now.saturating_sub(last);
                    let dead = last != 0 && idle > liveness_budget_ms;
                    (dead || guard.revoked, idle)
                };
                if should_revoke {
                    let mut guard = shared_for_watchdog.lock().unwrap();
                    if !guard.revoked {
                        guard.revoked = true;
                        eprintln!(
                            "[GS] VS blessing lost (no fresh ticket in {} ms, limit {} ms) → session revoked",
                            idle_ms, liveness_budget_ms
                        );
                        let _ = revoke_tx.send(true);
                    }
                }
            }
        });
    }

    loop {
        let pair = conn.accept_bi().await;
        let (_send, mut recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] accept_bi error: {e:?}");
                break;
            }
        };

        let pt: PlayTicket = match recv_msg(&mut recv).await {
            Ok(pt) => pt,
            Err(e) => {
                eprintln!("[GS] bad ticket: {e:?}");
                continue;
            }
        };

        // Verify the incoming ticket against our last (counter, hash)
        match verify_and_hash_ticket(last_counter, last_hash, &pt, &vs_pub) {
            Ok(new_hash) => {
                // publish freshest ticket into shared + watchers
                let now = now_ms();
                {
                    let mut guard = shared.lock().unwrap();
                    // move current to prev, then set latest
                    guard.prev_ticket = guard.latest_ticket.take();
                    guard.latest_ticket = Some(pt.clone());
                    guard.last_ticket_ms = now;
                    // once revoked=true we don't flip it back here
                }
                let _ = ticket_tx.send(Some(pt.clone()));
                println!("[GS] ticket #{} (time_ok=true)", pt.counter);

                last_counter = pt.counter;
                last_hash = new_hash;
            }
            Err(e) => {
                eprintln!("[GS] ticket verification failed: {e:?}");
                break;
            }
        }
    }

    Ok(())
}
