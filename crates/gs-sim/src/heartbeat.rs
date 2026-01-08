//! GS heartbeat & transcript attestation loop.
//!
//! - Heartbeats use a **unidirectional** stream (open_uni).
//! - TranscriptDigest/ProtectedReceipt round-trip uses a bi-stream with timeout.
//! - Implements retry logic with exponential backoff for network resilience.

pub async fn heartbeat_loop(
    conn: quinn::Connection,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eph_sk: ed25519_dalek::SigningKey,
    session_id: [u8; 16],
    shared: crate::state::Shared,
) -> anyhow::Result<()> {
    use common::{
        config::GsConfig,
        crypto::{heartbeat_sign_bytes, now_ms, sign},
        framing::{recv_msg, send_msg},
        proto::{Heartbeat, ProtectedReceipt, TranscriptDigest},
        retry::retry_with_backoff,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    // Load configuration (could be passed as parameter in production)
    let config = GsConfig::default();

    loop {
        // Configurable heartbeat interval
        sleep(Duration::from_millis(config.heartbeat_interval_ms)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        // Snapshot state without holding mutex across awaits
        let (receipt_tip_now, sw_hash_now, positions_vec) = {
            let guard = match shared.lock() {
                Ok(g) => g,
                Err(p) => {
                    eprintln!("[GS] shared mutex poisoned in heartbeat_loop; using inner");
                    p.into_inner()
                }
            };
            let mut pos_out = Vec::with_capacity(guard.players.len());
            for (pubkey, ps) in guard.players.iter() {
                pos_out.push((*pubkey, ps.x, ps.y));
            }
            (guard.receipt_tip, guard.sw_hash, pos_out)
        };

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now, &sw_hash_now);
        let sig_gs_bytes = sign(&eph_sk, &to_sign);

        // (1) HEARTBEAT — unidirectional stream with retry
        // TODO: Add periodic TPM re-attestation quotes
        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sw_hash: sw_hash_now,
            sig_gs: sig_gs_bytes.to_vec(),
            tpm_quote: None, // TPM re-attestation not yet implemented for heartbeats
        };

        let send_heartbeat = || {
            let conn = conn.clone();
            let hb = hb.clone();
            async move {
                let mut send = conn.open_uni().await?;
                send_msg(&mut send, &hb).await?;
                Ok::<_, anyhow::Error>(())
            }
        };

        match retry_with_backoff(&config.retry, "heartbeat_send", send_heartbeat).await {
            Ok(_) => {
                println!("[GS] ♥ heartbeat {c}");
            }
            Err(e) => {
                eprintln!("[GS] heartbeat send failed after retries: {e:?}");
                // Continue trying; VS may recover
            }
        }

        // (2) TRANSCRIPT DIGEST — bi-stream round trip with timeout and retry
        let td = TranscriptDigest {
            session_id,
            gs_counter: c,
            receipt_tip: receipt_tip_now,
            positions: positions_vec,
        };

        let send_transcript = || {
            let conn = conn.clone();
            let td = td.clone();
            let timeout_duration = Duration::from_millis(config.transcript_response_timeout_ms);
            async move {
                let (mut send2, mut recv2) = conn.open_bi().await?;
                send_msg(&mut send2, &td).await?;

                // CRITICAL: Add timeout for VS response to prevent indefinite blocking
                let pr = timeout(timeout_duration, recv_msg::<ProtectedReceipt>(&mut recv2))
                    .await
                    .map_err(|_| anyhow::anyhow!("timeout waiting for ProtectedReceipt"))??;

                if pr.session_id == session_id
                    && pr.gs_counter == c
                    && pr.receipt_tip == receipt_tip_now
                {
                    Ok(pr)
                } else {
                    Err(anyhow::anyhow!("ProtectedReceipt mismatch"))
                }
            }
        };

        match retry_with_backoff(&config.retry, "transcript_digest", send_transcript).await {
            Ok(_) => {
                println!("[GS] VS ProtectedReceipt ok for counter {c}");
            }
            Err(e) => {
                eprintln!("[GS] transcript digest failed after retries: {e:?}");
                // Continue; heartbeats still establish liveness
            }
        }
    }
}
