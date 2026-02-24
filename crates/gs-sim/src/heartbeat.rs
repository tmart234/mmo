//! GS heartbeat & transcript attestation loop.
//!
//! - Heartbeats use a **unidirectional** stream (open_uni).
//! - TranscriptDigest/ProtectedReceipt round-trip uses a bi-stream with timeout.
//! - Implements retry logic with exponential backoff for network resilience.
//! - Stage 1.2: Periodic TPM re-attestation every ~60 seconds to detect hot-patching.

use common::tpm::TpmProvider;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

/// Interval between TPM re-attestation quotes (in heartbeat cycles).
/// With 2-second heartbeats, 30 cycles = ~60 seconds.
const TPM_REATTEST_INTERVAL: u64 = 30;

/// PCR indices to include in re-attestation quotes.
/// PCR 0: Binary measurement (sw_hash)
/// PCR 1: Configuration measurement (gs_id)
const TPM_PCRS: &[u8] = &[0, 1];

/// Heartbeat loop without TPM (backward-compatible wrapper).
/// For TPM-enabled attestation, use `heartbeat_loop_with_tpm` directly.
#[allow(dead_code)] // Public API for callers that don't need TPM
pub async fn heartbeat_loop(
    conn: quinn::Connection,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eph_sk: ed25519_dalek::SigningKey,
    session_id: [u8; 16],
    shared: crate::state::Shared,
) -> anyhow::Result<()> {
    heartbeat_loop_with_tpm(conn, counter, eph_sk, session_id, shared, None).await
}

/// Heartbeat loop with optional TPM for continuous attestation.
///
/// Stage 1.2: If TPM is provided, generates a re-attestation quote every
/// TPM_REATTEST_INTERVAL heartbeats (~60 seconds) and attaches it to the
/// Heartbeat message. This allows VS to detect if:
/// - The GS binary was modified in memory (hot-patching)
/// - Configuration was changed after startup
/// - Any PCR values drifted from the baseline established at join
///
/// The quote nonce is derived from (session_id || gs_counter || receipt_tip)
/// to ensure freshness and prevent replay of old quotes.
pub async fn heartbeat_loop_with_tpm(
    conn: quinn::Connection,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eph_sk: ed25519_dalek::SigningKey,
    session_id: [u8; 16],
    shared: crate::state::Shared,
    tpm: Option<Arc<TokioMutex<Box<dyn TpmProvider>>>>,
) -> anyhow::Result<()> {
    use common::{
        config::GsConfig,
        crypto::{heartbeat_sign_bytes, now_ms, sha256, sign},
        framing::{recv_msg, send_msg},
        proto::{Heartbeat, ProtectedReceipt, TranscriptDigest},
        retry::retry_with_backoff,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    // Load configuration
    let config = GsConfig::default();

    // Track when we last did TPM re-attestation
    let mut last_tpm_counter: u64 = 0;

    loop {
        // Configurable heartbeat interval
        sleep(Duration::from_millis(config.heartbeat_interval_ms)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        // Snapshot state without holding mutex across awaits.
        //
        // Priority 1 (DA Black Hole): drain da_buffer so VS gets all ClientInput
        //   bytes before signing the ProtectedReceipt.
        // Priority 2 (Ghost Snapshot): compute snapshot_root = sha256(positions),
        //   then fold it into receipt_tip so positions are cryptographically
        //   committed to the signed transcript chain.
        let (receipt_tip_now, sw_hash_now, positions_vec, snapshot_root, da_payload) = {
            let mut guard = match shared.lock() {
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

            // Priority 2: commit the current position snapshot into the receipt_tip.
            // snapshot_root = sha256(bincode(positions))
            // new_receipt_tip = sha256(prev_receipt_tip || snapshot_root)
            // This means the VS speed-check is over positions that are part of the
            // signed chain, not a "trust me bro" side-channel.
            let positions_bytes =
                bincode::serialize(&pos_out).expect("serialize positions for snapshot_root");
            let snapshot_root = sha256(&positions_bytes);
            let extended_tip =
                sha256(&[guard.receipt_tip.as_ref(), snapshot_root.as_ref()].concat());
            guard.receipt_tip = extended_tip;

            // Priority 1: drain the DA buffer so VS can durably store the inputs.
            let da_payload = std::mem::take(&mut guard.da_buffer);

            (
                extended_tip,
                guard.sw_hash,
                pos_out,
                snapshot_root,
                da_payload,
            )
        };

        let to_sign = heartbeat_sign_bytes(
            &session_id,
            c,
            now,
            &receipt_tip_now,
            &sw_hash_now,
            &snapshot_root,
        );
        let sig_gs_bytes = sign(&eph_sk, &to_sign);

        // =====================================================================
        // Stage 1.2: Periodic TPM Re-Attestation
        //
        // Why periodic re-attestation matters:
        // - Initial attestation at JoinRequest proves code identity at startup
        // - An attacker could modify memory AFTER startup (hot-patching)
        // - Periodic quotes prove code hasn't been modified since join
        //
        // Quote nonce derivation:
        // - nonce = sha256(session_id || gs_counter || receipt_tip)
        // - This binds the quote to a specific point in time/state
        // - VS can verify nonce matches what it expects
        // - Prevents replay of old valid quotes
        // =====================================================================
        let tpm_quote = if let Some(ref tpm_arc) = tpm {
            // Only re-attest every TPM_REATTEST_INTERVAL heartbeats
            if c >= last_tpm_counter + TPM_REATTEST_INTERVAL {
                last_tpm_counter = c;

                // Derive nonce from session state for freshness
                let nonce_preimage = {
                    let mut buf = Vec::with_capacity(16 + 8 + 32);
                    buf.extend_from_slice(&session_id);
                    buf.extend_from_slice(&c.to_le_bytes());
                    buf.extend_from_slice(&receipt_tip_now);
                    buf
                };
                let nonce_32 = sha256(&nonce_preimage);

                // Generate TPM quote (this may take a few ms)
                match tpm_arc.lock().await.quote(TPM_PCRS, &nonce_32) {
                    Ok(quote) => {
                        println!(
                            "[GS] TPM re-attestation quote generated (counter={}, pcrs={:?})",
                            c, TPM_PCRS
                        );
                        Some(quote)
                    }
                    Err(e) => {
                        eprintln!("[GS] TPM re-attestation failed (counter={}): {:?}", c, e);
                        // Continue without quote - VS will notice missing re-attestation
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // (1) HEARTBEAT — unidirectional stream with retry
        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sw_hash: sw_hash_now,
            // Priority 2 (Ghost Snapshot fix): snapshot_root is now part of the
            // signed Heartbeat so the VS can cryptographically verify that the
            // positions in the TranscriptDigest were committed before the HB was
            // signed, closing the Ghost Snapshot exploit.
            snapshot_root,
            sig_gs: sig_gs_bytes.to_vec(),
            tpm_quote, // Stage 1.2: Include TPM quote when available
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
                if hb.tpm_quote.is_some() {
                    println!("[GS] ♥ heartbeat {c} (with TPM quote)");
                } else {
                    println!("[GS] ♥ heartbeat {c}");
                }
            }
            Err(e) => {
                eprintln!("[GS] heartbeat send failed after retries: {e:?}");
            }
        }

        // (2) TRANSCRIPT DIGEST — bi-stream round trip with timeout and retry
        let td = TranscriptDigest {
            session_id,
            gs_counter: c,
            receipt_tip: receipt_tip_now,
            positions: positions_vec,
            // Priority 1 (DA Black Hole fix): raw ClientInput bytes for VS DA log.
            // Note: snapshot_root has been moved to the signed Heartbeat (Fix 2).
            da_payload,
        };

        let send_transcript = || {
            let conn = conn.clone();
            let td = td.clone();
            let timeout_duration = Duration::from_millis(config.transcript_response_timeout_ms);
            async move {
                let (mut send2, mut recv2) = conn.open_bi().await?;
                send_msg(&mut send2, &td).await?;

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
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use common::crypto::sha256;

    #[test]
    fn test_nonce_derivation_is_deterministic() {
        let session_id = [0xAA; 16];
        let counter = 42u64;
        let receipt_tip = [0xBB; 32];

        let mut buf1 = Vec::new();
        buf1.extend_from_slice(&session_id);
        buf1.extend_from_slice(&counter.to_le_bytes());
        buf1.extend_from_slice(&receipt_tip);

        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&session_id);
        buf2.extend_from_slice(&counter.to_le_bytes());
        buf2.extend_from_slice(&receipt_tip);

        assert_eq!(
            sha256(&buf1),
            sha256(&buf2),
            "nonce derivation must be deterministic"
        );
    }

    #[test]
    fn test_nonce_changes_with_counter() {
        let session_id = [0xAA; 16];
        let receipt_tip = [0xBB; 32];

        let mut buf1 = Vec::new();
        buf1.extend_from_slice(&session_id);
        buf1.extend_from_slice(&1u64.to_le_bytes());
        buf1.extend_from_slice(&receipt_tip);

        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&session_id);
        buf2.extend_from_slice(&2u64.to_le_bytes());
        buf2.extend_from_slice(&receipt_tip);

        assert_ne!(
            sha256(&buf1),
            sha256(&buf2),
            "different counters must produce different nonces"
        );
    }
}
