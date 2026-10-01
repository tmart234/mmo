//! Server Liveness and the Transparency Log (EVD-02, EVD-03).
//!
//! Every verified Checkpoint is logged as a checkpoint leaf (match, epoch,
//! digest), batched and retried in order, so a log outage delays entries
//! without holding up SARs. Players check the Checkpoints their game
//! server showed them against those leaves; one that differs, signed by
//! the same instance key for the same match and epoch, is a proven split
//! view: a player reports it here, and the instance is revoked at once.

use anyhow::{anyhow, Context, Result};
use common::framing::{recv_msg, send_msg};
use common::proto::{EquivocationReport, ReportAnswer};
use fpp_crypto::{KeyRole, KeySet};
use fpp_tokens::instance_id;
use fpp_wire::Checkpoint;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::ctx::Ctx;

/// Append what arrives on `rx` with `writer`, in order, batching.
pub async fn upload(writer: svc_log::Writer, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut backoff = Duration::from_millis(200);
    loop {
        if queue.is_empty() {
            match rx.recv().await {
                Some(e) => queue.push_back(e),
                None => return,
            }
        }
        while let Ok(e) = rx.try_recv() {
            queue.push_back(e);
        }
        let batch: Vec<Vec<u8>> = queue.iter().take(256).cloned().collect();
        let n = batch.len();
        match writer.append(batch).await {
            Ok(_) => {
                queue.drain(..n);
                backoff = Duration::from_millis(200);
            }
            Err(e) => {
                eprintln!(
                    "[liveness] Transparency Log: {e:#} ({} entries waiting)",
                    queue.len()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    }
}

/// Judge a report: is `signed` a Checkpoint by the match's instance key,
/// for an epoch whose verified (logged) Checkpoint differs?
pub fn judge(ctx: &Ctx, signed: &[u8]) -> Result<ReportAnswer> {
    let payload = fpp_wire::cose::Sign1::decode(signed)
        .and_then(|s| <Checkpoint as fpp_wire::Payload>::from_cbor(&s.payload))
        .map_err(|e| anyhow!("not a Checkpoint: {e}"))?;
    let match_id = payload.match_id.0;
    let Some(session) = ctx.sessions.get(&match_id).map(|s| s.clone()) else {
        return Ok(ReportAnswer::Rejected("no such match here".into()));
    };
    let mut keys = KeySet::default();
    keys.insert_ed25519(
        KeyRole::GsInstance,
        ed25519_dalek::VerifyingKey::from_bytes(&session.instance_pub)?,
    );
    let verified = match fpp_crypto::verify::<Checkpoint>(signed, &keys) {
        Ok(v) => v,
        Err(e) => {
            return Ok(ReportAnswer::Rejected(format!(
                "not signed by the match's instance key: {e}"
            )))
        }
    };
    if verified.payload.gs_instance_id != instance_id(&session.instance_pub) {
        return Ok(ReportAnswer::Rejected(
            "another instance's Checkpoint".into(),
        ));
    }
    let epoch = verified.payload.epoch;
    let Some(logged) = session.verified.get(epoch as usize).copied() else {
        return Ok(ReportAnswer::Rejected(format!(
            "epoch {epoch} not checkpointed here yet"
        )));
    };
    if logged == verified.digest {
        return Ok(ReportAnswer::Rejected(
            "the same Checkpoint as logged".into(),
        ));
    }
    // Proven: the instance signed two Checkpoints for one (match, epoch).
    ctx.log_entry(fpp_log::leaf::equivocation(
        &match_id,
        epoch,
        &logged.0,
        &verified.digest.0,
    ));
    ctx.keep_evidence(match_id, signed.to_vec());
    ctx.revoke(
        &match_id,
        &format!("equivocation at epoch {epoch}, reported by a player"),
    );
    Ok(ReportAnswer::Revoked)
}

/// Answer a player's report on an opened connection.
pub async fn report(mut o: common::admission::Opened, ctx: Ctx, deadline: Duration) -> Result<()> {
    let r: EquivocationReport = tokio::time::timeout(deadline, recv_msg(&mut o.recv))
        .await
        .map_err(|_| anyhow!("report timed out"))?
        .context("recv EquivocationReport")?;
    let answer = judge(&ctx, &r.checkpoint)?;
    send_msg(&mut o.send, &answer).await?;
    let _ = tokio::time::timeout(Duration::from_secs(2), o.conn.closed()).await;
    Ok(())
}
