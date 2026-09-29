// crates/vs/src/watchdog.rs
use quinn::Connection;
use tokio::time::{sleep, Duration};

use crate::ctx::VsCtx;
use common::crypto::now_ms;

/// Revoke and close when Checkpoints stop arriving, or once revoked.
pub fn spawn_watchdog(conn: &Connection, ctx: VsCtx, session_id: [u8; 16]) {
    let conn = conn.clone();
    let ctx = ctx.clone();

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(1)).await;

            let (last_seen_ms, revoked) = if let Some(sess) = ctx.sessions.get(&session_id) {
                (sess.last_seen_ms, sess.revoked)
            } else {
                // session gone; nothing to watch
                break;
            };

            if revoked {
                eprintln!(
                    "[VS] watchdog closing session {}.. (revoked)",
                    hex::encode(&session_id[..4])
                );
                conn.close(0u32.into(), b"revoked");
                break;
            }

            let idle_ms = now_ms().saturating_sub(last_seen_ms);
            let timeout_ms = ctx.config.checkpoint_timeout_ms;

            if idle_ms > timeout_ms {
                ctx.revoke(&session_id, &format!("no checkpoint for {idle_ms} ms"));
                conn.close(0u32.into(), b"checkpoint timeout");
                break;
            }
        }
    });
}
