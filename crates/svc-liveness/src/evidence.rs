//! Verified Checkpoints to the Evidence Store, in order, each retried until
//! stored: a store that is down delays evidence, it does not lose it (while
//! this process runs) or hold up the SAR chain.

use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;

/// Upload what arrives on `rx` with `client`.
pub async fn upload(
    client: svc_evidence::Client,
    mut rx: mpsc::UnboundedReceiver<([u8; 16], Vec<u8>)>,
) {
    let mut queue: VecDeque<([u8; 16], Vec<u8>)> = VecDeque::new();
    let mut backoff = Duration::from_millis(200);
    loop {
        if queue.is_empty() {
            match rx.recv().await {
                Some(item) => queue.push_back(item),
                None => return,
            }
        }
        while let Ok(item) = rx.try_recv() {
            queue.push_back(item);
        }
        let (match_id, object) = queue.front().cloned().expect("not empty");
        match client.put(match_id, object).await {
            Ok(_) => {
                queue.pop_front();
                backoff = Duration::from_millis(200);
            }
            Err(e) => {
                eprintln!(
                    "[liveness] Evidence Store: {e:#} ({} Checkpoint(s) waiting)",
                    queue.len()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(10));
            }
        }
    }
}
