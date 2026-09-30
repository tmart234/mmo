//! Following the Revocation Feed from another service of the cell: long
//! polls over mutual TLS, reconnecting as needed, each event's Enforcement
//! signature checked before it is handed on.

use crate::api::revocation::{Request, Response};
use fpp_crypto::KeySet;
use fpp_wire::RevocationEvent;
use std::net::SocketAddr;
use std::time::Duration;

/// Follow the feed at `addr` as `identity`, from the start, calling
/// `apply(event, signed bytes)` for each event that verifies under the
/// Enforcement key in `keys`. Runs until the task is dropped.
pub async fn follow<F>(identity: crate::Identity, addr: SocketAddr, keys: KeySet, mut apply: F)
where
    F: FnMut(RevocationEvent, Vec<u8>) + Send,
{
    let name = identity.name.clone();
    let endpoint = match crate::mtls::client_endpoint(&identity) {
        Ok(e) => e,
        Err(e) => return eprintln!("[{name}] revocation feed: {e:#}"),
    };
    let mut next = 0u64;
    let mut conn: Option<quinn::Connection> = None;
    loop {
        let c = match conn.as_ref().filter(|c| c.close_reason().is_none()) {
            Some(c) => c.clone(),
            None => match tokio::time::timeout(
                Duration::from_secs(5),
                crate::mtls::connect(&endpoint, addr, "revocation"),
            )
            .await
            {
                Ok(Ok(c)) => {
                    conn = Some(c.clone());
                    c
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
        };
        let request = Request::Since {
            from: next,
            wait_ms: 10_000,
        };
        let answer = tokio::time::timeout(Duration::from_secs(15), crate::call(&c, &request)).await;
        match answer {
            Ok(Ok(Response::Events(events))) => {
                for (seq, cose) in events {
                    next = next.max(seq + 1);
                    match fpp_crypto::verify::<RevocationEvent>(&cose, &keys) {
                        Ok(v) => apply(v.payload, cose),
                        Err(e) => eprintln!("[{name}] revocation event {seq} refused: {e}"),
                    }
                }
            }
            Ok(Ok(other)) => {
                eprintln!("[{name}] revocation feed: {other:?}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            // (a broken or silent connection: connect again)
            Ok(Err(_)) | Err(_) => conn = None,
        }
    }
}
