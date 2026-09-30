//! Request/response over QUIC streams: one request and its response per
//! bidirectional stream, bincode-framed, at most [`MAX_MESSAGE`] bytes.

use anyhow::{anyhow, Context, Result};
use common::framing::{recv_msg_max, send_msg};
use quinn::{Connection, Endpoint};
use serde::{de::DeserializeOwned, Serialize};
use std::future::Future;
use std::sync::Arc;

pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;

/// The calling service (from its certificate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller(pub String);

impl Caller {
    /// Whether the caller is one of `allowed`.
    pub fn is(&self, allowed: &[String]) -> bool {
        allowed.iter().any(|a| a == &self.0)
    }
}

pub async fn call<Req: Serialize, Resp: DeserializeOwned>(
    conn: &Connection,
    request: &Req,
) -> Result<Resp> {
    let (mut send, mut recv) = conn.open_bi().await.context("open stream")?;
    send_msg(&mut send, request).await?;
    recv_msg_max(&mut recv, MAX_MESSAGE).await
}

/// Serve `handler` on `endpoint` until it closes: each connection's caller
/// is named by its certificate, and every request is handled with it.
pub async fn serve<Req, Resp, H, Fut>(endpoint: Endpoint, handler: H)
where
    Req: DeserializeOwned + Send + 'static,
    Resp: Serialize + Send + Sync + 'static,
    H: Fn(Caller, Req) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    let handler = Arc::new(handler);
    while let Some(incoming) = endpoint.accept().await {
        let handler = handler.clone();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let conn = incoming.await?;
                let caller = Caller(
                    crate::mtls::peer_service(&conn)
                        .ok_or_else(|| anyhow!("caller without a cell name"))?,
                );
                loop {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(s) => s,
                        Err(_) => return Ok(()),
                    };
                    let handler = handler.clone();
                    let caller = caller.clone();
                    tokio::spawn(async move {
                        let Ok(request) = recv_msg_max::<Req>(&mut recv, MAX_MESSAGE).await else {
                            return;
                        };
                        let response = handler(caller, request).await;
                        let _ = send_msg(&mut send, &response).await;
                    });
                }
            }
            .await;
            if let Err(e) = result {
                eprintln!("[svc] connection: {e:#}");
            }
        });
    }
}
