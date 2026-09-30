//! The opening of every connection to a public trust-plane service
//! (Server Liveness, the Verifier, the Broker): the peer asks for a
//! challenge (`ChallengeRequest`), and the service answers with a fresh,
//! single-use nonce (`AttestChallenge`, F04) that the peer's request must
//! then be bound to.

use anyhow::{anyhow, bail, Context, Result};
use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use rand::{rngs::OsRng, RngCore};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

use crate::framing::{recv_msg, send_msg_continue};
use crate::pki::{self, ServerIdentity};
use crate::proto::{AttestChallenge, ChallengeRequest, ADMISSION_VERSION};

/// Default deadline for a new connection to finish the QUIC handshake, the
/// challenge and its request. Idle connections are dropped (F08).
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

/// A peer's connection after the challenge: its first stream, on which its
/// request (bound to `challenge`) comes next.
pub struct Opened {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub challenge: [u8; 32],
}

/// A public endpoint presenting `identity`, on all interfaces at `bind`'s port.
pub fn server_endpoint(identity: &ServerIdentity, bind: SocketAddr) -> Result<Endpoint> {
    let ip = match bind {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    Endpoint::server(
        pki::quic_server_config(identity)?,
        SocketAddr::new(ip, bind.port()),
    )
    .with_context(|| format!("bind {bind}"))
}

/// Accept peers on `endpoint` until it closes, handling each with `handle`
/// in its own task. A peer must first prove it receives traffic at its
/// source address (QUIC Retry) before any per-connection work.
pub async fn serve<H, Fut>(endpoint: Endpoint, name: &'static str, handle: H)
where
    H: Fn(Incoming) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    while let Some(incoming) = endpoint.accept().await {
        if !incoming.remote_address_validated() {
            if let Err(e) = incoming.retry() {
                eprintln!("[{name}] retry failed: {e}");
            }
            continue;
        }
        let task = handle(incoming);
        tokio::spawn(async move {
            if let Err(e) = task.await {
                eprintln!("[{name}] connection: {e:#}");
            }
        });
    }
}

/// Service side: complete the handshake and give the peer a challenge, all
/// within `deadline`, so a peer that connects and goes quiet cannot hold a
/// task (F08).
pub async fn accept_challenge(incoming: Incoming, deadline: Duration) -> Result<Opened> {
    timeout(deadline, async {
        let conn = incoming.await.context("handshake")?;
        let (mut send, mut recv) = conn.accept_bi().await.context("accept stream")?;
        let hello: ChallengeRequest = recv_msg(&mut recv).await.context("recv ChallengeRequest")?;
        if hello.version != ADMISSION_VERSION {
            bail!("unsupported admission version {}", hello.version);
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        send_msg_continue(&mut send, &AttestChallenge { nonce: challenge })
            .await
            .context("send AttestChallenge")?;
        Ok(Opened {
            conn,
            send,
            recv,
            challenge,
        })
    })
    .await
    .map_err(|_| anyhow!("admission timed out after {} ms", deadline.as_millis()))?
}

/// Peer side: connect to public service `service` at `addr` (its certificate
/// must chain to `ca_der` and name it) and get its challenge.
pub async fn request_challenge(ca_der: &[u8], addr: SocketAddr, service: &str) -> Result<Opened> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let endpoint = Endpoint::client(bind)?;
    let conn = endpoint
        .connect_with(
            pki::quic_client_config(ca_der)?,
            addr,
            &pki::server_name(service),
        )?
        .await
        .with_context(|| format!("connect to {service} at {addr}"))?;
    let (mut send, mut recv) = conn.open_bi().await?;
    send_msg_continue(
        &mut send,
        &ChallengeRequest {
            version: ADMISSION_VERSION,
        },
    )
    .await?;
    let AttestChallenge { nonce } = recv_msg(&mut recv)
        .await
        .with_context(|| format!("challenge from {service}"))?;
    Ok(Opened {
        conn,
        send,
        recv,
        challenge: nonce,
    })
}
