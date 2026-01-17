// crates/common/src/framing.rs
//
// Tiny length-prefixed bincode framing helpers for QUIC streams.
//
// Wire format:
//   [4-byte little-endian length][bincode payload]
//
// We use these in both directions on ad-hoc bi-streams:
//   GS -> VS (Heartbeat, TranscriptDigest)
//   VS -> GS (JoinAccept, PlayTicket, ProtectedReceipt)
//   etc.

use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use serde::{de::DeserializeOwned, Serialize};

/// Send one message on a QUIC SendStream, then FIN the send side.
///
/// Use this for request/response patterns where you send one message
/// and then are done sending (e.g., VS protocol messages).
///
/// Usage pattern:
/// ```ignore
/// let (mut send, mut recv) = conn.open_bi().await?;
/// send_msg(&mut send, &thing).await?;
/// // optionally read reply from `recv`
/// ```
pub async fn send_msg<T: Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    // serialize payload
    let buf = bincode::serialize(msg).context("bincode serialize send_msg")?;
    let len = buf.len() as u32;

    // write length prefix
    s.write_all(&len.to_le_bytes())
        .await
        .context("write len prefix")?;

    // write body
    s.write_all(&buf).await.context("write body")?;

    // finish the send half.
    //
    // In quinn 0.11.x, `finish()` is sync:
    // it returns Result<(), quinn::ClosedStream> and is NOT `.await`-able.
    s.finish().context("finish send stream")?;

    Ok(())
}

/// Send one message on a QUIC SendStream WITHOUT finishing the stream.
///
/// Use this for ongoing connections where you'll send multiple messages
/// (e.g., client<->GS game loop where ClientHello, then multiple Inputs).
///
/// The stream remains open for further writes after this call returns.
///
/// Usage pattern:
/// ```ignore
/// let (mut send, mut recv) = conn.open_bi().await?;
/// // Initial handshake
/// send_msg_continue(&mut send, &client_hello).await?;
/// let server_hello: ServerHello = recv_msg(&mut recv).await?;
/// // Game loop - keep sending inputs
/// loop {
///     send_msg_continue(&mut send, &input).await?;
///     let snapshot: WorldSnapshot = recv_msg(&mut recv).await?;
/// }
/// // When done, explicitly finish or just drop the stream
/// ```
pub async fn send_msg_continue<T: Serialize>(s: &mut SendStream, msg: &T) -> Result<()> {
    // serialize payload
    let buf = bincode::serialize(msg).context("bincode serialize send_msg_continue")?;
    let len = buf.len() as u32;

    // write length prefix
    s.write_all(&len.to_le_bytes())
        .await
        .context("write len prefix")?;

    // write body
    s.write_all(&buf).await.context("write body")?;

    // Do NOT finish() - stream stays open for more messages

    Ok(())
}

/// Receive exactly one framed message from a QUIC RecvStream.
///
/// Blocks until the full frame is read.
pub async fn recv_msg<T: DeserializeOwned>(r: &mut RecvStream) -> Result<T> {
    // read 4-byte little-endian length prefix
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)
        .await
        .context("read length prefix")?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    // Sanity check: reject absurdly large messages (> 16 MB)
    if len > 16 * 1024 * 1024 {
        anyhow::bail!("message too large: {} bytes (max 16MB)", len);
    }

    // read body of that length
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("read body payload")?;

    // bincode decode
    let msg: T = bincode::deserialize(&buf).context("bincode decode recv_msg")?;
    Ok(msg)
}

/// Receive a message with a timeout.
///
/// Returns `Ok(Some(msg))` if received within timeout,
/// `Ok(None)` if timeout expired, or `Err` on other errors.
pub async fn recv_msg_timeout<T: DeserializeOwned>(
    r: &mut RecvStream,
    timeout: std::time::Duration,
) -> Result<Option<T>> {
    use tokio::time::timeout as tokio_timeout;

    match tokio_timeout(timeout, recv_msg(r)).await {
        Ok(Ok(msg)) => Ok(Some(msg)),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Ok(None),
    }
}