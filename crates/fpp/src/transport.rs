//! Owned control-plane encrypted transport: `Noise_IK_25519_ChaChaPoly_SHA256`
//! over TCP, carrying bounded deterministic-CBOR messages.
//!
//! Replaces the entire second transport stack (`quinn`, `rustls`, `rcgen`,
//! `x509-parser`, and dual X.509 CAs) with the same Noise cipher suite already
//! owned in `crate::session`:
//!
//! - **Pinned server authentication (F01):** every client pins the authority's
//!   32-byte X25519 static public key from the regional [`crate::bundle::KeyBundle`].
//! - **Mutual authentication:** Noise IK transmits and authenticates the
//!   initiator's static X25519 public key in message 1, so privileged roles
//!   (Enforcement, Witness, Auditor, Broker → Liveness) authenticate by their
//!   pinned 32-byte key with zero X.509 certificates or CAs.
//! - **Bounded allocation (F07):** Noise frames are capped at 65,535 bytes;
//!   the logical CBOR length prefix is authenticated inside the first encrypted
//!   chunk and checked against `max_len` *before* allocating.
//! - **Deadlines (F08):** both sync (`std::net::TcpStream`) and async
//!   (`tokio::net::TcpStream`, feature `async-net`) enforce admission timeouts.
//! - **Full-duplex split:** after handshake, `into_stateless_transport_mode()`
//!   splits cleanly into independent lock-free `Sender` and `Receiver` halves
//!   with monotonic 64-bit nonces (rejected past `1 << 60`).

use crate::control::{CborMsg, MAX_CONTROL_FRAME};
use crate::session::{StaticKeypair, NOISE_PARAMS, REJECT_AFTER};
use crate::wire::WireError;
use std::sync::Arc;
use std::time::Duration;

/// Noise prologue for control-plane connections (distinct from `fpp/1/p2p`).
pub const CTRL_PROLOGUE: &[u8] = b"fpp/1/ctrl";

/// Default deadline for completing the Noise handshake and admission messages (F08).
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

/// AEAD tag overhead per Noise transport frame.
const TAG_LEN: usize = 16;
/// Maximum encrypted Noise message bytes on the wire (`u16::MAX`).
const MAX_NOISE_WIRE: usize = 65_535;
/// Maximum plaintext payload per Noise transport chunk.
const MAX_CHUNK: usize = MAX_NOISE_WIRE - TAG_LEN;

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Noise(&'static str),
    FrameTooLarge { len: usize, max: usize },
    Malformed(&'static str),
    Wire(WireError),
    Timeout,
    Exhausted,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport io: {e}"),
            TransportError::Noise(m) => write!(f, "noise: {m}"),
            TransportError::FrameTooLarge { len, max } => {
                write!(f, "frame length {len} exceeds cap {max}")
            }
            TransportError::Malformed(m) => write!(f, "transport framing: {m}"),
            TransportError::Wire(e) => write!(f, "wire: {e}"),
            TransportError::Timeout => f.write_str("admission timed out"),
            TransportError::Exhausted => f.write_str("transport nonce space exhausted"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        if matches!(
            e.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            TransportError::Timeout
        } else {
            TransportError::Io(e)
        }
    }
}

impl From<WireError> for TransportError {
    fn from(e: WireError) -> Self {
        TransportError::Wire(e)
    }
}

/// Shared Noise handshake builders.
fn build_initiator(
    local: &StaticKeypair,
    remote_pub: &[u8; 32],
) -> Result<snow::HandshakeState, TransportError> {
    if *remote_pub == [0u8; 32] {
        return Err(TransportError::Noise("refusing all-zero server static key"));
    }
    snow::Builder::new(NOISE_PARAMS.parse().expect("valid Noise params"))
        .prologue(CTRL_PROLOGUE)
        .and_then(|b| b.local_private_key(&local.private))
        .and_then(|b| b.remote_public_key(remote_pub))
        .and_then(|b| b.build_initiator())
        .map_err(|_| TransportError::Noise("build initiator"))
}

fn build_responder(local: &StaticKeypair) -> Result<snow::HandshakeState, TransportError> {
    snow::Builder::new(NOISE_PARAMS.parse().expect("valid Noise params"))
        .prologue(CTRL_PROLOGUE)
        .and_then(|b| b.local_private_key(&local.private))
        .and_then(|b| b.build_responder())
        .map_err(|_| TransportError::Noise("build responder"))
}

/// Check declared logical message length against `max` before allocating (F07).
pub fn check_frame_len(prefix: [u8; 4], max: usize) -> Result<usize, TransportError> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > max {
        return Err(TransportError::FrameTooLarge { len, max });
    }
    Ok(len)
}

// ============================================================================
// Sync Noise_IK TCP transport (pure std, zero tokio — used by fpp::gs_link & fpp-ffi)
// ============================================================================

pub mod sync {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    pub struct NoiseSender {
        stream: TcpStream,
        state: Arc<snow::StatelessTransportState>,
        nonce: u64,
        buf: Vec<u8>,
    }

    pub struct NoiseReceiver {
        stream: TcpStream,
        state: Arc<snow::StatelessTransportState>,
        nonce: u64,
        buf: Vec<u8>,
    }

    pub struct NoiseStream {
        pub sender: NoiseSender,
        pub receiver: NoiseReceiver,
        pub peer_static: [u8; 32],
    }

    fn write_noise_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), TransportError> {
        let len =
            u16::try_from(data.len()).map_err(|_| TransportError::Malformed("chunk > u16"))?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(data)?;
        Ok(())
    }

    fn read_noise_frame(
        stream: &mut TcpStream,
        out: &mut Vec<u8>,
    ) -> Result<usize, TransportError> {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr)?;
        let len = u16::from_be_bytes(hdr) as usize;
        if len == 0 {
            return Err(TransportError::Malformed("empty noise frame"));
        }
        out.resize(len, 0);
        stream.read_exact(out)?;
        Ok(len)
    }

    impl NoiseStream {
        /// Connect to `addr` and complete a Noise IK handshake pinned to `server_pub`.
        /// Uses an ephemeral client static key if `local` is `None`.
        pub fn connect(
            addr: SocketAddr,
            server_pub: &[u8; 32],
            local: Option<&StaticKeypair>,
            timeout: Duration,
        ) -> Result<Self, TransportError> {
            let owned;
            let local = match local {
                Some(k) => k,
                None => {
                    owned = StaticKeypair::generate();
                    &owned
                }
            };
            let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;

            let mut hs = build_initiator(local, server_pub)?;
            let mut wire = vec![0u8; 256];
            let n = hs
                .write_message(&[], &mut wire)
                .map_err(|_| TransportError::Noise("write msg1"))?;
            write_noise_frame(&mut stream, &wire[..n])?;
            stream.flush()?;

            let mut msg2 = Vec::new();
            read_noise_frame(&mut stream, &mut msg2)?;
            let mut plain = [0u8; 64];
            hs.read_message(&msg2, &mut plain)
                .map_err(|_| TransportError::Noise("server authentication failed"))?;
            let state = Arc::new(
                hs.into_stateless_transport_mode()
                    .map_err(|_| TransportError::Noise("transport mode"))?,
            );
            let rx_stream = stream.try_clone()?;
            Ok(Self {
                sender: NoiseSender {
                    stream,
                    state: state.clone(),
                    nonce: 0,
                    buf: Vec::new(),
                },
                receiver: NoiseReceiver {
                    stream: rx_stream,
                    state,
                    nonce: 0,
                    buf: Vec::new(),
                },
                peer_static: *server_pub,
            })
        }

        /// Accept one Noise IK handshake on `listener`.
        pub fn accept(
            listener: &TcpListener,
            local: &StaticKeypair,
            timeout: Duration,
        ) -> Result<Self, TransportError> {
            let (stream, _) = listener.accept()?;
            Self::accept_stream(stream, local, timeout)
        }

        pub fn accept_stream(
            mut stream: TcpStream,
            local: &StaticKeypair,
            timeout: Duration,
        ) -> Result<Self, TransportError> {
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;

            let mut hs = build_responder(local)?;
            let mut msg1 = Vec::new();
            read_noise_frame(&mut stream, &mut msg1)?;
            let mut plain = [0u8; 64];
            hs.read_message(&msg1, &mut plain)
                .map_err(|_| TransportError::Noise("client handshake failed"))?;
            let peer_static: [u8; 32] = hs
                .get_remote_static()
                .and_then(|s| s.try_into().ok())
                .ok_or(TransportError::Noise("missing client static key"))?;

            let mut wire = vec![0u8; 256];
            let n = hs
                .write_message(&[], &mut wire)
                .map_err(|_| TransportError::Noise("write msg2"))?;
            write_noise_frame(&mut stream, &wire[..n])?;
            stream.flush()?;

            let state = Arc::new(
                hs.into_stateless_transport_mode()
                    .map_err(|_| TransportError::Noise("transport mode"))?,
            );
            let rx_stream = stream.try_clone()?;
            Ok(Self {
                sender: NoiseSender {
                    stream,
                    state: state.clone(),
                    nonce: 0,
                    buf: Vec::new(),
                },
                receiver: NoiseReceiver {
                    stream: rx_stream,
                    state,
                    nonce: 0,
                    buf: Vec::new(),
                },
                peer_static,
            })
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), TransportError> {
            self.receiver.stream.set_read_timeout(dur)?;
            Ok(())
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> Result<(), TransportError> {
            self.sender.stream.set_write_timeout(dur)?;
            Ok(())
        }

        pub fn split(self) -> (NoiseSender, NoiseReceiver, [u8; 32]) {
            (self.sender, self.receiver, self.peer_static)
        }

        pub fn send<M: CborMsg>(&mut self, msg: &M) -> Result<(), TransportError> {
            self.sender.send(msg)
        }

        pub fn recv<M: CborMsg>(&mut self) -> Result<M, TransportError> {
            self.receiver.recv_max(MAX_CONTROL_FRAME)
        }

        pub fn recv_max<M: CborMsg>(&mut self, max: usize) -> Result<M, TransportError> {
            self.receiver.recv_max(max)
        }
    }

    impl NoiseSender {
        pub fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
            let len = u32::try_from(data.len())
                .map_err(|_| TransportError::Malformed("message > u32"))?;
            // First chunk carries the 4-byte length prefix + up to MAX_CHUNK - 4 bytes.
            let first_take = data.len().min(MAX_CHUNK - 4);
            let mut chunk = Vec::with_capacity(4 + first_take);
            chunk.extend_from_slice(&len.to_be_bytes());
            chunk.extend_from_slice(&data[..first_take]);
            self.write_chunk(&chunk)?;
            for rest in data[first_take..].chunks(MAX_CHUNK) {
                self.write_chunk(rest)?;
            }
            self.stream.flush()?;
            Ok(())
        }

        fn write_chunk(&mut self, plain: &[u8]) -> Result<(), TransportError> {
            if self.nonce >= REJECT_AFTER {
                return Err(TransportError::Exhausted);
            }
            self.buf.resize(plain.len() + TAG_LEN, 0);
            let n = self
                .state
                .write_message(self.nonce, plain, &mut self.buf)
                .map_err(|_| TransportError::Noise("encrypt"))?;
            self.nonce += 1;
            write_noise_frame(&mut self.stream, &self.buf[..n])
        }

        pub fn send<M: CborMsg>(&mut self, msg: &M) -> Result<(), TransportError> {
            self.send_bytes(&msg.encode())
        }

        pub fn shutdown(&self) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    impl NoiseReceiver {
        pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<(), TransportError> {
            self.stream.set_read_timeout(dur)?;
            Ok(())
        }

        fn read_chunk(&mut self, plain: &mut Vec<u8>) -> Result<(), TransportError> {
            if self.nonce >= REJECT_AFTER {
                return Err(TransportError::Exhausted);
            }
            let n = read_noise_frame(&mut self.stream, &mut self.buf)?;
            if n < TAG_LEN {
                return Err(TransportError::Malformed("short noise chunk"));
            }
            plain.resize(n - TAG_LEN, 0);
            let m = self
                .state
                .read_message(self.nonce, &self.buf[..n], plain)
                .map_err(|_| TransportError::Noise("decrypt"))?;
            self.nonce += 1;
            plain.truncate(m);
            Ok(())
        }

        pub fn recv_bytes(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
            let mut chunk = Vec::new();
            self.read_chunk(&mut chunk)?;
            if chunk.len() < 4 {
                return Err(TransportError::Malformed("short length prefix"));
            }
            let total = check_frame_len(chunk[..4].try_into().expect("4 bytes"), max)?;
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(&chunk[4..]);
            if out.len() > total {
                return Err(TransportError::Malformed("chunk overflow"));
            }
            while out.len() < total {
                self.read_chunk(&mut chunk)?;
                if out.len() + chunk.len() > total {
                    return Err(TransportError::Malformed("chunk overflow"));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }

        pub fn recv<M: CborMsg>(&mut self) -> Result<M, TransportError> {
            self.recv_max(MAX_CONTROL_FRAME)
        }

        pub fn recv_max<M: CborMsg>(&mut self, max: usize) -> Result<M, TransportError> {
            let raw = self.recv_bytes(max)?;
            Ok(M::decode(&raw)?)
        }
    }
}

// ============================================================================
// Async Noise_IK TCP transport (tokio, feature = "async-net" — used by fppd & fpp-sim)
// ============================================================================

#[cfg(feature = "async-net")]
pub mod async_io {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpStream;

    pub struct AsyncNoiseSender {
        stream: OwnedWriteHalf,
        state: Arc<snow::StatelessTransportState>,
        nonce: u64,
        buf: Vec<u8>,
    }

    pub struct AsyncNoiseReceiver {
        stream: OwnedReadHalf,
        state: Arc<snow::StatelessTransportState>,
        nonce: u64,
        buf: Vec<u8>,
    }

    pub struct AsyncNoiseStream {
        pub sender: AsyncNoiseSender,
        pub receiver: AsyncNoiseReceiver,
        pub peer_static: [u8; 32],
    }

    async fn write_frame<W: AsyncWriteExt + Unpin>(
        w: &mut W,
        data: &[u8],
    ) -> Result<(), TransportError> {
        let len =
            u16::try_from(data.len()).map_err(|_| TransportError::Malformed("chunk > u16"))?;
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(data).await?;
        Ok(())
    }

    async fn read_frame<R: AsyncReadExt + Unpin>(
        r: &mut R,
        out: &mut Vec<u8>,
    ) -> Result<usize, TransportError> {
        let mut hdr = [0u8; 2];
        r.read_exact(&mut hdr).await?;
        let len = u16::from_be_bytes(hdr) as usize;
        if len == 0 {
            return Err(TransportError::Malformed("empty noise frame"));
        }
        out.resize(len, 0);
        r.read_exact(out).await?;
        Ok(len)
    }

    impl AsyncNoiseStream {
        pub async fn connect(
            addr: SocketAddr,
            server_pub: &[u8; 32],
            local: Option<&StaticKeypair>,
            deadline: Duration,
        ) -> Result<Self, TransportError> {
            let owned;
            let local = match local {
                Some(k) => k,
                None => {
                    owned = StaticKeypair::generate();
                    &owned
                }
            };
            tokio::time::timeout(deadline, async {
                let mut stream = TcpStream::connect(addr).await?;
                stream.set_nodelay(true)?;
                let mut hs = build_initiator(local, server_pub)?;
                let mut wire = vec![0u8; 256];
                let n = hs
                    .write_message(&[], &mut wire)
                    .map_err(|_| TransportError::Noise("write msg1"))?;
                write_frame(&mut stream, &wire[..n]).await?;
                stream.flush().await?;

                let mut msg2 = Vec::new();
                read_frame(&mut stream, &mut msg2).await?;
                let mut plain = [0u8; 64];
                hs.read_message(&msg2, &mut plain)
                    .map_err(|_| TransportError::Noise("server authentication failed"))?;
                let state = Arc::new(
                    hs.into_stateless_transport_mode()
                        .map_err(|_| TransportError::Noise("transport mode"))?,
                );
                let (rx, tx) = stream.into_split();
                Ok(Self {
                    sender: AsyncNoiseSender {
                        stream: tx,
                        state: state.clone(),
                        nonce: 0,
                        buf: Vec::new(),
                    },
                    receiver: AsyncNoiseReceiver {
                        stream: rx,
                        state,
                        nonce: 0,
                        buf: Vec::new(),
                    },
                    peer_static: *server_pub,
                })
            })
            .await
            .map_err(|_| TransportError::Timeout)?
        }

        pub async fn accept(
            mut stream: TcpStream,
            local: &StaticKeypair,
            deadline: Duration,
        ) -> Result<Self, TransportError> {
            tokio::time::timeout(deadline, async {
                stream.set_nodelay(true)?;
                let mut hs = build_responder(local)?;
                let mut msg1 = Vec::new();
                read_frame(&mut stream, &mut msg1).await?;
                let mut plain = [0u8; 64];
                hs.read_message(&msg1, &mut plain)
                    .map_err(|_| TransportError::Noise("client handshake failed"))?;
                let peer_static: [u8; 32] = hs
                    .get_remote_static()
                    .and_then(|s| s.try_into().ok())
                    .ok_or(TransportError::Noise("missing client static key"))?;
                let mut wire = vec![0u8; 256];
                let n = hs
                    .write_message(&[], &mut wire)
                    .map_err(|_| TransportError::Noise("write msg2"))?;
                write_frame(&mut stream, &wire[..n]).await?;
                stream.flush().await?;
                let state = Arc::new(
                    hs.into_stateless_transport_mode()
                        .map_err(|_| TransportError::Noise("transport mode"))?,
                );
                let (rx, tx) = stream.into_split();
                Ok(Self {
                    sender: AsyncNoiseSender {
                        stream: tx,
                        state: state.clone(),
                        nonce: 0,
                        buf: Vec::new(),
                    },
                    receiver: AsyncNoiseReceiver {
                        stream: rx,
                        state,
                        nonce: 0,
                        buf: Vec::new(),
                    },
                    peer_static,
                })
            })
            .await
            .map_err(|_| TransportError::Timeout)?
        }

        pub fn split(self) -> (AsyncNoiseSender, AsyncNoiseReceiver, [u8; 32]) {
            (self.sender, self.receiver, self.peer_static)
        }

        pub async fn send<M: CborMsg>(&mut self, msg: &M) -> Result<(), TransportError> {
            self.sender.send(msg).await
        }

        pub async fn recv<M: CborMsg>(&mut self) -> Result<M, TransportError> {
            self.receiver.recv_max(MAX_CONTROL_FRAME).await
        }

        pub async fn recv_max<M: CborMsg>(&mut self, max: usize) -> Result<M, TransportError> {
            self.receiver.recv_max(max).await
        }

        pub async fn recv_timeout<M: CborMsg>(
            &mut self,
            max: usize,
            deadline: Duration,
        ) -> Result<M, TransportError> {
            tokio::time::timeout(deadline, self.receiver.recv_max(max))
                .await
                .map_err(|_| TransportError::Timeout)?
        }
    }

    impl AsyncNoiseSender {
        pub async fn send_bytes(&mut self, data: &[u8]) -> Result<(), TransportError> {
            let len = u32::try_from(data.len())
                .map_err(|_| TransportError::Malformed("message > u32"))?;
            let first_take = data.len().min(MAX_CHUNK - 4);
            let mut chunk = Vec::with_capacity(4 + first_take);
            chunk.extend_from_slice(&len.to_be_bytes());
            chunk.extend_from_slice(&data[..first_take]);
            self.write_chunk(&chunk).await?;
            for rest in data[first_take..].chunks(MAX_CHUNK) {
                self.write_chunk(rest).await?;
            }
            self.stream.flush().await?;
            Ok(())
        }

        async fn write_chunk(&mut self, plain: &[u8]) -> Result<(), TransportError> {
            if self.nonce >= REJECT_AFTER {
                return Err(TransportError::Exhausted);
            }
            self.buf.resize(plain.len() + TAG_LEN, 0);
            let n = self
                .state
                .write_message(self.nonce, plain, &mut self.buf)
                .map_err(|_| TransportError::Noise("encrypt"))?;
            self.nonce += 1;
            write_frame(&mut self.stream, &self.buf[..n]).await
        }

        pub async fn send<M: CborMsg>(&mut self, msg: &M) -> Result<(), TransportError> {
            self.send_bytes(&msg.encode()).await
        }

        pub async fn shutdown(&mut self) {
            let _ = self.stream.shutdown().await;
        }
    }

    impl AsyncNoiseReceiver {
        async fn read_chunk(&mut self, plain: &mut Vec<u8>) -> Result<(), TransportError> {
            if self.nonce >= REJECT_AFTER {
                return Err(TransportError::Exhausted);
            }
            let n = read_frame(&mut self.stream, &mut self.buf).await?;
            if n < TAG_LEN {
                return Err(TransportError::Malformed("short noise chunk"));
            }
            plain.resize(n - TAG_LEN, 0);
            let m = self
                .state
                .read_message(self.nonce, &self.buf[..n], plain)
                .map_err(|_| TransportError::Noise("decrypt"))?;
            self.nonce += 1;
            plain.truncate(m);
            Ok(())
        }

        pub async fn recv_bytes(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
            let mut chunk = Vec::new();
            self.read_chunk(&mut chunk).await?;
            if chunk.len() < 4 {
                return Err(TransportError::Malformed("short length prefix"));
            }
            let total = check_frame_len(chunk[..4].try_into().expect("4 bytes"), max)?;
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(&chunk[4..]);
            if out.len() > total {
                return Err(TransportError::Malformed("chunk overflow"));
            }
            while out.len() < total {
                self.read_chunk(&mut chunk).await?;
                if out.len() + chunk.len() > total {
                    return Err(TransportError::Malformed("chunk overflow"));
                }
                out.extend_from_slice(&chunk);
            }
            Ok(out)
        }

        pub async fn recv<M: CborMsg>(&mut self) -> Result<M, TransportError> {
            self.recv_max(MAX_CONTROL_FRAME).await
        }

        pub async fn recv_max<M: CborMsg>(&mut self, max: usize) -> Result<M, TransportError> {
            let raw = self.recv_bytes(max).await?;
            Ok(M::decode(&raw)?)
        }
    }
}
