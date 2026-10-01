//! Reference client for the FPP prototype.
//!
//! 1. [`request_admission`]: prove a fresh session key to the Verifier and
//!    receive an Attestation Result; present it to the Broker and receive a
//!    Session Admission Token and the game server to join (its address and
//!    static key). Each is a separate service with its own key.
//! 2. [`GameClient::connect`]: join the game server over fpp-session (Noise
//!    IK to the key the Broker named), check its SAR binds that same key and
//!    the SAT's audience, then present `Admit{SAT, AR}`.
//! 3. [`GameClient::step`]: one tick: send intent as an `InputFrame`
//!    (unreliable, with redundancy), commit to each epoch's inputs with a
//!    signed `InputCommit` (reliable), and process snapshots, SAR updates and
//!    Checkpoint heads. The client stops the moment the server's SAR chain
//!    breaks or goes stale ([`SessionEnd::SarLapsed`]).

pub use anyhow::{anyhow, bail, Context, Result};

pub mod tpm;
pub mod transparency;

use common::{
    admission::request_challenge,
    crypto::{evidence_request_sign_bytes, match_request_sign_bytes},
    framing::{recv_msg, send_msg, send_msg_continue},
    keys::KeyBundle,
    proto::{
        ClientCmd, CredentialChallenge, CredentialResponse, EvidenceAnswer, EvidenceRequest,
        MatchAnswer, MatchRequest, WorldSnapshot,
    },
};
use ed25519_dalek::SigningKey;
use fpp_crypto::{Ed25519Signer, KeySet, SessionSigner};
use fpp_session::{JoinConfig, Joiner, JoinerEvent};
use fpp_tokens::{control::Control, verify_ar, verify_sat, SarChain, SessionAdmissionToken};
use fpp_types::{Digest, Reason};
use fpp_wire::{msg::frame_leaf_data, InputCommit, InputFrame};
use rand::rngs::OsRng;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Must match the server (`gs_sim::game`).
pub const TICK_HZ: u32 = 30;
pub const TICKS_PER_EPOCH: u32 = 30;
/// Unreliable payload kind of a snapshot.
const SNAPSHOT: u8 = 0x10;
/// Frames per InputFrame (1 + redundancy).
const REDUNDANCY: usize = 4;
/// How far ahead of the server's tick the client sends intent.
const LEAD_TICKS: u32 = 3;
/// No SAR for this long: the server is no longer blessed.
pub const SAR_GRACE: Duration = Duration::from_secs(6);

/// Why a session ended (downcast from the `anyhow::Error`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The server's SAR chain broke, expired or stopped: not blessed any more.
    SarLapsed,
    /// The server kicked us (`fpp_types::Reason` code).
    Kicked(u16),
    /// The server refused our admission.
    Rejected(u16),
    /// The Verifier or the Broker refused to admit us.
    Refused(u16),
}

impl std::fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session ended: {self:?}")
    }
}

impl std::error::Error for SessionEnd {}

/// What the client trusts: the CA of the services' TLS certificates and the
/// regional key bundle (Verifier, Broker, Server Liveness keys).
#[derive(Clone)]
pub struct ClientTrust {
    pub ca_der: Vec<u8>,
    pub bundle: KeyBundle,
}

impl ClientTrust {
    pub fn load_default() -> Result<Self> {
        Ok(Self {
            ca_der: common::pki::load_ca(common::pki::DEFAULT_CA_CERT)?,
            bundle: KeyBundle::load(common::keys::DEFAULT_BUNDLE)?,
        })
    }

    pub fn keyset(&self) -> KeySet {
        self.bundle.keyset()
    }
}

/// A session key, held here or in hardware.
pub type SessionSigning = Box<dyn SessionSigner + Send + Sync>;

/// Everything needed to join a match.
pub struct Credentials {
    /// Session key: proves itself to the server, signs InputCommits
    /// (Ed25519, or ES256 for a key held in hardware).
    pub session: SessionSigning,
    pub ar: Vec<u8>,
    pub sat: Vec<u8>,
    pub sat_claims: SessionAdmissionToken,
    pub gs_addr: SocketAddr,
    pub gs_noise_static: [u8; 32],
}

fn unix_s() -> u64 {
    common::crypto::now_ms() / 1000
}

/// Where a client asks for admission: the region's Verifier and Broker.
#[derive(Clone, Copy, Debug)]
pub struct Services {
    pub verifier: SocketAddr,
    pub broker: SocketAddr,
    /// The Transparency Log (gossip) and Server Liveness (split-view
    /// reports).
    pub log: SocketAddr,
    pub liveness: SocketAddr,
}

impl Default for Services {
    /// A development cell on this machine.
    fn default() -> Self {
        Self {
            verifier: "127.0.0.1:4445".parse().expect("addr"),
            broker: "127.0.0.1:4446".parse().expect("addr"),
            log: "127.0.0.1:4447".parse().expect("addr"),
            liveness: "127.0.0.1:4444".parse().expect("addr"),
        }
    }
}

/// Ask the Verifier for an AR, then the Broker for a SAT for `queue`, with
/// a fresh session key.
pub async fn request_admission(
    services: &Services,
    trust: &ClientTrust,
    queue: &str,
) -> Result<Credentials> {
    let session = Ed25519Signer::new(SigningKey::generate(&mut OsRng));
    request_admission_with(services, trust, queue, Box::new(session)).await
}

/// A device's platform evidence for the Verifier (roadmap P3).
pub trait Attestor: Send + Sync {
    /// Evidence bound to the Verifier's challenge and the session key
    /// (`SessionKey::to_bytes`).
    fn evidence(&self, verifier_challenge: &[u8; 32], session_pub: &[u8]) -> Result<Vec<u8>>;
    /// `TPM2_ActivateCredential`, when the Verifier asks (TPM evidence).
    fn activate(&self, _challenge: &CredentialChallenge) -> Result<Vec<u8>> {
        bail!("this device has no TPM to activate a credential")
    }
}

/// [`request_admission`] with a given session key.
pub async fn request_admission_with(
    services: &Services,
    trust: &ClientTrust,
    queue: &str,
    session: SessionSigning,
) -> Result<Credentials> {
    request_admission_attested(services, trust, queue, session, None).await
}

/// [`request_admission_with`] with the device's platform evidence.
pub async fn request_admission_attested(
    services: &Services,
    trust: &ClientTrust,
    queue: &str,
    session: SessionSigning,
    attestor: Option<&dyn Attestor>,
) -> Result<Credentials> {
    request_admission_for_build(services, trust, queue, session, attestor, client_build()).await
}

/// [`request_admission_attested`] for a game's own build (a C game that
/// gets its tokens from `fpp-ticket`): the `client_build` its AR carries
/// where the platform does not measure one.
pub async fn request_admission_for_build(
    services: &Services,
    trust: &ClientTrust,
    queue: &str,
    session: SessionSigning,
    attestor: Option<&dyn Attestor>,
    client_build: [u8; 32],
) -> Result<Credentials> {
    let session_key = session.session_key();
    let session_pub = session_key.to_bytes();
    let keys = trust.keyset();

    // ---- Verifier: the session key and the device's evidence, for an AR.
    let mut v = request_challenge(&trust.ca_der, services.verifier, "verifier").await?;
    let platform = std::env::consts::OS.to_string();
    let evidence = match attestor {
        Some(a) => a.evidence(&v.challenge, &session_pub)?,
        None => Vec::new(), // no platform evidence: tier D0
    };
    let msg = evidence_request_sign_bytes(
        &v.challenge,
        &session_pub,
        &platform,
        &client_build,
        &evidence,
    );
    let pop_sig: [u8; 64] = session
        .sign(&msg)
        .try_into()
        .map_err(|_| anyhow!("the session key's signature is not 64 bytes"))?;
    // (the stream stays open: the Verifier may ask for credential activation)
    send_msg_continue(
        &mut v.send,
        &EvidenceRequest {
            session_pub,
            pop_sig,
            platform,
            client_build,
            evidence,
        },
    )
    .await?;
    let mut answer: EvidenceAnswer = recv_msg(&mut v.recv).await.context("recv EvidenceAnswer")?;
    if let EvidenceAnswer::Activate(credential) = &answer {
        let attestor = attestor.context("the Verifier asked for credential activation")?;
        let secret = attestor.activate(credential)?;
        send_msg(&mut v.send, &CredentialResponse { secret }).await?;
        answer = recv_msg(&mut v.recv).await.context("recv EvidenceAnswer")?;
    }
    v.conn.close(0u32.into(), b"thanks");
    let ar = match answer {
        EvidenceAnswer::Ar(ar) => ar,
        EvidenceAnswer::Refused { code } => return Err(SessionEnd::Refused(code).into()),
        EvidenceAnswer::Activate(_) => bail!("the Verifier asked for activation twice"),
    };
    let ar_claims = verify_ar(&ar, &keys, unix_s()).map_err(|e| anyhow!("AR: {e}"))?;
    if ar_claims.cnf != session_key || ar_claims.nonce != v.challenge {
        bail!("AR is not for our session key and this request");
    }

    // ---- Broker: the AR, used by its key, for a match.
    let mut b = request_challenge(&trust.ca_der, services.broker, "broker").await?;
    let msg = match_request_sign_bytes(&b.challenge, &ar, queue);
    let pop_sig: [u8; 64] = session
        .sign(&msg)
        .try_into()
        .map_err(|_| anyhow!("the session key's signature is not 64 bytes"))?;
    send_msg(
        &mut b.send,
        &MatchRequest {
            ar: ar.clone(),
            queue: queue.into(),
            pop_sig,
        },
    )
    .await?;
    let answer: MatchAnswer = recv_msg(&mut b.recv).await.context("recv MatchAnswer")?;
    b.conn.close(0u32.into(), b"thanks");
    let (sat, gs_addr, gs_noise_static) = match answer {
        MatchAnswer::Refused { code } => return Err(SessionEnd::Refused(code).into()),
        MatchAnswer::Granted {
            sat,
            gs_addr,
            gs_noise_static,
        } => (sat, gs_addr, gs_noise_static),
    };
    // Check what we were given before using it.
    let sat_claims = verify_sat(&sat, &keys, unix_s()).map_err(|e| anyhow!("SAT: {e}"))?;
    if sat_claims.cnf != session_key || sat_claims.ar_cti != ar_claims.cti {
        bail!("SAT is not bound to our session key and AR");
    }
    Ok(Credentials {
        session,
        ar,
        sat,
        sat_claims,
        gs_addr: gs_addr.parse().context("bad GS address from the Broker")?,
        gs_noise_static,
    })
}

/// The build this client claims to the Verifier (an AR's `client_build`
/// where the platform does not measure it): a game server's client-build
/// list must name it (`fpp_admission_add_client_build`).
pub fn client_build() -> [u8; 32] {
    common::crypto::sha256(env!("CARGO_PKG_VERSION").as_bytes())
}

pub fn addr_bytes(a: &SocketAddr) -> Vec<u8> {
    a.to_string().into_bytes()
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClientEvent {
    Snapshot(WorldSnapshot),
    CheckpointHead { epoch: u32, digest: Digest },
}

pub struct GameClient {
    socket: UdpSocket,
    joiner: Joiner<Vec<u8>>,
    keys: KeySet,
    creds: Credentials,
    sar: Option<SarChain>,
    last_sar: Instant,
    sar_grace: Duration,
    start: Instant,
    slot: u16,
    tick: u32,
    recent: VecDeque<(u32, Vec<u8>)>,
    epoch: u32,
    epoch_frames: Vec<(u32, Vec<u8>)>,
    prev_commit: Digest,
    /// Checkpoints the server sent, verified under its instance key (to
    /// check against the Transparency Log, 04 §7.6: [`transparency`]).
    pub heads: Vec<transparency::Head>,
}

impl GameClient {
    pub fn slot(&self) -> u16 {
        self.slot
    }

    /// The match this client was admitted to.
    pub fn match_id(&self) -> [u8; 16] {
        self.creds.sat_claims.match_id.0
    }

    /// A Checkpoint from the server: signed by the instance key its SAR
    /// certifies, for this match. One that is not is the server lying.
    fn on_checkpoint(&mut self, signed: Vec<u8>) -> Result<transparency::Head> {
        let Some(chain) = self.sar.as_ref() else {
            bail!("a Checkpoint before any SAR");
        };
        let mut keys = KeySet::default();
        keys.insert_ed25519(
            fpp_crypto::KeyRole::GsInstance,
            ed25519_dalek::VerifyingKey::from_bytes(&chain.current().cnf)?,
        );
        let v = fpp_crypto::verify::<fpp_wire::Checkpoint>(&signed, &keys)
            .map_err(|e| anyhow!("the server sent a Checkpoint it did not sign: {e}"))?;
        if v.payload.match_id != self.creds.sat_claims.match_id {
            bail!("the server sent a Checkpoint of another match");
        }
        let head = transparency::Head {
            epoch: v.payload.epoch,
            digest: v.digest,
            signed,
        };
        self.heads.push(head.clone());
        Ok(head)
    }

    /// Highest SAR sequence seen.
    pub fn sar_seq(&self) -> Option<u64> {
        self.sar.as_ref().map(|c| c.current().seq)
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    async fn flush(&mut self) -> Result<()> {
        while let Some(t) = self.joiner.poll_transmit() {
            self.socket.send_to(&t.packet, self.creds.gs_addr).await?;
        }
        Ok(())
    }

    fn control(&mut self, msg: &Control) -> Result<()> {
        self.joiner
            .send_reliable(&msg.encode())
            .map_err(|e| anyhow!("send control: {e}"))
    }

    /// A SAR from the server: start or extend the chain, and check it
    /// certifies the server we dialled for the match our SAT is for.
    fn on_sar(&mut self, sar: &[u8]) -> Result<()> {
        let now = unix_s();
        let r = match self.sar.as_mut() {
            None => SarChain::start(sar, &self.keys, now).map(|c| self.sar = Some(c)),
            Some(c) => c.update(sar, &self.keys, now),
        };
        let bound = self.sar.as_ref().is_some_and(|c| {
            c.current().noise_static == Some(self.creds.gs_noise_static)
                && c.current().sub == self.creds.sat_claims.aud
        });
        if r.is_err() || !bound {
            return Err(SessionEnd::SarLapsed.into());
        }
        self.last_sar = Instant::now();
        Ok(())
    }

    /// Join the server named in `creds` and get admitted.
    pub async fn connect(
        creds: Credentials,
        trust: &ClientTrust,
        timeout: Duration,
    ) -> Result<Self> {
        Self::connect_with_grace(creds, trust, timeout, SAR_GRACE).await
    }

    pub async fn connect_with_grace(
        creds: Credentials,
        trust: &ClientTrust,
        timeout: Duration,
        sar_grace: Duration,
    ) -> Result<Self> {
        let bind: SocketAddr = if creds.gs_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = UdpSocket::bind(bind).await?;
        let joiner = Joiner::new(
            JoinConfig {
                host_static: creds.gs_noise_static,
                invite_secret: None,
                // The AR travels in Admit; the first handshake packet stays small.
                attestation: Vec::new(),
                hello: Vec::new(),
            },
            creds.session.as_ref(),
            addr_bytes(&creds.gs_addr),
        )
        .map_err(|e| anyhow!("join: {e}"))?;
        let mut c = Self {
            socket,
            joiner,
            keys: trust.keyset(),
            creds,
            sar: None,
            last_sar: Instant::now(),
            sar_grace,
            start: Instant::now(),
            slot: 0,
            tick: 0,
            recent: VecDeque::new(),
            epoch: 0,
            epoch_frames: Vec::new(),
            prev_commit: Digest::default(),
            heads: Vec::new(),
        };
        let deadline = Instant::now() + timeout;
        let mut next_retry = Instant::now() + Duration::from_millis(500);
        let mut admit_sent = false;
        let mut buf = vec![0u8; 2048];
        c.flush().await?;
        loop {
            let now = Instant::now();
            if now >= deadline {
                bail!("timed out joining {}", c.creds.gs_addr);
            }
            if now >= next_retry && !c.joiner.is_connected() {
                c.joiner.retry().map_err(|e| anyhow!("retry: {e}"))?;
                next_retry = now + Duration::from_millis(500);
            }
            let wait = next_retry
                .min(deadline)
                .saturating_duration_since(now)
                .max(Duration::from_millis(5));
            if let Ok(Ok((n, from))) =
                tokio::time::timeout(wait, c.socket.recv_from(&mut buf)).await
            {
                let _ = c.joiner.recv(addr_bytes(&from), &buf[..n]);
            }
            let _ = c.joiner.tick(c.now_ms());
            while let Some(ev) = c.joiner.poll_event() {
                match ev {
                    JoinerEvent::Message { payload } => match Control::decode(&payload) {
                        Ok(Control::SarUpdate { sar }) => {
                            c.on_sar(&sar)?;
                            if !admit_sent {
                                let admit = Control::Admit {
                                    sat: c.creds.sat.clone(),
                                    ar: c.creds.ar.clone(),
                                    // Possession of the session key was proven in the
                                    // fpp-session handshake (AdmitPop, 04 §7.7).
                                    pop: Vec::new(),
                                };
                                c.control(&admit)?;
                                admit_sent = true;
                            }
                        }
                        Ok(Control::Admitted { slot, start_tick }) => {
                            c.slot = slot;
                            // Aim a little ahead so intents arrive before their tick.
                            c.tick = start_tick + LEAD_TICKS;
                            c.epoch = c.tick / TICKS_PER_EPOCH;
                            c.flush().await?;
                            return Ok(c);
                        }
                        Ok(Control::Reject { code }) => {
                            return Err(SessionEnd::Rejected(code).into())
                        }
                        Ok(Control::Kick { code }) => return Err(SessionEnd::Kicked(code).into()),
                        _ => {}
                    },
                    JoinerEvent::Closed { reason } => {
                        return Err(SessionEnd::Rejected(reason).into())
                    }
                    _ => {}
                }
            }
            c.flush().await?;
        }
    }

    fn commit_epoch(&mut self) -> Result<()> {
        let first = self.epoch * TICKS_PER_EPOCH;
        let leaves: Vec<Vec<u8>> = self
            .epoch_frames
            .iter()
            .map(|(t, p)| frame_leaf_data(*t, p))
            .collect();
        let commit = InputCommit {
            match_id: self.creds.sat_claims.match_id,
            slot: self.slot,
            epoch: self.epoch,
            first_tick: first,
            last_tick: first + TICKS_PER_EPOCH - 1,
            n: leaves.len() as u32,
            frames_root: fpp_merkle::root(&leaves),
            prev: self.prev_commit,
        };
        let signed = fpp_crypto::sign(self.creds.session.as_ref(), &commit);
        self.prev_commit = fpp_crypto::object_digest(&signed);
        self.epoch_frames.clear();
        self.control(&Control::InputCommit { commit: signed })
    }

    /// One tick: send `cmd`, then process what arrives for about one tick.
    pub async fn step(&mut self, cmd: &ClientCmd) -> Result<Vec<ClientEvent>> {
        let lapsed = self.last_sar.elapsed() > self.sar_grace
            || !self.sar.as_ref().is_some_and(|c| c.live(unix_s()));
        if lapsed {
            return Err(SessionEnd::SarLapsed.into());
        }
        let tick = self.tick;
        if tick / TICKS_PER_EPOCH != self.epoch {
            self.commit_epoch()?;
            self.epoch = tick / TICKS_PER_EPOCH;
        }
        let payload = bincode::serialize(cmd)?;
        self.epoch_frames.push((tick, payload.clone()));
        self.recent.push_front((tick, payload));
        self.recent.truncate(REDUNDANCY);
        let frame = InputFrame {
            slot: self.slot,
            tick,
            frames: self.recent.iter().cloned().collect(),
        };
        self.joiner
            .send(&frame.encode())
            .map_err(|e| anyhow!("send input: {e}"))?;
        self.tick += 1;
        let _ = self.joiner.tick(self.now_ms());
        self.flush().await?;

        let mut events = Vec::new();
        let until = Instant::now() + Duration::from_millis(1000 / u64::from(TICK_HZ));
        let mut buf = vec![0u8; 2048];
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) =
                tokio::time::timeout(left, self.socket.recv_from(&mut buf)).await
            else {
                break;
            };
            if self.joiner.recv(addr_bytes(&from), &buf[..n]).is_err() {
                continue;
            }
            while let Some(ev) = self.joiner.poll_event() {
                match ev {
                    JoinerEvent::Data { payload } if payload.first() == Some(&SNAPSHOT) => {
                        if let Ok(s) = bincode::deserialize::<WorldSnapshot>(&payload[1..]) {
                            // Stay LEAD ticks ahead of the server so intents
                            // arrive before their tick (never step backwards:
                            // a tick's intent is sent once).
                            let lead = u32::try_from(s.tick)
                                .unwrap_or(u32::MAX)
                                .saturating_add(LEAD_TICKS);
                            self.tick = self.tick.max(lead);
                            events.push(ClientEvent::Snapshot(s));
                        }
                    }
                    JoinerEvent::Message { payload } => match Control::decode(&payload) {
                        Ok(Control::SarUpdate { sar }) => self.on_sar(&sar)?,
                        Ok(Control::CheckpointHead { checkpoint }) => {
                            let head = self.on_checkpoint(checkpoint)?;
                            events.push(ClientEvent::CheckpointHead {
                                epoch: head.epoch,
                                digest: head.digest,
                            });
                        }
                        Ok(Control::Kick { code }) => return Err(SessionEnd::Kicked(code).into()),
                        _ => {}
                    },
                    JoinerEvent::Closed { reason } => {
                        let end = if reason == Reason::SarLapsed as u16 {
                            SessionEnd::SarLapsed
                        } else {
                            SessionEnd::Kicked(reason)
                        };
                        return Err(end.into());
                    }
                    _ => {}
                }
            }
            self.flush().await?;
        }
        Ok(events)
    }

    /// Leave politely.
    pub async fn bye(mut self) -> Result<()> {
        let _ = self.control(&Control::Bye);
        let _ = self.joiner.tick(self.now_ms());
        self.flush().await
    }
}
