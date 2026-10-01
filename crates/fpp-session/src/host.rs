//! The hosting player's endpoint: answers joins and keeps one session per peer.

use crate::hello::{HostHello, JoinHello};
use crate::packet::{self, Packet, COOKIE_LEN};
use crate::session::{kind, Frame, Session};
use crate::{random_u32, Error, StaticKeypair, Transmit, NOISE_PARAMS, PROLOGUE};
use fpp_crypto::KeySet;
use fpp_types::SessionKey;
use fpp_wire::AdmitPop;
use std::collections::{HashMap, VecDeque};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug)]
pub struct HostConfig {
    /// The host's static key; its public half goes into every invite.
    pub static_key: StaticKeypair,
    /// If set, joins must present it. It authorizes only: it is never used as
    /// key material, so every invite holder can know it.
    pub invite_secret: Option<[u8; 32]>,
    /// Ed25519 key that signs the host's Checkpoints, announced to joiners.
    pub instance_key: Option<[u8; 32]>,
    /// Title-defined bytes sent to every joiner in the handshake.
    pub hello: Vec<u8>,
    /// Established peers at most (the title's player limit).
    pub max_peers: usize,
    /// Handshakes answered but not yet confirmed, at most. The oldest is
    /// dropped first, so a flood of joins cannot grow memory.
    pub max_pending: usize,
}

impl HostConfig {
    pub fn new(static_key: StaticKeypair) -> Self {
        Self {
            static_key,
            invite_secret: None,
            instance_key: None,
            hello: Vec::new(),
            max_peers: 64,
            max_pending: 64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    /// A player completed the handshake and proved its session key.
    PeerJoined {
        peer: u32,
        /// FPP session key: verify this player's InputCommits with it.
        session_key: SessionKey,
        /// The signed AdmitPop, for the evidence bundle.
        admit_pop: Vec<u8>,
        /// Attestation Result bytes; empty means no device evidence (tier D0).
        /// Unverified here: appraise it before placing the player in a
        /// verified lobby.
        attestation: Vec<u8>,
        hello: Vec<u8>,
    },
    Data {
        peer: u32,
        payload: Vec<u8>,
    },
    /// A message on the reliable channel, delivered once and in order.
    Message {
        peer: u32,
        payload: Vec<u8>,
    },
    /// The peer's address changed after it answered a path challenge.
    PeerMigrated {
        peer: u32,
    },
    /// The peer closed the session (reason: fpp_types::Reason code).
    PeerLeft {
        peer: u32,
        reason: u16,
    },
}

struct Pending {
    session_key: SessionKey,
    admit_pop: Vec<u8>,
    attestation: Vec<u8>,
    hello: Vec<u8>,
}

struct Slot<A> {
    session: Session<A>,
    /// `None` until the joiner's first data packet confirms the handshake.
    peer: Option<u32>,
    pending: Option<Pending>,
}

pub struct Host<A> {
    cfg: HostConfig,
    /// By our (local) receiver index.
    slots: HashMap<u32, Slot<A>>,
    /// Peer id → (local index, session key).
    peers: HashMap<u32, (u32, SessionKey)>,
    pending_order: VecDeque<u32>,
    next_peer: u32,
    tx: VecDeque<Transmit<A>>,
    events: VecDeque<HostEvent>,
    /// Time from the last `tick`.
    now_ms: u64,
    /// Keys join cookies; never leaves the host.
    cookie_secret: [u8; 32],
}

/// A cookie is valid in the minute it was made and the next one.
const COOKIE_PERIOD_MS: u64 = 60_000;

impl<A: Clone + Eq + AsRef<[u8]>> Host<A> {
    pub fn new(cfg: HostConfig) -> Self {
        Self {
            cfg,
            slots: HashMap::new(),
            peers: HashMap::new(),
            pending_order: VecDeque::new(),
            next_peer: 1,
            tx: VecDeque::new(),
            events: VecDeque::new(),
            now_ms: 0,
            cookie_secret: {
                let mut k = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
                k
            },
        }
    }

    pub fn static_public_key(&self) -> [u8; 32] {
        self.cfg.static_key.public
    }

    /// Process one received datagram. On `Err` the datagram was dropped and
    /// nothing changed.
    pub fn recv(&mut self, from: A, datagram: &[u8]) -> Result<(), Error> {
        match packet::parse(datagram)? {
            Packet::Init {
                sender,
                noise,
                cookie,
            } => {
                if self.under_load() {
                    match cookie {
                        Some(c) if self.cookie_valid(&from, &c) => {}
                        Some(_) => return Err(Error::Cookie),
                        None => {
                            // One hash, no DH: a spoofed flood costs us almost
                            // nothing, and the reply is smaller than the request.
                            let c = self.cookie_for(&from, self.now_ms / COOKIE_PERIOD_MS);
                            self.tx.push_back(Transmit {
                                to: from,
                                packet: packet::cookie(sender, &c),
                            });
                            return Ok(());
                        }
                    }
                }
                self.on_init(from, sender, noise)
            }
            Packet::Data {
                receiver,
                counter,
                sealed,
            } => self.on_data(from, receiver, counter, sealed),
            Packet::Resp { .. } | Packet::Cookie { .. } => Err(Error::State),
        }
    }

    /// Half the pending-join budget in use: require cookies.
    fn under_load(&self) -> bool {
        self.pending_order.len() * 2 >= self.cfg.max_pending
    }

    fn cookie_for(&self, addr: &A, period: u64) -> [u8; COOKIE_LEN] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"fpp/1/p2p-cookie\0");
        h.update(self.cookie_secret);
        h.update(period.to_le_bytes());
        h.update((addr.as_ref().len() as u32).to_le_bytes());
        h.update(addr.as_ref());
        // Truncated keyed hash: without the full digest there is no length
        // extension, and the secret never leaves the host.
        h.finalize()[..COOKIE_LEN].try_into().expect("16 bytes")
    }

    fn cookie_valid(&self, addr: &A, cookie: &[u8; COOKIE_LEN]) -> bool {
        let period = self.now_ms / COOKIE_PERIOD_MS;
        [Some(period), period.checked_sub(1)]
            .into_iter()
            .flatten()
            .any(|p| bool::from(self.cookie_for(addr, p).ct_eq(cookie)))
    }

    /// Advance time: send pending acks and due retransmissions on every
    /// session. Call once per game tick with a monotonic clock in ms.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), Error> {
        self.now_ms = self.now_ms.max(now_ms);
        let mut tx = std::mem::take(&mut self.tx);
        let mut r = Ok(());
        for slot in self.slots.values_mut().filter(|s| s.peer.is_some()) {
            if let Err(e) = slot.session.tick(self.now_ms, &mut tx) {
                r = Err(e);
            }
        }
        self.tx = tx;
        r
    }

    /// Queue a message on the peer's reliable ordered channel (at most
    /// [`crate::MAX_MESSAGE`] bytes). It is resent from `tick` until acked.
    pub fn send_reliable(&mut self, peer: u32, payload: &[u8]) -> Result<(), Error> {
        let now = self.now_ms;
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session(peer)
            .and_then(|s| s.send_reliable(payload, now, &mut tx));
        self.tx = tx;
        r
    }

    fn on_init(&mut self, from: A, sender: u32, noise: &[u8]) -> Result<(), Error> {
        let params = NOISE_PARAMS.parse().expect("valid Noise params");
        let mut hs = snow::Builder::new(params)
            .local_private_key(&self.cfg.static_key.private)
            .and_then(|b| b.prologue(PROLOGUE))
            .and_then(|b| b.build_responder())
            .map_err(|_| Error::Handshake)?;
        let mut payload = vec![0u8; noise.len()];
        let n = hs
            .read_message(noise, &mut payload)
            .map_err(|_| Error::Handshake)?;
        let join = JoinHello::decode(&payload[..n])?;

        if let Some(expected) = &self.cfg.invite_secret {
            let ok = join
                .invite
                .is_some_and(|got| bool::from(got.ct_eq(expected)));
            if !ok {
                return Err(Error::Invite);
            }
        }
        let joiner_static: [u8; 32] = hs
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Handshake)?;
        self.check_binding(&join, &joiner_static)?;

        let reply = HostHello {
            instance_key: self.cfg.instance_key,
            app: self.cfg.hello.clone(),
        }
        .encode()?;
        let mut msg2 = vec![0u8; 64 + reply.len()];
        let n = hs
            .write_message(&reply, &mut msg2)
            .map_err(|_| Error::Handshake)?;
        msg2.truncate(n);
        let transport = hs
            .into_stateless_transport_mode()
            .map_err(|_| Error::Handshake)?;

        let index = self.fresh_index();
        self.tx.push_back(Transmit {
            to: from.clone(),
            packet: packet::resp(index, sender, &msg2),
        });
        self.slots.insert(
            index,
            Slot {
                session: Session::new(transport, sender, from),
                peer: None,
                pending: Some(Pending {
                    session_key: join.session_key,
                    admit_pop: join.admit_pop,
                    attestation: join.attestation,
                    hello: join.app,
                }),
            },
        );
        self.pending_order.push_back(index);
        while self.pending_order.len() > self.cfg.max_pending {
            if let Some(old) = self.pending_order.pop_front() {
                self.slots.remove(&old);
            }
        }
        Ok(())
    }

    /// The session key must have signed an AdmitPop for exactly this channel.
    fn check_binding(&self, join: &JoinHello, joiner_static: &[u8; 32]) -> Result<(), Error> {
        let mut keys = KeySet::default();
        keys.insert_session(&join.session_key)
            .ok_or(Error::Binding)?;
        let pop = fpp_crypto::verify::<AdmitPop>(&join.admit_pop, &keys)
            .map_err(|_| Error::Binding)?
            .payload;
        let binding = [self.cfg.static_key.public, *joiner_static].concat();
        if pop.channel != AdmitPop::NOISE_IK || pop.binding != binding {
            return Err(Error::Binding);
        }
        Ok(())
    }

    fn fresh_index(&self) -> u32 {
        loop {
            let i = random_u32();
            if i != 0 && !self.slots.contains_key(&i) {
                return i;
            }
        }
    }

    fn on_data(&mut self, from: A, index: u32, counter: u64, sealed: &[u8]) -> Result<(), Error> {
        let slot = self.slots.get_mut(&index).ok_or(Error::UnknownSession)?;
        let (k, body) = slot.session.open(counter, sealed)?;
        if slot.peer.is_none() {
            self.confirm(index)?;
        }
        let slot = self.slots.get_mut(&index).expect("confirmed slot");
        let peer = slot.peer.expect("confirmed");
        match slot
            .session
            .handle(&from, k, body, self.now_ms, &mut self.tx)?
        {
            Frame::App(payload) => self.events.push_back(HostEvent::Data { peer, payload }),
            Frame::Messages(msgs) => self.events.extend(
                msgs.into_iter()
                    .map(|payload| HostEvent::Message { peer, payload }),
            ),
            Frame::Nothing => {}
            Frame::Migrated => self.events.push_back(HostEvent::PeerMigrated { peer }),
            Frame::Closed(reason) => {
                self.remove(peer);
                self.events.push_back(HostEvent::PeerLeft { peer, reason });
            }
        }
        Ok(())
    }

    /// First authenticated packet on a new session: the joiner holds the keys
    /// (a replayed handshake message can never get here).
    fn confirm(&mut self, index: u32) -> Result<(), Error> {
        self.pending_order.retain(|&i| i != index);
        let slot = self.slots.get_mut(&index).expect("slot exists");
        let p = slot.pending.take().expect("pending join");
        // The same session key joining again (a restarted handshake) takes
        // over its peer id; the old session ends.
        let existing = self
            .peers
            .iter()
            .find(|(_, (_, key))| *key == p.session_key)
            .map(|(&peer, &(old, _))| (peer, old));
        if let Some((peer, old)) = existing {
            slot.peer = Some(peer);
            self.slots.remove(&old);
            self.peers.insert(peer, (index, p.session_key));
            return Ok(());
        }
        if self.peers.len() >= self.cfg.max_peers {
            let reason = (fpp_types::Reason::ServerFull as u16).to_le_bytes();
            let _ = slot.session.send(kind::CLOSE, &reason, &mut self.tx);
            self.slots.remove(&index);
            return Err(Error::Full);
        }
        let peer = self.next_peer;
        self.next_peer += 1;
        slot.peer = Some(peer);
        self.peers.insert(peer, (index, p.session_key));
        self.events.push_back(HostEvent::PeerJoined {
            peer,
            session_key: p.session_key,
            admit_pop: p.admit_pop,
            attestation: p.attestation,
            hello: p.hello,
        });
        Ok(())
    }

    fn session(&mut self, peer: u32) -> Result<&mut Session<A>, Error> {
        let &(index, _) = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        Ok(&mut self.slots.get_mut(&index).expect("peer slot").session)
    }

    /// Queue an application datagram (at most [`crate::MAX_PAYLOAD`] bytes) to a peer.
    pub fn send(&mut self, peer: u32, payload: &[u8]) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session(peer)
            .and_then(|s| s.send(kind::APP, payload, &mut tx));
        self.tx = tx;
        r
    }

    /// Queue an empty keepalive (keeps NAT bindings open when idle).
    pub fn keepalive(&mut self, peer: u32) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session(peer)
            .and_then(|s| s.send(kind::KEEPALIVE, &[], &mut tx));
        self.tx = tx;
        r
    }

    /// Tell the peer why, then forget it (e.g. `Reason::TierInsufficient`).
    pub fn disconnect(&mut self, peer: u32, reason: u16) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session(peer)
            .and_then(|s| s.send(kind::CLOSE, &reason.to_le_bytes(), &mut tx));
        self.tx = tx;
        self.remove(peer);
        r
    }

    fn remove(&mut self, peer: u32) {
        if let Some((index, _)) = self.peers.remove(&peer) {
            self.slots.remove(&index);
        }
    }

    /// The peer's validated address.
    pub fn peer_address(&self, peer: u32) -> Option<&A> {
        let (index, _) = self.peers.get(&peer)?;
        self.slots.get(index).map(|s| &s.session.remote)
    }

    /// The session key `peer` proved in its handshake.
    pub fn peer_session_key(&self, peer: u32) -> Option<SessionKey> {
        self.peers.get(&peer).map(|(_, key)| *key)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit<A>> {
        self.tx.pop_front()
    }

    /// The next datagram without removing it (lets the C ABI size its buffers).
    pub fn peek_transmit(&self) -> Option<&Transmit<A>> {
        self.tx.front()
    }

    pub fn poll_event(&mut self) -> Option<HostEvent> {
        self.events.pop_front()
    }

    /// The next event without removing it (lets the C ABI size its buffer).
    pub fn peek_event(&self) -> Option<&HostEvent> {
        self.events.front()
    }
}
