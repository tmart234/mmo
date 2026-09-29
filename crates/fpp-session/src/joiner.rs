//! A joining player's endpoint: one session to the host.

use crate::hello::{HostHello, JoinHello};
use crate::packet::{self, Packet};
use crate::session::{kind, Frame, Session};
use crate::{random_u32, Error, StaticKeypair, Transmit, NOISE_PARAMS, PROLOGUE};
use fpp_crypto::Ed25519Signer;
use fpp_wire::AdmitPop;
use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct JoinConfig {
    /// The host's static public key, from the invite (never from the network).
    pub host_static: [u8; 32],
    /// The invite's secret, if the host requires one.
    pub invite_secret: Option<[u8; 32]>,
    /// Attestation Result for this device's session key; empty for none (D0).
    pub attestation: Vec<u8>,
    /// Title-defined bytes for the host (e.g. player name, build).
    pub hello: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinerEvent {
    /// The host answered and is authenticated by its invite key.
    Connected {
        /// Key the host signs Checkpoints with, if it keeps evidence.
        instance_key: Option<[u8; 32]>,
        hello: Vec<u8>,
    },
    Data {
        payload: Vec<u8>,
    },
    /// The host's address changed after it answered a path challenge.
    HostMigrated,
    /// The host closed the session (reason: fpp_types::Reason code).
    Closed {
        reason: u16,
    },
}

enum State<A> {
    Handshaking {
        hs: Box<snow::HandshakeState>,
        index: u32,
    },
    Connected {
        session: Box<Session<A>>,
        index: u32,
    },
    Closed,
}

pub struct Joiner<A> {
    host_static: [u8; 32],
    static_key: StaticKeypair,
    /// Encoded JoinHello, including the AdmitPop signed once at creation.
    hello: Vec<u8>,
    host_addr: A,
    state: State<A>,
    tx: VecDeque<Transmit<A>>,
    events: VecDeque<JoinerEvent>,
}

impl<A: Clone + Eq> Joiner<A> {
    /// Start joining `host_addr`; the first handshake packet is queued.
    /// `session_key` is the player's FPP session key: it signs the AdmitPop
    /// now and this player's InputCommits later.
    pub fn new(cfg: JoinConfig, session_key: &Ed25519Signer, host_addr: A) -> Result<Self, Error> {
        let static_key = StaticKeypair::generate();
        let pop = AdmitPop {
            channel: AdmitPop::NOISE_IK.into(),
            binding: [cfg.host_static, static_key.public].concat(),
        };
        let hello = JoinHello {
            invite: cfg.invite_secret,
            session_key: session_key.verifying_key().to_bytes(),
            admit_pop: fpp_crypto::sign(session_key, &pop),
            attestation: cfg.attestation,
            app: cfg.hello,
        }
        .encode()?;
        let mut j = Self {
            host_static: cfg.host_static,
            static_key,
            hello,
            host_addr,
            state: State::Closed,
            tx: VecDeque::new(),
            events: VecDeque::new(),
        };
        j.start()?;
        Ok(j)
    }

    fn start(&mut self) -> Result<(), Error> {
        let params = NOISE_PARAMS.parse().expect("valid Noise params");
        let mut hs = snow::Builder::new(params)
            .local_private_key(&self.static_key.private)
            .and_then(|b| b.remote_public_key(&self.host_static))
            .and_then(|b| b.prologue(PROLOGUE))
            .and_then(|b| b.build_initiator())
            .map_err(|_| Error::Handshake)?;
        let mut msg1 = vec![0u8; 128 + self.hello.len()];
        let n = hs
            .write_message(&self.hello, &mut msg1)
            .map_err(|_| Error::Handshake)?;
        msg1.truncate(n);
        let index = random_u32() | 1;
        self.tx.push_back(Transmit {
            to: self.host_addr.clone(),
            packet: packet::init(index, &msg1),
        });
        self.state = State::Handshaking {
            hs: Box::new(hs),
            index,
        };
        Ok(())
    }

    /// Send a fresh handshake if still not connected (call on the game's
    /// retry timer, e.g. every 500 ms). No effect once connected.
    pub fn retry(&mut self) -> Result<(), Error> {
        match self.state {
            State::Connected { .. } => Ok(()),
            _ => self.start(),
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Connected { .. })
    }

    /// Process one received datagram. On `Err` it was dropped and nothing changed.
    pub fn recv(&mut self, from: A, datagram: &[u8]) -> Result<(), Error> {
        match packet::parse(datagram)? {
            Packet::Resp {
                sender,
                receiver,
                noise,
            } => self.on_resp(sender, receiver, noise),
            Packet::Data {
                receiver,
                counter,
                sealed,
            } => self.on_data(from, receiver, counter, sealed),
            Packet::Init { .. } => Err(Error::State),
        }
    }

    fn on_resp(&mut self, sender: u32, receiver: u32, noise: &[u8]) -> Result<(), Error> {
        let State::Handshaking { hs, index } = &mut self.state else {
            return Err(Error::State);
        };
        if receiver != *index {
            return Err(Error::UnknownSession);
        }
        let index = *index;
        // A forged response fails here and leaves the handshake as it was
        // (snow restores its state on a failed read).
        let mut payload = vec![0u8; noise.len()];
        let n = hs
            .read_message(noise, &mut payload)
            .map_err(|_| Error::Handshake)?;
        let State::Handshaking { hs, .. } = std::mem::replace(&mut self.state, State::Closed)
        else {
            unreachable!("checked above");
        };
        // From here on the response was authentic; a bad hello from the real
        // host ends this attempt (`retry` starts a new one).
        let hello = HostHello::decode(&payload[..n])?;
        let transport = hs
            .into_stateless_transport_mode()
            .map_err(|_| Error::Handshake)?;
        // Keep sending to the address we dialled; path validation decides
        // whether the host has moved.
        let mut session = Session::new(transport, sender, self.host_addr.clone());
        // Confirm at once: the host admits us on our first data packet.
        session.send(kind::KEEPALIVE, &[], &mut self.tx)?;
        self.state = State::Connected {
            session: Box::new(session),
            index,
        };
        self.events.push_back(JoinerEvent::Connected {
            instance_key: hello.instance_key,
            hello: hello.app,
        });
        Ok(())
    }

    fn on_data(
        &mut self,
        from: A,
        receiver: u32,
        counter: u64,
        sealed: &[u8],
    ) -> Result<(), Error> {
        let State::Connected { session, index } = &mut self.state else {
            return Err(Error::State);
        };
        if receiver != *index {
            return Err(Error::UnknownSession);
        }
        let (k, body) = session.open(counter, sealed)?;
        match session.handle(&from, k, body, &mut self.tx)? {
            Frame::App(payload) => self.events.push_back(JoinerEvent::Data { payload }),
            Frame::Nothing => {}
            Frame::Migrated => self.events.push_back(JoinerEvent::HostMigrated),
            Frame::Closed(reason) => {
                self.state = State::Closed;
                self.events.push_back(JoinerEvent::Closed { reason });
            }
        }
        Ok(())
    }

    fn session(&mut self) -> Result<&mut Session<A>, Error> {
        match &mut self.state {
            State::Connected { session, .. } => Ok(session),
            _ => Err(Error::State),
        }
    }

    /// Queue an application datagram (at most [`crate::MAX_PAYLOAD`] bytes).
    pub fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session()
            .and_then(|s| s.send(kind::APP, payload, &mut tx));
        self.tx = tx;
        r
    }

    pub fn keepalive(&mut self) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session()
            .and_then(|s| s.send(kind::KEEPALIVE, &[], &mut tx));
        self.tx = tx;
        r
    }

    /// Tell the host we are leaving, then stop.
    pub fn close(&mut self, reason: u16) -> Result<(), Error> {
        let mut tx = std::mem::take(&mut self.tx);
        let r = self
            .session()
            .and_then(|s| s.send(kind::CLOSE, &reason.to_le_bytes(), &mut tx));
        self.tx = tx;
        self.state = State::Closed;
        r
    }

    /// The host's validated address.
    pub fn host_address(&self) -> &A {
        match &self.state {
            State::Connected { session, .. } => &session.remote,
            _ => &self.host_addr,
        }
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit<A>> {
        self.tx.pop_front()
    }

    /// The next datagram without removing it (lets the C ABI size its buffers).
    pub fn peek_transmit(&self) -> Option<&Transmit<A>> {
        self.tx.front()
    }

    pub fn poll_event(&mut self) -> Option<JoinerEvent> {
        self.events.pop_front()
    }

    pub fn peek_event(&self) -> Option<&JoinerEvent> {
        self.events.front()
    }
}
