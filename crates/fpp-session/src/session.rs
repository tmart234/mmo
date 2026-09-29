//! An established session: sealing and opening data packets, and path
//! validation (a peer's address changes only after it proves, from the new
//! address, that it holds the session keys).

use crate::packet::data_header;
use crate::replay::ReplayWindow;
use crate::{Error, Transmit, MAX_PACKET, MAX_PAYLOAD, REJECT_AFTER};
use snow::StatelessTransportState;
use std::collections::VecDeque;
use subtle::ConstantTimeEq;

/// Frame kinds inside a data packet.
pub(crate) mod kind {
    pub const APP: u8 = 0;
    /// Empty; confirms a new session and keeps NAT bindings open.
    pub const KEEPALIVE: u8 = 1;
    /// 8 random bytes, sent to an address the peer has not yet proven.
    pub const PATH_CHALLENGE: u8 = 2;
    /// Echo of a challenge, sent back from the address it arrived on.
    pub const PATH_RESPONSE: u8 = 3;
    /// u16le reason code (fpp_types::Reason); the session ends.
    pub const CLOSE: u8 = 4;
}

/// Send one challenge per this many authenticated packets from an unproven
/// address, so a lost challenge is retried without flooding the path.
const CHALLENGE_EVERY: u32 = 8;

/// What an authenticated packet carried, for the endpoint to report.
pub(crate) enum Frame {
    App(Vec<u8>),
    Nothing,
    Migrated,
    Closed(u16),
}

struct Probe<A> {
    addr: A,
    token: [u8; 8],
    seen: u32,
}

pub(crate) struct Session<A> {
    transport: StatelessTransportState,
    remote_index: u32,
    send_counter: u64,
    replay: ReplayWindow,
    /// Validated address of the peer: the only place we send to.
    pub remote: A,
    probe: Option<Probe<A>>,
}

impl<A: Clone + Eq> Session<A> {
    pub fn new(transport: StatelessTransportState, remote_index: u32, remote: A) -> Self {
        Self {
            transport,
            remote_index,
            send_counter: 0,
            replay: ReplayWindow::default(),
            remote,
            probe: None,
        }
    }

    pub fn seal(&mut self, kind: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        if self.send_counter >= REJECT_AFTER {
            return Err(Error::Exhausted);
        }
        let counter = self.send_counter;
        self.send_counter += 1;
        let mut plain = Vec::with_capacity(1 + body.len());
        plain.push(kind);
        plain.extend_from_slice(body);
        let mut out = vec![0u8; 13 + plain.len() + 16];
        out[..13].copy_from_slice(&data_header(self.remote_index, counter));
        let n = self
            .transport
            .write_message(counter, &plain, &mut out[13..])
            .map_err(|_| Error::TooLarge)?;
        out.truncate(13 + n);
        debug_assert!(out.len() <= MAX_PACKET);
        Ok(out)
    }

    /// Seal a frame to the validated address.
    pub fn send(
        &mut self,
        kind: u8,
        body: &[u8],
        tx: &mut VecDeque<Transmit<A>>,
    ) -> Result<(), Error> {
        let packet = self.seal(kind, body)?;
        tx.push_back(Transmit {
            to: self.remote.clone(),
            packet,
        });
        Ok(())
    }

    /// Authenticate and decrypt; the counter is marked seen only on success.
    pub fn open(&mut self, counter: u64, sealed: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        if counter >= REJECT_AFTER || !self.replay.check(counter) {
            return Err(Error::Replay);
        }
        let mut plain = vec![0u8; sealed.len()];
        let n = self
            .transport
            .read_message(counter, sealed, &mut plain)
            .map_err(|_| Error::Decrypt)?;
        self.replay.mark(counter);
        plain.truncate(n);
        let kind = *plain.first().ok_or(Error::Malformed)?;
        plain.remove(0);
        Ok((kind, plain))
    }

    /// Act on an authenticated frame that arrived from `from`.
    pub fn handle(
        &mut self,
        from: &A,
        kind: u8,
        body: Vec<u8>,
        tx: &mut VecDeque<Transmit<A>>,
    ) -> Result<Frame, Error> {
        if kind == kind::PATH_RESPONSE {
            let proven = match &self.probe {
                Some(p) => p.addr == *from && bool::from(p.token.ct_eq(&body[..])),
                None => false,
            };
            if !proven {
                return Ok(Frame::Nothing);
            }
            self.remote = from.clone();
            self.probe = None;
            return Ok(Frame::Migrated);
        }
        if *from == self.remote {
            // Traffic from the validated address again: abandon any probe
            // (a replayed or reordered packet must not start a migration).
            self.probe = None;
        } else if kind != kind::PATH_CHALLENGE {
            // A challenge alone does not start a probe: the peer's next real
            // packet from that address will, if it has really moved.
            self.challenge(from, tx)?;
        }
        match kind {
            kind::APP => Ok(Frame::App(body)),
            kind::KEEPALIVE if body.is_empty() => Ok(Frame::Nothing),
            kind::PATH_CHALLENGE if body.len() == 8 => {
                // Answer on the path the challenge arrived on.
                let packet = self.seal(kind::PATH_RESPONSE, &body)?;
                tx.push_back(Transmit {
                    to: from.clone(),
                    packet,
                });
                Ok(Frame::Nothing)
            }
            kind::CLOSE if body.len() == 2 => {
                Ok(Frame::Closed(u16::from_le_bytes([body[0], body[1]])))
            }
            _ => Err(Error::Malformed),
        }
    }

    fn challenge(&mut self, from: &A, tx: &mut VecDeque<Transmit<A>>) -> Result<(), Error> {
        let probe = match &mut self.probe {
            Some(p) if p.addr == *from => p,
            _ => {
                let mut token = [0u8; 8];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
                self.probe.insert(Probe {
                    addr: from.clone(),
                    token,
                    seen: 0,
                })
            }
        };
        let due = probe.seen % CHALLENGE_EVERY == 0;
        probe.seen = probe.seen.wrapping_add(1);
        if due {
            let token = probe.token;
            let packet = self.seal(kind::PATH_CHALLENGE, &token)?;
            tx.push_back(Transmit {
                to: from.clone(),
                packet,
            });
        }
        Ok(())
    }
}
