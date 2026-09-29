//! Reliable, ordered message channel on top of the unreliable session.
//!
//! For the few things that must arrive (InputCommits, Checkpoint heads,
//! title events such as "match over"); per-tick state stays unreliable and
//! latest-wins. Messages carry a sequence number; the receiver delivers them
//! in order, buffers up to [`WINDOW`] early ones, and acknowledges with a
//! cumulative ack plus a 64-bit selective bitmap once per `tick`. The sender
//! retransmits after an RTO derived from measured round trips (Karn's rule:
//! retransmitted messages give no sample), doubling per retry.
//!
//! Clock-free except for the `now_ms` the endpoint passes in on each tick.

use std::collections::BTreeMap;

/// Messages in flight (sent, unacknowledged) per session. Also the receive
/// window: messages further ahead than this are dropped and resent later.
pub const WINDOW: u32 = 64;
/// RTO before any round trip is measured.
const INITIAL_RTO_MS: u64 = 200;
const MIN_RTO_MS: u64 = 60;
const MAX_RTO_MS: u64 = 2_000;

struct Unacked {
    payload: Vec<u8>,
    sent_ms: u64,
    retries: u32,
}

#[derive(Default)]
pub(crate) struct Reliable {
    next_seq: u32,
    unacked: BTreeMap<u32, Unacked>,
    next_expected: u32,
    early: BTreeMap<u32, Vec<u8>>,
    ack_due: bool,
    srtt_ms: Option<u64>,
}

/// Wire body of an ACK frame: `next_expected:u32 ‖ bitmap:u64` (bit i set =
/// `next_expected + 1 + i` received).
pub(crate) const ACK_LEN: usize = 12;

impl Reliable {
    pub fn can_send(&self) -> bool {
        (self.unacked.len() as u32) < WINDOW
    }

    /// Assign a sequence number; returns the frame body to send now.
    pub fn push(&mut self, payload: &[u8], now_ms: u64) -> Vec<u8> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.unacked.insert(
            seq,
            Unacked {
                payload: payload.to_vec(),
                sent_ms: now_ms,
                retries: 0,
            },
        );
        body(seq, payload)
    }

    /// A RELIABLE frame arrived: returns the messages now deliverable in order.
    pub fn on_message(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        self.ack_due = true;
        let ahead = seq.wrapping_sub(self.next_expected);
        if ahead >= WINDOW {
            // Already delivered (a retransmission whose ack was lost), or too
            // far ahead: either way the ack tells the sender where we are.
            return Vec::new();
        }
        self.early.insert(seq, payload);
        let mut out = Vec::new();
        while let Some(p) = self.early.remove(&self.next_expected) {
            out.push(p);
            self.next_expected = self.next_expected.wrapping_add(1);
        }
        out
    }

    pub fn ack_body(&mut self) -> Option<[u8; ACK_LEN]> {
        if !std::mem::take(&mut self.ack_due) {
            return None;
        }
        let mut bits = 0u64;
        for &seq in self.early.keys() {
            let i = seq.wrapping_sub(self.next_expected).wrapping_sub(1);
            if i < 64 {
                bits |= 1 << i;
            }
        }
        let mut b = [0u8; ACK_LEN];
        b[..4].copy_from_slice(&self.next_expected.to_le_bytes());
        b[4..].copy_from_slice(&bits.to_le_bytes());
        Some(b)
    }

    pub fn on_ack(&mut self, body: &[u8], now_ms: u64) {
        let Ok(b) = <[u8; ACK_LEN]>::try_from(body) else {
            return;
        };
        let next = u32::from_le_bytes(b[..4].try_into().expect("4"));
        let bits = u64::from_le_bytes(b[4..].try_into().expect("8"));
        let acked: Vec<u32> = self
            .unacked
            .keys()
            .copied()
            .filter(|&seq| {
                // Only sequence numbers we actually sent can be acked.
                let behind = next.wrapping_sub(seq);
                let i = seq.wrapping_sub(next).wrapping_sub(1);
                (1..=WINDOW).contains(&behind) || (i < 64 && bits & (1 << i) != 0)
            })
            .collect();
        for seq in acked {
            let u = self.unacked.remove(&seq).expect("listed");
            if u.retries == 0 {
                let sample = now_ms.saturating_sub(u.sent_ms);
                self.srtt_ms = Some(match self.srtt_ms {
                    None => sample,
                    Some(s) => (7 * s + sample) / 8,
                });
            }
        }
    }

    fn rto_ms(&self, retries: u32) -> u64 {
        let base = self
            .srtt_ms
            .map_or(INITIAL_RTO_MS, |s| (2 * s).clamp(MIN_RTO_MS, MAX_RTO_MS));
        base.saturating_mul(1 << retries.min(5)).min(MAX_RTO_MS)
    }

    /// Frame bodies to retransmit now.
    pub fn due(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let rto: Vec<(u32, u64)> = self
            .unacked
            .iter()
            .map(|(&s, u)| (s, self.rto_ms(u.retries)))
            .collect();
        for (seq, rto) in rto {
            let u = self.unacked.get_mut(&seq).expect("listed");
            if now_ms.saturating_sub(u.sent_ms) >= rto {
                u.sent_ms = now_ms;
                u.retries += 1;
                out.push(body(seq, &u.payload));
            }
        }
        out
    }

    #[cfg(test)]
    pub fn in_flight(&self) -> usize {
        self.unacked.len()
    }
}

fn body(seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + payload.len());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// Split a RELIABLE frame body.
pub(crate) fn split(body: &[u8]) -> Option<(u32, Vec<u8>)> {
    let seq = u32::from_le_bytes(body.get(..4)?.try_into().ok()?);
    Some((seq, body[4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deliver(from: &mut Reliable, to: &mut Reliable, frame: &[u8]) -> Vec<Vec<u8>> {
        let _ = from;
        let (seq, p) = split(frame).unwrap();
        to.on_message(seq, p)
    }

    #[test]
    fn in_order_despite_loss_and_reordering() {
        let (mut a, mut b) = (Reliable::default(), Reliable::default());
        let f0 = a.push(b"m0", 0);
        let _lost = a.push(b"m1", 0);
        let f2 = a.push(b"m2", 0);
        assert_eq!(deliver(&mut a, &mut b, &f2), Vec::<Vec<u8>>::new());
        assert_eq!(deliver(&mut a, &mut b, &f0), vec![b"m0".to_vec()]);
        let ack = b.ack_body().unwrap();
        a.on_ack(&ack, 50);
        assert_eq!(a.in_flight(), 1, "m0 and m2 acked (cumulative + bitmap)");
        // m1 is retransmitted after the RTO and releases m2 behind it.
        assert!(a.due(60).is_empty());
        let resent = a.due(1_000);
        assert_eq!(resent.len(), 1);
        assert_eq!(
            deliver(&mut a, &mut b, &resent[0]),
            vec![b"m1".to_vec(), b"m2".to_vec()]
        );
        a.on_ack(&b.ack_body().unwrap(), 1_050);
        assert_eq!(a.in_flight(), 0);
        assert!(b.ack_body().is_none(), "one ack per batch of arrivals");
    }

    #[test]
    fn duplicates_are_not_redelivered_but_are_reacked() {
        let (mut a, mut b) = (Reliable::default(), Reliable::default());
        let f0 = a.push(b"once", 0);
        assert_eq!(deliver(&mut a, &mut b, &f0).len(), 1);
        b.ack_body();
        assert!(deliver(&mut a, &mut b, &f0).is_empty());
        assert!(b.ack_body().is_some());
    }

    #[test]
    fn window_bounds_memory() {
        let (mut a, mut b) = (Reliable::default(), Reliable::default());
        for i in 0..WINDOW {
            assert!(a.can_send());
            a.push(&[i as u8], 0);
        }
        assert!(!a.can_send());
        // Far-ahead sequence numbers are refused, not buffered.
        assert!(b.on_message(WINDOW + 5, vec![1]).is_empty());
        assert!(b.early.is_empty());
    }

    #[test]
    fn rto_follows_measured_rtt_and_backs_off() {
        let mut a = Reliable::default();
        a.push(b"x", 0);
        a.on_ack(
            &{
                let mut b = [0u8; ACK_LEN];
                b[..4].copy_from_slice(&1u32.to_le_bytes());
                b
            },
            40,
        );
        assert_eq!(a.srtt_ms, Some(40));
        assert_eq!(a.rto_ms(0), 80);
        assert_eq!(a.rto_ms(2), 320);
        assert_eq!(a.rto_ms(10), MAX_RTO_MS);
    }

    #[test]
    fn acks_for_unsent_sequence_numbers_are_ignored() {
        let mut a = Reliable::default();
        a.push(b"x", 0);
        let mut forged = [0u8; ACK_LEN];
        forged[..4].copy_from_slice(&1000u32.to_le_bytes());
        a.on_ack(&forged, 10);
        assert_eq!(a.in_flight(), 1);
    }
}
