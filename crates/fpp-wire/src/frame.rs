//! `InputFrame` datagram (04-protocol.md §7.3): fixed little-endian layout,
//! not CBOR, because it is sent every tick.
//!
//! ```text
//! u8 type = 0x01 ‖ u16 slot ‖ u32 tick ‖ u8 n (1..=8)
//! n × { u32 tick_i ‖ u16 len_i ‖ payload_i }      ; newest first
//! ```
//!
//! The first entry is `tick` itself; the rest repeat earlier ticks so one
//! lost datagram costs nothing. Decoding is strict: exact length, ticks
//! strictly descending, none after `tick`.

use crate::WireError;

pub const INPUT_FRAME: u8 = 0x01;
/// Frames per datagram (1 + redundancy).
pub const MAX_FRAMES: usize = 8;
/// Largest payload per frame.
pub const MAX_INTENT: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputFrame {
    pub slot: u16,
    pub tick: u32,
    /// `(tick_i, payload_i)`, newest first; `frames[0].0 == tick`.
    pub frames: Vec<(u32, Vec<u8>)>,
}

const WHAT: &str = "InputFrame";

impl InputFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + self.frames.iter().map(|f| 6 + f.1.len()).sum::<usize>());
        out.push(INPUT_FRAME);
        out.extend_from_slice(&self.slot.to_le_bytes());
        out.extend_from_slice(&self.tick.to_le_bytes());
        out.push(self.frames.len() as u8);
        for (t, p) in &self.frames {
            out.extend_from_slice(&t.to_le_bytes());
            out.extend_from_slice(&(p.len() as u16).to_le_bytes());
            out.extend_from_slice(p);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, WireError> {
        let err = |f| WireError::Schema(WHAT, f);
        let take = |at: &mut usize, n: usize| -> Result<&[u8], WireError> {
            let s = b.get(*at..*at + n).ok_or(WireError::Truncated)?;
            *at += n;
            Ok(s)
        };
        let mut at = 0;
        if take(&mut at, 1)?[0] != INPUT_FRAME {
            return Err(err("type"));
        }
        let slot = u16::from_le_bytes(take(&mut at, 2)?.try_into().expect("2"));
        let tick = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4"));
        let n = take(&mut at, 1)?[0] as usize;
        if n == 0 || n > MAX_FRAMES {
            return Err(err("n"));
        }
        let mut frames: Vec<(u32, Vec<u8>)> = Vec::with_capacity(n);
        for i in 0..n {
            let t = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4"));
            let len = u16::from_le_bytes(take(&mut at, 2)?.try_into().expect("2")) as usize;
            if len > MAX_INTENT {
                return Err(err("payload length"));
            }
            let ordered = match frames.last() {
                None => t == tick,
                Some((prev, _)) => t < *prev,
            };
            if !ordered {
                return Err(err(if i == 0 { "first tick" } else { "tick order" }));
            }
            frames.push((t, take(&mut at, len)?.to_vec()));
        }
        if at != b.len() {
            return Err(WireError::TrailingBytes);
        }
        Ok(Self { slot, tick, frames })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> InputFrame {
        InputFrame {
            slot: 3,
            tick: 100,
            frames: vec![(100, vec![1, 2]), (99, vec![]), (97, vec![7; 10])],
        }
    }

    #[test]
    fn round_trips() {
        assert_eq!(InputFrame::decode(&sample().encode()).unwrap(), sample());
    }

    #[test]
    fn rejects_malformed() {
        let good = sample().encode();
        assert!(InputFrame::decode(&good[..good.len() - 1]).is_err());
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(InputFrame::decode(&trailing).is_err());
        let mut f = sample();
        f.frames.swap(1, 2);
        assert!(InputFrame::decode(&f.encode()).is_err(), "ascending ticks");
        let mut f = sample();
        f.frames[0].0 = 101;
        assert!(
            InputFrame::decode(&f.encode()).is_err(),
            "first frame must be `tick`"
        );
        let mut f = sample();
        f.frames = (0..9).map(|i| (100 - i, vec![])).collect();
        assert!(InputFrame::decode(&f.encode()).is_err(), "n > 8");
        let mut f = sample();
        f.frames[0].1 = vec![0; MAX_INTENT + 1];
        assert!(InputFrame::decode(&f.encode()).is_err());
    }
}
