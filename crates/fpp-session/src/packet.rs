//! Datagram layout (all integers little-endian):
//!
//! ```text
//! Init  = 0x01 ‖ sender_index:u32 ‖ noise_msg1
//! Resp  = 0x02 ‖ sender_index:u32 ‖ receiver_index:u32 ‖ noise_msg2
//! Data  = 0x03 ‖ receiver_index:u32 ‖ counter:u64 ‖ AEAD(kind:u8 ‖ body)
//! Cookie     = 0x04 ‖ receiver_index:u32 ‖ cookie:16      (host under load)
//! InitCookie = 0x05 ‖ cookie:16 ‖ sender_index:u32 ‖ noise_msg1
//! ```
//!
//! The counter is the AEAD nonce, so altering it (or the index, which selects
//! the keys) makes decryption fail.

use crate::{Error, MAX_PACKET};

pub(crate) const INIT: u8 = 1;
pub(crate) const RESP: u8 = 2;
pub(crate) const DATA: u8 = 3;
pub(crate) const COOKIE: u8 = 4;
pub(crate) const INIT_COOKIE: u8 = 5;
pub(crate) const COOKIE_LEN: usize = 16;

/// Noise IK message 1 without payload: e (32) + encrypted s (32 + 16) + payload tag (16).
const MIN_MSG1: usize = 32 + 48 + 16;
/// Noise IK message 2 without payload: e (32) + payload tag (16).
const MIN_MSG2: usize = 32 + 16;
/// Kind byte + AEAD tag.
const MIN_SEALED: usize = 1 + 16;

pub(crate) enum Packet<'a> {
    Init {
        sender: u32,
        noise: &'a [u8],
        cookie: Option<[u8; COOKIE_LEN]>,
    },
    Cookie {
        receiver: u32,
        cookie: [u8; COOKIE_LEN],
    },
    Resp {
        sender: u32,
        receiver: u32,
        noise: &'a [u8],
    },
    Data {
        receiver: u32,
        counter: u64,
        sealed: &'a [u8],
    },
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

pub(crate) fn parse(b: &[u8]) -> Result<Packet<'_>, Error> {
    if b.len() > MAX_PACKET {
        return Err(Error::Malformed);
    }
    match b.first() {
        Some(&INIT) if b.len() >= 5 + MIN_MSG1 => Ok(Packet::Init {
            sender: u32_at(b, 1),
            noise: &b[5..],
            cookie: None,
        }),
        Some(&INIT_COOKIE) if b.len() >= 21 + MIN_MSG1 => Ok(Packet::Init {
            sender: u32_at(b, 17),
            noise: &b[21..],
            cookie: Some(b[1..17].try_into().expect("16 bytes")),
        }),
        Some(&COOKIE) if b.len() == 5 + COOKIE_LEN => Ok(Packet::Cookie {
            receiver: u32_at(b, 1),
            cookie: b[5..].try_into().expect("16 bytes"),
        }),
        Some(&RESP) if b.len() >= 9 + MIN_MSG2 => Ok(Packet::Resp {
            sender: u32_at(b, 1),
            receiver: u32_at(b, 5),
            noise: &b[9..],
        }),
        Some(&DATA) if b.len() >= 13 + MIN_SEALED => Ok(Packet::Data {
            receiver: u32_at(b, 1),
            counter: u64::from_le_bytes(b[5..13].try_into().expect("8 bytes")),
            sealed: &b[13..],
        }),
        _ => Err(Error::Malformed),
    }
}

pub(crate) fn init(sender: u32, noise: &[u8], cookie: Option<&[u8; COOKIE_LEN]>) -> Vec<u8> {
    let mut p = Vec::with_capacity(21 + noise.len());
    match cookie {
        None => p.push(INIT),
        Some(c) => {
            p.push(INIT_COOKIE);
            p.extend_from_slice(c);
        }
    }
    p.extend_from_slice(&sender.to_le_bytes());
    p.extend_from_slice(noise);
    p
}

pub(crate) fn resp(sender: u32, receiver: u32, noise: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + noise.len());
    p.push(RESP);
    p.extend_from_slice(&sender.to_le_bytes());
    p.extend_from_slice(&receiver.to_le_bytes());
    p.extend_from_slice(noise);
    p
}

/// Data packet header; the sealed frame is appended by the caller.
pub(crate) fn data_header(receiver: u32, counter: u64) -> [u8; 13] {
    let mut h = [0u8; 13];
    h[0] = DATA;
    h[1..5].copy_from_slice(&receiver.to_le_bytes());
    h[5..13].copy_from_slice(&counter.to_le_bytes());
    h
}

pub(crate) fn cookie(receiver: u32, cookie: &[u8; COOKIE_LEN]) -> Vec<u8> {
    let mut p = Vec::with_capacity(5 + COOKIE_LEN);
    p.push(COOKIE);
    p.extend_from_slice(&receiver.to_le_bytes());
    p.extend_from_slice(cookie);
    p
}
