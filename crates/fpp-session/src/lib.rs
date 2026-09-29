//! Secure player-hosted sessions for classic games (milestone M2;
//! docs/anticheat/04-protocol.md §7.7).
//!
//! Replaces a game's own tunnel keying and sealing when one player hosts the
//! match (Halo: CE findings H03–H05 in docs/anticheat/08-reference-title-halo.md):
//!
//! - **Key agreement per player.** `Noise_IK_25519_ChaChaPoly_SHA256`: the
//!   joiner knows the host's static public key from the invite, so the host is
//!   authenticated and each player gets independent keys with forward secrecy.
//!   Holding the invite no longer lets one player read or forge another's
//!   traffic; the invite secret only *authorizes* a join.
//! - **Session key binding.** The joiner signs an [`AdmitPop`] with its FPP
//!   session key (the key that signs its InputCommits) over the host and
//!   joiner static keys, so the host knows which evidence key is on which
//!   channel.
//! - **Replay protection.** Explicit 64-bit packet counters, a
//!   [`replay::WINDOW`]-packet sliding window, and a hard counter limit.
//! - **Path validation.** A peer's address changes only after it answers an
//!   encrypted challenge sent to the new address, so neither replayed nor
//!   spoofed packets can redirect a player's traffic.
//! - **Selective reliability.** Datagrams are unreliable and latest-wins by
//!   default; a small reliable ordered channel ([`reliable`]) carries what
//!   must arrive (InputCommits, Checkpoint heads, title events).
//! - **Join floods.** Under load the host answers a join with a cookie bound
//!   to the joiner's address instead of doing the handshake's DH work, so
//!   spoofed floods cost it one hash each.
//! - **Device trust carried, not decided.** A joiner may attach an
//!   Attestation Result; the host sees it in [`HostEvent::PeerJoined`] and can
//!   place the player in a lobby of matching trust or disconnect it.
//!
//! The crate does no I/O (like `quinn-proto`): the game owns its UDP socket,
//! feeds received datagrams in with `recv`, and drains `poll_transmit` and
//! `poll_event`. Addresses are an opaque type `A` compared by equality.
//!
//! [`AdmitPop`]: fpp_wire::AdmitPop

#![forbid(unsafe_code)]

mod hello;
mod host;
mod joiner;
mod packet;
pub mod reliable;
pub mod replay;
mod session;

pub use host::{Host, HostConfig, HostEvent};
pub use joiner::{JoinConfig, Joiner, JoinerEvent};

/// Noise protocol name. Changing it is a protocol version change.
pub const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_SHA256";
/// Noise prologue: both sides must agree on the protocol and its version.
pub const PROLOGUE: &[u8] = b"fpp/1/p2p";
/// Version carried in both handshake payloads.
pub const VERSION: u64 = 1;

/// Largest datagram this crate produces or accepts: a 1500-byte MTU minus
/// IPv6 and UDP headers, so packets are never fragmented.
pub const MAX_PACKET: usize = 1452;
/// Bytes a data packet adds around its payload: type, receiver index,
/// counter, frame kind and the AEAD tag.
pub const DATA_OVERHEAD: usize = 1 + 4 + 8 + 1 + 16;
/// Largest application payload per datagram.
pub const MAX_PAYLOAD: usize = MAX_PACKET - DATA_OVERHEAD;
/// Largest message on the reliable channel (4 bytes go to its sequence number).
pub const MAX_MESSAGE: usize = MAX_PAYLOAD - 4;
/// Largest Attestation Result a joiner may attach.
pub const MAX_ATTESTATION: usize = 512;
/// Largest title-defined hello (either direction).
pub const MAX_HELLO: usize = 256;
/// Largest opaque address accepted through the C ABI.
pub const MAX_ADDRESS: usize = 128;
/// A session stops sending at this counter; the joiner must join again.
/// Far beyond any match (2^60 packets), but keeps nonces from ever wrapping.
pub const REJECT_AFTER: u64 = 1 << 60;

/// A static X25519 key pair (the host's identity in its invites; a joiner
/// makes a fresh one per [`Joiner`]).
#[derive(Clone)]
pub struct StaticKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let mut private = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut private);
        Self::from_private(private)
    }

    pub fn from_private(private: [u8; 32]) -> Self {
        let public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Self { private, public }
    }
}

impl core::fmt::Debug for StaticKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "StaticKeypair(public={:02x?}..)", &self.public[..4])
    }
}

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit<A> {
    pub to: A,
    pub packet: Vec<u8>,
}

/// Why a received datagram was dropped, or a call refused. Games drop the
/// datagram and may count these as Signals; none of them is fatal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// Not a well-formed packet of this protocol, or too large.
    Malformed,
    /// No session with that receiver index (stale, or never existed).
    UnknownSession,
    /// The packet counter was already seen or is older than the window.
    Replay,
    /// Authentication failed (wrong keys, or tampered).
    Decrypt,
    /// The Noise handshake failed.
    Handshake,
    /// Peer speaks another protocol version.
    Version,
    /// The join did not carry the host's invite secret.
    Invite,
    /// The session-key proof (AdmitPop) is missing, invalid or for another channel.
    Binding,
    /// Too many peers.
    Full,
    /// Valid, but not expected in the current state (e.g. data before connecting).
    State,
    /// The packet counter limit was reached; join again.
    Exhausted,
    /// A payload, hello or attestation exceeds its limit.
    TooLarge,
    /// No such peer.
    UnknownPeer,
    /// The reliable channel has `reliable::WINDOW` unacknowledged messages;
    /// try again after the next `tick`.
    Congested,
    /// The host is under load and the join carried no valid cookie; the
    /// joiner retries with the cookie it was sent.
    Cookie,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

fn random_u32() -> u32 {
    rand::RngCore::next_u32(&mut rand::rngs::OsRng)
}
