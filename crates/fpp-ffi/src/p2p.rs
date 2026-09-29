//! Secure player-hosted sessions (milestone M2) over the game's own UDP
//! socket: `fpp_p2p_host_*` for the hosting player, `fpp_p2p_joiner_*` for
//! everyone else. See crates/fpp-session and docs/anticheat/04-protocol.md §7.7.
//!
//! The SDK never touches the network. After every received datagram
//! (`*_recv`) and every send, drain `*_poll_transmit` until it returns
//! `FPP_STATUS_EMPTY` and hand each packet to `sendto`; drain `*_poll_event`
//! the same way. Addresses are opaque bytes chosen by the game (for example
//! a `struct sockaddr_in`), 1 to `FPP_P2P_MAX_ADDRESS` bytes, compared
//! byte-for-byte and returned exactly as given.

use super::{emit, fixed, free, guard, handle, handle_mut, input, FppSigner, FppStatus, Res};
use fpp_session::{
    Error, Host, HostConfig, HostEvent, JoinConfig, Joiner, JoinerEvent, StaticKeypair, Transmit,
};

/// Largest datagram the SDK produces or accepts (no IP fragmentation).
pub const FPP_P2P_MAX_PACKET: usize = 1452;
/// Largest payload for `fpp_p2p_host_send` / `fpp_p2p_joiner_send`.
pub const FPP_P2P_MAX_PAYLOAD: usize = 1422;
/// Largest message for `fpp_p2p_*_send_reliable`.
pub const FPP_P2P_MAX_MESSAGE: usize = 1418;
/// Largest address blob.
pub const FPP_P2P_MAX_ADDRESS: usize = 128;
/// Largest Attestation Result a joiner may attach.
pub const FPP_P2P_MAX_ATTESTATION: usize = 512;
/// Largest title-defined hello, either direction.
pub const FPP_P2P_MAX_HELLO: usize = 256;

const _: () = assert!(FPP_P2P_MAX_PACKET == fpp_session::MAX_PACKET);
const _: () = assert!(FPP_P2P_MAX_PAYLOAD == fpp_session::MAX_PAYLOAD);
const _: () = assert!(FPP_P2P_MAX_MESSAGE == fpp_session::MAX_MESSAGE);
const _: () = assert!(FPP_P2P_MAX_ADDRESS == fpp_session::MAX_ADDRESS);
const _: () = assert!(FPP_P2P_MAX_ATTESTATION == fpp_session::MAX_ATTESTATION);
const _: () = assert!(FPP_P2P_MAX_HELLO == fpp_session::MAX_HELLO);

impl From<Error> for FppStatus {
    fn from(e: Error) -> Self {
        match e {
            Error::Malformed => FppStatus::P2pMalformed,
            Error::UnknownSession => FppStatus::P2pUnknownSession,
            Error::Replay => FppStatus::P2pReplay,
            Error::Decrypt => FppStatus::P2pDecrypt,
            Error::Handshake => FppStatus::P2pHandshake,
            Error::Version => FppStatus::Version,
            Error::Invite => FppStatus::P2pInvite,
            Error::Binding => FppStatus::P2pBinding,
            Error::Full => FppStatus::P2pFull,
            Error::State => FppStatus::P2pState,
            Error::Exhausted => FppStatus::P2pExhausted,
            Error::TooLarge => FppStatus::P2pTooLarge,
            Error::UnknownPeer => FppStatus::P2pUnknownPeer,
            Error::Congested => FppStatus::P2pCongested,
            Error::Cookie => FppStatus::P2pCookie,
        }
    }
}

/// What a poll returned (`FppP2pEvent.kind`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FppP2pEventKind {
    /// Host: a player joined. `peer`; `key` = its session key (verify its
    /// InputCommits with it); data = attestation ‖ admit_pop ‖ hello.
    PeerJoined = 1,
    /// Host (`peer` set) or joiner: an application datagram; data = payload.
    Data = 2,
    /// Host: `peer`'s address changed after it answered a path challenge.
    PeerMigrated = 3,
    /// Host: `peer` left with `reason`.
    PeerLeft = 4,
    /// Joiner: connected. `has_key`/`key` = the host's Checkpoint key;
    /// data = the host's hello.
    Connected = 5,
    /// Joiner: the host's address changed after it answered a path challenge.
    HostMigrated = 6,
    /// Joiner: the host closed the session with `reason`.
    Closed = 7,
    /// Host (`peer` set) or joiner: a reliable-channel message, delivered
    /// once and in order; data = payload.
    Message = 8,
}

/// One event. Variable-size fields go into the caller's data buffer; the
/// `*_len` fields say how to split it.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FppP2pEvent {
    pub kind: FppP2pEventKind,
    pub peer: u32,
    /// `fpp_types::Reason` code (PeerLeft, Closed).
    pub reason: u16,
    pub has_key: u8,
    pub key: [u8; 32],
    /// PeerJoined: the first `attestation_len` data bytes are the joiner's
    /// Attestation Result (0 = none, device tier D0). Not verified by the SDK.
    pub attestation_len: usize,
    /// PeerJoined: the next `admit_pop_len` bytes are its signed AdmitPop
    /// (keep it in the match's evidence bundle).
    pub admit_pop_len: usize,
    /// Total bytes written to the data buffer.
    pub data_len: usize,
}

impl FppP2pEvent {
    fn new(kind: FppP2pEventKind) -> Self {
        Self {
            kind,
            peer: 0,
            reason: 0,
            has_key: 0,
            key: [0; 32],
            attestation_len: 0,
            admit_pop_len: 0,
            data_len: 0,
        }
    }
}

fn host_event(e: &HostEvent) -> (FppP2pEvent, Vec<u8>) {
    match e {
        HostEvent::PeerJoined {
            peer,
            session_key,
            admit_pop,
            attestation,
            hello,
        } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::PeerJoined);
            ev.peer = *peer;
            ev.has_key = 1;
            ev.key = *session_key;
            ev.attestation_len = attestation.len();
            ev.admit_pop_len = admit_pop.len();
            (ev, [&attestation[..], admit_pop, hello].concat())
        }
        HostEvent::Data { peer, payload } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::Data);
            ev.peer = *peer;
            (ev, payload.clone())
        }
        HostEvent::Message { peer, payload } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::Message);
            ev.peer = *peer;
            (ev, payload.clone())
        }
        HostEvent::PeerMigrated { peer } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::PeerMigrated);
            ev.peer = *peer;
            (ev, Vec::new())
        }
        HostEvent::PeerLeft { peer, reason } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::PeerLeft);
            ev.peer = *peer;
            ev.reason = *reason;
            (ev, Vec::new())
        }
    }
}

fn joiner_event(e: &JoinerEvent) -> (FppP2pEvent, Vec<u8>) {
    match e {
        JoinerEvent::Connected {
            instance_key,
            hello,
        } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::Connected);
            if let Some(k) = instance_key {
                ev.has_key = 1;
                ev.key = *k;
            }
            (ev, hello.clone())
        }
        JoinerEvent::Data { payload } => (FppP2pEvent::new(FppP2pEventKind::Data), payload.clone()),
        JoinerEvent::Message { payload } => {
            (FppP2pEvent::new(FppP2pEventKind::Message), payload.clone())
        }
        JoinerEvent::HostMigrated => (FppP2pEvent::new(FppP2pEventKind::HostMigrated), Vec::new()),
        JoinerEvent::Closed { reason } => {
            let mut ev = FppP2pEvent::new(FppP2pEventKind::Closed);
            ev.reason = *reason;
            (ev, Vec::new())
        }
    }
}

/// # Safety
/// `ptr` valid for `len` bytes.
unsafe fn address(ptr: *const u8, len: usize) -> Result<Vec<u8>, FppStatus> {
    if len == 0 || len > FPP_P2P_MAX_ADDRESS {
        return Err(FppStatus::InvalidArgument);
    }
    // SAFETY: forwarded caller contract.
    Ok(unsafe { input(ptr, len) }?.to_vec())
}

/// # Safety
/// `ptr` NULL or valid for 32 bytes.
unsafe fn optional32(ptr: *const u8) -> Result<Option<[u8; 32]>, FppStatus> {
    if ptr.is_null() {
        Ok(None)
    } else {
        // SAFETY: forwarded caller contract.
        unsafe { fixed(ptr) }.map(Some)
    }
}

/// Copy `bytes` to `(out, cap)`, storing the size in `*len` (which must be valid).
///
/// # Safety
/// `out` NULL or valid for `cap` writes; `len` valid for a write.
unsafe fn copy_out(bytes: &[u8], out: *mut u8, cap: usize, len: *mut usize) -> Res {
    // SAFETY: forwarded caller contract.
    unsafe { *len = bytes.len() };
    if bytes.is_empty() {
        return Ok(());
    }
    if out.is_null() || cap < bytes.len() {
        return Err(FppStatus::BufferTooSmall);
    }
    // SAFETY: `out` valid for `cap >= bytes.len()` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    Ok(())
}

/// Shared by host and joiner: copy the front datagram out, then pop it.
///
/// # Safety
/// Output pointers valid as documented on the public functions.
unsafe fn transmit_out(
    front: Option<&Transmit<Vec<u8>>>,
    to: *mut u8,
    to_cap: usize,
    to_len: *mut usize,
    packet: *mut u8,
    cap: usize,
    len: *mut usize,
) -> Result<bool, FppStatus> {
    if to_len.is_null() || len.is_null() {
        return Err(FppStatus::NullPointer);
    }
    let Some(t) = front else {
        return Err(FppStatus::Empty);
    };
    // Report both sizes before failing on either, so one retry suffices.
    // SAFETY: checked non-null above.
    unsafe {
        *to_len = t.to.len();
        *len = t.packet.len();
    }
    if to.is_null() || to_cap < t.to.len() || packet.is_null() || cap < t.packet.len() {
        return Err(FppStatus::BufferTooSmall);
    }
    // SAFETY: sizes checked above; caller contract.
    unsafe {
        copy_out(&t.to, to, to_cap, to_len)?;
        copy_out(&t.packet, packet, cap, len)?;
    }
    Ok(true)
}

/// # Safety
/// `event` valid for a write; `data` NULL or valid for `cap` writes.
unsafe fn event_out(
    front: Option<(FppP2pEvent, Vec<u8>)>,
    event: *mut FppP2pEvent,
    data: *mut u8,
    cap: usize,
) -> Result<bool, FppStatus> {
    if event.is_null() {
        return Err(FppStatus::NullPointer);
    }
    let Some((mut ev, bytes)) = front else {
        return Err(FppStatus::Empty);
    };
    ev.data_len = bytes.len();
    // SAFETY: non-null, caller contract.
    unsafe { *event = ev };
    if !bytes.is_empty() {
        if data.is_null() || cap < bytes.len() {
            return Err(FppStatus::BufferTooSmall);
        }
        // SAFETY: `data` valid for `cap >= bytes.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len()) };
    }
    Ok(true)
}

// ------------------------------------------------------------------ keys

/// Generate a static X25519 key pair (the host's identity for its invites).
/// `private_out` and `public_out`: 32 bytes each. Keep the private key secret;
/// put the public key in the invite.
///
/// # Safety
/// Both pointers valid for 32 writes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_keypair_generate(
    private_out: *mut u8,
    public_out: *mut u8,
) -> FppStatus {
    guard(|| {
        let k = StaticKeypair::generate();
        unsafe { super::write_fixed(private_out, &k.private) }?;
        unsafe { super::write_fixed(public_out, &k.public) }
    })
}

/// The public key for a 32-byte static private key (e.g. one the game saved).
///
/// # Safety
/// Both pointers valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_public_key(
    private_key: *const u8,
    public_out: *mut u8,
) -> FppStatus {
    guard(|| {
        let k = StaticKeypair::from_private(unsafe { fixed(private_key) }?);
        unsafe { super::write_fixed(public_out, &k.public) }
    })
}

// ------------------------------------------------------------------ host

/// The hosting player's endpoint.
pub struct FppP2pHost {
    inner: Host<Vec<u8>>,
}

/// Create a host. `static_private`: 32 bytes. `invite_secret`: 32 bytes that
/// joiners must present, or NULL for none (it authorizes only; it is never
/// used as a key). `instance_public_key`: 32-byte Ed25519 key that signs this
/// host's Checkpoints, announced to joiners, or NULL. `hello`: title bytes
/// for every joiner (≤ `FPP_P2P_MAX_HELLO`). `max_peers`: player limit.
///
/// # Safety
/// Pointers valid as documented; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_new(
    static_private: *const u8,
    invite_secret: *const u8,
    instance_public_key: *const u8,
    hello: *const u8,
    hello_len: usize,
    max_peers: u32,
    out: *mut *mut FppP2pHost,
) -> FppStatus {
    guard(|| {
        let hello = unsafe { input(hello, hello_len) }?;
        if hello.len() > FPP_P2P_MAX_HELLO || max_peers == 0 {
            return Err(FppStatus::InvalidArgument);
        }
        let mut cfg = HostConfig::new(StaticKeypair::from_private(unsafe {
            fixed(static_private)
        }?));
        cfg.invite_secret = unsafe { optional32(invite_secret) }?;
        cfg.instance_key = unsafe { optional32(instance_public_key) }?;
        cfg.hello = hello.to_vec();
        cfg.max_peers = max_peers as usize;
        unsafe {
            emit(
                out,
                FppP2pHost {
                    inner: Host::new(cfg),
                },
            )
        }
    })
}

/// Feed one datagram received from `from`. A non-OK status means it was
/// dropped (count it; do not disconnect anyone over it).
///
/// # Safety
/// `host` a live handle; `from` valid for `from_len`; `datagram` valid for `len`.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_recv(
    host: *mut FppP2pHost,
    from: *const u8,
    from_len: usize,
    datagram: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle_mut(host) }?;
        let from = unsafe { address(from, from_len) }?;
        let datagram = unsafe { input(datagram, len) }?;
        Ok(h.inner.recv(from, datagram)?)
    })
}

/// Queue an application datagram for `peer` (≤ `FPP_P2P_MAX_PAYLOAD` bytes).
///
/// # Safety
/// `host` a live handle; `payload` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_send(
    host: *mut FppP2pHost,
    peer: u32,
    payload: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle_mut(host) }?;
        let payload = unsafe { input(payload, len) }?;
        Ok(h.inner.send(peer, payload)?)
    })
}

/// Queue a message on `peer`'s reliable ordered channel (≤
/// `FPP_P2P_MAX_MESSAGE` bytes): InputCommits, Checkpoint heads, events that
/// must arrive. It is resent from `fpp_p2p_host_tick` until acknowledged.
/// Per-tick game state belongs in `fpp_p2p_host_send` (unreliable).
///
/// # Safety
/// `host` a live handle; `payload` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_send_reliable(
    host: *mut FppP2pHost,
    peer: u32,
    payload: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle_mut(host) }?;
        let payload = unsafe { input(payload, len) }?;
        Ok(h.inner.send_reliable(peer, payload)?)
    })
}

/// Advance time (a monotonic clock in ms): queues acks and due
/// retransmissions for every peer and ages join cookies. Call once per game
/// tick, then drain `fpp_p2p_host_poll_transmit`.
///
/// # Safety
/// `host` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_tick(host: *mut FppP2pHost, now_ms: u64) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(host) }?.inner.tick(now_ms)?))
}

/// Queue an empty keepalive for `peer` (when idle, to hold NAT bindings open).
///
/// # Safety
/// `host` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_keepalive(host: *mut FppP2pHost, peer: u32) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(host) }?.inner.keepalive(peer)?))
}

/// Tell `peer` why (an `fpp_types::Reason` code, e.g. 5 = tier insufficient)
/// and forget it.
///
/// # Safety
/// `host` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_disconnect(
    host: *mut FppP2pHost,
    peer: u32,
    reason: u16,
) -> FppStatus {
    guard(|| {
        Ok(unsafe { handle_mut(host) }?
            .inner
            .disconnect(peer, reason)?)
    })
}

/// Take the next datagram to send: its destination into `(to, to_cap)` and
/// its bytes into `(packet, cap)`. Returns `FPP_STATUS_EMPTY` when none is
/// queued. On `FPP_STATUS_BUFFER_TOO_SMALL` both sizes are reported and the
/// datagram stays queued. Buffers of `FPP_P2P_MAX_ADDRESS` and
/// `FPP_P2P_MAX_PACKET` bytes always suffice.
///
/// # Safety
/// `host` a live handle; `to`/`packet` NULL or valid for their capacities;
/// `to_len`/`len` valid for writes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_poll_transmit(
    host: *mut FppP2pHost,
    to: *mut u8,
    to_cap: usize,
    to_len: *mut usize,
    packet: *mut u8,
    cap: usize,
    len: *mut usize,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle_mut(host) }?;
        let front = h.inner.peek_transmit();
        if unsafe { transmit_out(front, to, to_cap, to_len, packet, cap, len) }? {
            h.inner.poll_transmit();
        }
        Ok(())
    })
}

/// Take the next event into `*event`, with its variable-size data in
/// `(data, cap)`. Returns `FPP_STATUS_EMPTY` when none is queued. On
/// `FPP_STATUS_BUFFER_TOO_SMALL`, `event->data_len` holds the size needed and
/// the event stays queued. A buffer of `FPP_P2P_MAX_PACKET` bytes always suffices.
///
/// # Safety
/// `host` a live handle; `event` valid for a write; `data` NULL or valid for `cap`.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_poll_event(
    host: *mut FppP2pHost,
    event: *mut FppP2pEvent,
    data: *mut u8,
    cap: usize,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle_mut(host) }?;
        let front = h.inner.peek_event().map(host_event);
        if unsafe { event_out(front, event, data, cap) }? {
            h.inner.poll_event();
        }
        Ok(())
    })
}

/// Number of joined players.
///
/// # Safety
/// `host` a live handle; `out` valid for a write.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_peer_count(
    host: *const FppP2pHost,
    out: *mut u32,
) -> FppStatus {
    guard(|| {
        let h = unsafe { handle(host) }?;
        let out = unsafe { out.as_mut() }.ok_or(FppStatus::NullPointer)?;
        *out = h.inner.peer_count() as u32;
        Ok(())
    })
}

/// # Safety
/// `host` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_host_free(host: *mut FppP2pHost) {
    unsafe { free(host) }
}

// ------------------------------------------------------------------ joiner

/// A joining player's endpoint.
pub struct FppP2pJoiner {
    inner: Joiner<Vec<u8>>,
}

/// Start joining the host at `host_addr`. `host_static_public`: 32 bytes from
/// the invite (never from the network). `invite_secret`: 32 bytes or NULL.
/// `session_key`: this player's FPP session key, which proves itself to the
/// host now and signs InputCommits later. `attestation`: this device's
/// Attestation Result, or empty (≤ `FPP_P2P_MAX_ATTESTATION`). `hello`:
/// title bytes for the host (≤ `FPP_P2P_MAX_HELLO`). The first handshake
/// datagram is queued; drain `fpp_p2p_joiner_poll_transmit`.
///
/// # Safety
/// Pointers valid as documented; `out` valid for a pointer write.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_new(
    host_static_public: *const u8,
    invite_secret: *const u8,
    session_key: *const FppSigner,
    attestation: *const u8,
    attestation_len: usize,
    hello: *const u8,
    hello_len: usize,
    host_addr: *const u8,
    host_addr_len: usize,
    out: *mut *mut FppP2pJoiner,
) -> FppStatus {
    guard(|| {
        let key = unsafe { handle(session_key) }?;
        let cfg = JoinConfig {
            host_static: unsafe { fixed(host_static_public) }?,
            invite_secret: unsafe { optional32(invite_secret) }?,
            attestation: unsafe { input(attestation, attestation_len) }?.to_vec(),
            hello: unsafe { input(hello, hello_len) }?.to_vec(),
        };
        let addr = unsafe { address(host_addr, host_addr_len) }?;
        let j = Joiner::new(cfg, &key.inner, addr)?;
        key.inner.check()?;
        unsafe { emit(out, FppP2pJoiner { inner: j }) }
    })
}

/// Feed one datagram received from `from`. Non-OK: it was dropped.
///
/// # Safety
/// `joiner` a live handle; `from` valid for `from_len`; `datagram` valid for `len`.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_recv(
    joiner: *mut FppP2pJoiner,
    from: *const u8,
    from_len: usize,
    datagram: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let j = unsafe { handle_mut(joiner) }?;
        let from = unsafe { address(from, from_len) }?;
        let datagram = unsafe { input(datagram, len) }?;
        Ok(j.inner.recv(from, datagram)?)
    })
}

/// Queue an application datagram for the host (≤ `FPP_P2P_MAX_PAYLOAD`).
/// `FPP_STATUS_P2P_STATE` until connected.
///
/// # Safety
/// `joiner` a live handle; `payload` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_send(
    joiner: *mut FppP2pJoiner,
    payload: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let j = unsafe { handle_mut(joiner) }?;
        let payload = unsafe { input(payload, len) }?;
        Ok(j.inner.send(payload)?)
    })
}

/// Queue a message on the reliable ordered channel (≤ `FPP_P2P_MAX_MESSAGE`).
///
/// # Safety
/// `joiner` a live handle; `payload` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_send_reliable(
    joiner: *mut FppP2pJoiner,
    payload: *const u8,
    len: usize,
) -> FppStatus {
    guard(|| {
        let j = unsafe { handle_mut(joiner) }?;
        let payload = unsafe { input(payload, len) }?;
        Ok(j.inner.send_reliable(payload)?)
    })
}

/// Advance time (monotonic ms): queues an ack and due retransmissions.
/// Call once per game tick.
///
/// # Safety
/// `joiner` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_tick(joiner: *mut FppP2pJoiner, now_ms: u64) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(joiner) }?.inner.tick(now_ms)?))
}

/// Queue an empty keepalive.
///
/// # Safety
/// `joiner` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_keepalive(joiner: *mut FppP2pJoiner) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(joiner) }?.inner.keepalive()?))
}

/// Queue a fresh handshake if not connected yet (call on a retry timer,
/// e.g. every 500 ms). No effect once connected.
///
/// # Safety
/// `joiner` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_retry(joiner: *mut FppP2pJoiner) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(joiner) }?.inner.retry()?))
}

/// Tell the host we leave (`reason`: an `fpp_types::Reason` code), then stop.
///
/// # Safety
/// `joiner` a live handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_close(joiner: *mut FppP2pJoiner, reason: u16) -> FppStatus {
    guard(|| Ok(unsafe { handle_mut(joiner) }?.inner.close(reason)?))
}

/// Like `fpp_p2p_host_poll_transmit`.
///
/// # Safety
/// As for `fpp_p2p_host_poll_transmit`, with a live joiner handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_poll_transmit(
    joiner: *mut FppP2pJoiner,
    to: *mut u8,
    to_cap: usize,
    to_len: *mut usize,
    packet: *mut u8,
    cap: usize,
    len: *mut usize,
) -> FppStatus {
    guard(|| {
        let j = unsafe { handle_mut(joiner) }?;
        let front = j.inner.peek_transmit();
        if unsafe { transmit_out(front, to, to_cap, to_len, packet, cap, len) }? {
            j.inner.poll_transmit();
        }
        Ok(())
    })
}

/// Like `fpp_p2p_host_poll_event`.
///
/// # Safety
/// As for `fpp_p2p_host_poll_event`, with a live joiner handle.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_poll_event(
    joiner: *mut FppP2pJoiner,
    event: *mut FppP2pEvent,
    data: *mut u8,
    cap: usize,
) -> FppStatus {
    guard(|| {
        let j = unsafe { handle_mut(joiner) }?;
        let front = j.inner.peek_event().map(joiner_event);
        if unsafe { event_out(front, event, data, cap) }? {
            j.inner.poll_event();
        }
        Ok(())
    })
}

/// # Safety
/// `joiner` NULL or a live handle; not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn fpp_p2p_joiner_free(joiner: *mut FppP2pJoiner) {
    unsafe { free(joiner) }
}
