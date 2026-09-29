//! Selective reliability and join-flood defence, end to end.

use ed25519_dalek::SigningKey;
use fpp_crypto::Ed25519Signer;
use fpp_session::*;

type Addr = &'static str;
const HOST: Addr = "host:1";
const ALICE: Addr = "alice:2";

fn host(max_pending: usize) -> Host<Addr> {
    let mut cfg = HostConfig::new(StaticKeypair::from_private([0x42; 32]));
    cfg.max_pending = max_pending;
    Host::new(cfg)
}

fn joiner(h: &Host<Addr>, seed: u8) -> Joiner<Addr> {
    let cfg = JoinConfig {
        host_static: h.static_public_key(),
        invite_secret: None,
        attestation: Vec::new(),
        hello: Vec::new(),
    };
    Joiner::new(
        cfg,
        &Ed25519Signer::new(SigningKey::from_bytes(&[seed; 32])),
        HOST,
    )
    .unwrap()
}

/// Move queued datagrams both ways; `drop(n)` decides whether the n-th is lost.
fn pump(h: &mut Host<Addr>, j: &mut Joiner<Addr>, n: &mut u32, drop: impl Fn(u32) -> bool) {
    loop {
        let mut moved = false;
        while let Some(t) = j.poll_transmit() {
            moved = true;
            *n += 1;
            if !drop(*n) {
                let _ = h.recv(ALICE, &t.packet);
            }
        }
        while let Some(t) = h.poll_transmit() {
            moved = true;
            *n += 1;
            if !drop(*n) {
                let _ = j.recv(HOST, &t.packet);
            }
        }
        if !moved {
            return;
        }
    }
}

fn connect(h: &mut Host<Addr>) -> (Joiner<Addr>, u32) {
    let mut j = joiner(h, 0x51);
    pump(h, &mut j, &mut 0, |_| false);
    let peer = match h.poll_event() {
        Some(HostEvent::PeerJoined { peer, .. }) => peer,
        other => panic!("{other:?}"),
    };
    j.poll_event();
    (j, peer)
}

#[test]
fn reliable_messages_arrive_once_and_in_order_over_a_lossy_link() {
    let mut h = host(64);
    let (mut j, peer) = connect(&mut h);
    let sent: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 1 + i as usize * 7]).collect();
    for m in &sent[..20] {
        h.send_reliable(peer, m).unwrap();
        j.send_reliable(m).unwrap();
    }
    let mut got_j = Vec::new();
    let mut got_h = Vec::new();
    let mut n = 0;
    // 30 Hz ticks, every third datagram lost in both directions (acks too).
    for tick in 0..300u64 {
        if tick == 5 {
            for m in &sent[20..] {
                h.send_reliable(peer, m).unwrap();
                j.send_reliable(m).unwrap();
            }
        }
        h.tick(tick * 33).unwrap();
        j.tick(tick * 33).unwrap();
        pump(&mut h, &mut j, &mut n, |i| i % 3 == 0);
        while let Some(e) = j.poll_event() {
            if let JoinerEvent::Message { payload } = e {
                got_j.push(payload);
            }
        }
        while let Some(e) = h.poll_event() {
            if let HostEvent::Message { payload, .. } = e {
                got_h.push(payload);
            }
        }
    }
    assert_eq!(got_j, sent);
    assert_eq!(got_h, sent);
}

#[test]
fn unreliable_data_is_never_retransmitted() {
    let mut h = host(64);
    let (mut j, peer) = connect(&mut h);
    h.send(peer, b"state @ tick 7").unwrap();
    assert!(h.poll_transmit().is_some()); // lost
    for t in 0..100 {
        h.tick(t * 33).unwrap();
    }
    assert!(h.poll_transmit().is_none());
    assert!(j.poll_event().is_none());
}

#[test]
fn reliable_channel_applies_backpressure() {
    let mut h = host(64);
    let (_j, peer) = connect(&mut h);
    for _ in 0..reliable::WINDOW {
        h.send_reliable(peer, b"commit").unwrap();
    }
    assert_eq!(
        h.send_reliable(peer, b"one too many"),
        Err(Error::Congested)
    );
    assert_eq!(
        h.send_reliable(peer, &vec![0; MAX_MESSAGE + 1]),
        Err(Error::TooLarge)
    );
}

/// Under load, spoofed joins cost the host one hash and a 21-byte reply each
/// (smaller than the request: no amplification), and create no state.
#[test]
fn join_flood_gets_cookies_and_real_players_still_join() {
    let mut h = host(4);
    // Two unconfirmed joins put the host under load.
    for seed in [1, 2] {
        let mut j = joiner(&h, seed);
        h.recv("spoof:0", &j.poll_transmit().unwrap().packet)
            .unwrap();
        h.poll_transmit();
    }
    let spoofed = joiner(&h, 3).poll_transmit().unwrap().packet;
    for _ in 0..1000 {
        h.recv("spoof:9", &spoofed).unwrap();
        let reply = h.poll_transmit().unwrap();
        assert!(reply.packet.len() == 21 && reply.packet.len() < spoofed.len());
    }
    // A real player follows the cookie and joins without any extra calls.
    let mut alice = joiner(&h, 0x51);
    pump(&mut h, &mut alice, &mut 0, |_| false);
    assert!(alice.is_connected());
    assert!(matches!(h.poll_event(), Some(HostEvent::PeerJoined { .. })));
}

#[test]
fn cookies_are_bound_to_the_address_and_expire() {
    let mut h = host(2);
    let mut first = joiner(&h, 1);
    h.recv("spoof:0", &first.poll_transmit().unwrap().packet)
        .unwrap();
    h.poll_transmit();

    let mut alice = joiner(&h, 0x51);
    h.recv(ALICE, &alice.poll_transmit().unwrap().packet)
        .unwrap();
    let cookie = h.poll_transmit().unwrap();
    alice.recv(HOST, &cookie.packet).unwrap();
    let with_cookie = alice.poll_transmit().unwrap().packet;
    assert_eq!(with_cookie[0], 5, "retried with the cookie at once");

    // Replayed from another address: refused.
    assert_eq!(h.recv("mallory:3", &with_cookie), Err(Error::Cookie));
    // Two cookie periods later: refused.
    h.tick(2 * 60_000 + 1).unwrap();
    assert_eq!(h.recv(ALICE, &with_cookie), Err(Error::Cookie));
}
