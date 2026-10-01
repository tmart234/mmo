//! M2 exit tests: the attacks behind Halo: CE findings H03 and H04
//! (docs/anticheat/08-reference-title-halo.md §2) fail against fpp-session.

use ed25519_dalek::SigningKey;
use fpp_crypto::Ed25519Signer;
use fpp_session::*;
use fpp_types::Reason;

type Addr = &'static str;
const HOST: Addr = "host:1000";
const ALICE: Addr = "alice:2000";
const MALLORY: Addr = "mallory:3000";
const INVITE: [u8; 32] = [7; 32];

fn signer(b: u8) -> Ed25519Signer {
    Ed25519Signer::new(SigningKey::from_bytes(&[b; 32]))
}

fn host_with(f: impl FnOnce(&mut HostConfig)) -> Host<Addr> {
    let mut cfg = HostConfig::new(StaticKeypair::from_private([0x42; 32]));
    cfg.invite_secret = Some(INVITE);
    cfg.instance_key = Some(signer(0x61).verifying_key().to_bytes());
    cfg.hello = b"slayer/bloodgulch".to_vec();
    f(&mut cfg);
    Host::new(cfg)
}

fn join_cfg(host: &Host<Addr>) -> JoinConfig {
    JoinConfig {
        host_static: host.static_public_key(),
        invite_secret: Some(INVITE),
        attestation: Vec::new(),
        hello: b"alice".to_vec(),
    }
}

/// Deliver everything each side queued, as `from`, until both are quiet.
/// Returns every datagram that crossed, for attackers to replay.
fn pump(host: &mut Host<Addr>, j: &mut Joiner<Addr>, j_addr: Addr) -> Vec<Transmit<Addr>> {
    let mut seen = Vec::new();
    loop {
        let mut moved = false;
        while let Some(t) = j.poll_transmit() {
            moved = true;
            if t.to == HOST {
                let _ = host.recv(j_addr, &t.packet);
            }
            seen.push(t);
        }
        while let Some(t) = host.poll_transmit() {
            moved = true;
            if t.to == j_addr {
                let _ = j.recv(HOST, &t.packet);
            }
            seen.push(t);
        }
        if !moved {
            return seen;
        }
    }
}

fn connect(host: &mut Host<Addr>, key: &Ed25519Signer, addr: Addr) -> (Joiner<Addr>, u32) {
    let mut j = Joiner::new(join_cfg(host), key, HOST).unwrap();
    pump(host, &mut j, addr);
    assert!(j.is_connected());
    let peer = match host.poll_event() {
        Some(HostEvent::PeerJoined { peer, .. }) => peer,
        other => panic!("expected PeerJoined, got {other:?}"),
    };
    assert!(matches!(
        j.poll_event(),
        Some(JoinerEvent::Connected { .. })
    ));
    (j, peer)
}

#[test]
fn join_binds_session_key_and_carries_hellos() {
    let mut host = host_with(|_| {});
    let alice = signer(0x51);
    let mut cfg = join_cfg(&host);
    cfg.attestation = b"AR(cwt)".to_vec();
    let mut j = Joiner::new(cfg, &alice, HOST).unwrap();
    pump(&mut host, &mut j, ALICE);
    match host.poll_event().unwrap() {
        HostEvent::PeerJoined {
            session_key,
            attestation,
            hello,
            admit_pop,
            ..
        } => {
            assert_eq!(
                session_key,
                fpp_types::SessionKey::Ed25519(alice.verifying_key().to_bytes())
            );
            assert_eq!(attestation, b"AR(cwt)");
            assert_eq!(hello, b"alice");
            // The proof is a normal FPP object: it verifies with the session key.
            let mut keys = fpp_crypto::KeySet::default();
            keys.insert_ed25519(fpp_crypto::KeyRole::Session, alice.verifying_key());
            let pop = fpp_crypto::verify::<fpp_wire::AdmitPop>(&admit_pop, &keys).unwrap();
            assert_eq!(&pop.payload.binding[..32], &host.static_public_key());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        j.poll_event(),
        Some(JoinerEvent::Connected {
            instance_key: Some(signer(0x61).verifying_key().to_bytes()),
            hello: b"slayer/bloodgulch".to_vec(),
        })
    );
}

#[test]
fn data_flows_both_ways() {
    let mut host = host_with(|_| {});
    let (mut j, peer) = connect(&mut host, &signer(0x51), ALICE);
    j.send(b"tick 1: fire").unwrap();
    host.send(peer, b"snapshot 1").unwrap();
    pump(&mut host, &mut j, ALICE);
    assert_eq!(
        host.poll_event(),
        Some(HostEvent::Data {
            peer,
            payload: b"tick 1: fire".to_vec()
        })
    );
    assert_eq!(
        j.poll_event(),
        Some(JoinerEvent::Data {
            payload: b"snapshot 1".to_vec()
        })
    );
}

/// H03: every player holds the invite, but that no longer yields anyone
/// else's keys. Mallory joins legitimately, records all of Alice's traffic,
/// and can neither read it nor inject into Alice's session.
#[test]
fn invite_holder_cannot_read_or_forge_another_players_traffic() {
    let mut host = host_with(|_| {});
    let (mut mallory, _) = connect(&mut host, &signer(0x66), MALLORY);

    let mut alice = Joiner::new(join_cfg(&host), &signer(0x51), HOST).unwrap();
    alice.send(b"never sent before connecting").unwrap_err();
    let mut captured = pump(&mut host, &mut alice, ALICE);
    let peer = match host.poll_event() {
        Some(HostEvent::PeerJoined { peer, .. }) => peer,
        other => panic!("{other:?}"),
    };
    alice.send(b"secret plan: flank left").unwrap();
    host.send(peer, b"alice's private state").unwrap();
    captured.extend(pump(&mut host, &mut alice, ALICE));
    while host.poll_event().is_some() {}

    for t in &captured {
        // Nothing Alice or the host sent is readable by Mallory's session...
        assert!(mallory.recv(HOST, &t.packet).is_err());
        assert!(mallory.poll_event().is_none());
        // ...or contains the plaintext.
        assert!(!t.packet.windows(b"flank".len()).any(|w| w == b"flank"));
    }
    // Forging: flip one ciphertext bit of Alice's data packet and send it as Alice.
    let data = captured
        .iter()
        .rfind(|t| t.to == HOST && t.packet[0] == 3)
        .unwrap();
    let mut forged = data.packet.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    // Use a fresh counter so only authentication, not replay, can stop it.
    forged[5..13].copy_from_slice(&999u64.to_le_bytes());
    assert_eq!(host.recv(ALICE, &forged), Err(Error::Decrypt));
    assert!(host.poll_event().is_none());
}

/// A host impostor (anyone without the host's static private key, e.g. a
/// player who read the invite) cannot answer a join.
#[test]
fn only_the_invited_host_can_answer() {
    let host = host_with(|_| {});
    let mut impostor = Host::new({
        let mut c = HostConfig::new(StaticKeypair::from_private([0x99; 32]));
        c.invite_secret = Some(INVITE);
        c
    });
    let mut j = Joiner::new(join_cfg(&host), &signer(0x51), HOST).unwrap();
    let init = j.poll_transmit().unwrap();
    assert_eq!(impostor.recv(ALICE, &init.packet), Err(Error::Handshake));
    assert!(impostor.poll_transmit().is_none());
}

#[test]
fn join_requires_the_invite_secret() {
    for secret in [None, Some([8u8; 32])] {
        let mut host = host_with(|_| {});
        let mut cfg = join_cfg(&host);
        cfg.invite_secret = secret;
        let mut j = Joiner::new(cfg, &signer(0x51), HOST).unwrap();
        let init = j.poll_transmit().unwrap();
        assert_eq!(host.recv(ALICE, &init.packet), Err(Error::Invite));
        assert!(host.poll_transmit().is_none());
    }
}

/// H04 (replay): a recorded packet is accepted once.
#[test]
fn replayed_packets_are_dropped() {
    let mut host = host_with(|_| {});
    let (mut j, _) = connect(&mut host, &signer(0x51), ALICE);
    j.send(b"pick up rocket launcher").unwrap();
    let t = j.poll_transmit().unwrap();
    host.recv(ALICE, &t.packet).unwrap();
    assert_eq!(host.recv(ALICE, &t.packet), Err(Error::Replay));
    assert!(matches!(host.poll_event(), Some(HostEvent::Data { .. })));
    assert!(host.poll_event().is_none());
}

/// A replayed handshake message gets an answer nobody can use: no peer
/// joins, and the real session is untouched.
#[test]
fn replayed_join_admits_nobody() {
    let mut host = host_with(|_| {});
    let mut alice = Joiner::new(join_cfg(&host), &signer(0x51), HOST).unwrap();
    let init = alice.poll_transmit().unwrap();
    host.recv(ALICE, &init.packet).unwrap();
    let resp = host.poll_transmit().unwrap();
    alice.recv(HOST, &resp.packet).unwrap();
    pump(&mut host, &mut alice, ALICE);
    let peer = match host.poll_event() {
        Some(HostEvent::PeerJoined { peer, .. }) => peer,
        other => panic!("{other:?}"),
    };

    host.recv(MALLORY, &init.packet).unwrap(); // answered, but useless
    let resp2 = host.poll_transmit().unwrap();
    assert_eq!(resp2.to, MALLORY);
    assert!(host.poll_event().is_none());
    assert_eq!(host.peer_count(), 1);
    assert_eq!(host.peer_address(peer), Some(&ALICE));
    alice.send(b"still here").unwrap();
    pump(&mut host, &mut alice, ALICE);
    assert!(matches!(host.poll_event(), Some(HostEvent::Data { .. })));
}

/// H04 (redirect): an on-path attacker who races Alice's fresh packet from
/// its own address gets the data delivered once (it is authentic) but never
/// becomes Alice's address, even if it relays the challenge to Alice.
#[test]
fn raced_packet_cannot_redirect_a_session() {
    let mut host = host_with(|_| {});
    let (mut alice, peer) = connect(&mut host, &signer(0x51), ALICE);
    alice.send(b"move").unwrap();
    let t = alice.poll_transmit().unwrap();

    host.recv(MALLORY, &t.packet).unwrap();
    assert!(matches!(host.poll_event(), Some(HostEvent::Data { .. })));
    let challenge = host.poll_transmit().unwrap();
    assert_eq!(challenge.to, MALLORY);
    // The original arrives later: it is now a replay.
    assert_eq!(host.recv(ALICE, &t.packet), Err(Error::Replay));

    // Mallory relays the challenge to Alice; Alice answers from her own
    // address, which is not the one being validated.
    alice.recv(MALLORY, &challenge.packet).unwrap();
    let response = alice.poll_transmit().unwrap();
    assert!(alice.poll_transmit().is_none());
    assert_eq!(
        response.to, MALLORY,
        "a response goes back where the challenge came from"
    );
    host.recv(ALICE, &response.packet).unwrap();
    assert_eq!(host.peer_address(peer), Some(&ALICE));
    // Even delivering the response from Mallory's address fails: Mallory
    // cannot produce it, only relay Alice's, which the host already saw.
    assert_eq!(host.recv(MALLORY, &response.packet), Err(Error::Replay));
    assert_eq!(host.peer_address(peer), Some(&ALICE));
    host.send(peer, b"to alice").unwrap();
    assert_eq!(host.poll_transmit().unwrap().to, ALICE);
}

/// Legitimate roaming (NAT rebinding): the new address answers the
/// challenge, and traffic follows it.
#[test]
fn nat_rebinding_migrates_after_validation() {
    const ALICE_NEW: Addr = "alice:2001";
    let mut host = host_with(|_| {});
    let (mut alice, peer) = connect(&mut host, &signer(0x51), ALICE);
    alice.send(b"after rebind").unwrap();
    let t = alice.poll_transmit().unwrap();
    host.recv(ALICE_NEW, &t.packet).unwrap();
    let _ = host.poll_event();
    host.send(peer, b"before validation").unwrap();
    let challenge = host.poll_transmit().unwrap();
    assert_eq!(challenge.to, ALICE_NEW);
    assert_eq!(
        host.poll_transmit().unwrap().to,
        ALICE,
        "unvalidated: old path"
    );

    alice.recv(HOST, &challenge.packet).unwrap();
    let response = alice.poll_transmit().unwrap();
    assert!(alice.poll_transmit().is_none());
    host.recv(ALICE_NEW, &response.packet).unwrap();
    assert_eq!(host.poll_event(), Some(HostEvent::PeerMigrated { peer }));
    assert_eq!(host.peer_address(peer), Some(&ALICE_NEW));
    host.send(peer, b"after validation").unwrap();
    assert_eq!(host.poll_transmit().unwrap().to, ALICE_NEW);
}

#[test]
fn rejoin_with_same_session_key_keeps_the_peer() {
    let mut host = host_with(|_| {});
    let alice = signer(0x51);
    let (_old, peer) = connect(&mut host, &alice, ALICE);
    let mut again = Joiner::new(join_cfg(&host), &alice, HOST).unwrap();
    pump(&mut host, &mut again, "alice:2002");
    assert!(again.is_connected());
    assert!(host.poll_event().is_none(), "no second PeerJoined");
    assert_eq!(host.peer_count(), 1);
    assert_eq!(host.peer_address(peer), Some(&"alice:2002"));
}

#[test]
fn full_host_closes_extra_joiners() {
    let mut host = host_with(|c| c.max_peers = 1);
    connect(&mut host, &signer(0x51), ALICE);
    let mut late = Joiner::new(join_cfg(&host), &signer(0x52), HOST).unwrap();
    pump(&mut host, &mut late, "bob:4000");
    assert!(host.poll_event().is_none());
    assert!(matches!(
        late.poll_event(),
        Some(JoinerEvent::Connected { .. })
    ));
    assert_eq!(
        late.poll_event(),
        Some(JoinerEvent::Closed {
            reason: Reason::ServerFull as u16
        })
    );
}

#[test]
fn host_can_refuse_a_player_after_seeing_its_attestation() {
    let mut host = host_with(|_| {});
    let (mut j, peer) = connect(&mut host, &signer(0x51), ALICE);
    host.disconnect(peer, Reason::TierInsufficient as u16)
        .unwrap();
    pump(&mut host, &mut j, ALICE);
    assert_eq!(
        j.poll_event(),
        Some(JoinerEvent::Closed {
            reason: Reason::TierInsufficient as u16
        })
    );
    assert_eq!(host.peer_count(), 0);
    assert_eq!(j.send(b"x"), Err(Error::State));
}

#[test]
fn join_floods_are_bounded() {
    let mut host = host_with(|c| c.max_pending = 4);
    for _ in 0..50 {
        let mut j = Joiner::new(join_cfg(&host), &signer(0x51), HOST).unwrap();
        host.recv(MALLORY, &j.poll_transmit().unwrap().packet)
            .unwrap();
        let _ = host.poll_transmit();
    }
    // The newest pending join still completes.
    let mut j = Joiner::new(join_cfg(&host), &signer(0x52), HOST).unwrap();
    pump(&mut host, &mut j, ALICE);
    assert!(matches!(
        host.poll_event(),
        Some(HostEvent::PeerJoined { .. })
    ));
}

#[test]
fn limits_keep_every_packet_under_the_mtu() {
    let mut host = host_with(|c| c.hello = vec![1; MAX_HELLO]);
    let mut cfg = join_cfg(&host);
    cfg.attestation = vec![2; MAX_ATTESTATION];
    cfg.hello = vec![3; MAX_HELLO];
    let mut j = Joiner::new(cfg, &signer(0x51), HOST).unwrap();
    // The largest join must leave room for the 16-byte cookie a loaded host asks for.
    let init = j.peek_transmit().unwrap().packet.len();
    assert!(init + 16 <= MAX_PACKET, "largest join is {init} bytes");
    let seen = pump(&mut host, &mut j, ALICE);
    assert!(j.is_connected());
    assert!(seen.iter().all(|t| t.packet.len() <= MAX_PACKET));

    j.send(&vec![0; MAX_PAYLOAD]).unwrap();
    assert_eq!(j.poll_transmit().unwrap().packet.len(), MAX_PACKET);
    assert_eq!(j.send(&vec![0; MAX_PAYLOAD + 1]), Err(Error::TooLarge));

    let mut too_big = join_cfg(&host);
    too_big.attestation = vec![0; MAX_ATTESTATION + 1];
    assert!(matches!(
        Joiner::new(too_big, &signer(0x51), HOST),
        Err(Error::TooLarge)
    ));
}

#[test]
fn garbage_never_panics() {
    let mut host = host_with(|_| {});
    let (mut j, _) = connect(&mut host, &signer(0x51), ALICE);
    let mut x: u64 = 0x9e3779b97f4a7c15;
    for len in 0..300 {
        let mut b = vec![0u8; len];
        for byte in &mut b {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = x as u8;
        }
        if let Some(first) = b.first_mut() {
            *first = (len % 4) as u8;
        }
        let _ = host.recv(MALLORY, &b);
        let _ = j.recv(MALLORY, &b);
    }
    assert!(host.poll_event().is_none());
}
