//! Player-hosted session endpoints (fpp-session) on untrusted datagrams:
//! a host, and a joiner already connected to it, both fed arbitrary bytes.
#![no_main]

use ed25519_dalek::SigningKey;
use fpp_crypto::Ed25519Signer;
use fpp_session::{Host, HostConfig, JoinConfig, Joiner, StaticKeypair};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cfg = HostConfig::new(StaticKeypair::from_private([0x42; 32]));
    cfg.invite_secret = Some([7; 32]);
    let mut host: Host<[u8; 1]> = Host::new(cfg);
    let join = JoinConfig {
        host_static: host.static_public_key(),
        invite_secret: Some([7; 32]),
        attestation: Vec::new(),
        hello: Vec::new(),
    };
    let key = Ed25519Signer::new(SigningKey::from_bytes(&[0x51; 32]));
    let mut joiner = Joiner::new(join, &key, [0]).expect("joiner");
    let init = joiner.poll_transmit().expect("init");
    host.recv([1], &init.packet).expect("init accepted");
    let resp = host.poll_transmit().expect("resp");
    joiner.recv([0], &resp.packet).expect("resp accepted");
    let confirm = joiner.poll_transmit().expect("confirm");
    host.recv([1], &confirm.packet).expect("confirm accepted");

    // Split the input into datagrams; the first byte of each picks a sender.
    for chunk in data.split(|&b| b == 0xff) {
        let (from, datagram) = chunk.split_first().map_or((2, chunk), |(f, d)| (f % 4, d));
        let _ = host.recv([from], datagram);
        let _ = joiner.recv([from], datagram);
        while host.poll_transmit().is_some() {}
        while joiner.poll_transmit().is_some() {}
        while host.poll_event().is_some() {}
        while joiner.poll_event().is_some() {}
        let _ = host.tick(u64::from(from) * 1_000);
        let _ = joiner.tick(u64::from(from) * 1_000);
    }
});
