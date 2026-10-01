//! A development Verifier: signs an Attestation Result (04-protocol.md §6.1)
//! for a session key, at a chosen tier, without appraising any evidence.
//! For tests of admission policies (fpp_ar_verify; a Halo host's
//! `network.minimum_tier`). A real Verifier issues these only after
//! appraising a device's evidence.
//!
//!     cargo run -p fpp-ffi --example mint_ar -- key <seed hex>
//!     cargo run -p fpp-ffi --example mint_ar -- session <seed hex>
//!     cargo run -p fpp-ffi --example mint_ar -- ar <seed hex> <session public hex> <tier> <out>
//!         [platform] [issued seconds from now]

use ed25519_dalek::SigningKey;
use fpp_crypto::{sign, Ed25519Signer};
use fpp_tokens::{AttestationResult, Features};
use fpp_types::{BuildId, DeviceTier, Did};
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

fn hex32(text: &str) -> [u8; 32] {
    let text = text.trim();
    let mut out = [0u8; 32];
    if text.len() != 64 {
        fail("expected 64 hexadecimal digits");
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .unwrap_or_else(|_| fail("not hexadecimal"));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fail(message: &str) -> ! {
    eprintln!("mint_ar: {message}");
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // the public key of a seed: a Verifier's (network.verifier_keys) or a session key's
        Some("key") | Some("session") if args.len() == 2 => {
            println!("{}", hex(SigningKey::from_bytes(&hex32(&args[1])).verifying_key().as_bytes()));
        }
        Some("ar") if (5..=7).contains(&args.len()) => {
            let session = hex32(&args[2]);
            let tier = args[3]
                .parse::<u64>()
                .ok()
                .and_then(DeviceTier::from_u64)
                .unwrap_or_else(|| fail("tier is 0..3"));
            let platform = args.get(5).cloned().unwrap_or_else(|| "windows".into());
            let issued: i64 = args.get(6).map_or(0, |s| s.parse().unwrap_or_else(|_| fail("bad issued")));
            let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs();
            let iat = now.checked_add_signed(issued).unwrap_or_else(|| fail("bad issued"));
            let ar = AttestationResult {
                iss: "ver.dev".into(),
                iat,
                exp: iat + 1800,
                cti: rand::random(),
                cnf: fpp_types::SessionKey::Ed25519(session),
                nonce: [0; 32],
                did: Did(rand::random()),
                tier,
                features: Features {
                    secure_boot: Some(tier >= DeviceTier::D2Hardware),
                    key_in_hw: Some(tier >= DeviceTier::D2Hardware),
                    ..Features::default()
                },
                client_build: BuildId([0; 32]),
                platform,
                policy_ver: 0,
                warnings: vec!["dev-verifier".into()],
            };
            let verifier = Ed25519Signer::new(SigningKey::from_bytes(&hex32(&args[1])));
            std::fs::write(&args[4], sign(&verifier, &ar)).unwrap_or_else(|e| fail(&e.to_string()));
            eprintln!("mint_ar: wrote {} (tier D{}, bound to {})", args[4], tier as u8, hex(&session));
        }
        _ => fail("usage: key <seed> | session <seed> | ar <seed> <session> <tier> <out> [platform] [issued]"),
    }
}
