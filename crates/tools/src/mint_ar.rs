//! A development Verifier: signs an Attestation Result (04-protocol.md §6.1)
//! for a session key, at a chosen tier, without appraising any evidence.
//! For tests of admission policies (a Halo host's `network.minimum_tier`);
//! a real Verifier issues these only after appraising a device's evidence.
//!
//!     mint_ar key --seed <64 hex>                 # the Verifier's public key
//!     mint_ar session --seed <64 hex>             # a session key's public key
//!     mint_ar ar --seed <64 hex> --session <64 hex> --tier 2 --out ar.cbor

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use fpp_crypto::{sign, Ed25519Signer};
use fpp_tokens::{AttestationResult, Features};
use fpp_types::{BuildId, DeviceTier, Did};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the Verifier public key of a seed (hex), for a host's
    /// network.verifier_keys.
    Key {
        #[arg(long)]
        seed: String,
    },
    /// Print the Ed25519 public key of a session key seed (hex).
    Session {
        #[arg(long)]
        seed: String,
    },
    /// Sign an Attestation Result for a session public key.
    Ar {
        /// The Verifier's 32-byte signing seed, hex.
        #[arg(long)]
        seed: String,
        /// The session public key it is bound to (cnf), hex.
        #[arg(long)]
        session: String,
        /// Device tier, 0..3.
        #[arg(long, default_value_t = 2)]
        tier: u8,
        #[arg(long, default_value = "windows")]
        platform: String,
        /// Seconds valid (at most 1800).
        #[arg(long, default_value_t = 1800)]
        lifetime: u64,
        /// Seconds from now it was issued (negative: in the past).
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        issued: i64,
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 {
        bail!("expected 64 hexadecimal digits");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).context("not hexadecimal")?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Key { seed } | Command::Session { seed } => {
            println!(
                "{}",
                hex(SigningKey::from_bytes(&hex32(&seed)?)
                    .verifying_key()
                    .as_bytes())
            );
        }
        Command::Ar {
            seed,
            session,
            tier,
            platform,
            lifetime,
            issued,
            out,
        } => {
            let tier = DeviceTier::from_u64(tier.into()).ok_or_else(|| anyhow!("tier is 0..3"))?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let iat = now
                .checked_add_signed(issued)
                .ok_or_else(|| anyhow!("bad --issued"))?;
            let session = hex32(&session)?;
            let ar = AttestationResult {
                iss: "ver.dev".into(),
                iat,
                exp: iat + lifetime.min(1800),
                cti: rand::random(),
                cnf: session,
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
            let verifier = Ed25519Signer::new(SigningKey::from_bytes(&hex32(&seed)?));
            std::fs::write(&out, sign(&verifier, &ar))?;
            eprintln!(
                "wrote {} (tier D{}, bound to {})",
                out.display(),
                tier as u8,
                hex(&session)
            );
        }
    }
    Ok(())
}
