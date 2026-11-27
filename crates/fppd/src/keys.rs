//! Isolated per-role key custody under one state directory (`dir/`).
//!
//! Every trust-plane role holds its own independent keypair (never derived
//! from a shared seed) with strict `fpp::crypto::KeyRole` context allowlists:
//! - `transport.seed`  — X25519 Noise IK static key for the authority endpoint
//! - `admin.seed`      — X25519 Noise IK static key for authorized operators/roles
//! - `liveness.seed`   — Ed25519 Server Liveness key (`fpp/1/sar`)
//! - `verifier.seed`   — Ed25519 Verifier key (`fpp/1/attestation-result`)
//! - `verifier/did.seed` — 32-byte publisher HMAC key for unlinkable Device IDs (ID-02)
//! - `broker.seed`     — Ed25519 Broker key (`fpp/1/sat`)
//! - `enforcement.seed`— Ed25519 Enforcement key (`fpp/1/revocation`)
//! - `log.seed` + `log.mldsa` — Hybrid Ed25519 + ML-DSA-65 Log key (`FPP-S1H`)
//! - `witness.seed`    — Ed25519 Transparency Log witness key

use crate::policy::AuthorityPolicy;
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use fpp::bundle::{KeyBundle, LogKeys};
use fpp::crypto::hybrid::HybridSigner;
use fpp::crypto::Ed25519Signer;
use fpp::session::StaticKeypair;
use std::collections::BTreeMap;
use std::path::Path;

pub const LOG_ORIGIN: &str = "fpp.dev/log";
pub const WITNESS_NAME: &str = "fpp.dev/witness";

/// Load or generate a 32-byte seed under `dir/<subdir>/<name>.seed` with mode 0600.
pub fn load_or_create_seed(dir: &Path, subdir: &str, name: &str) -> Result<[u8; 32]> {
    let sub = dir.join(subdir);
    let path = sub.join(format!("{name}.seed"));
    if let Ok(bytes) = std::fs::read(&path) {
        return bytes
            .try_into()
            .map_err(|_| anyhow!("{} is not 32 bytes", path.display()));
    }
    let seed: [u8; 32] = rand::random();
    std::fs::create_dir_all(&sub).with_context(|| format!("mkdir {}", sub.display()))?;
    std::fs::write(&path, seed).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(seed)
}

pub fn load_ed25519(dir: &Path, role: &str) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&load_or_create_seed(
        dir, role, "ed25519",
    )?))
}

pub fn load_noise(dir: &Path, name: &str) -> Result<StaticKeypair> {
    Ok(StaticKeypair::from_private(load_or_create_seed(
        dir, name, "noise",
    )?))
}

pub fn load_log_hybrid(dir: &Path) -> Result<HybridSigner> {
    let ed = load_or_create_seed(dir, "log", "ed25519")?;
    let ml = load_or_create_seed(dir, "log", "mldsa65")?;
    HybridSigner::from_seeds(&ed, &ml).map_err(|e| anyhow!("hybrid log key: {e:?}"))
}

/// Complete isolated key material for an all-in-one authority cell.
pub struct CellKeys {
    pub transport: StaticKeypair,
    pub admin: StaticKeypair,
    pub liveness: Ed25519Signer,
    pub verifier: Ed25519Signer,
    /// Per-publisher 32-byte HMAC secret for hardware Device IDs (ID-02):
    /// stable for bans within this game/publisher, unlinkable across publishers.
    pub did_key: [u8; 32],
    pub broker: Ed25519Signer,
    pub enforcement: Ed25519Signer,
    pub log: HybridSigner,
    pub witness: SigningKey,
}

impl CellKeys {
    /// Load (or create on first run) every role's independent key in `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        Ok(Self {
            transport: load_noise(dir, "transport")?,
            admin: load_noise(dir, "admin")?,
            liveness: Ed25519Signer::new(load_ed25519(dir, "liveness")?),
            verifier: Ed25519Signer::new(load_ed25519(dir, "verifier")?),
            did_key: load_or_create_seed(dir, "verifier", "did")?,
            broker: Ed25519Signer::new(load_ed25519(dir, "broker")?),
            enforcement: Ed25519Signer::new(load_ed25519(dir, "enforcement")?),
            log: load_log_hybrid(dir)?,
            witness: load_ed25519(dir, "witness")?,
        })
    }

    /// Public regional key bundle using the default `fpp.dev` domain.
    pub fn bundle(&self) -> KeyBundle {
        self.bundle_for(&AuthorityPolicy::default())
    }

    /// Public regional key bundle for a specific game/publisher `policy`.
    pub fn bundle_for(&self, policy: &AuthorityPolicy) -> KeyBundle {
        KeyBundle {
            transport_pub: self.transport.public,
            role_transport: BTreeMap::new(),
            verifier_ar: self.verifier.verifying_key(),
            broker_sat: self.broker.verifying_key(),
            server_liveness: self.liveness.verifying_key(),
            enforcement: self.enforcement.verifying_key(),
            log: Some(LogKeys {
                origin: policy.log_origin(),
                ed25519: self.log.ed25519_public().to_bytes(),
                ml_dsa: self.log.ml_dsa_public().to_vec(),
                witnesses: vec![(
                    policy.witness_name(),
                    self.witness.verifying_key().to_bytes(),
                )],
            }),
        }
    }
}
