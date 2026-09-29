//! FPP service keys for the prototype (04-protocol.md §4).
//!
//! The prototype VS plays three FPP roles until P2 splits it into services:
//! Verifier (signs ARs), Broker (signs SATs) and Server Liveness (signs
//! SARs). Each role has its own key, because a key may sign only its role's
//! contexts. For development they are derived from the one VS seed on disk;
//! relying parties load only the public **key bundle** (`keys/fpp_key_bundle.json`),
//! which in production is signed by the Publisher Root chain and fetched per region.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use fpp_crypto::{Ed25519Signer, KeyRole, KeySet};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const DEFAULT_BUNDLE: &str = "keys/fpp_key_bundle.json";

/// The VS's role keys.
pub struct ServiceKeys {
    pub verifier: Ed25519Signer,
    pub broker: Ed25519Signer,
    pub liveness: Ed25519Signer,
}

fn derive(role: &str, seed: &[u8; 32]) -> Ed25519Signer {
    let mut h = Sha256::new();
    h.update(b"mmo/dev-role-key/v1\0");
    h.update(role.as_bytes());
    h.update([0]);
    h.update(seed);
    Ed25519Signer::new(SigningKey::from_bytes(&h.finalize().into()))
}

impl ServiceKeys {
    /// Derive the three role keys from the VS seed (dev only).
    pub fn derive(vs_seed: &[u8; 32]) -> Self {
        Self {
            verifier: derive("verifier-ar", vs_seed),
            broker: derive("broker-sat", vs_seed),
            liveness: derive("server-liveness", vs_seed),
        }
    }

    pub fn bundle(&self) -> KeyBundle {
        KeyBundle {
            verifier_ar: self.verifier.verifying_key(),
            broker_sat: self.broker.verifying_key(),
            server_liveness: self.liveness.verifying_key(),
        }
    }
}

/// Public keys relying parties trust, by role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    pub verifier_ar: VerifyingKey,
    pub broker_sat: VerifyingKey,
    pub server_liveness: VerifyingKey,
}

impl KeyBundle {
    pub fn keyset(&self) -> KeySet {
        let mut k = KeySet::default();
        k.insert_ed25519(KeyRole::VerifierAr, self.verifier_ar);
        k.insert_ed25519(KeyRole::BrokerSat, self.broker_sat);
        k.insert_ed25519(KeyRole::ServerLiveness, self.server_liveness);
        k
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::json!({
            "verifier_ar": hex::encode(self.verifier_ar.to_bytes()),
            "broker_sat": hex::encode(self.broker_sat.to_bytes()),
            "server_liveness": hex::encode(self.server_liveness.to_bytes()),
        });
        let path = path.as_ref();
        std::fs::write(path, serde_json::to_string_pretty(&json)? + "\n")
            .with_context(|| format!("write {}", path.display()))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "read {} (generate it with `cargo run -p tools --bin gen_keys`)",
                path.display()
            )
        })?;
        let v: serde_json::Value = serde_json::from_str(&text).context("key bundle JSON")?;
        let key = |name: &str| -> Result<VerifyingKey> {
            let bytes: [u8; 32] = hex::decode(v[name].as_str().context(name.to_owned())?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{name}: not 32 bytes"))?;
            VerifyingKey::from_bytes(&bytes).with_context(|| format!("{name}: invalid key"))
        };
        Ok(Self {
            verifier_ar: key("verifier_ar")?,
            broker_sat: key("broker_sat")?,
            server_liveness: key("server_liveness")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_get_distinct_keys_and_the_bundle_round_trips() {
        let keys = ServiceKeys::derive(&[7; 32]);
        let b = keys.bundle();
        assert_ne!(b.verifier_ar, b.broker_sat);
        assert_ne!(b.broker_sat, b.server_liveness);
        let dir = std::env::temp_dir().join(format!("bundle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("b.json");
        b.save(&p).unwrap();
        assert_eq!(KeyBundle::load(&p).unwrap(), b);
    }
}
