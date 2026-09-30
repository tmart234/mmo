//! The regional key bundle (04-protocol.md §4): the public keys of the
//! Verifier (ARs), the Broker (SATs), Server Liveness (SARs) and
//! Enforcement (revocation events), which relying parties (clients, game
//! servers) trust.
//!
//! Each service makes its own signing key in its own cell directory and
//! publishes only the public half (`fpp-svc`); `fpp-cell bundle` gathers
//! them into `keys/fpp_key_bundle.json`. In production the bundle is signed
//! by the Publisher Root chain and fetched per region.

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use fpp_crypto::{KeyRole, KeySet};
use std::path::Path;

pub const DEFAULT_BUNDLE: &str = "keys/fpp_key_bundle.json";

/// Public keys relying parties trust, by role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    pub verifier_ar: VerifyingKey,
    pub broker_sat: VerifyingKey,
    pub server_liveness: VerifyingKey,
    pub enforcement: VerifyingKey,
}

impl KeyBundle {
    pub fn keyset(&self) -> KeySet {
        let mut k = KeySet::default();
        k.insert_ed25519(KeyRole::VerifierAr, self.verifier_ar);
        k.insert_ed25519(KeyRole::BrokerSat, self.broker_sat);
        k.insert_ed25519(KeyRole::ServerLiveness, self.server_liveness);
        k.insert_ed25519(KeyRole::Enforcement, self.enforcement);
        k
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::json!({
            "verifier_ar": hex::encode(self.verifier_ar.to_bytes()),
            "broker_sat": hex::encode(self.broker_sat.to_bytes()),
            "server_liveness": hex::encode(self.server_liveness.to_bytes()),
            "enforcement": hex::encode(self.enforcement.to_bytes()),
        });
        let path = path.as_ref();
        std::fs::write(path, serde_json::to_string_pretty(&json)? + "\n")
            .with_context(|| format!("write {}", path.display()))
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "read {} (gather it with `fpp-cell bundle` once the services have started)",
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
            enforcement: key("enforcement")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn the_bundle_round_trips() {
        let key = |n: u8| SigningKey::from_bytes(&[n; 32]).verifying_key();
        let b = KeyBundle {
            verifier_ar: key(1),
            broker_sat: key(2),
            server_liveness: key(3),
            enforcement: key(4),
        };
        let dir = std::env::temp_dir().join(format!("bundle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("b.json");
        b.save(&p).unwrap();
        assert_eq!(KeyBundle::load(&p).unwrap(), b);
    }
}
