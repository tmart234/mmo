//! A service's signing keys, made in its own directory of the cell
//! (`<cell>/<service>/`, which no other service needs to see), and the
//! public halves it publishes in the cell's shared `<cell>/public/<service>`
//! for the others to read.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use std::path::Path;

/// A service's published public keys: `key value` lines (hex).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicKeys {
    pub name: String,
    pub ed25519: [u8; 32],
    pub ml_dsa: Option<Vec<u8>>,
}

impl PublicKeys {
    pub fn write(&self, cell: &Path, service: &str) -> Result<()> {
        let mut text = format!(
            "name {}\ned25519 {}\n",
            self.name,
            hex::encode(self.ed25519)
        );
        if let Some(ml) = &self.ml_dsa {
            text.push_str(&format!("ml-dsa-65 {}\n", hex::encode(ml)));
        }
        let dir = cell.join("public");
        std::fs::create_dir_all(&dir)?;
        // (written whole, then renamed: a reader never sees half a file)
        let tmp = dir.join(format!("{service}.tmp"));
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, dir.join(service))?;
        Ok(())
    }

    pub fn read(cell: &Path, service: &str) -> Result<PublicKeys> {
        let path = cell.join("public").join(service);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read {} (start {service} first)", path.display()))?;
        let mut out = PublicKeys::default();
        for line in text.lines() {
            let (k, v) = line
                .split_once(' ')
                .ok_or_else(|| anyhow!("{}: bad line", path.display()))?;
            match k {
                "name" => out.name = v.to_string(),
                "ed25519" => {
                    out.ed25519 = hex::decode(v)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(|| anyhow!("{}: ed25519 key", path.display()))?
                }
                "ml-dsa-65" => {
                    out.ml_dsa = Some(
                        hex::decode(v).map_err(|_| anyhow!("{}: ml-dsa key", path.display()))?,
                    )
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Service `service`'s Ed25519 signing key (made on first use in its own
/// directory), with its public key published under `name`.
pub fn ed25519(cell: &Path, service: &str, name: &str) -> Result<SigningKey> {
    let key = SigningKey::from_bytes(&crate::cell::signing_seed(cell, service, "ed25519")?);
    PublicKeys {
        name: name.to_string(),
        ed25519: key.verifying_key().to_bytes(),
        ml_dsa: None,
    }
    .write(cell, service)?;
    Ok(key)
}

/// The key bundle of a cell: the public keys the Verifier, the Broker and
/// Server Liveness published there.
pub fn bundle(cell: &Path) -> Result<common::keys::KeyBundle> {
    let key = |service: &str| -> Result<ed25519_dalek::VerifyingKey> {
        ed25519_dalek::VerifyingKey::from_bytes(&PublicKeys::read(cell, service)?.ed25519)
            .with_context(|| format!("{service}: invalid key"))
    };
    Ok(common::keys::KeyBundle {
        verifier_ar: key("verifier")?,
        broker_sat: key("broker")?,
        server_liveness: key("liveness")?,
    })
}
