//! Signed notes (C2SP `signed-note`), tree heads (`tlog-checkpoint`) and
//! witness cosignatures (`tlog-cosignature`, `cosignature/v1`): the formats
//! Go's `golang.org/x/mod/sumdb/note`, Sigsum and the witness network use,
//! so any of their verifiers can check this log.
//!
//! A note is text ending in a newline, a blank line, then signature lines
//! `— <name> <base64(key hash ‖ signature)>`. The key hash is the first four
//! bytes of `SHA-256(name ‖ "\n" ‖ alg ‖ public key)`.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{b64, LogError};

/// Signature algorithm bytes.
pub const ALG_ED25519: u8 = 0x01;
pub const ALG_COSIGNATURE_V1: u8 = 0x04;
/// FPP's ML-DSA-65 line (suite FPP-S1H: the log key is hybrid). 0xff is
/// the signed-note identifier left for signature types defined elsewhere;
/// verifiers that do not know it ignore the line, as notes require.
pub const ALG_FPP_ML_DSA_65: u8 = 0xff;

const DASH: &str = "\u{2014} ";

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['+', ' ', '\n', '\t']) && name.is_ascii()
}

pub fn key_hash(name: &str, alg: u8, public: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([alg]);
    h.update(public);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// A verifier key in Go's `note` form: `name+hash+base64(alg ‖ key)`.
pub fn verifier_key(name: &str, alg: u8, public: &[u8]) -> String {
    let mut k = vec![alg];
    k.extend_from_slice(public);
    format!(
        "{name}+{}+{}",
        hex(&key_hash(name, alg, public)),
        b64::encode(&k)
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A note, split into its text and signature lines (name, bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub text: String,
    pub signatures: Vec<(String, Vec<u8>)>,
}

impl Note {
    pub fn parse(note: &str) -> Result<Note, LogError> {
        let bad = || LogError::Note("malformed");
        let split = note.rfind("\n\n").ok_or_else(bad)?;
        let text = &note[..split + 1];
        let sigs = &note[split + 2..];
        if text.contains("\n\n") || !sigs.ends_with('\n') || note.len() > 1 << 20 {
            return Err(bad());
        }
        let mut signatures = Vec::new();
        for line in sigs.lines() {
            let rest = line.strip_prefix(DASH).ok_or_else(bad)?;
            let (name, sig) = rest.split_once(' ').ok_or_else(bad)?;
            let sig = b64::decode(sig).ok_or_else(bad)?;
            if !valid_name(name) || sig.len() < 5 || sig.len() > 8192 {
                return Err(bad());
            }
            signatures.push((name.to_string(), sig));
        }
        if signatures.is_empty() || signatures.len() > 100 {
            return Err(bad());
        }
        Ok(Note {
            text: text.to_string(),
            signatures,
        })
    }

    pub fn encode(&self) -> String {
        let mut out = self.text.clone();
        out.push('\n');
        for (name, sig) in &self.signatures {
            out.push_str(&signature_line(name, sig));
        }
        out
    }

    /// The Ed25519 signature by `name`/`public` over the text, if valid.
    pub fn verify(&self, name: &str, public: &[u8; 32]) -> Result<(), LogError> {
        let hash = key_hash(name, ALG_ED25519, public);
        let key = VerifyingKey::from_bytes(public).map_err(|_| LogError::Note("key"))?;
        for (n, sig) in &self.signatures {
            if n == name && sig.len() == 68 && sig[..4] == hash {
                let s =
                    Signature::from_slice(&sig[4..]).map_err(|_| LogError::Note("signature"))?;
                return key
                    .verify(self.text.as_bytes(), &s)
                    .map_err(|_| LogError::Note("signature does not verify"));
            }
        }
        Err(LogError::Note("no signature by that key"))
    }

    /// The log's ML-DSA-65 signature (FPP-S1H) by `name`/`public`.
    pub fn verify_ml_dsa(&self, name: &str, public: &[u8]) -> Result<(), LogError> {
        let hash = key_hash(name, ALG_FPP_ML_DSA_65, public);
        for (n, sig) in &self.signatures {
            if n == name && sig.len() > 4 && sig[..4] == hash {
                return if fpp_crypto::hybrid::ml_dsa_verify(public, self.text.as_bytes(), &sig[4..])
                {
                    Ok(())
                } else {
                    Err(LogError::Note("ML-DSA signature does not verify"))
                };
            }
        }
        Err(LogError::Note("no ML-DSA signature by that key"))
    }

    /// Both halves of a hybrid (FPP-S1H) signature.
    pub fn verify_hybrid(&self, name: &str, ed: &[u8; 32], ml: &[u8]) -> Result<(), LogError> {
        self.verify(name, ed)?;
        self.verify_ml_dsa(name, ml)
    }

    /// A witness's `cosignature/v1` over the text (a checkpoint): its
    /// timestamp, if valid.
    pub fn verify_cosignature(&self, name: &str, public: &[u8; 32]) -> Result<u64, LogError> {
        let hash = key_hash(name, ALG_COSIGNATURE_V1, public);
        let key = VerifyingKey::from_bytes(public).map_err(|_| LogError::Note("key"))?;
        for (n, sig) in &self.signatures {
            if n == name && sig.len() == 76 && sig[..4] == hash {
                let time = u64::from_be_bytes(sig[4..12].try_into().expect("8 bytes"));
                let s =
                    Signature::from_slice(&sig[12..]).map_err(|_| LogError::Note("cosignature"))?;
                return key
                    .verify(&cosigned_message(&self.text, time), &s)
                    .map(|_| time)
                    .map_err(|_| LogError::Note("cosignature does not verify"));
            }
        }
        Err(LogError::Note("no cosignature by that witness"))
    }
}

fn signature_line(name: &str, sig: &[u8]) -> String {
    format!("{DASH}{name} {}\n", b64::encode(sig))
}

/// Sign `text` (ending in a newline) as a note by `name`.
pub fn sign(text: &str, name: &str, key: &SigningKey) -> Result<String, LogError> {
    if !text.ends_with('\n') || text.contains("\n\n") || !valid_name(name) {
        return Err(LogError::Note("text or name"));
    }
    let mut sig = key_hash(name, ALG_ED25519, &key.verifying_key().to_bytes()).to_vec();
    sig.extend_from_slice(&key.sign(text.as_bytes()).to_bytes());
    Ok(format!("{text}\n{}", signature_line(name, &sig)))
}

/// Sign `text` with a hybrid key: the Ed25519 line, then the ML-DSA-65 one.
pub fn sign_hybrid(
    text: &str,
    name: &str,
    key: &fpp_crypto::hybrid::HybridSigner,
) -> Result<String, LogError> {
    let mut note = sign(text, name, key.ed25519())?;
    let mut sig = key_hash(name, ALG_FPP_ML_DSA_65, key.ml_dsa_public()).to_vec();
    sig.extend(key.sign_ml_dsa(text.as_bytes()));
    note.push_str(&signature_line(name, &sig));
    Ok(note)
}

fn cosigned_message(text: &str, time: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {time}\n{text}").into_bytes()
}

/// A witness's cosignature line over a checkpoint's text.
pub fn cosign(text: &str, name: &str, key: &SigningKey, time: u64) -> String {
    let mut sig = key_hash(name, ALG_COSIGNATURE_V1, &key.verifying_key().to_bytes()).to_vec();
    sig.extend_from_slice(&time.to_be_bytes());
    sig.extend_from_slice(&key.sign(&cosigned_message(text, time)).to_bytes());
    signature_line(name, &sig)
}

/// A tree head (`tlog-checkpoint`): origin, size, root hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
}

impl Checkpoint {
    pub fn text(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            b64::encode(&self.root)
        )
    }

    pub fn parse(text: &str) -> Result<Checkpoint, LogError> {
        let bad = || LogError::Note("checkpoint");
        let mut lines = text.lines();
        let origin = lines.next().filter(|o| !o.is_empty()).ok_or_else(bad)?;
        let size = lines.next().ok_or_else(bad)?;
        if size.is_empty()
            || (size.len() > 1 && size.starts_with('0'))
            || !size.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad());
        }
        let root = b64::decode(lines.next().ok_or_else(bad)?).ok_or_else(bad)?;
        Ok(Checkpoint {
            origin: origin.to_string(),
            size: size.parse().map_err(|_| bad())?,
            root: root.try_into().map_err(|_| bad())?,
        })
    }
}
