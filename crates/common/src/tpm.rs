//! TPM (Trusted Platform Module) abstraction layer.
//!
//! Provides trait-based interface for attestation with multiple backends:
//! - Software TPM simulator (for testing)
//! - Real TPM 2.0 hardware (for production)
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │   Game Server (GS) / Client              │
//! │  ┌────────────────────────────────────┐  │
//! │  │   TpmProvider trait                │  │
//! │  │  - quote()                         │  │
//! │  │  - extend_pcr()                    │  │
//! │  │  - get_endorsement_key()           │  │
//! │  └──────────┬────────────┬────────────┘  │
//! │             │            │                │
//! │      ┌──────▼──────┐  ┌─▼────────────┐   │
//! │      │ SimulatedTPM│  │ HardwareTPM  │   │
//! │      │  (Testing)  │  │ (Production) │   │
//! │      └─────────────┘  └──────────────┘   │
//! └──────────────────────────────────────────┘
//!
//!                   ▼ Attestation Quote
//!
//! ┌──────────────────────────────────────────┐
//! │   Verification Server (VS)               │
//! │  ┌────────────────────────────────────┐  │
//! │  │   verify_quote()                   │  │
//! │  │  - Check signature                 │  │
//! │  │  - Validate PCR values             │  │
//! │  │  - Verify EK certificate chain     │  │
//! │  └────────────────────────────────────┘  │
//! └──────────────────────────────────────────┘
//! ```

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PCR (Platform Configuration Register) index.
/// TPM 2.0 typically has 24 PCRs (0-23).
pub type PcrIndex = u8;

/// PCR value (SHA-256 hash, 32 bytes).
pub type PcrValue = [u8; 32];

/// TPM Quote: signed attestation of PCR values + nonce.
///
/// This structure represents a TPM quote that proves:
/// 1. The current state of specified PCRs
/// 2. Freshness via nonce
/// 3. Authenticity via signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    /// PCR values included in this quote (index -> value).
    pub pcr_values: HashMap<PcrIndex, PcrValue>,

    /// Nonce provided by verifier (prevents replay attacks).
    pub nonce: [u8; 32],

    /// Signature over (pcr_values || nonce) using TPM's Attestation Key.
    pub signature: Vec<u8>,

    /// Attestation Key public key (for signature verification).
    pub ak_pub: Vec<u8>,

    /// Optional: Endorsement Key certificate (for AK certification).
    pub ek_cert: Option<Vec<u8>>,
}

/// TPM provider trait: abstract interface for attestation operations.
///
/// Implementors: `SimulatedTpm`, `HardwareTpm`.
pub trait TpmProvider: Send + Sync {
    /// Generate an attestation quote for specified PCRs.
    ///
    /// # Arguments
    /// * `pcr_indices` - Which PCRs to include in the quote
    /// * `nonce` - Challenge from verifier (for freshness)
    ///
    /// # Returns
    /// A signed quote containing PCR values and signature.
    fn quote(&self, pcr_indices: &[PcrIndex], nonce: &[u8; 32]) -> Result<TpmQuote>;

    /// Extend a PCR with new measurement data.
    ///
    /// PCR extension is: `PCR[n] = SHA256(PCR[n] || new_data)`
    ///
    /// # Arguments
    /// * `pcr_index` - Which PCR to extend
    /// * `data` - Data to hash into the PCR
    fn extend_pcr(&mut self, pcr_index: PcrIndex, data: &[u8]) -> Result<()>;

    /// Get the Endorsement Key public key (for certification).
    fn get_endorsement_key(&self) -> Result<Vec<u8>>;

    /// Get current value of a PCR (for debugging).
    fn read_pcr(&self, pcr_index: PcrIndex) -> Result<PcrValue>;
}

/// Verify a TPM quote.
///
/// # Arguments
/// * `quote` - The quote to verify
/// * `expected_nonce` - Expected nonce (must match)
/// * `expected_pcrs` - Optional expected PCR values to check against
///
/// # Returns
/// Ok(()) if quote is valid, Err otherwise.
pub fn verify_quote(
    quote: &TpmQuote,
    expected_nonce: &[u8; 32],
    expected_pcrs: Option<&HashMap<PcrIndex, PcrValue>>,
) -> Result<()> {
    // 1. Check nonce (prevents replay)
    if &quote.nonce != expected_nonce {
        return Err(anyhow!("nonce mismatch"));
    }

    // 2. Verify signature over (pcr_values || nonce)
    // TODO: Implement proper signature verification with AK public key
    // For now, this is a placeholder - real implementation needs:
    // - Parse ak_pub (ed25519 or RSA)
    // - Reconstruct message: bincode::serialize(&(pcr_values, nonce))
    // - Verify signature

    // 3. Check PCR values if expected values provided
    if let Some(expected) = expected_pcrs {
        for (idx, expected_val) in expected.iter() {
            match quote.pcr_values.get(idx) {
                Some(actual_val) if actual_val == expected_val => {}
                Some(actual_val) => {
                    return Err(anyhow!(
                        "PCR[{}] mismatch: expected {:02x?}, got {:02x?}",
                        idx,
                        expected_val,
                        actual_val
                    ));
                }
                None => {
                    return Err(anyhow!("PCR[{}] missing from quote", idx));
                }
            }
        }
    }

    Ok(())
}

/// PCR bank for software TPM simulation.
#[derive(Debug, Clone)]
struct PcrBank {
    pcrs: HashMap<PcrIndex, PcrValue>,
}

impl PcrBank {
    fn new() -> Self {
        let mut pcrs = HashMap::new();
        // Initialize all PCRs to zero (TPM reset state)
        for i in 0..24 {
            pcrs.insert(i, [0u8; 32]);
        }
        Self { pcrs }
    }

    fn extend(&mut self, index: PcrIndex, data: &[u8]) {
        use sha2::{Digest, Sha256};

        let current = self.pcrs.get(&index).copied().unwrap_or([0u8; 32]);
        let mut hasher = Sha256::new();
        hasher.update(current);
        hasher.update(data);
        let new_val: [u8; 32] = hasher.finalize().into();
        self.pcrs.insert(index, new_val);
    }

    fn read(&self, index: PcrIndex) -> PcrValue {
        self.pcrs.get(&index).copied().unwrap_or([0u8; 32])
    }
}

/// Software TPM simulator for testing.
///
/// Provides TPM-like functionality without real hardware:
/// - Simulated PCR bank
/// - Software-based signing (ed25519)
/// - No actual hardware root of trust
///
/// **SECURITY NOTE:** This is for testing only! Do not use in production.
pub struct SimulatedTpm {
    pcr_bank: PcrBank,
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl SimulatedTpm {
    /// Create a new simulated TPM with random keys.
    pub fn new() -> Self {
        use rand::rngs::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            pcr_bank: PcrBank::new(),
            signing_key,
            verifying_key,
        }
    }

    /// Create a simulated TPM with deterministic keys (for testing).
    pub fn new_deterministic(seed: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();

        Self {
            pcr_bank: PcrBank::new(),
            signing_key,
            verifying_key,
        }
    }
}

impl Default for SimulatedTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmProvider for SimulatedTpm {
    fn quote(&self, pcr_indices: &[PcrIndex], nonce: &[u8; 32]) -> Result<TpmQuote> {
        use ed25519_dalek::Signer;

        // Collect requested PCR values
        let mut pcr_values = HashMap::new();
        for &idx in pcr_indices {
            pcr_values.insert(idx, self.pcr_bank.read(idx));
        }

        // Create message to sign: (pcr_values || nonce)
        let message = bincode::serialize(&(&pcr_values, nonce))?;

        // Sign with attestation key (in real TPM, this is a restricted key)
        let signature = self.signing_key.sign(&message);

        Ok(TpmQuote {
            pcr_values,
            nonce: *nonce,
            signature: signature.to_vec(),
            ak_pub: self.verifying_key.to_bytes().to_vec(),
            ek_cert: None, // Software TPM has no EK certificate
        })
    }

    fn extend_pcr(&mut self, pcr_index: PcrIndex, data: &[u8]) -> Result<()> {
        if pcr_index >= 24 {
            return Err(anyhow!("invalid PCR index: {}", pcr_index));
        }
        self.pcr_bank.extend(pcr_index, data);
        Ok(())
    }

    fn get_endorsement_key(&self) -> Result<Vec<u8>> {
        // In real TPM, EK is a unique key burned into hardware
        // For simulation, we just return the AK public key
        Ok(self.verifying_key.to_bytes().to_vec())
    }

    fn read_pcr(&self, pcr_index: PcrIndex) -> Result<PcrValue> {
        if pcr_index >= 24 {
            return Err(anyhow!("invalid PCR index: {}", pcr_index));
        }
        Ok(self.pcr_bank.read(pcr_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_tpm_quote() {
        let mut tpm = SimulatedTpm::new();

        // Extend PCR 0 with some data
        tpm.extend_pcr(0, b"test measurement").unwrap();

        // Generate quote
        let nonce = [42u8; 32];
        let quote = tpm.quote(&[0, 1], &nonce).unwrap();

        assert_eq!(quote.nonce, nonce);
        assert!(quote.pcr_values.contains_key(&0));
        assert!(quote.pcr_values.contains_key(&1));
        assert!(!quote.signature.is_empty());
    }

    #[test]
    fn test_pcr_extension() {
        let mut tpm = SimulatedTpm::new();

        let initial = tpm.read_pcr(0).unwrap();
        assert_eq!(initial, [0u8; 32]);

        tpm.extend_pcr(0, b"measurement1").unwrap();
        let after1 = tpm.read_pcr(0).unwrap();
        assert_ne!(after1, [0u8; 32]);

        tpm.extend_pcr(0, b"measurement2").unwrap();
        let after2 = tpm.read_pcr(0).unwrap();
        assert_ne!(after2, after1);
    }

    #[test]
    fn test_deterministic_tpm() {
        let seed = [1u8; 32];
        let tpm1 = SimulatedTpm::new_deterministic(&seed);
        let tpm2 = SimulatedTpm::new_deterministic(&seed);

        let nonce = [0u8; 32];
        let quote1 = tpm1.quote(&[0], &nonce).unwrap();
        let quote2 = tpm2.quote(&[0], &nonce).unwrap();

        assert_eq!(quote1.ak_pub, quote2.ak_pub);
    }
}
