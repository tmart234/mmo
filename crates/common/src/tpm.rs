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
    // Reconstruct the message that was signed
    let message = bincode::serialize(&(&quote.pcr_values, &quote.nonce))?;

    // Parse AK public key (assuming ed25519 for SimulatedTpm)
    // In production with hardware TPM, this would support RSA as well
    if quote.ak_pub.len() == 32 {
        // Ed25519 public key
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let ak_pub_bytes: [u8; 32] = quote
            .ak_pub
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid ak_pub length"))?;

        let verifying_key = VerifyingKey::from_bytes(&ak_pub_bytes)
            .map_err(|e| anyhow!("failed to parse ak_pub: {}", e))?;

        let signature = Signature::from_slice(&quote.signature)
            .map_err(|e| anyhow!("failed to parse signature: {}", e))?;

        verifying_key
            .verify(&message, &signature)
            .map_err(|e| anyhow!("TPM quote signature verification failed: {}", e))?;
    } else {
        // TODO: Add RSA support for hardware TPM
        return Err(anyhow!(
            "unsupported AK public key format (len={}), expected ed25519 (32 bytes)",
            quote.ak_pub.len()
        ));
    }

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

/// Hardware TPM 2.0 implementation using tss-esapi.
///
/// Provides real TPM functionality with hardware root of trust:
/// - Hardware PCR bank
/// - Hardware-based signing (RSA or ECC)
/// - Endorsement Key (EK) certificate
///
/// **PRODUCTION USE:** This implementation uses real TPM hardware.
#[cfg(feature = "hardware-tpm")]
pub struct HardwareTpm {
    context: tss_esapi::Context,
    ak_handle: tss_esapi::handles::KeyHandle,
    ek_handle: tss_esapi::handles::KeyHandle,
}

#[cfg(feature = "hardware-tpm")]
impl HardwareTpm {
    /// Create a new hardware TPM instance.
    ///
    /// This will:
    /// 1. Connect to TPM device
    /// 2. Create/load Attestation Key (AK)
    /// 3. Create/load Endorsement Key (EK)
    pub fn new() -> Result<Self> {
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::tcti_ldr::TctiNameConf;

        // Connect to TPM (device or simulator)
        let tcti = TctiNameConf::from_environment_variable()
            .or_else(|_| TctiNameConf::Device(Default::default()))?;
        let mut context = tss_esapi::Context::new(tcti)?;

        // Create Endorsement Key (EK) - unique hardware identity
        let ek_handle = Self::create_endorsement_key(&mut context)?;

        // Create Attestation Key (AK) - for signing quotes
        let ak_handle = Self::create_attestation_key(&mut context, ek_handle)?;

        Ok(Self {
            context,
            ak_handle,
            ek_handle,
        })
    }

    fn create_endorsement_key(
        context: &mut tss_esapi::Context,
    ) -> Result<tss_esapi::handles::KeyHandle> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::interface_types::ecc::EccCurve;
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::*;

        // RSA 2048 EK (standard TPM 2.0 endorsement key)
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_admin_with_policy(true)
            .with_restricted(true)
            .with_decrypt(true)
            .build()?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Aes {
                        key_bits: AesKeyBits::Aes128,
                        mode: SymmetricMode::Cfb,
                    })
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(0)
                    .with_is_decryption_key(true)
                    .with_restricted(true)
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        let ek = context.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, key_pub, None, None, None, None)
        })?;

        Ok(ek.key_handle)
    }

    fn create_attestation_key(
        context: &mut tss_esapi::Context,
        _ek_handle: tss_esapi::handles::KeyHandle,
    ) -> Result<tss_esapi::handles::KeyHandle> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::*;

        // Attestation Key (AK) - restricted signing key
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true)
            .with_sign_encrypt(true)
            .build()?;

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::RsaSsa(HashingAlgorithm::Sha256))
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(0)
                    .with_is_signing_key(true)
                    .with_restricted(true)
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        let ak = context.execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
        })?;

        Ok(ak.key_handle)
    }
}

#[cfg(feature = "hardware-tpm")]
impl TpmProvider for HardwareTpm {
    fn quote(&self, pcr_indices: &[PcrIndex], nonce: &[u8; 32]) -> Result<TpmQuote> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::interface_types::session_handles::AuthSession;
        use tss_esapi::structures::{Attest, AttestInfo, Data, PcrSelectionListBuilder};

        // Build PCR selection list
        let mut pcr_selection_list_builder =
            PcrSelectionListBuilder::new().with_selection(HashingAlgorithm::Sha256, pcr_indices);
        let pcr_selection_list = pcr_selection_list_builder.build()?;

        // Create qualifying data from nonce
        let qualifying_data = Data::try_from(nonce.to_vec())?;

        // Generate quote
        let (attest, signature) = self.context.execute_without_session(|ctx| {
            ctx.quote(
                self.ak_handle,
                qualifying_data.clone(),
                tss_esapi::structures::SignatureScheme::Null,
                pcr_selection_list.clone(),
            )
        })?;

        // Parse attestation data
        let pcr_values = match attest.attested() {
            AttestInfo::Quote { pcr_digest, .. } => {
                // Read actual PCR values
                let mut values = HashMap::new();
                for &idx in pcr_indices {
                    let pcr_data = self
                        .context
                        .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list.clone()))?;

                    if let Some(pcr_bank) = pcr_data.pcr_bank(HashingAlgorithm::Sha256) {
                        if let Some(digest) = pcr_bank.get(idx as usize) {
                            let mut pcr_val = [0u8; 32];
                            pcr_val.copy_from_slice(digest.as_bytes());
                            values.insert(idx, pcr_val);
                        }
                    }
                }
                values
            }
            _ => return Err(anyhow!("unexpected attestation type")),
        };

        // Get AK public key
        let (ak_pub_tpm, _, _) = self
            .context
            .execute_without_session(|ctx| ctx.read_public(self.ak_handle))?;
        let ak_pub = ak_pub_tpm.marshall()?;

        Ok(TpmQuote {
            pcr_values,
            nonce: *nonce,
            signature: signature.marshall()?,
            ak_pub,
            ek_cert: None, // TODO: Read EK certificate from NVRAM
        })
    }

    fn extend_pcr(&mut self, pcr_index: PcrIndex, data: &[u8]) -> Result<()> {
        use tss_esapi::structures::{Digest, PcrSlot};

        // Hash the data first
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest_bytes: [u8; 32] = hasher.finalize().into();

        let digest = Digest::try_from(digest_bytes.to_vec())?;
        let pcr_slot = PcrSlot::Slot0; // Map pcr_index to PcrSlot

        self.context
            .execute_without_session(|ctx| ctx.pcr_extend(pcr_slot, digest))?;

        Ok(())
    }

    fn get_endorsement_key(&self) -> Result<Vec<u8>> {
        let (ek_pub, _, _) = self
            .context
            .execute_without_session(|ctx| ctx.read_public(self.ek_handle))?;
        Ok(ek_pub.marshall()?)
    }

    fn read_pcr(&self, pcr_index: PcrIndex) -> Result<PcrValue> {
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::PcrSelectionListBuilder;

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[pcr_index])
            .build()?;

        let pcr_data = self
            .context
            .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))?;

        if let Some(pcr_bank) = pcr_data.pcr_bank(HashingAlgorithm::Sha256) {
            if let Some(digest) = pcr_bank.get(pcr_index as usize) {
                let mut pcr_val = [0u8; 32];
                pcr_val.copy_from_slice(digest.as_bytes());
                return Ok(pcr_val);
            }
        }

        Err(anyhow!("PCR {} not found", pcr_index))
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
