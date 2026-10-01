//! A PC client's TPM 2.0 (roadmap P3), through tpm2-tools
//! (`common::tpm2`): the session key is made in the TPM and certified by an
//! Attestation Key, and every admission carries a quote over the
//! Verifier's challenge and that key, with the measured-boot log
//! (`crates/svc-verifier/src/tpm.rs` appraises it). The Verifier then asks
//! the TPM to activate a credential, which ties the AK to the certified EK.
//!
//! On Windows a game would make the same evidence with the Platform Crypto
//! Provider (NCrypt) and `Tbsi_GetTCGLog`; this reference uses tpm2-tools,
//! on Linux or against a software TPM.

use crate::Attestor;
use anyhow::Result;
use common::proto::CredentialChallenge;
use common::tpm2::{Tpm2, Tpm2Options, TpmSessionKey};
use fpp_tokens::evidence::{attest_challenge, Evidence, TpmEvidence};

/// The PCRs a client quotes: firmware and boot manager (0–7) and Windows'
/// boot configuration (11–15).
pub const CLIENT_PCRS: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15];

pub struct TpmDevice {
    tpm: Tpm2,
    session_public: Vec<u8>,
    certify: (Vec<u8>, Vec<u8>),
}

impl TpmDevice {
    /// Open the TPM, make an AK and a session key in it, and have the AK
    /// certify the key. The key signs the session (ES256).
    pub fn open(opts: Tpm2Options) -> Result<(Self, TpmSessionKey)> {
        let tpm = Tpm2::open(opts)?;
        let key = tpm.session_key()?;
        let certify = tpm.certify(&key)?;
        Ok((
            TpmDevice {
                tpm,
                session_public: key.public_area.clone(),
                certify,
            },
            key,
        ))
    }

    /// The evidence as a TPM made it (for tests that tamper with it).
    pub fn tpm_evidence(
        &self,
        verifier_challenge: &[u8; 32],
        session_pub: &[u8],
    ) -> Result<TpmEvidence> {
        let e = self
            .tpm
            .evidence(&attest_challenge(verifier_challenge, session_pub))?;
        Ok(TpmEvidence {
            ek_public: e.ek_public,
            ek_chain: e.ek_chain,
            ak_public: e.ak_public,
            quote: e.attest,
            quote_signature: e.signature,
            pcrs: e.pcrs.into_iter().collect(),
            boot_log: e.boot_log.unwrap_or_default(),
            session_public: self.session_public.clone(),
            certify: self.certify.0.clone(),
            certify_signature: self.certify.1.clone(),
        })
    }
}

impl Attestor for TpmDevice {
    fn evidence(&self, verifier_challenge: &[u8; 32], session_pub: &[u8]) -> Result<Vec<u8>> {
        Ok(Evidence::Tpm(Box::new(
            self.tpm_evidence(verifier_challenge, session_pub)?,
        ))
        .encode())
    }

    fn activate(&self, challenge: &CredentialChallenge) -> Result<Vec<u8>> {
        self.tpm.activate(challenge)
    }
}
