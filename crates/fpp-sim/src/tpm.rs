//! PC client TPM 2.0 attestor over `fpp::tpm2_collect`.

use crate::client::Attestor;
use anyhow::{anyhow, Result};
use fpp::control::CredentialChallenge;
use fpp::tokens::evidence::{attest_challenge, Evidence, TpmEvidence};
use fpp::tpm2_collect::{Tpm2, Tpm2Options, TpmSessionKey};

/// PCRs a PC client quotes: firmware/boot manager (0–7) and Windows boot config (11–15).
pub const CLIENT_PCRS: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 15];

pub struct TpmDevice {
    tpm: Tpm2,
    session_public: Vec<u8>,
    certify: (Vec<u8>, Vec<u8>),
}

impl TpmDevice {
    /// Open the TPM, create an AK and an ES256 session key inside it, and have
    /// the AK certify the session key.
    pub fn open(opts: Tpm2Options) -> Result<(Self, TpmSessionKey)> {
        let tpm = Tpm2::open(opts).map_err(|e| anyhow!("{e}"))?;
        let key = tpm.session_key().map_err(|e| anyhow!("{e}"))?;
        let certify = tpm.certify(&key).map_err(|e| anyhow!("{e}"))?;
        Ok((
            TpmDevice {
                tpm,
                session_public: key.public_area.clone(),
                certify,
            },
            key,
        ))
    }

    pub fn tpm_evidence(
        &self,
        verifier_challenge: &[u8; 32],
        session_pub: &[u8],
    ) -> Result<TpmEvidence> {
        let mut e = self
            .tpm
            .evidence(&attest_challenge(verifier_challenge, session_pub))
            .map_err(|e| anyhow!("{e}"))?;
        e.session_public = self.session_public.clone();
        e.certify = self.certify.0.clone();
        e.certify_signature = self.certify.1.clone();
        Ok(e)
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
        self.tpm.activate(challenge).map_err(|e| anyhow!("{e}"))
    }
}
