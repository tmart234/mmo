//! Unified TPM 2.0 appraisal for BOTH game-server admission (Server Liveness)
//! and PC client admission (Verifier), eliminating the previously duplicated
//! EK/AK/quote/credential-activation code across `svc-liveness` and `svc-verifier`.

use crate::tpm::certify::verify_session_key;
use crate::tpm::{
    appraise, eventlog, make_credential, verify_ek, wbcl, Evidence, Policy, Public, Registry,
    TpmError,
};
use crate::{AttestError, BootClaims, Claims, KeyStorage};
use fpp::control::{join_quote_nonce, CredentialChallenge};
use fpp::crypto::ct_eq;
use fpp::tokens::evidence::{attest_challenge, TpmEvidence};
use rand::{rngs::OsRng, RngCore};
use std::collections::BTreeMap;

/// PCRs a PC client's quote must cover: Secure Boot (7) and Windows boot config (12–14).
pub const CLIENT_REQUIRED_PCRS: [u8; 4] = [7, 12, 13, 14];

/// Second-round-trip credential activation challenge and expected secret.
#[derive(Clone, Debug)]
pub struct Activation {
    pub challenge: CredentialChallenge,
    pub secret: Vec<u8>,
}

impl Activation {
    /// Constant-time check that the peer's TPM opened the exact secret.
    pub fn opened(&self, answer: &[u8]) -> bool {
        ct_eq(&self.secret, answer)
    }
}

/// Result of appraising a game server's TPM 2.0 evidence.
#[derive(Debug)]
pub struct GsTpmAdmission {
    pub ek_digest: [u8; 32],
    pub build: Option<([u8; 32], String)>,
    pub secure_boot: Option<bool>,
    pub activation: Activation,
}

fn map_tpm_err(what: &'static str, e: TpmError) -> AttestError {
    match e {
        TpmError::Certificate(c) => c,
        TpmError::NonceMismatch => AttestError::ChallengeMismatch,
        TpmError::BadSignature => AttestError::BadSignature(what),
        TpmError::Malformed(m) => AttestError::Malformed(m),
        TpmError::Policy(p) => AttestError::Policy(p),
        _ => AttestError::Policy(what),
    }
}

/// Shared steps: parse EK & AK, verify EK certificate chain to pinned roots,
/// appraise quote against `nonce` and `policy`, and build credential activation.
fn appraise_common(
    ek_roots: &[Vec<u8>],
    ev: &TpmEvidence,
    nonce: &[u8; 32],
    policy: &Policy<'_>,
    now_unix: i64,
) -> Result<(Public, [u8; 32], crate::tpm::Appraisal, Activation), AttestError> {
    if ek_roots.is_empty() {
        return Err(AttestError::Policy("no TPM manufacturer roots configured"));
    }
    let ek = Public::from_tpm2b(&ev.ek_public).map_err(|e| map_tpm_err("EK public area", e))?;
    let endorsement = verify_ek(&ek, &ev.ek_chain, ek_roots, Some(now_unix))
        .map_err(|e| map_tpm_err("EK certificate", e))?;
    let ak = Public::from_tpm2b(&ev.ak_public).map_err(|e| map_tpm_err("AK public area", e))?;

    let pcrs: BTreeMap<u8, Vec<u8>> = ev.pcrs.iter().cloned().collect();
    let boot_log = (!ev.boot_log.is_empty()).then(|| ev.boot_log.clone());
    let ima_log = (!ev.ima_log.is_empty()).then(|| ev.ima_log.clone());

    let appraisal = appraise(
        &ak,
        &Evidence {
            attest: ev.quote.clone(),
            signature: ev.quote_signature.clone(),
            pcrs,
            boot_log,
            ima_log,
        },
        nonce,
        policy,
    )
    .map_err(|e| map_tpm_err("quote", e))?;

    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let name = ak.name().map_err(|e| map_tpm_err("AK name", e))?;
    let cred = make_credential(&ek, &name, &secret).map_err(|e| map_tpm_err("credential", e))?;
    let activation = Activation {
        challenge: CredentialChallenge {
            id_object: cred.id_object,
            encrypted_secret: cred.encrypted_secret,
        },
        secret,
    };
    Ok((ak, endorsement.ek_digest, appraisal, activation))
}

/// Appraise a game server's TPM 2.0 join evidence (Server Liveness, F05/F06/F21).
#[allow(clippy::too_many_arguments)]
pub fn appraise_gs_join(
    ek_roots: &[Vec<u8>],
    build_registry: &Registry,
    gs_program_path: Option<&str>,
    require_secure_boot: bool,
    challenge: &[u8; 32],
    join_sign_bytes: &[u8],
    claimed_sw_hash: &[u8; 32],
    ev: &TpmEvidence,
    now_unix: i64,
) -> Result<GsTpmAdmission, AttestError> {
    let policy = Policy {
        registry: build_registry,
        program: gs_program_path,
        require_secure_boot,
        allow_ima_violations: false,
    };
    let nonce = join_quote_nonce(challenge, join_sign_bytes);
    let (_ak, ek_digest, appraisal, activation) =
        appraise_common(ek_roots, ev, &nonce, &policy, now_unix)?;

    let build = match appraisal.program {
        Some((hash, label)) => {
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| AttestError::Malformed("measured hash size"))?;
            if &hash != claimed_sw_hash {
                return Err(AttestError::Policy(
                    "GS reported sw_hash disagrees with kernel IMA measurement",
                ));
            }
            Some((hash, label))
        }
        None => None,
    };
    Ok(GsTpmAdmission {
        ek_digest,
        build,
        secure_boot: appraisal.secure_boot,
        activation,
    })
}

/// Appraise a PC client's TPM 2.0 evidence (Verifier, P3.2).
pub fn appraise_pc_client(
    ek_roots: &[Vec<u8>],
    ev: &TpmEvidence,
    verifier_challenge: &[u8; 32],
    session_pub: &[u8],
    now_unix: i64,
) -> Result<(Claims, Activation), AttestError> {
    let empty = Registry::default();
    let policy = Policy {
        registry: &empty,
        program: None,
        require_secure_boot: false,
        allow_ima_violations: false,
    };
    let nonce = attest_challenge(verifier_challenge, session_pub);
    let (ak, ek_digest, appraisal, activation) =
        appraise_common(ek_roots, ev, &nonce, &policy, now_unix)?;

    let mut warnings = Vec::new();
    let mut windows = wbcl::WindowsBoot::default();
    let measured_boot = if !ev.boot_log.is_empty() {
        let log = eventlog::replay(&ev.boot_log).map_err(|e| map_tpm_err("boot log", e))?;
        for pcr in CLIENT_REQUIRED_PCRS {
            let quoted = appraisal
                .quote
                .pcrs
                .get(&pcr)
                .ok_or(AttestError::Policy("the quote leaves out a required PCR"))?;
            let replayed = log.pcrs.get(&pcr).cloned().unwrap_or_else(|| vec![0; 32]);
            if *quoted != replayed {
                return Err(AttestError::Policy(
                    "the boot log does not explain a quoted PCR",
                ));
            }
        }
        windows = wbcl::windows_boot(&log, &CLIENT_REQUIRED_PCRS)
            .map_err(|e| map_tpm_err("SIPA events", e))?;
        true
    } else {
        warnings.push("no-boot-log".to_string());
        false
    };

    let session = verify_session_key(&ak, &ev.certify, &ev.certify_signature, &ev.session_public)
        .map_err(|e| map_tpm_err("session key certification", e))?;
    if session != session_pub {
        return Err(AttestError::Policy(
            "the certified key is not the session key",
        ));
    }

    let secure_boot = appraisal.secure_boot;
    let verified_boot = if secure_boot == Some(false) {
        warnings.push("secure-boot-off".into());
        Some(false)
    } else if windows.measured {
        for (on, name) in [
            (windows.test_signing, "test-signing"),
            (windows.kernel_debug, "kernel-debug"),
            (windows.boot_debugging, "boot-debugging"),
            (windows.hypervisor_debug, "hypervisor-debug"),
            (windows.safe_mode, "safe-mode"),
            (windows.winpe, "winpe"),
        ] {
            if on == Some(true) {
                warnings.push(name.into());
            }
        }
        if windows.code_integrity == Some(false) {
            warnings.push("code-integrity-off".into());
        }
        if secure_boot != Some(true) {
            warnings.push("secure-boot-not-measured".into());
        }
        Some(secure_boot == Some(true) && !windows.kernel_open())
    } else {
        warnings.push("os-not-measured".into());
        None
    };
    if windows.measured && windows.hvci != Some(true) {
        warnings.push("hvci-off".into());
    }

    let claims = Claims {
        platform: if windows.measured { "windows" } else { "pc" },
        key_storage: KeyStorage::Tpm,
        verified_boot,
        app_attested: false,
        session_key_in_hw: true,
        os_patch_level: None,
        hardware_identity: Some(ek_digest.to_vec()),
        boot: BootClaims {
            measured_boot: Some(measured_boot),
            vbs: windows.vbs,
            hvci: windows.hvci,
            iommu: windows.dma_protection,
        },
        app: None,
        warnings,
    };
    Ok((claims, activation))
}
