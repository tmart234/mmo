//! A PC's TPM 2.0 evidence (roadmap P3; 03 §4.2 D2 "TPM 2.0 EK chain +
//! measured boot + Secure Boot"), on `attest-tpm`:
//!
//! 1. the EK certificate chains to a TPM manufacturer root this Verifier
//!    pins (a software TPM's does not), and certifies the EK presented;
//! 2. the quote verifies with the AK, over `attest_challenge(challenge,
//!    session_pub)`: this admission, this session key (a replayed quote
//!    names another challenge);
//! 3. the measured-boot log replays to every quoted PCR, including the
//!    ones it does not touch (an omitted event would leave its PCR
//!    unexplained); Secure Boot from PCR 7, and Windows' boot configuration
//!    (test-signing, debuggers, code integrity, VBS, HVCI, boot DMA
//!    protection) from the SIPA events in PCRs 12–14 ([`attest_tpm::wbcl`]);
//! 4. the session key is a P-256 key the TPM made and keeps, certified by
//!    the AK, and it is the key the AR will be bound to;
//! 5. credential activation (a second round trip): a secret encrypted to
//!    the EK for the AK's Name, which only that TPM opens. Until then the
//!    AK, and so steps 2–4, could be anyone's.

use attest_core::{AttestError, BootClaims, Claims, KeyStorage};
use attest_tpm::certify::verify_session_key;
use attest_tpm::{appraise, eventlog, make_credential, verify_ek, wbcl, Evidence, Policy, Public};
use fpp_tokens::evidence::{attest_challenge, TpmEvidence};
use rand::{rngs::OsRng, RngCore};

/// PCRs a PC's quote must cover: Secure Boot's policy (7) and Windows' boot
/// configuration (12–14). Each must be explained by the log.
pub const REQUIRED_PCRS: [u8; 4] = [7, 12, 13, 14];

/// The second round trip: what the client's TPM must open.
pub struct Activation {
    pub id_object: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
    pub secret: Vec<u8>,
}

impl Activation {
    /// Whether `answer` is the secret (constant time).
    pub fn opened(&self, answer: &[u8]) -> bool {
        self.secret.len() == answer.len()
            && self
                .secret
                .iter()
                .zip(answer)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

fn tpm_err(what: &'static str) -> impl Fn(attest_tpm::TpmError) -> AttestError {
    move |e| {
        eprintln!("[verifier] TPM evidence: {what}: {e}");
        match e {
            attest_tpm::TpmError::Certificate(c) => c,
            attest_tpm::TpmError::NonceMismatch => AttestError::ChallengeMismatch,
            attest_tpm::TpmError::BadSignature => AttestError::BadSignature(what),
            attest_tpm::TpmError::Malformed(m) => AttestError::Malformed(m),
            attest_tpm::TpmError::Policy(p) => AttestError::Policy(p),
            _ => AttestError::Policy(what),
        }
    }
}

/// Steps 1–4, and the credential for step 5.
pub fn appraise_tpm(
    ek_roots: &[Vec<u8>],
    t: &TpmEvidence,
    verifier_challenge: &[u8; 32],
    session_pub: &[u8],
    now_unix: i64,
) -> Result<(Claims, Activation), AttestError> {
    if ek_roots.is_empty() {
        return Err(AttestError::Policy(
            "no TPM manufacturer roots on this Verifier",
        ));
    }
    let ek = Public::from_tpm2b(&t.ek_public).map_err(tpm_err("EK public area"))?;
    let endorsement =
        verify_ek(&ek, &t.ek_chain, ek_roots, Some(now_unix)).map_err(tpm_err("EK certificate"))?;
    let ak = Public::from_tpm2b(&t.ak_public).map_err(tpm_err("AK public area"))?;

    let boot_log = (!t.boot_log.is_empty()).then(|| t.boot_log.clone());
    let pcrs = t.pcrs.iter().cloned().collect();
    let registry = attest_tpm::Registry::default();
    let appraisal = appraise(
        &ak,
        &Evidence {
            attest: t.quote.clone(),
            signature: t.quote_signature.clone(),
            pcrs,
            boot_log: boot_log.clone(),
            ima_log: None,
        },
        &attest_challenge(verifier_challenge, session_pub),
        &Policy {
            registry: &registry,
            program: None,
            require_secure_boot: false,
            allow_ima_violations: false,
        },
    )
    .map_err(tpm_err("quote"))?;

    let mut warnings = Vec::new();
    let mut windows = wbcl::WindowsBoot::default();
    let measured_boot = match &boot_log {
        Some(log) => {
            let log = eventlog::replay(log).map_err(tpm_err("boot log"))?;
            for pcr in REQUIRED_PCRS {
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
            windows = wbcl::windows_boot(&log, &REQUIRED_PCRS).map_err(tpm_err("SIPA events"))?;
            true
        }
        None => {
            warnings.push("no-boot-log".to_string());
            false
        }
    };

    let session = verify_session_key(&ak, &t.certify, &t.certify_signature, &t.session_public)
        .map_err(tpm_err("session key certification"))?;
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
        // (a TPM, but no OS whose boot we can read: Linux and others)
        warnings.push("os-not-measured".into());
        None
    };
    if windows.measured && windows.hvci != Some(true) {
        warnings.push("hvci-off".into());
    }

    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let name = ak.name().map_err(tpm_err("AK name"))?;
    let credential = make_credential(&ek, &name, &secret).map_err(tpm_err("credential"))?;
    let claims = Claims {
        platform: if windows.measured { "windows" } else { "pc" },
        key_storage: KeyStorage::Tpm,
        verified_boot,
        app_attested: false,
        session_key_in_hw: true,
        os_patch_level: None,
        hardware_identity: Some(endorsement.ek_digest.to_vec()),
        boot: BootClaims {
            measured_boot: Some(measured_boot),
            vbs: windows.vbs,
            hvci: windows.hvci,
            iommu: windows.dma_protection,
        },
        // (Windows does not measure the game: the build is self-reported)
        app: None,
        warnings,
    };
    Ok((
        claims,
        Activation {
            id_object: credential.id_object,
            encrypted_secret: credential.encrypted_secret,
            secret,
        },
    ))
}
