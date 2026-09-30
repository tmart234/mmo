//! Appraisal of a TPM-equipped machine: a verified quote, the logs it
//! vouches for, and a policy.
//!
//! This is where a game server stops vouching for itself (finding F06).
//! The old `sw_hash` was the binary's hash *of itself*: a modified binary
//! reports the hash of the unmodified one. Here the program's hash comes
//! from the kernel's IMA log, which the kernel wrote before the program
//! ran, whose replay must match the quoted PCR 10, and it must be listed in
//! the Build Registry: the hashes of builds CI made from reviewed source
//! and published with signed provenance.

use std::collections::BTreeMap;

use crate::eventlog;
use crate::ima::{self, Measurement, IMA_PCR};
use crate::public::Public;
use crate::quote::{verify_quote, Pcrs, Quote};
use crate::{alg, TpmError};

/// The builds a Verifier accepts: SHA-256 of a program to a label (its
/// version, and where its provenance is).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pub builds: BTreeMap<Vec<u8>, String>,
}

impl Registry {
    /// `sha256sum` output (`<hex>  <label>`), one build per line; `#`
    /// starts a comment.
    pub fn parse(text: &str) -> Result<Self, TpmError> {
        let mut builds = BTreeMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (hash, label) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let hash = decode_hex(hash).ok_or(TpmError::Malformed("registry hash"))?;
            if hash.len() != 32 {
                return Err(TpmError::Malformed("registry hash"));
            }
            builds.insert(hash, label.trim().trim_start_matches('*').to_string());
        }
        Ok(Registry { builds })
    }

    pub fn label(&self, sha256: &[u8]) -> Option<&str> {
        self.builds.get(sha256).map(String::as_str)
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// What the machine sends (beside its enrolled AK).
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    /// `TPMS_ATTEST` and `TPMT_SIGNATURE`, as the TPM gave them.
    pub attest: Vec<u8>,
    pub signature: Vec<u8>,
    /// The quoted PCRs' values (SHA-256 bank).
    pub pcrs: Pcrs,
    /// `binary_bios_measurements`, if the machine booted with UEFI.
    pub boot_log: Option<Vec<u8>>,
    /// `binary_runtime_measurements`.
    pub ima_log: Option<Vec<u8>>,
}

/// What the Verifier requires.
#[derive(Clone, Debug)]
pub struct Policy<'a> {
    pub registry: &'a Registry,
    /// The program whose build must be in the registry (its path as the
    /// kernel saw it), e.g. `/opt/fpp/gs`. `None`: no program check.
    pub program: Option<&'a str>,
    /// Require the boot log's `SecureBoot` to be on.
    pub require_secure_boot: bool,
    /// Accept IMA violations (files changed while measured). Off: any
    /// violation fails appraisal.
    pub allow_ima_violations: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appraisal {
    pub quote: Quote,
    /// Secure Boot as measured, `None` without a boot log (or no event).
    pub secure_boot: Option<bool>,
    /// The program's measured hash and its registry label.
    pub program: Option<(Vec<u8>, String)>,
    /// Everything IMA measured, for the record.
    pub measurements: Vec<Measurement>,
}

/// Appraise `evidence` for the nonce, with the machine's enrolled AK.
pub fn appraise(
    ak: &Public,
    evidence: &Evidence,
    nonce: &[u8],
    policy: &Policy<'_>,
) -> Result<Appraisal, TpmError> {
    let quote = verify_quote(
        ak,
        &evidence.attest,
        &evidence.signature,
        nonce,
        &evidence.pcrs,
    )?;
    if quote.hash_alg != alg::SHA256 {
        return Err(TpmError::Unsupported("PCR bank other than SHA-256"));
    }
    let mut secure_boot = None;
    if let Some(log) = &evidence.boot_log {
        let boot = eventlog::replay(log)?;
        for (index, value) in &boot.pcrs {
            match quote.pcrs.get(index) {
                Some(quoted) if quoted == value => {}
                Some(_) => {
                    return Err(TpmError::Policy(
                        "boot log does not replay to the quoted PCRs",
                    ))
                }
                // (a PCR the quote leaves out is claimed by nothing)
                None => {}
            }
        }
        if quote.pcrs.contains_key(&7) && boot.pcrs.contains_key(&7) {
            secure_boot = boot.secure_boot()?;
        }
    }
    if policy.require_secure_boot && secure_boot != Some(true) {
        return Err(TpmError::Policy("Secure Boot is not measured as on"));
    }
    let mut measurements = Vec::new();
    let mut program = None;
    if let Some(log) = &evidence.ima_log {
        let log = ima::replay(log)?;
        match quote.pcrs.get(&IMA_PCR) {
            Some(quoted) if *quoted == log.pcr10 => {}
            Some(_) => {
                return Err(TpmError::Policy(
                    "IMA log does not replay to the quoted PCR 10",
                ))
            }
            None => return Err(TpmError::Policy("the quote does not cover PCR 10")),
        }
        if log.violations > 0 && !policy.allow_ima_violations {
            return Err(TpmError::Policy("IMA recorded violations"));
        }
        measurements = log.measurements;
    }
    if let Some(path) = policy.program {
        if evidence.ima_log.is_none() {
            return Err(TpmError::Policy(
                "no IMA log: the program's build is unknown",
            ));
        }
        // every measurement of the program (a replaced file is measured
        // again) must be a registered build
        for m in measurements.iter().filter(|m| m.path == path) {
            if m.file_hash_alg != "sha256" {
                return Err(TpmError::Policy(
                    "program measured without SHA-256 (ima_hash=sha256)",
                ));
            }
            let label = policy
                .registry
                .label(&m.file_hash)
                .ok_or(TpmError::Policy("the program is not a registered build"))?;
            program = Some((m.file_hash.clone(), label.to_string()));
        }
        if program.is_none() {
            return Err(TpmError::Policy("the program was never measured"));
        }
    }
    Ok(Appraisal {
        quote,
        secure_boot,
        program,
        measurements,
    })
}
