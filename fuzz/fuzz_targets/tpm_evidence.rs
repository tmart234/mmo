//! TPM evidence parsers and appraisal (`fpp_attest::tpm`) on untrusted input: never panic.
#![no_main]

use fpp_attest::tpm::quote::{Attest, Signature};
use fpp_attest::tpm::{
    appraise, certify, eventlog, ima, wbcl, Evidence, Pcrs, Policy, Public, Registry,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => {
            let _ = Public::from_tpm2b(body);
        }
        1 => {
            let _ = Attest::parse(body);
            let _ = Signature::parse(body);
        }
        2 => {
            if let Ok(log) = eventlog::replay(body) {
                let _ = log.secure_boot();
            }
        }
        3 => {
            let _ = ima::replay(body);
        }
        4 => {
            if let Ok(log) = eventlog::replay(body) {
                let _ = wbcl::windows_boot(&log, &[7, 12, 13, 14]);
            }
        }
        5 => {
            let _ = certify::Certification::parse(body);
            let parts: Vec<&[u8]> = body.splitn(4, |b| *b == 0xa5).collect();
            if let [key, attest, signature, session] = parts.as_slice() {
                if let Ok(ak) = Public::from_tpm2b(key) {
                    let _ = certify::verify_session_key(&ak, attest, signature, session);
                }
            }
            let _ = fpp::tokens::evidence::Evidence::decode(body);
        }
        _ => {
            let parts: Vec<&[u8]> = body.splitn(5, |b| *b == 0xa5).collect();
            let [key, attest, signature, boot, measurements] = parts.as_slice() else {
                return;
            };
            let Ok(ak) = Public::from_tpm2b(key) else {
                return;
            };
            let registry = Registry::default();
            let policy = Policy {
                registry: &registry,
                program: Some("/opt/fpp/gs"),
                require_secure_boot: true,
                allow_ima_violations: false,
            };
            let mut pcrs = Pcrs::new();
            pcrs.insert(10, vec![0; 32]);
            let evidence = Evidence {
                attest: attest.to_vec(),
                signature: signature.to_vec(),
                pcrs,
                boot_log: Some(boot.to_vec()),
                ima_log: Some(measurements.to_vec()),
            };
            let _ = appraise(&ak, &evidence, &[0u8; 32], &policy);
        }
    }
});
