//! TPM evidence parsers and appraisal (attest-tpm) consume what a machine
//! sends: never panic.
#![no_main]

use attest_tpm::quote::{Attest, Signature};
use attest_tpm::{appraise, eventlog, ima, Evidence, Pcrs, Policy, Public, Registry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 5 {
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
        _ => {
            // a whole appraisal: key, quote, signature and logs cut from the input
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
