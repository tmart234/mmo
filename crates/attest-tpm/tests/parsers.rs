//! The parsers on their own (no TPM): logs, the registry, and malformed
//! input, which must be refused, never panic.

use attest_tpm::eventlog::{self, Event, EV_SEPARATOR};
use attest_tpm::ima::{self, ima_ng_record};
use attest_tpm::public::hash;
use attest_tpm::quote::{Attest, Signature};
use attest_tpm::{alg, Public, Registry};

fn extend(pcr: &[u8], digest: &[u8]) -> Vec<u8> {
    hash(alg::SHA256, &[pcr, digest].concat()).unwrap()
}

#[test]
fn boot_log_replays_with_startup_locality() {
    let data = vec![0u8; 4];
    let sep = Event {
        pcr: 0,
        kind: EV_SEPARATOR,
        sha256: hash(alg::SHA256, &data).unwrap(),
        data,
    };
    let log = eventlog::encode(std::slice::from_ref(&sep), Some(3));
    let boot = eventlog::replay(&log).unwrap();
    let mut start = vec![0u8; 32];
    start[31] = 3;
    assert_eq!(boot.pcrs[&0], extend(&start, &sep.sha256));
    assert_eq!(boot.secure_boot().unwrap(), None);
}

#[test]
fn ima_violation_extends_ones() {
    let (mut record, _) = ima_ng_record(&[1u8; 32], "/tmp/x");
    // (a violation: zero template digest)
    record[4..24].fill(0);
    let log = ima::replay(&record).unwrap();
    assert_eq!(log.violations, 1);
    assert!(log.measurements.is_empty());
    assert_eq!(log.pcr10, extend(&[0u8; 32], &[0xff; 32]));

    let (good, digest) = ima_ng_record(&[2u8; 32], "/opt/fpp/gs");
    let log = ima::replay(&good).unwrap();
    assert_eq!(log.pcr10, extend(&[0u8; 32], &digest));
    assert_eq!(log.measurements[0].path, "/opt/fpp/gs");
    assert_eq!(log.measurements[0].file_hash, vec![2u8; 32]);
    assert_eq!(log.measurements[0].file_hash_alg, "sha256");
}

#[test]
fn registry_is_sha256sum_output() {
    let h = hex::encode([0xabu8; 32]);
    let r = Registry::parse(&format!("# builds\n{h} *gs-linux-x86_64  # v1\n\n")).unwrap();
    assert_eq!(r.label(&[0xab; 32]), Some("gs-linux-x86_64"));
    assert!(Registry::parse("abc  short").is_err());
    assert!(Registry::parse("zz  x").is_err());
}

#[test]
fn truncated_input_is_refused_not_a_panic() {
    let (record, _) = ima_ng_record(&[3u8; 32], "/opt/fpp/gs");
    let boot = eventlog::encode(&[], Some(0));
    for n in 0..record.len() {
        let _ = ima::replay(&record[..n]);
    }
    for n in 0..boot.len() {
        let _ = eventlog::replay(&boot[..n]);
    }
    // arbitrary bytes into every TPM structure parser
    let mut seed = 1u32;
    for len in 0..300 {
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (seed >> 16) as u8
            })
            .collect();
        let _ = Public::from_tpm2b(&bytes);
        let _ = Public::from_tpmt(&bytes);
        let _ = Attest::parse(&bytes);
        let _ = Signature::parse(&bytes);
        let _ = eventlog::replay(&bytes);
        let _ = ima::replay(&bytes);
    }
}
