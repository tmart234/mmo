//! The Linux Integrity Measurement Architecture's log
//! (`/sys/kernel/security/ima/binary_runtime_measurements`), replayed into
//! PCR 10.
//!
//! With an IMA policy that measures executables (`measure func=BPRM_CHECK`,
//! or `ima_policy=tcb`), the kernel hashes every program *before* running
//! it and extends PCR 10 with the record. That is how a game server's
//! binary is known without asking the binary (finding F06): the kernel
//! measured it, the TPM holds the result, and a quote proves the log.

use crate::public::hash;
use crate::{alg, TpmError};

pub const IMA_PCR: u8 = 10;

/// One measurement: a file's hash and path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub template: String,
    /// e.g. `sha256`.
    pub file_hash_alg: String,
    pub file_hash: Vec<u8>,
    pub path: String,
}

/// A replayed IMA log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImaLog {
    pub measurements: Vec<Measurement>,
    /// Records the kernel could not measure (a file changed while open,
    /// and the like): each extends all ones, and each is a reason for doubt.
    pub violations: usize,
    /// What PCR 10 must hold (SHA-256 bank).
    pub pcr10: Vec<u8>,
}

struct Le<'a>(&'a [u8]);

impl<'a> Le<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], TpmError> {
        if self.0.len() < n {
            return Err(TpmError::Malformed("IMA log"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, TpmError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn field(&mut self) -> Result<&'a [u8], TpmError> {
        let n = self.u32()? as usize;
        self.bytes(n)
    }
}

fn parse_template(template: &str, data: &[u8]) -> Result<(String, Vec<u8>, String), TpmError> {
    if template != "ima-ng"
        && template != "ima-sig"
        && template != "ima-ngv2"
        && template != "ima-sigv2"
    {
        return Err(TpmError::Unsupported(
            "IMA template (use ima-ng or ima-sig)",
        ));
    }
    let mut r = Le(data);
    let digest = r.field()?;
    // "d-ng": "<alg>:\0<digest>"; "d-ngv2" adds a type: "<type>:<alg>:\0<digest>"
    let colon = digest
        .iter()
        .rposition(|b| *b == b':')
        .ok_or(TpmError::Malformed("IMA digest field"))?;
    if digest.get(colon + 1) != Some(&0) {
        return Err(TpmError::Malformed("IMA digest field"));
    }
    let prefix = std::str::from_utf8(&digest[..colon])
        .map_err(|_| TpmError::Malformed("IMA digest algorithm"))?;
    let alg_name = prefix.rsplit(':').next().unwrap_or(prefix).to_string();
    let file_hash = digest[colon + 2..].to_vec();
    let name = r.field()?;
    let path = String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned();
    Ok((alg_name, file_hash, path))
}

/// Parse and replay a binary IMA log (the measuring host's byte order:
/// little-endian, as on x86 and ARM).
pub fn replay(log: &[u8]) -> Result<ImaLog, TpmError> {
    let mut r = Le(log);
    let mut pcr10 = vec![0u8; 32];
    let mut measurements = Vec::new();
    let mut violations = 0;
    while !r.0.is_empty() {
        let pcr = r.u32()?;
        let template_digest = r.bytes(20)?;
        let name = r.field()?;
        if name.len() > 255 {
            return Err(TpmError::Malformed("IMA template name"));
        }
        let template = String::from_utf8_lossy(name).into_owned();
        let data = r.field()?;
        if pcr != IMA_PCR as u32 {
            return Err(TpmError::Unsupported("IMA records outside PCR 10"));
        }
        // (a violation's digest is zeros, and the kernel extends ones)
        let extend = if template_digest.iter().all(|b| *b == 0) {
            violations += 1;
            vec![0xffu8; 32]
        } else {
            hash(alg::SHA256, data)?
        };
        let mut input = pcr10.clone();
        input.extend_from_slice(&extend);
        pcr10 = hash(alg::SHA256, &input)?;
        if template_digest.iter().all(|b| *b == 0) {
            continue;
        }
        let (file_hash_alg, file_hash, path) = parse_template(&template, data)?;
        measurements.push(Measurement {
            template,
            file_hash_alg,
            file_hash,
            path,
        });
    }
    Ok(ImaLog {
        measurements,
        violations,
        pcr10,
    })
}

/// An `ima-ng` template's data and its record (for tests and tools):
/// returns (record bytes, what PCR 10's SHA-256 bank is extended with).
pub fn ima_ng_record(file_sha256: &[u8], path: &str) -> (Vec<u8>, Vec<u8>) {
    let mut digest = b"sha256:\0".to_vec();
    digest.extend_from_slice(file_sha256);
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    let mut data = Vec::new();
    data.extend_from_slice(&(digest.len() as u32).to_le_bytes());
    data.extend(digest);
    data.extend_from_slice(&(name.len() as u32).to_le_bytes());
    data.extend(name);
    let sha1 = hash(alg::SHA1, &data).expect("sha1");
    let mut record = (IMA_PCR as u32).to_le_bytes().to_vec();
    record.extend(sha1);
    record.extend_from_slice(&6u32.to_le_bytes());
    record.extend_from_slice(b"ima-ng");
    record.extend_from_slice(&(data.len() as u32).to_le_bytes());
    record.extend_from_slice(&data);
    (record, hash(alg::SHA256, &data).expect("sha256"))
}
