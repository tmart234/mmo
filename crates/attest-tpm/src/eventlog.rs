//! The TCG measured-boot event log (PC Client Platform Firmware Profile,
//! "crypto agile" format: a `Spec ID Event03` header, then
//! `TCG_PCR_EVENT2` records), replayed into PCR values.
//!
//! PCR values alone say little (every firmware update changes them). The
//! log says what was measured; replaying it and matching the quoted PCRs
//! proves the log is the one the TPM saw, and then its events can be
//! appraised: here, Secure Boot's state from PCR 7.

use std::collections::BTreeMap;

use crate::public::hash;
use crate::{alg, TpmError};

pub const EV_NO_ACTION: u32 = 0x3;
pub const EV_SEPARATOR: u32 = 0x4;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00e0;

/// `EFI_GLOBAL_VARIABLE`, the vendor GUID of `SecureBoot`, as stored.
pub const EFI_GLOBAL_VARIABLE: [u8; 16] = [
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
];

struct Le<'a>(&'a [u8]);

impl<'a> Le<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], TpmError> {
        if self.0.len() < n {
            return Err(TpmError::Malformed("event log"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16, TpmError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, TpmError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, TpmError> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}

/// One measured event (its SHA-256 digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub pcr: u32,
    pub kind: u32,
    pub sha256: Vec<u8>,
    pub data: Vec<u8>,
}

/// A replayed log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootLog {
    pub events: Vec<Event>,
    /// What each PCR the log touches must hold (SHA-256 bank).
    pub pcrs: BTreeMap<u8, Vec<u8>>,
}

/// Parse and replay a crypto-agile log (`/sys/kernel/security/tpm0/
/// binary_bios_measurements`) into the SHA-256 bank.
pub fn replay(log: &[u8]) -> Result<BootLog, TpmError> {
    let mut r = Le(log);
    // the header: a SHA-1-format event carrying the Spec ID
    let _pcr = r.u32()?;
    if r.u32()? != EV_NO_ACTION {
        return Err(TpmError::Malformed("event log header"));
    }
    r.bytes(20)?;
    let size = r.u32()? as usize;
    let mut spec = Le(r.bytes(size)?);
    if spec.bytes(16)? != b"Spec ID Event03\0" {
        return Err(TpmError::Unsupported("event log format (not crypto agile)"));
    }
    spec.bytes(4 + 4)?;
    let count = spec.u32()?;
    if count > 8 {
        return Err(TpmError::Malformed("event log algorithms"));
    }
    let mut sizes = BTreeMap::new();
    for _ in 0..count {
        let a = spec.u16()?;
        let s = spec.u16()?;
        sizes.insert(a, s as usize);
    }
    if !sizes.contains_key(&alg::SHA256) {
        return Err(TpmError::Unsupported("event log without SHA-256"));
    }
    let mut pcrs: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut events = Vec::new();
    while !r.0.is_empty() {
        let pcr = r.u32()?;
        let kind = r.u32()?;
        let digests = r.u32()?;
        if digests as usize > sizes.len() {
            return Err(TpmError::Malformed("event digests"));
        }
        let mut sha256 = None;
        for _ in 0..digests {
            let a = r.u16()?;
            let s = *sizes
                .get(&a)
                .ok_or(TpmError::Malformed("event digest algorithm"))?;
            let d = r.bytes(s)?;
            if a == alg::SHA256 {
                sha256 = Some(d.to_vec());
            }
        }
        let size = r.u32()? as usize;
        let data = r.bytes(size)?.to_vec();
        if pcr > 23 {
            return Err(TpmError::Malformed("event PCR"));
        }
        if kind == EV_NO_ACTION {
            // (not extended; one sets PCR 0's starting value: the locality
            // the firmware started in)
            if pcr == 0 && data.len() == 17 && data.starts_with(b"StartupLocality\0") {
                let mut start = vec![0u8; 32];
                start[31] = data[16];
                pcrs.insert(0, start);
            }
            continue;
        }
        let sha256 = sha256.ok_or(TpmError::Malformed("event without a SHA-256 digest"))?;
        let value = pcrs.entry(pcr as u8).or_insert_with(|| vec![0u8; 32]);
        let mut input = value.clone();
        input.extend_from_slice(&sha256);
        *value = hash(alg::SHA256, &input)?;
        events.push(Event {
            pcr,
            kind,
            sha256,
            data,
        });
    }
    Ok(BootLog { events, pcrs })
}

/// A UEFI variable event's (vendor GUID, name, data).
pub fn variable(event: &Event) -> Result<([u8; 16], String, &[u8]), TpmError> {
    let mut r = Le(&event.data);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(r.bytes(16)?);
    let name_len = r.u64()? as usize;
    let data_len = r.u64()? as usize;
    if name_len > 256 {
        return Err(TpmError::Malformed("variable name"));
    }
    let name: Vec<u16> = (0..name_len).map(|_| r.u16()).collect::<Result<_, _>>()?;
    let data = r.bytes(data_len)?;
    Ok((guid, String::from_utf16_lossy(&name), data))
}

impl BootLog {
    /// Secure Boot's state as the firmware measured it into PCR 7: the
    /// `SecureBoot` variable's value, `None` if the log never measured it.
    /// The event's digest must be the SHA-256 of its data, or its content
    /// is not what the TPM saw.
    pub fn secure_boot(&self) -> Result<Option<bool>, TpmError> {
        for e in &self.events {
            if e.pcr != 7 || e.kind != EV_EFI_VARIABLE_DRIVER_CONFIG {
                continue;
            }
            let (guid, name, data) = variable(e)?;
            if guid != EFI_GLOBAL_VARIABLE || name != "SecureBoot" {
                continue;
            }
            if hash(alg::SHA256, &e.data)? != e.sha256 {
                return Err(TpmError::Policy(
                    "SecureBoot event's data is not what was measured",
                ));
            }
            return Ok(Some(data == [1]));
        }
        Ok(None)
    }
}

/// Encode a crypto-agile log (SHA-256 only): for tests and tools.
pub fn encode(events: &[Event], startup_locality: Option<u8>) -> Vec<u8> {
    let mut spec = b"Spec ID Event03\0".to_vec();
    spec.extend_from_slice(&0u32.to_le_bytes()); // platform class
    spec.extend_from_slice(&[0, 2, 0, 2]); // version 2.0, errata 0, uintn 8 bytes
    spec.extend_from_slice(&1u32.to_le_bytes());
    spec.extend_from_slice(&alg::SHA256.to_le_bytes());
    spec.extend_from_slice(&32u16.to_le_bytes());
    spec.push(0); // no vendor info
    let mut out = Vec::new();
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
    out.extend_from_slice(&[0u8; 20]);
    out.extend_from_slice(&(spec.len() as u32).to_le_bytes());
    out.extend(spec);
    let mut record = |pcr: u32, kind: u32, digest: &[u8], data: &[u8]| {
        out.extend_from_slice(&pcr.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&alg::SHA256.to_le_bytes());
        out.extend_from_slice(digest);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    };
    if let Some(locality) = startup_locality {
        let mut data = b"StartupLocality\0".to_vec();
        data.push(locality);
        record(0, EV_NO_ACTION, &[0u8; 32], &data);
    }
    for e in events {
        record(e.pcr, e.kind, &e.sha256, &e.data);
    }
    out
}

/// A `UEFI_VARIABLE_DATA` (for tests and tools).
pub fn variable_data(guid: [u8; 16], name: &str, data: &[u8]) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let mut out = guid.to_vec();
    out.extend_from_slice(&(name.len() as u64).to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    for c in name {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}
