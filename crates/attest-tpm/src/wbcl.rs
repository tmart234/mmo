//! Windows' boot configuration in the measured-boot log (the Windows Boot
//! Configuration Log, WBCL): what the boot manager and the OS loader
//! measured about how Windows was started, as SIPA events (`wbcl.h` in the
//! Windows SDK).
//!
//! The loader logs them as `EV_EVENT_TAG` events, mostly into PCRs 12–14.
//! Each event's data is a list of `{u32 type, u32 size, data}` (little
//! endian); a type with the aggregation bit holds a nested list. Only
//! events in PCRs the quote covers, whose digest is the SHA-256 of their
//! data, are read: their content is then what the TPM saw.
//!
//! What a Verifier reads here: test-signing (unsigned kernel drivers),
//! the kernel debugger and boot debugging, code integrity, safe mode and
//! WinPE (all of which let a cheat run in the kernel), and the hypervisor
//! protections: VBS (the secure kernel launched) and HVCI (kernel code
//! integrity enforced by the hypervisor), and boot DMA protection (IOMMU).
//!
//! Not checked against a real Windows machine yet: the logs in the tests
//! follow `wbcl.h`. The first real Windows 11 log is the next check.

use crate::eventlog::BootLog;
use crate::public::hash;
use crate::{alg, TpmError};

/// `EV_EVENT_TAG`.
pub const EV_EVENT_TAG: u32 = 0x6;

/// SIPA event types (`wbcl.h`).
pub mod sipa {
    /// A type with this bit holds a nested list of events.
    pub const AGGREGATION: u32 = 0x4000_0000;
    pub const TRUSTBOUNDARY: u32 = 0x4001_0001;
    pub const BOOTDEBUGGING: u32 = 0x0004_0001;
    pub const OSKERNELDEBUG: u32 = 0x0005_0001;
    pub const CODEINTEGRITY: u32 = 0x0005_0002;
    pub const TESTSIGNING: u32 = 0x0005_0003;
    pub const SAFEMODE: u32 = 0x0005_0005;
    pub const WINPE: u32 = 0x0005_0006;
    pub const HYPERVISOR_LAUNCH_TYPE: u32 = 0x0005_000A;
    pub const HYPERVISOR_DEBUG: u32 = 0x0005_000D;
    pub const VSM_LAUNCH_TYPE: u32 = 0x0005_0012;
    pub const HYPERVISOR_BOOT_DMA_PROTECTION: u32 = 0x0005_0030;
    pub const VBS_HVCI_POLICY: u32 = 0x000A_0007;
}

/// What the log says about how Windows started. `None`: not measured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowsBoot {
    /// Any SIPA event at all (the Windows boot manager ran and measured).
    pub measured: bool,
    pub test_signing: Option<bool>,
    pub kernel_debug: Option<bool>,
    pub boot_debugging: Option<bool>,
    pub hypervisor_debug: Option<bool>,
    pub code_integrity: Option<bool>,
    pub safe_mode: Option<bool>,
    pub winpe: Option<bool>,
    /// The hypervisor was launched.
    pub hypervisor: Option<bool>,
    /// The secure kernel (VBS) was launched.
    pub vbs: Option<bool>,
    /// HVCI: the hypervisor enforces kernel code integrity.
    pub hvci: Option<bool>,
    /// Boot DMA protection (the IOMMU guards memory from devices).
    pub dma_protection: Option<bool>,
}

impl WindowsBoot {
    /// The kernel can run code Microsoft did not sign, or be driven by a
    /// debugger: a cheat can live in the kernel.
    pub fn kernel_open(&self) -> bool {
        [
            self.test_signing,
            self.kernel_debug,
            self.boot_debugging,
            self.hypervisor_debug,
            self.safe_mode,
            self.winpe,
        ]
        .contains(&Some(true))
            || self.code_integrity == Some(false)
    }
}

/// A flag measured more than once (a resume from hibernation measures
/// again): "on" if it was ever on, for flags that weaken the system...
fn any(slot: &mut Option<bool>, v: bool) {
    *slot = Some(slot.unwrap_or(false) || v);
}

/// ...and "on" only if it was always on, for protections.
fn all(slot: &mut Option<bool>, v: bool) {
    *slot = Some(slot.unwrap_or(true) && v);
}

/// A SIPA value: a BOOLEAN, or a little-endian integer; non-zero is on.
fn value(data: &[u8]) -> Result<bool, TpmError> {
    match data.len() {
        1 | 2 | 4 | 8 => Ok(data.iter().any(|b| *b != 0)),
        _ => Err(TpmError::Malformed("SIPA value size")),
    }
}

fn walk(data: &[u8], depth: u32, out: &mut WindowsBoot) -> Result<(), TpmError> {
    if depth > 4 {
        return Err(TpmError::Malformed("SIPA nesting"));
    }
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 8 {
            return Err(TpmError::Malformed("SIPA event header"));
        }
        let kind = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes"));
        let size = u32::from_le_bytes(rest[4..8].try_into().expect("4 bytes")) as usize;
        let body = rest
            .get(8..8 + size)
            .ok_or(TpmError::Malformed("SIPA event size"))?;
        rest = &rest[8 + size..];
        out.measured = true;
        if kind & sipa::AGGREGATION != 0 {
            walk(body, depth + 1, out)?;
            continue;
        }
        match kind {
            sipa::TESTSIGNING => any(&mut out.test_signing, value(body)?),
            sipa::OSKERNELDEBUG => any(&mut out.kernel_debug, value(body)?),
            sipa::BOOTDEBUGGING => any(&mut out.boot_debugging, value(body)?),
            sipa::HYPERVISOR_DEBUG => any(&mut out.hypervisor_debug, value(body)?),
            sipa::SAFEMODE => any(&mut out.safe_mode, value(body)?),
            sipa::WINPE => any(&mut out.winpe, value(body)?),
            sipa::CODEINTEGRITY => all(&mut out.code_integrity, value(body)?),
            sipa::HYPERVISOR_LAUNCH_TYPE => all(&mut out.hypervisor, value(body)?),
            sipa::VSM_LAUNCH_TYPE => all(&mut out.vbs, value(body)?),
            sipa::VBS_HVCI_POLICY => all(&mut out.hvci, value(body)?),
            sipa::HYPERVISOR_BOOT_DMA_PROTECTION => all(&mut out.dma_protection, value(body)?),
            _ => {}
        }
    }
    Ok(())
}

/// Windows' boot configuration from a replayed log, reading only events in
/// `quoted` PCRs (whose replay the caller matched against the quote).
pub fn windows_boot(log: &BootLog, quoted: &[u8]) -> Result<WindowsBoot, TpmError> {
    let mut out = WindowsBoot::default();
    for e in &log.events {
        if e.kind != EV_EVENT_TAG || !quoted.contains(&(e.pcr as u8)) {
            continue;
        }
        if hash(alg::SHA256, &e.data)? != e.sha256 {
            return Err(TpmError::Policy(
                "a SIPA event's data is not what was measured",
            ));
        }
        walk(&e.data, 0, &mut out)?;
    }
    Ok(out)
}

/// One SIPA event (for tests and tools).
pub fn sipa_event(kind: u32, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::{self, Event};

    fn log(events: &[(u32, Vec<u8>)]) -> BootLog {
        let events: Vec<Event> = events
            .iter()
            .map(|(pcr, data)| Event {
                pcr: *pcr,
                kind: EV_EVENT_TAG,
                sha256: hash(alg::SHA256, data).unwrap(),
                data: data.clone(),
            })
            .collect();
        eventlog::replay(&eventlog::encode(&events, None)).unwrap()
    }

    fn config(test_signing: bool, hvci: bool) -> Vec<u8> {
        let inner = [
            sipa_event(sipa::TESTSIGNING, &[test_signing as u8]),
            sipa_event(sipa::OSKERNELDEBUG, &[0]),
            sipa_event(sipa::CODEINTEGRITY, &[1]),
            sipa_event(sipa::VSM_LAUNCH_TYPE, &1u32.to_le_bytes()),
            sipa_event(sipa::VBS_HVCI_POLICY, &(hvci as u64).to_le_bytes()),
        ]
        .concat();
        sipa_event(sipa::TRUSTBOUNDARY, &inner)
    }

    #[test]
    fn reads_nested_configuration() {
        let w = windows_boot(&log(&[(12, config(false, true))]), &[12]).unwrap();
        assert!(w.measured);
        assert_eq!(w.test_signing, Some(false));
        assert_eq!(w.hvci, Some(true));
        assert_eq!(w.vbs, Some(true));
        assert!(!w.kernel_open());
        let w = windows_boot(&log(&[(12, config(true, false))]), &[12]).unwrap();
        assert!(w.kernel_open());
        assert_eq!(w.hvci, Some(false));
    }

    #[test]
    fn unquoted_pcrs_say_nothing() {
        let w = windows_boot(&log(&[(12, config(true, false))]), &[7]).unwrap();
        assert_eq!(w, WindowsBoot::default());
    }

    #[test]
    fn a_weakening_measured_once_counts() {
        // measured clean, then again after a resume with test-signing on
        let l = log(&[(12, config(false, true)), (12, config(true, true))]);
        assert_eq!(windows_boot(&l, &[12]).unwrap().test_signing, Some(true));
        // a protection must hold every time
        let l = log(&[(12, config(false, true)), (12, config(false, false))]);
        assert_eq!(windows_boot(&l, &[12]).unwrap().hvci, Some(false));
    }

    #[test]
    fn content_must_be_what_was_measured() {
        let mut l = log(&[(12, config(true, true))]);
        // the log claims test-signing off, the TPM saw it on
        l.events[0].data = config(false, true);
        assert!(windows_boot(&l, &[12]).is_err());
    }

    #[test]
    fn malformed_lists_are_refused() {
        let mut bad = config(false, true);
        bad.truncate(bad.len() - 1);
        assert!(windows_boot(&log(&[(12, bad)]), &[12]).is_err());
        let deep = (0..6).fold(sipa_event(sipa::TESTSIGNING, &[0]), |acc, _| {
            sipa_event(sipa::TRUSTBOUNDARY, &acc)
        });
        assert!(windows_boot(&log(&[(12, deep)]), &[12]).is_err());
        assert!(windows_boot(
            &log(&[(12, sipa_event(sipa::TESTSIGNING, &[0, 0, 0]))]),
            &[12]
        )
        .is_err());
    }
}
