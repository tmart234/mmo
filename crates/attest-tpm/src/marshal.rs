//! TPM 2.0 marshalling (TPM 2.0 Part 2): big-endian integers and `TPM2B`
//! byte strings with a 16-bit length. The TCG event logs are little-endian
//! and have their own reader ([`crate::eventlog`]).

use crate::TpmError;

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8], what: &'static str) -> Self {
        Reader { input, what }
    }

    fn err(&self) -> TpmError {
        TpmError::Malformed(self.what)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], TpmError> {
        if self.input.len() < n {
            return Err(self.err());
        }
        let (head, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, TpmError> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, TpmError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, TpmError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, TpmError> {
        let b = self.bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// A `TPM2B_*`: a 16-bit size, then that many bytes.
    pub fn tpm2b(&mut self) -> Result<&'a [u8], TpmError> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }

    pub fn end(&self) -> Result<(), TpmError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(TpmError::Malformed(self.what))
        }
    }
}

/// `TPM2B` of `v` (panics past 64 KiB, which nothing here makes).
pub(crate) fn tpm2b(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + v.len());
    out.extend_from_slice(&u16::try_from(v.len()).expect("TPM2B size").to_be_bytes());
    out.extend_from_slice(v);
    out
}
