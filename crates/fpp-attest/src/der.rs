//! A small strict DER reader for platform extensions (the Android
//! KeyDescription, the App Attest nonce). Definite lengths only, shortest
//! length forms, and every length checked against the bytes present.

use crate::AttestError;

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_CONTEXT: u8 = 2;

pub const TAG_BOOLEAN: u32 = 1;
pub const TAG_INTEGER: u32 = 2;
pub const TAG_OCTET_STRING: u32 = 4;
pub const TAG_ENUMERATED: u32 = 10;
pub const TAG_SEQUENCE: u32 = 16;
pub const TAG_SET: u32 = 17;

const MAX_TAG: u32 = 1 << 21;

fn err(what: &'static str) -> AttestError {
    AttestError::Malformed(what)
}

/// One DER element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn is(&self, class: u8, tag: u32) -> bool {
        self.class == class && self.tag == tag
    }

    fn expect(&self, tag: u32, what: &'static str) -> Result<&'a [u8], AttestError> {
        if self.is(CLASS_UNIVERSAL, tag) {
            Ok(self.value)
        } else {
            Err(err(what))
        }
    }

    /// The elements of a SEQUENCE or SET.
    pub fn children(&self, tag: u32, what: &'static str) -> Result<Vec<Tlv<'a>>, AttestError> {
        if !self.constructed {
            return Err(err(what));
        }
        read_all(self.expect(tag, what)?)
    }

    pub fn octets(&self, what: &'static str) -> Result<&'a [u8], AttestError> {
        self.expect(TAG_OCTET_STRING, what)
    }

    pub fn boolean(&self, what: &'static str) -> Result<bool, AttestError> {
        match self.expect(TAG_BOOLEAN, what)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(err(what)),
        }
    }

    /// A non-negative INTEGER or ENUMERATED that fits in 64 bits.
    pub fn uint(&self, what: &'static str) -> Result<u64, AttestError> {
        let v = if self.is(CLASS_UNIVERSAL, TAG_INTEGER) || self.is(CLASS_UNIVERSAL, TAG_ENUMERATED)
        {
            self.value
        } else {
            return Err(err(what));
        };
        match v {
            [] => Err(err(what)),
            [b, ..] if b & 0x80 != 0 => Err(err(what)),
            [0, next, ..] if next & 0x80 == 0 => Err(err(what)),
            _ => {
                let v = if v[0] == 0 { &v[1..] } else { v };
                if v.len() > 8 {
                    return Err(err(what));
                }
                Ok(v.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
            }
        }
    }

    /// The single element inside an EXPLICIT context tag.
    pub fn explicit(&self, what: &'static str) -> Result<Tlv<'a>, AttestError> {
        if !self.constructed || self.class != CLASS_CONTEXT {
            return Err(err(what));
        }
        let (inner, rest) = read(self.value)?;
        if !rest.is_empty() {
            return Err(err(what));
        }
        Ok(inner)
    }
}

/// Read one element; returns it and the bytes after it.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), AttestError> {
    let (&first, mut rest) = input.split_first().ok_or(err("truncated"))?;
    let class = first >> 6;
    let constructed = first & 0x20 != 0;
    let mut tag = (first & 0x1f) as u32;
    if tag == 0x1f {
        // High-tag-number form: base-128, no leading zero groups, and only
        // for tags that do not fit the short form.
        tag = 0;
        let mut first_group = true;
        loop {
            let (&b, r) = rest.split_first().ok_or(err("truncated tag"))?;
            rest = r;
            if first_group && b == 0x80 {
                return Err(err("tag padding"));
            }
            first_group = false;
            tag = (tag << 7) | (b & 0x7f) as u32;
            if tag >= MAX_TAG {
                return Err(err("tag too large"));
            }
            if b & 0x80 == 0 {
                break;
            }
        }
        if tag < 0x1f {
            return Err(err("tag form"));
        }
    }
    let (&l0, r) = rest.split_first().ok_or(err("truncated length"))?;
    rest = r;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return Err(err("length form"));
        }
        let (bytes, r) = rest.split_at(n);
        rest = r;
        if bytes[0] == 0 {
            return Err(err("length padding"));
        }
        let len = bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize);
        if len < 0x80 {
            return Err(err("length form"));
        }
        len
    };
    if len > rest.len() {
        return Err(err("truncated value"));
    }
    let (value, rest) = rest.split_at(len);
    Ok((
        Tlv {
            class,
            constructed,
            tag,
            value,
        },
        rest,
    ))
}

/// Read a whole buffer as a sequence of elements.
pub fn read_all(mut input: &[u8]) -> Result<Vec<Tlv<'_>>, AttestError> {
    let mut out = Vec::new();
    while !input.is_empty() {
        if out.len() >= 512 {
            return Err(err("too many elements"));
        }
        let (tlv, rest) = read(input)?;
        out.push(tlv);
        input = rest;
    }
    Ok(out)
}

/// Read exactly one element occupying all of `input`.
pub fn read_one(input: &[u8]) -> Result<Tlv<'_>, AttestError> {
    let (tlv, rest) = read(input)?;
    if !rest.is_empty() {
        return Err(err("trailing bytes"));
    }
    Ok(tlv)
}

/// A minimal DER writer, for tests and fixtures.
pub mod write {
    fn len(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else {
            let b = (n as u32).to_be_bytes();
            let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
            let mut out = vec![0x80 | b.len() as u8];
            out.extend(b);
            out
        }
    }

    fn identifier(class: u8, constructed: bool, tag: u32) -> Vec<u8> {
        let first = (class << 6) | if constructed { 0x20 } else { 0 };
        if tag < 0x1f {
            return vec![first | tag as u8];
        }
        let mut groups = vec![(tag & 0x7f) as u8];
        let mut t = tag >> 7;
        while t > 0 {
            groups.push(0x80 | (t & 0x7f) as u8);
            t >>= 7;
        }
        groups.reverse();
        let mut out = vec![first | 0x1f];
        out.extend(groups);
        out
    }

    pub fn tlv(class: u8, constructed: bool, tag: u32, value: &[u8]) -> Vec<u8> {
        let mut out = identifier(class, constructed, tag);
        out.extend(len(value.len()));
        out.extend_from_slice(value);
        out
    }

    pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0, true, super::TAG_SEQUENCE, &items.concat())
    }

    pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
        tlv(0, true, super::TAG_SET, &items.concat())
    }

    pub fn octets(v: &[u8]) -> Vec<u8> {
        tlv(0, false, super::TAG_OCTET_STRING, v)
    }

    pub fn boolean(v: bool) -> Vec<u8> {
        tlv(0, false, super::TAG_BOOLEAN, &[if v { 0xff } else { 0 }])
    }

    fn uint_bytes(v: u64) -> Vec<u8> {
        let mut b: Vec<u8> = v
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|x| *x == 0)
            .collect();
        if b.is_empty() || b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        b
    }

    pub fn int(v: u64) -> Vec<u8> {
        tlv(0, false, super::TAG_INTEGER, &uint_bytes(v))
    }

    pub fn enumerated(v: u64) -> Vec<u8> {
        tlv(0, false, super::TAG_ENUMERATED, &uint_bytes(v))
    }

    pub fn explicit(tag: u32, inner: &[u8]) -> Vec<u8> {
        tlv(2, true, tag, inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_high_tags_and_long_lengths() {
        let big = vec![7u8; 300];
        let enc = write::seq(&[
            write::explicit(704, &write::octets(&big)),
            write::int(202609),
        ]);
        let top = read_one(&enc).unwrap();
        let items = top.children(TAG_SEQUENCE, "seq").unwrap();
        assert!(items[0].is(CLASS_CONTEXT, 704));
        assert_eq!(
            items[0].explicit("rot").unwrap().octets("o").unwrap(),
            &big[..]
        );
        assert_eq!(items[1].uint("i").unwrap(), 202609);
    }

    #[test]
    fn rejects_malformed() {
        assert!(read(&[]).is_err());
        assert!(read(&[0x04, 0x05, 1]).is_err()); // truncated
        assert!(read(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_err()); // long form for a short length
        assert!(read(&[0x04, 0x80]).is_err()); // indefinite
        assert!(read(&[0xbf, 0x80, 0x01, 0x00]).is_err()); // padded tag
        assert!(read(&[0xbf, 0x05, 0x00]).is_err()); // high form for a low tag
        assert!(read_one(&[0x05, 0x00, 0x00]).is_err()); // trailing
        let neg = write::tlv(0, false, TAG_INTEGER, &[0x80]);
        assert!(read_one(&neg).unwrap().uint("n").is_err());
        let padded = write::tlv(0, false, TAG_INTEGER, &[0x00, 0x01]);
        assert!(read_one(&padded).unwrap().uint("n").is_err());
    }
}
