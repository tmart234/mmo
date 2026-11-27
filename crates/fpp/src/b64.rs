//! Base64 (RFC 4648 §4 standard padded, and §5 URL-safe unpadded).
//! Single implementation shared across the entire workspace (Transparency Log
//! signed notes, Play Integrity tokens, etc.).

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Standard base64 with `=` padding (RFC 4648 §4), as C2SP signed notes use.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(STD[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Strict standard base64 decode: canonical padding, no whitespace, no stray bits.
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = if i >= 4 - pad {
                0
            } else {
                STD.iter().position(|a| a == c)? as u32
            };
            n = (n << 6) | v;
        }
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        if decoded[keep..].iter().any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(&decoded[..keep]);
    }
    Some(out)
}

/// URL-safe base64 without padding (RFC 4648 §5), as JWE/JWS and Play Integrity use.
pub fn encode_url(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(URL[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Standard or URL-safe base64 decode, padded or unpadded, rejecting stray bits.
pub fn decode_any(input: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for c in input.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    (n < 6 && bits & ((1 << n) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded).unwrap(), plain.as_bytes());
            assert_eq!(decode_any(coded).unwrap(), plain.as_bytes());
        }
        assert!(decode("Zg=").is_none());
        assert!(decode("Zh==").is_none());
        assert!(decode("Zg==Zg==").is_none());
        assert!(decode("Z!==").is_none());
    }

    #[test]
    fn url_round_trip() {
        let data: Vec<u8> = (0u8..=255).collect();
        let u = encode_url(&data);
        assert!(!u.contains('+') && !u.contains('/') && !u.contains('='));
        assert_eq!(decode_any(&u).unwrap(), data);
    }
}
