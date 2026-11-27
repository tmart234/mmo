//! The regional key bundle (04-protocol.md §4): the public signing keys of
//! the Verifier (ARs), Broker (SATs), Server Liveness (SARs), Enforcement
//! (revocations), Transparency Log (+ witnesses), and the Noise IK static
//! X25519 transport public key(s) of the authority endpoint(s).
//!
//! Zero external JSON/serde dependencies: serialized in deterministic CBOR
//! (`encode_cbor` / `decode_cbor`) and in human-readable JSON (`save` / `load`)
//! via a small, strict, owned parser.

use crate::crypto::{KeyRole, KeySet};
use crate::wire::cbor::{self, text_map, MapView, Value};
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;
use std::path::Path;

pub const DEFAULT_BUNDLE: &str = "keys/fpp_key_bundle.json";

/// Errors loading or parsing a [`KeyBundle`].
#[derive(Debug)]
pub enum BundleError {
    Io(std::io::Error),
    Format(String),
}

impl core::fmt::Display for BundleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BundleError::Io(e) => write!(f, "key bundle io: {e}"),
            BundleError::Format(m) => write!(f, "key bundle: {m}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<std::io::Error> for BundleError {
    fn from(e: std::io::Error) -> Self {
        BundleError::Io(e)
    }
}

/// The Transparency Log's keys (hybrid, FPP-S1H) and its witnesses'.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogKeys {
    /// The log's name in its checkpoints.
    pub origin: String,
    pub ed25519: [u8; 32],
    pub ml_dsa: Vec<u8>,
    /// Witnesses (name, Ed25519 key) whose cosignatures count.
    pub witnesses: Vec<(String, [u8; 32])>,
}

/// Public keys relying parties trust, by role, plus pinned Noise transport key(s).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    /// Pinned X25519 static public key of the regional authority endpoint
    /// (Noise_IK_25519_ChaChaPoly_SHA256). All-zero only in offline-only bundles.
    pub transport_pub: [u8; 32],
    /// Optional per-role Noise transport public keys when roles run in
    /// separate processes (`"liveness"`, `"verifier"`, `"broker"`, `"log"`,
    /// `"revocation"`, `"evidence"`). Falls back to `transport_pub`.
    pub role_transport: BTreeMap<String, [u8; 32]>,
    pub verifier_ar: VerifyingKey,
    pub broker_sat: VerifyingKey,
    pub server_liveness: VerifyingKey,
    pub enforcement: VerifyingKey,
    /// The region's Transparency Log, if it has one.
    pub log: Option<LogKeys>,
}

impl KeyBundle {
    /// Pinned Noise static public key for `role` (or the default authority key).
    pub fn transport_key(&self, role: &str) -> Result<[u8; 32], BundleError> {
        let k = self
            .role_transport
            .get(role)
            .copied()
            .unwrap_or(self.transport_pub);
        if k == [0u8; 32] {
            return Err(BundleError::Format(format!(
                "no pinned transport key for {role:?}"
            )));
        }
        Ok(k)
    }

    pub fn keyset(&self) -> KeySet {
        let mut k = KeySet::default();
        k.insert_ed25519(KeyRole::VerifierAr, self.verifier_ar);
        k.insert_ed25519(KeyRole::BrokerSat, self.broker_sat);
        k.insert_ed25519(KeyRole::ServerLiveness, self.server_liveness);
        k.insert_ed25519(KeyRole::Enforcement, self.enforcement);
        k
    }

    /// Deterministic CBOR representation of the bundle.
    pub fn encode_cbor(&self) -> Vec<u8> {
        let mut entries: Vec<(&str, Value)> = vec![
            (
                "broker_sat",
                Value::bytes(self.broker_sat.to_bytes().to_vec()),
            ),
            (
                "enforcement",
                Value::bytes(self.enforcement.to_bytes().to_vec()),
            ),
            (
                "server_liveness",
                Value::bytes(self.server_liveness.to_bytes().to_vec()),
            ),
            ("transport_pub", Value::bytes(self.transport_pub.to_vec())),
            (
                "verifier_ar",
                Value::bytes(self.verifier_ar.to_bytes().to_vec()),
            ),
        ];
        if !self.role_transport.is_empty() {
            let map = self
                .role_transport
                .iter()
                .map(|(k, v)| (Value::text(k), Value::bytes(v.to_vec())))
                .collect();
            entries.push(("role_transport", Value::Map(map)));
        }
        if let Some(l) = &self.log {
            let witnesses = l
                .witnesses
                .iter()
                .map(|(n, k)| {
                    text_map([
                        ("ed25519", Value::bytes(k.to_vec())),
                        ("name", Value::text(n)),
                    ])
                })
                .collect();
            entries.push((
                "log",
                text_map([
                    ("ed25519", Value::bytes(l.ed25519.to_vec())),
                    ("ml_dsa", Value::bytes(l.ml_dsa.clone())),
                    ("origin", Value::text(&l.origin)),
                    ("witnesses", Value::Array(witnesses)),
                ]),
            ));
        }
        cbor::encode(&text_map(entries)).expect("KeyBundle CBOR encodes")
    }

    /// Decode a deterministic CBOR bundle.
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self, BundleError> {
        let v = cbor::decode(bytes).map_err(|e| BundleError::Format(e.to_string()))?;
        let m = MapView::new(&v, "KeyBundle").map_err(|e| BundleError::Format(e.to_string()))?;
        let vk = |name: &'static str| -> Result<VerifyingKey, BundleError> {
            let b = m
                .fixed::<32>(name)
                .map_err(|e| BundleError::Format(e.to_string()))?;
            VerifyingKey::from_bytes(&b).map_err(|_| BundleError::Format(format!("{name}: key")))
        };
        let transport_pub = match m.field("transport_pub") {
            Ok(_) => m
                .fixed::<32>("transport_pub")
                .map_err(|e| BundleError::Format(e.to_string()))?,
            Err(_) => [0u8; 32],
        };
        let mut role_transport = BTreeMap::new();
        if let Ok(Value::Map(entries)) = m.field("role_transport") {
            for (k, val) in entries {
                let Some(name) = k.as_text() else {
                    return Err(BundleError::Format("role_transport key".into()));
                };
                let b: [u8; 32] = val
                    .as_bytes()
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| BundleError::Format("role_transport val".into()))?;
                role_transport.insert(name.to_string(), b);
            }
        }
        let log = match m.field("log") {
            Ok(lv) => {
                let lm =
                    MapView::new(lv, "LogKeys").map_err(|e| BundleError::Format(e.to_string()))?;
                let origin = lm
                    .text("origin")
                    .map_err(|e| BundleError::Format(e.to_string()))?
                    .to_string();
                let ed25519 = lm
                    .fixed::<32>("ed25519")
                    .map_err(|e| BundleError::Format(e.to_string()))?;
                let ml_dsa = lm
                    .bytes("ml_dsa")
                    .map_err(|e| BundleError::Format(e.to_string()))?
                    .to_vec();
                let ws = lm
                    .field("witnesses")
                    .ok()
                    .and_then(Value::as_array)
                    .ok_or_else(|| BundleError::Format("witnesses".into()))?;
                let mut witnesses = Vec::with_capacity(ws.len());
                for w in ws {
                    let wm = MapView::new(w, "Witness")
                        .map_err(|e| BundleError::Format(e.to_string()))?;
                    let wname = wm
                        .text("name")
                        .map_err(|e| BundleError::Format(e.to_string()))?
                        .to_string();
                    let wed = wm
                        .fixed::<32>("ed25519")
                        .map_err(|e| BundleError::Format(e.to_string()))?;
                    witnesses.push((wname, wed));
                }
                Some(LogKeys {
                    origin,
                    ed25519,
                    ml_dsa,
                    witnesses,
                })
            }
            Err(_) => None,
        };
        Ok(Self {
            transport_pub,
            role_transport,
            verifier_ar: vk("verifier_ar")?,
            broker_sat: vk("broker_sat")?,
            server_liveness: vk("server_liveness")?,
            enforcement: vk("enforcement")?,
            log,
        })
    }

    /// Write the bundle as pretty JSON (atomic rename via sibling `.tmp` file).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), BundleError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let text = self.to_json();
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }

    /// Load a bundle from JSON (or CBOR if the file starts with CBOR major type 5).
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let raw = std::fs::read(path.as_ref())?;
        if raw.first().is_some_and(|b| (b >> 5) == 5) {
            return Self::decode_cbor(&raw);
        }
        let text = std::str::from_utf8(&raw)
            .map_err(|_| BundleError::Format("key bundle is not UTF-8".into()))?;
        Self::from_json(text)
    }

    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!(
            "  \"transport_pub\": \"{}\",\n",
            hex_encode(&self.transport_pub)
        ));
        if !self.role_transport.is_empty() {
            s.push_str("  \"role_transport\": {\n");
            for (i, (k, v)) in self.role_transport.iter().enumerate() {
                let comma = if i + 1 < self.role_transport.len() {
                    ","
                } else {
                    ""
                };
                s.push_str(&format!(
                    "    {}: \"{}\"{comma}\n",
                    json_escape(k),
                    hex_encode(v)
                ));
            }
            s.push_str("  },\n");
        }
        s.push_str(&format!(
            "  \"verifier_ar\": \"{}\",\n",
            hex_encode(&self.verifier_ar.to_bytes())
        ));
        s.push_str(&format!(
            "  \"broker_sat\": \"{}\",\n",
            hex_encode(&self.broker_sat.to_bytes())
        ));
        s.push_str(&format!(
            "  \"server_liveness\": \"{}\",\n",
            hex_encode(&self.server_liveness.to_bytes())
        ));
        s.push_str(&format!(
            "  \"enforcement\": \"{}\",\n",
            hex_encode(&self.enforcement.to_bytes())
        ));
        match &self.log {
            None => s.push_str("  \"log\": null\n"),
            Some(l) => {
                s.push_str("  \"log\": {\n");
                s.push_str(&format!("    \"origin\": {},\n", json_escape(&l.origin)));
                s.push_str(&format!(
                    "    \"ed25519\": \"{}\",\n",
                    hex_encode(&l.ed25519)
                ));
                s.push_str(&format!("    \"ml_dsa\": \"{}\",\n", hex_encode(&l.ml_dsa)));
                s.push_str("    \"witnesses\": [");
                for (i, (name, key)) in l.witnesses.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!(
                        "\n      {{\"name\": {}, \"ed25519\": \"{}\"}}",
                        json_escape(name),
                        hex_encode(key)
                    ));
                }
                if !l.witnesses.is_empty() {
                    s.push_str("\n    ");
                }
                s.push_str("]\n  }\n");
            }
        }
        s.push_str("}\n");
        s
    }

    pub fn from_json(text: &str) -> Result<Self, BundleError> {
        let root = parse_json(text)?;
        let obj = root.as_obj()?;
        let hex32 = |val: &JVal, name: &str| -> Result<[u8; 32], BundleError> {
            let s = val.as_str(name)?;
            let b = hex_decode(s).ok_or_else(|| BundleError::Format(format!("{name}: bad hex")))?;
            b.try_into()
                .map_err(|_| BundleError::Format(format!("{name}: not 32 bytes")))
        };
        let vk = |name: &str| -> Result<VerifyingKey, BundleError> {
            let v = obj
                .get(name)
                .ok_or_else(|| BundleError::Format(format!("missing {name}")))?;
            let b = hex32(v, name)?;
            VerifyingKey::from_bytes(&b)
                .map_err(|_| BundleError::Format(format!("{name}: invalid Ed25519 key")))
        };
        let transport_pub = match obj.get("transport_pub") {
            Some(JVal::Null) | None => [0u8; 32],
            Some(v) => hex32(v, "transport_pub")?,
        };
        let mut role_transport = BTreeMap::new();
        if let Some(rt) = obj.get("role_transport") {
            if !matches!(rt, JVal::Null) {
                for (k, v) in rt.as_obj()? {
                    role_transport.insert(k.clone(), hex32(v, k)?);
                }
            }
        }
        let log = match obj.get("log") {
            None | Some(JVal::Null) => None,
            Some(lv) => {
                let lo = lv.as_obj()?;
                let origin = lo
                    .get("origin")
                    .ok_or_else(|| BundleError::Format("missing log.origin".into()))?
                    .as_str("log.origin")?
                    .to_string();
                let ed25519 = hex32(
                    lo.get("ed25519")
                        .ok_or_else(|| BundleError::Format("missing log.ed25519".into()))?,
                    "log.ed25519",
                )?;
                let ml_str = lo
                    .get("ml_dsa")
                    .ok_or_else(|| BundleError::Format("missing log.ml_dsa".into()))?
                    .as_str("log.ml_dsa")?;
                let ml_dsa = hex_decode(ml_str)
                    .ok_or_else(|| BundleError::Format("log.ml_dsa: bad hex".into()))?;
                let ws = lo
                    .get("witnesses")
                    .ok_or_else(|| BundleError::Format("missing log.witnesses".into()))?
                    .as_arr("log.witnesses")?;
                let mut witnesses = Vec::with_capacity(ws.len());
                for w in ws {
                    let wo = w.as_obj()?;
                    let wname = wo
                        .get("name")
                        .ok_or_else(|| BundleError::Format("missing witness.name".into()))?
                        .as_str("witness.name")?
                        .to_string();
                    let wed = hex32(
                        wo.get("ed25519")
                            .ok_or_else(|| BundleError::Format("missing witness.ed25519".into()))?,
                        "witness.ed25519",
                    )?;
                    witnesses.push((wname, wed));
                }
                Some(LogKeys {
                    origin,
                    ed25519,
                    ml_dsa,
                    witnesses,
                })
            }
        };
        Ok(Self {
            transport_pub,
            role_transport,
            verifier_ar: vk("verifier_ar")?,
            broker_sat: vk("broker_sat")?,
            server_liveness: vk("server_liveness")?,
            enforcement: vk("enforcement")?,
            log,
        })
    }
}

// ------------------------------------------------------------------ tiny zero-dep JSON & hex

pub fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0xf) as usize] as char);
    }
    out
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push((nib(b[i])? << 4) | nib(b[i + 1])?);
    }
    Some(out)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

enum JVal {
    Null,
    Str(String),
    Arr(Vec<JVal>),
    Obj(BTreeMap<String, JVal>),
}

impl JVal {
    fn as_obj(&self) -> Result<&BTreeMap<String, JVal>, BundleError> {
        match self {
            JVal::Obj(m) => Ok(m),
            _ => Err(BundleError::Format("expected JSON object".into())),
        }
    }

    fn as_arr(&self, name: &str) -> Result<&[JVal], BundleError> {
        match self {
            JVal::Arr(a) => Ok(a),
            _ => Err(BundleError::Format(format!("{name}: expected array"))),
        }
    }

    fn as_str(&self, name: &str) -> Result<&str, BundleError> {
        match self {
            JVal::Str(s) => Ok(s),
            _ => Err(BundleError::Format(format!("{name}: expected string"))),
        }
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, expected: u8) -> Result<(), BundleError> {
        self.skip_ws();
        if self.b.get(self.i) == Some(&expected) {
            self.i += 1;
            Ok(())
        } else {
            Err(BundleError::Format(format!(
                "expected '{}' at byte {}",
                expected as char, self.i
            )))
        }
    }

    fn parse_str(&mut self) -> Result<String, BundleError> {
        self.eat(b'"')?;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.i >= self.b.len() {
                        return Err(BundleError::Format("truncated escape".into()));
                    }
                    let esc = self.b[self.i];
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        _ => return Err(BundleError::Format("unsupported JSON escape".into())),
                    }
                }
                _ => {
                    // Valid UTF-8 because input was `&str`.
                    let start = self.i - 1;
                    while self.i < self.b.len() && (self.b[self.i] & 0xc0) == 0x80 {
                        self.i += 1;
                    }
                    let s = std::str::from_utf8(&self.b[start..self.i])
                        .map_err(|_| BundleError::Format("bad utf8".into()))?;
                    out.push_str(s);
                }
            }
        }
        Err(BundleError::Format("unterminated string".into()))
    }

    fn parse_val(&mut self, depth: usize) -> Result<JVal, BundleError> {
        if depth > 8 {
            return Err(BundleError::Format("JSON nesting too deep".into()));
        }
        match self.peek() {
            Some(b'"') => Ok(JVal::Str(self.parse_str()?)),
            Some(b'n') => {
                if self.b[self.i..].starts_with(b"null") {
                    self.i += 4;
                    Ok(JVal::Null)
                } else {
                    Err(BundleError::Format("bad literal".into()))
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut arr = Vec::new();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(JVal::Arr(arr));
                }
                loop {
                    arr.push(self.parse_val(depth + 1)?);
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(JVal::Arr(arr));
                        }
                        _ => return Err(BundleError::Format("expected ',' or ']'".into())),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut map = BTreeMap::new();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(JVal::Obj(map));
                }
                loop {
                    let k = self.parse_str()?;
                    self.eat(b':')?;
                    let v = self.parse_val(depth + 1)?;
                    map.insert(k, v);
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(JVal::Obj(map));
                        }
                        _ => return Err(BundleError::Format("expected ',' or '}'".into())),
                    }
                }
            }
            _ => Err(BundleError::Format(format!(
                "unexpected JSON token at byte {}",
                self.i
            ))),
        }
    }
}

fn parse_json(text: &str) -> Result<JVal, BundleError> {
    let mut p = JsonParser {
        b: text.as_bytes(),
        i: 0,
    };
    let v = p.parse_val(0)?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(BundleError::Format("trailing JSON bytes".into()));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn bundle_round_trips_json_and_cbor() {
        let key = |n: u8| SigningKey::from_bytes(&[n; 32]).verifying_key();
        let mut role_transport = BTreeMap::new();
        role_transport.insert("verifier".into(), [0x11; 32]);
        let b = KeyBundle {
            transport_pub: [0x99; 32],
            role_transport,
            verifier_ar: key(1),
            broker_sat: key(2),
            server_liveness: key(3),
            enforcement: key(4),
            log: Some(LogKeys {
                origin: "fpp.test/log".into(),
                ed25519: [5; 32],
                ml_dsa: vec![6; 1952],
                witnesses: vec![("fpp.test/witness".into(), [7; 32])],
            }),
        };
        let json = b.to_json();
        assert_eq!(KeyBundle::from_json(&json).unwrap(), b);
        let cbor = b.encode_cbor();
        assert_eq!(KeyBundle::decode_cbor(&cbor).unwrap(), b);
    }
}
