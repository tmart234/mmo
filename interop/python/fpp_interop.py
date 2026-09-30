#!/usr/bin/env python3
"""Independent FPP v1 verifier (P1 exit criterion).

A second implementation of the FPP v1 wire rules, written from
docs/anticheat/04-protocol.md without reusing any Rust code, using only the
Python standard library:

- strict deterministic CBOR decoding and canonical encoding (RFC 8949 §4.2.1)
- COSE_Sign1 verification with FPP's header rules, key roles and verification
  order (04-protocol.md §2.1)
- Ed25519 verification after RFC 8032 §5.1.7 (pure Python)
- RFC 9162 Merkle tree hashes

Usage: fpp_interop.py [interop/vectors/fpp1.json]
Exits non-zero if any vector disagrees with this implementation.
"""

import hashlib
import json
import sys
from pathlib import Path

FPP_VERSION = 1
MAX_DEPTH = 16
HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID = 1, 2, 3, 4
HDR_FPP_CTX, HDR_FPP_V = -65537, -65538
EDDSA = -8

ROLE_CONTEXTS = {
    "publisher_root": ["fpp/1/cert"],
    "build_signing": ["fpp/1/build-manifest"],
    "policy_signing": ["fpp/1/policy"],
    "verifier_ar": ["fpp/1/attestation-result"],
    "broker_sat": ["fpp/1/sat"],
    "server_liveness": ["fpp/1/sar"],
    "log": ["fpp/1/tree-head", "fpp/1/log-receipt"],
    "enforcement": ["fpp/1/revocation", "fpp/1/enforcement-record"],
    "gs_instance": ["fpp/1/checkpoint", "fpp/1/host-batch"],
    "session": ["fpp/1/admit-pop", "fpp/1/input-commit", "fpp/1/integrity-report"],
}
HYBRID_REQUIRED = {"publisher_root", "build_signing", "policy_signing", "log"}

TYPES = {
    "input-commit": ("fpp/1/input-commit", "application/fpp-input-commit+cbor"),
    "checkpoint": ("fpp/1/checkpoint", "application/fpp-checkpoint+cbor"),
    "admit-pop": ("fpp/1/admit-pop", "application/fpp-admit-pop+cbor"),
    "attestation-result": ("fpp/1/attestation-result", "application/fpp-ar+cwt"),
    "sat": ("fpp/1/sat", "application/fpp-sat+cwt"),
    "sar": ("fpp/1/sar", "application/fpp-sar+cwt"),
    "revocation": ("fpp/1/revocation", "application/fpp-revocation+cbor"),
}


class Reject(Exception):
    def __init__(self, category, detail):
        super().__init__(f"{category}: {detail}")
        self.category = category


# ------------------------------------------------------------------ CBOR


def _argument(buf, pos, info):
    if info < 24:
        return info, pos
    sizes = {24: (1, 24), 25: (2, 0x100), 26: (4, 0x10000), 27: (8, 0x100000000)}
    if info == 31:
        raise Reject("encoding", "indefinite length")
    if info not in sizes:
        raise Reject("encoding", "reserved additional information")
    n, minimum = sizes[info]
    if pos + n > len(buf):
        raise Reject("encoding", "truncated head")
    value = int.from_bytes(buf[pos:pos + n], "big")
    if value < minimum:
        raise Reject("encoding", "non-shortest head")
    return value, pos + n


def _item(buf, pos, depth):
    if pos >= len(buf):
        raise Reject("encoding", "truncated")
    initial = buf[pos]
    pos += 1
    major, info = initial >> 5, initial & 0x1F
    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if info not in simple:
            raise Reject("encoding", "float/undefined/simple value not allowed")
        return simple[info], pos
    if major == 6:
        raise Reject("encoding", "tags not allowed")
    arg, pos = _argument(buf, pos, info)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > len(buf) - pos:
            raise Reject("encoding", "truncated string")
        raw = bytes(buf[pos:pos + arg])
        pos += arg
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError:
            raise Reject("encoding", "invalid UTF-8")
    if depth == 0:
        raise Reject("encoding", "nesting too deep")
    if major == 4:
        if arg > len(buf) - pos:
            raise Reject("encoding", "truncated array")
        items = []
        for _ in range(arg):
            value, pos = _item(buf, pos, depth - 1)
            items.append(value)
        return items, pos
    # major == 5
    if arg > (len(buf) - pos) // 2:
        raise Reject("encoding", "truncated map")
    out, previous = {}, None
    for _ in range(arg):
        start = pos
        key, pos = _item(buf, pos, depth - 1)
        if isinstance(key, bool) or not isinstance(key, (int, str)):
            raise Reject("encoding", "map key must be int or text")
        encoded_key = bytes(buf[start:pos])
        if previous is not None and previous >= encoded_key:
            raise Reject("encoding", "map keys unsorted or duplicated")
        previous = encoded_key
        value, pos = _item(buf, pos, depth - 1)
        out[key] = value
    return out, pos


def cbor_decode(buf):
    value, pos = _item(buf, 0, MAX_DEPTH)
    if pos != len(buf):
        raise Reject("encoding", "trailing bytes")
    return value


def _head(major, arg):
    if arg < 24:
        return bytes([major << 5 | arg])
    for info, n in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * n):
            return bytes([major << 5 | info]) + arg.to_bytes(n, "big")
    raise ValueError("integer out of CBOR range")


def cbor_encode(v):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor_encode(x) for x in v)
    if isinstance(v, dict):
        entries = sorted((cbor_encode(k), cbor_encode(x)) for k, x in v.items())
        return _head(5, len(entries)) + b"".join(k + x for k, x in entries)
    raise TypeError(f"cannot encode {type(v)}")


# ------------------------------------------------------------------ Ed25519 (RFC 8032)

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_BY = 4 * pow(5, P - 2, P) % P
_BX = _recover_x(_BY, 0)
BASE = (_BX, _BY, 1, _BX * _BY % P)


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, point):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, point)
        point = _add(point, point)
        s >>= 1
    return q


def _equal(p1, p2):
    return (p1[0] * p2[2] - p2[0] * p1[2]) % P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % P == 0


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public), _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return _equal(_mul(s, BASE), _add(r, _mul(k, a)))


# ------------------------------------------------------------------ Merkle (RFC 9162)


def leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def mth(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


# ------------------------------------------------------------------ keys and COSE


def cose_key_ed25519(public):
    return {1: 1, -1: 6, -2: public}


def key_digest(public):
    return hashlib.sha256(cbor_encode(cose_key_ed25519(public))).digest()


def parse_protected(raw):
    header = cbor_decode(raw)
    if not isinstance(header, dict):
        raise Reject("header", "protected header is not a map")
    fields = {}
    for label, value in header.items():
        if label == HDR_CRIT:
            raise Reject("header", "crit is not allowed")
        if label == HDR_ALG and isinstance(value, int) and not isinstance(value, bool):
            fields["alg"] = value
        elif label == HDR_CONTENT_TYPE and isinstance(value, str):
            fields["content_type"] = value
        elif label == HDR_KID and isinstance(value, bytes) and len(value) == 16:
            fields["kid"] = value
        elif label == HDR_FPP_CTX and isinstance(value, str):
            fields["ctx"] = value
        elif label == HDR_FPP_V and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            fields["version"] = value
        elif label not in (HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, HDR_FPP_CTX, HDR_FPP_V):
            raise Reject("header", f"unknown header parameter {label}")
    for name in ("alg", "content_type", "kid", "ctx", "version"):
        if name not in fields:
            raise Reject("header", f"missing or malformed {name}")
    return fields


def _require(cond, what):
    if not cond:
        raise Reject("schema", what)


def _uint(m, name, bits):
    v = m.get(name)
    _require(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << bits, name)
    return v


def _fixed(m, name, size):
    v = m.get(name)
    _require(isinstance(v, bytes) and len(v) == size, name)
    return v


def parse_input_commit(m):
    _require(isinstance(m, dict), "InputCommit is not a map")
    c = {
        "match_id": _fixed(m, "match_id", 16).hex(),
        "slot": _uint(m, "slot", 16),
        "epoch": _uint(m, "epoch", 32),
        "first_tick": _uint(m, "first_tick", 32),
        "last_tick": _uint(m, "last_tick", 32),
        "n": _uint(m, "n", 32),
        "frames_root": _fixed(m, "frames_root", 32).hex(),
        "prev": _fixed(m, "prev", 32).hex(),
    }
    _require(c["first_tick"] <= c["last_tick"], "first_tick > last_tick")
    _require(c["n"] <= c["last_tick"] - c["first_tick"] + 1, "more frames than ticks")
    return c


def parse_checkpoint(m):
    _require(isinstance(m, dict), "Checkpoint is not a map")
    ticks = m.get("ticks")
    _require(
        isinstance(ticks, list) and len(ticks) == 2
        and all(isinstance(t, int) and not isinstance(t, bool) and 0 <= t < 1 << 32 for t in ticks)
        and ticks[0] <= ticks[1],
        "ticks",
    )
    c = {
        "match_id": _fixed(m, "match_id", 16).hex(),
        "gs_instance_id": _fixed(m, "gs_instance_id", 32).hex(),
        "build_id": _fixed(m, "build_id", 32).hex(),
        "policy_ver": _uint(m, "policy_ver", 64),
        "epoch": _uint(m, "epoch", 32),
        "ticks": list(ticks),
        "prev": _fixed(m, "prev", 32).hex(),
    }
    for root in ("inputs", "events", "rng", "roster"):
        c[f"{root}_root"] = _fixed(m, f"{root}_root", 32).hex()
        c[f"{root}_n"] = _uint(m, f"{root}_n", 32)
    c["state_root"] = _fixed(m, "state_root", 32).hex()
    return c


def parse_admit_pop(m):
    _require(isinstance(m, dict), "AdmitPop is not a map")
    channel, binding = m.get("channel"), m.get("binding")
    _require(isinstance(channel, str) and 1 <= len(channel.encode()) <= 32, "channel")
    _require(isinstance(binding, bytes) and 32 <= len(binding) <= 64, "binding")
    return {"channel": channel, "binding": binding.hex()}


# ---- tokens (04-protocol.md §6): integer claim keys, CWT/EAT style

AR_MAX_S, SAT_MAX_S, SAR_MAX_S = 1800, 6 * 3600, 120
FEATURE_FLAGS = ("secure_boot", "measured_boot", "hvci", "vbs", "iommu", "runtime_report",
                 "key_in_hw", "strong_integrity", "app_attested")


def _claim(m, key, what):
    _require(key in m, what)
    return m[key]


def _cuint(m, key, what, bits=64):
    v = _claim(m, key, what)
    _require(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << bits, what)
    return v


def _cbytes(m, key, what, size):
    v = _claim(m, key, what)
    _require(isinstance(v, bytes) and len(v) == size, what)
    return v.hex()


def _ctext(m, key, what, max_len):
    v = _claim(m, key, what)
    _require(isinstance(v, str) and 0 < len(v.encode()) <= max_len, what)
    return v


def _okp_key(v, what):
    """An Ed25519 COSE_Key {1: 1, -1: 6, -2: x}, exactly."""
    _require(isinstance(v, dict) and set(v) == {1, -1, -2} and v[1] == 1 and v[-1] == 6
             and isinstance(v[-2], bytes) and len(v[-2]) == 32, what)
    _require(_decompress(v[-2]) is not None, what)
    return v[-2]


def _cnf(m):
    v = _claim(m, 8, "cnf")
    _require(isinstance(v, dict) and set(v) == {1}, "cnf")
    return _okp_key(v[1], "cnf").hex()


def _lifetime(m, max_s):
    iat, exp = _cuint(m, 6, "iat"), _cuint(m, 4, "exp")
    _require(iat < exp <= iat + max_s, "exp: lifetime")
    return iat, exp


def _tier(m):
    t = _cuint(m, -65602, "tier")
    _require(t <= 3, "tier")
    return t


def parse_attestation_result(m):
    _require(isinstance(m, dict), "AR is not a map")
    _require(m.get(265) == "tag:fpp,2026:ar/1", "eat_profile")
    iat, exp = _lifetime(m, AR_MAX_S)
    feats_in = _claim(m, -65603, "features")
    _require(isinstance(feats_in, dict), "features")
    feats = {}
    for k, v in feats_in.items():
        _require(isinstance(k, str), "features key")
        if k in FEATURE_FLAGS:
            _require(isinstance(v, bool), k)
            feats[k] = v
        elif k == "os_patch_age_days":
            _require(isinstance(v, int) and not isinstance(v, bool) and v >= 0, k)
            feats[k] = v
    warnings = m.get(-65607, [])
    if -65607 in m:
        _require(isinstance(warnings, list) and 0 < len(warnings) <= 16
                 and all(isinstance(w, str) for w in warnings), "warnings")
    return {
        "iss": _ctext(m, 1, "iss", 64), "iat": iat, "exp": exp,
        "cti": _cbytes(m, 7, "cti", 16), "cnf": _cnf(m), "nonce": _cbytes(m, 10, "eat_nonce", 32),
        "did": _cbytes(m, -65601, "did", 32), "tier": _tier(m), "features": feats,
        "client_build": _cbytes(m, -65604, "client_build", 32),
        "platform": _ctext(m, -65605, "platform", 32), "policy_ver": _cuint(m, -65606, "policy_ver"),
        "warnings": warnings,
    }


def parse_sat(m):
    _require(isinstance(m, dict), "SAT is not a map")
    iat, exp = _lifetime(m, SAT_MAX_S)
    return {
        "iss": _ctext(m, 1, "iss", 64), "sub": _cbytes(m, 2, "sub", 32), "aud": _cbytes(m, 3, "aud", 32),
        "iat": iat, "exp": exp, "cti": _cbytes(m, 7, "cti", 16), "cnf": _cnf(m),
        "did": _cbytes(m, -65601, "did", 32), "tier": _tier(m),
        "match_id": _cbytes(m, -65620, "match_id", 16), "slot": _cuint(m, -65621, "slot", 16),
        "queue": _ctext(m, -65622, "queue", 64), "policy_ver": _cuint(m, -65606, "policy_ver"),
        "ar_cti": _cbytes(m, -65623, "ar_cti", 16),
    }


def parse_sar(m):
    _require(isinstance(m, dict), "SAR is not a map")
    iat, exp = _lifetime(m, SAR_MAX_S)
    opt = lambda key, what: _cbytes(m, key, what, 32) if key in m else None
    c = {
        "iss": _ctext(m, 1, "iss", 64), "sub": _cbytes(m, 2, "sub", 32), "iat": iat, "exp": exp,
        "cnf": _cnf(m), "tls_spki_sha256": opt(-65640, "tls_spki_sha256"),
        "noise_static": opt(-65647, "noise_static"),
        "server_class": _cuint(m, -65641, "server_class"), "build_id": _cbytes(m, -65642, "build_id", 32),
        "region": _ctext(m, -65643, "region", 32), "seq": _cuint(m, -65644, "seq"),
        "prev": _cbytes(m, -65645, "prev", 32),
        "vrf_pub": _okp_key(m[-65646], "vrf_pub").hex() if -65646 in m else None,
    }
    _require(c["server_class"] <= 3, "server_class")
    _require(c["sub"] == key_digest(bytes.fromhex(c["cnf"])).hex(), "sub != digest(cnf)")
    _require(c["tls_spki_sha256"] or c["noise_static"], "no transport binding")
    return c


# ---- enforcement (04-protocol.md §9): text keys

SUBJECT_ID_LEN = {0: 32, 1: 32, 2: 32, 3: 16, 4: 32, 5: 32}  # account, device, session, sat, gs_instance, build


def parse_revocation(m):
    _require(isinstance(m, dict), "RevocationEvent is not a map")
    subject = m.get("subject")
    _require(isinstance(subject, dict), "subject")
    kind = _uint(subject, "kind", 8)
    _require(kind in SUBJECT_ID_LEN, "subject kind")
    subject_id = _fixed(subject, "id", SUBJECT_ID_LEN[kind])
    action = _uint(m, "action", 8)
    _require(action <= 6, "action")
    scope_in = m.get("scope")
    _require(isinstance(scope_in, dict), "scope")
    scope = {}
    for k in ("titles", "queues", "regions"):
        if k in scope_in:
            v = scope_in[k]
            _require(isinstance(v, list) and 1 <= len(v) <= 16
                     and all(isinstance(x, str) and 1 <= len(x.encode()) <= 64 for x in v), f"scope {k}")
            scope[k] = v
    effective_at = _uint(m, "effective_at", 64)
    expires_at = None
    if "expires_at" in m:
        expires_at = _uint(m, "expires_at", 64)
        _require(expires_at > effective_at, "expires_at <= effective_at")
    return {
        "id": _fixed(m, "id", 16).hex(), "subject_kind": kind, "subject_id": subject_id.hex(),
        "action": action, "scope": scope, "effective_at": effective_at, "expires_at": expires_at,
        "reason": _uint(m, "reason", 16), "record": _fixed(m, "record", 32).hex(),
    }


PARSERS = {"input-commit": parse_input_commit, "checkpoint": parse_checkpoint, "admit-pop": parse_admit_pop,
           "attestation-result": parse_attestation_result, "sat": parse_sat, "sar": parse_sar,
           "revocation": parse_revocation}


def verify(cose, kind, keys):
    """Verify in the normative order; raise Reject(category) on failure."""
    obj = cbor_decode(cose)
    if not isinstance(obj, list) or len(obj) != 4:
        raise Reject("header", "COSE_Sign1 must be a 4-element array")
    protected_raw, unprotected, payload, signature = obj
    if not isinstance(protected_raw, bytes):
        raise Reject("header", "protected header is not a bstr")
    if not (isinstance(unprotected, dict) and not unprotected):
        raise Reject("header", "unprotected header must be an empty map")
    if not isinstance(payload, bytes):
        raise Reject("header", "payload must be an attached bstr")
    if not isinstance(signature, bytes):
        raise Reject("header", "signature is not a bstr")
    h = parse_protected(protected_raw)
    if h["version"] != FPP_VERSION:
        raise Reject("version", h["version"])
    expected_ctx, expected_ct = TYPES[kind]
    if h["ctx"] != expected_ctx or h["content_type"] != expected_ct:
        raise Reject("ctx", h["ctx"])
    key = keys.get(h["kid"])
    if key is None:
        raise Reject("kid", h["kid"].hex())
    if key["role"] in HYBRID_REQUIRED or h["ctx"] not in ROLE_CONTEXTS[key["role"]]:
        raise Reject("role", key["role"])
    if h["alg"] != key["alg"]:
        raise Reject("alg", h["alg"])
    to_be_signed = cbor_encode(["Signature1", protected_raw, b"", payload])
    if not ed25519_verify(key["public"], to_be_signed, signature):
        raise Reject("signature", "Ed25519 verification failed")
    return PARSERS[kind](cbor_decode(payload)), key


# ------------------------------------------------------------------ vector runner


class Runner:
    def __init__(self):
        self.failures = 0
        self.checks = 0

    def check(self, cond, what):
        self.checks += 1
        if not cond:
            self.failures += 1
            print(f"FAIL {what}")


def run(path):
    vectors = json.loads(Path(path).read_text())
    r = Runner()
    r.check(vectors["fpp_version"] == FPP_VERSION, "fpp_version")

    # Ed25519 against RFC 8032 §7.1 TEST 1, independent of the vector file.
    rfc_pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    rfc_sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    r.check(ed25519_verify(rfc_pub, b"", rfc_sig), "Ed25519 RFC 8032 TEST 1")
    r.check(not ed25519_verify(rfc_pub, b"x", rfc_sig), "Ed25519 RFC 8032 TEST 1 (wrong message)")
    for t in vectors["ed25519_rfc8032"]:
        r.check(bytes.fromhex(t["public"]) == rfc_pub and bytes.fromhex(t["signature"]) == rfc_sig,
                "vector file carries the RFC 8032 TEST 1 signature")

    ct = vectors["merkle_ct"]
    leaves = [bytes.fromhex(x) for x in ct["leaves"]]
    for n, root in enumerate(ct["roots"], start=1):
        r.check(mth(leaves[:n]).hex() == root, f"Merkle CT root size {n}")
    r.check(mth([]).hex() == ct["empty_root"], "Merkle empty root")
    r.check(leaf_hash(b"").hex() == ct["leaf_hash_of_empty"], "Merkle leaf hash")

    keys, by_name = {}, {}
    for k in vectors["keys"]:
        public = bytes.fromhex(k["public"])
        digest = key_digest(public)
        r.check(digest.hex() == k["key_digest"], f"key digest {k['name']}")
        r.check(digest[:16].hex() == k["kid"], f"kid {k['name']}")
        entry = {"role": k["role"], "alg": k["alg"], "public": public, "name": k["name"]}
        by_name[k["name"]] = entry
        if k["known"]:
            keys[digest[:16]] = entry

    by_object = {o["name"]: o for o in vectors["objects"]}
    for o in vectors["objects"]:
        name, cose = o["name"], bytes.fromhex(o["cose"])
        try:
            payload, key = verify(cose, o["type"], keys)
            outcome = None
        except Reject as e:
            payload, key, outcome = None, None, e.category
        if o["expect"] == "reject":
            r.check(outcome == o["category"], f"{name}: expected reject/{o['category']}, got {outcome or 'valid'}")
            continue
        r.check(outcome is None, f"{name}: expected valid, got reject/{outcome}")
        if outcome is not None:
            continue
        r.check(payload == o["payload"], f"{name}: payload fields")
        r.check(hashlib.sha256(cose).hexdigest() == o["digest"], f"{name}: object digest")
        derive = o["derive"]
        r.check(key["name"] == derive["signer"], f"{name}: signer")
        if o["type"] == "revocation":
            continue
        if o["type"] in ("attestation-result", "sat"):
            if o["type"] == "sat":
                ar = parse_attestation_result(cbor_decode(cbor_decode(bytes.fromhex(by_object[derive["ar_object"]]["cose"]))[2]))
                r.check(payload["ar_cti"] == ar["cti"] and payload["cnf"] == ar["cnf"] and payload["tier"] <= ar["tier"],
                        f"{name}: SAT backed by its AR (cti, cnf, tier)")
            continue
        if o["type"] == "sar":
            prev = derive["prev_object"]
            expected = (hashlib.sha256(cbor_decode(bytes.fromhex(by_object[prev]["cose"]))[2]).hexdigest()
                        if prev else "00" * 32)
            r.check(payload["prev"] == expected, f"{name}: prev is SHA-256 of the previous SAR payload")
            if prev:
                r.check(payload["seq"] == parse_sar(cbor_decode(cbor_decode(bytes.fromhex(by_object[prev]["cose"]))[2]))["seq"] + 1,
                        f"{name}: seq continues")
            continue
        if o["type"] == "admit-pop":
            binding = derive["host_static"] + derive["joiner_static"]
            r.check(payload["channel"] == "fpp-p2p/noise-ik" and payload["binding"] == binding,
                    f"{name}: binding is host static key || joiner static key")
            continue
        prev = derive["prev_object"]
        expected_prev = hashlib.sha256(bytes.fromhex(by_object[prev]["cose"])).hexdigest() if prev else "00" * 32
        r.check(payload["prev"] == expected_prev, f"{name}: prev chain")
        if o["type"] == "input-commit":
            frames = [int(t).to_bytes(4, "little") + bytes.fromhex(p) for t, p in derive["frames"]]
            r.check(mth(frames).hex() == payload["frames_root"], f"{name}: frames_root")
            r.check(len(frames) == payload["n"], f"{name}: n")
        else:
            input_leaves = [
                cbor_encode({
                    "slot": leaf["slot"],
                    "commit": bytes.fromhex(leaf["commit"]) if leaf["commit"] else None,
                    "applied": bytes.fromhex(leaf["applied"]),
                })
                for leaf in derive["input_leaves"]
            ]
            for root, items in (("inputs", input_leaves),
                                ("events", [bytes.fromhex(x) for x in derive["events"]]),
                                ("rng", [bytes.fromhex(x) for x in derive["rng"]]),
                                ("roster", [bytes.fromhex(x) for x in derive["roster"]])):
                r.check(mth(items).hex() == payload[f"{root}_root"], f"{name}: {root}_root")
                r.check(len(items) == payload[f"{root}_n"], f"{name}: {root}_n")
            state = hashlib.sha256(bytes.fromhex(derive["state"])).hexdigest()
            r.check(state == payload["state_root"], f"{name}: state_root")
            r.check(key_digest(key["public"]).hex() == payload["gs_instance_id"], f"{name}: gs_instance_id")
            for leaf in derive["input_leaves"]:
                if leaf["commit"]:
                    committed = [c for c in vectors["objects"] if c["expect"] == "valid" and c.get("digest") == leaf["commit"]]
                    r.check(len(committed) == 1, f"{name}: input leaf slot {leaf['slot']} references a known InputCommit")

    print(f"{r.checks - r.failures}/{r.checks} checks passed ({len(vectors['objects'])} objects)")
    return r.failures == 0


if __name__ == "__main__":
    default = Path(__file__).resolve().parents[1] / "vectors" / "fpp1.json"
    sys.exit(0 if run(sys.argv[1] if len(sys.argv) > 1 else default) else 1)
