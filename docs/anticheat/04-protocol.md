# 04 — Fair-Play Protocol (FPP) v1

Status: Draft v1 (normative language per RFC 2119). Schemas are CDDL (RFC 8610).
This document specifies the wire protocol that realizes
[03-architecture.md](03-architecture.md). It is designed to be implementable
from the spec alone, in any language, with no reliance on obscurity.

---

## 1. Layering

| Plane | Transport | Peers | Content |
|-------|-----------|-------|---------|
| **Control** | HTTP/3 (QUIC), TLS 1.3 server auth; mTLS between services | IA/client ↔ Verifier, Broker, Log gossip | Challenges, evidence, tokens |
| **Session** | QUIC v1, ALPN `fpp/1`, streams + DATAGRAM (RFC 9221) | Client ↔ GS | Admission, input frames, commits, snapshots, integrity reports |
| **Evidence** | HTTP/3 mTLS | Host Agent ↔ Log, Evidence Store; auditors | Checkpoints, host batches, receipts, proofs |
| **Enforcement** | Regional pub/sub, mTLS | Enforcement → Brokers, GS, Server Liveness | Revocation events |

The real-time game payload (input intent bits, snapshots) is **title-defined**
and **not signed**. QUIC AEAD protects it in transit. FPP defines the envelope,
the commitments over it, and everything around it.

## 2. Encoding and signatures

- **Encoding.** Deterministic CBOR (RFC 8949 §4.2.1, core deterministic
  encoding). Receivers MUST reject non-deterministic encodings of signed payloads
  (duplicate keys, non-minimal integers, indefinite lengths).
- **Signed objects** are `COSE_Sign1` (RFC 9052). Objects signed by long-lived
  roots use `COSE_Sign` with **two** signatures (Ed25519 and ML-DSA-65), and
  both MUST verify.
- **Protected header** MUST contain:
  - `alg` (1)
  - `kid` (4): SHA-256 of the signer's COSE_Key, truncated to 16 bytes
  - `content type` (3): the FPP media type, e.g. `application/fpp-checkpoint+cbor`
  - `fpp-ctx` (label **−65537**, private use): the domain-separation string, e.g.
    `"fpp/1/checkpoint"`
  - `fpp-v` (label **−65538**): protocol version, `1`
- **Key purpose binding.** Every key is registered with an allowlist of `fpp-ctx`
  values (§4). A verifier MUST reject a signature whose `fpp-ctx` is not in the
  signer key's allowlist. That makes cross-protocol signature reuse impossible,
  which the prototype did not prevent.
- **Tokens** are CWTs (RFC 8392) inside COSE_Sign1. Attestation Results follow
  EAT (RFC 9711) with a registered `eat_profile`. Proof-of-possession uses `cnf`
  (RFC 8747).
- **Merkle trees** use RFC 9162 §2.1 hashing: `leaf = SHA-256(0x00 ‖ d)`,
  `node = SHA-256(0x01 ‖ l ‖ r)`. The Merkle Tree Hash of an empty list is
  `SHA-256("")`.

## 3. Cryptographic suites

| Suite | Use | Algorithms |
|-------|-----|------------|
| **FPP-T1** (transport) | All QUIC/TLS | TLS 1.3; groups `X25519MLKEM768` (preferred), `X25519`; AEAD `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`. Certificates: ECDSA P-256 or Ed25519. |
| **FPP-S1** (short-lived objects) | Tokens, commits, checkpoints, reports, revocations | Ed25519 (COSE `EdDSA`, −8), SHA-256. ES256 (ECDSA P-256, −7) is also allowed **only** for device-held session keys, because TPMs and Apple's Secure Enclave generally lack Ed25519. |
| **FPP-S1H** (long-lived roots) | Build manifests, policies, log tree heads, Verifier/Broker CA certs | `COSE_Sign` with Ed25519 **and** ML-DSA-65 (FIPS 204) |
| **FPP-VRF1** | Outcome randomness | ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) |
| Platform-dictated | Evidence only (Verifier-internal) | TPM AK (RSA-2048 / ECC P-256), Android key attestation (ECDSA P-256), App Attest (ECDSA P-256), SEV-SNP VCEK (ECDSA P-384), TDX quote (ECDSA P-256) |

Rationale: platform evidence algorithms vary and are not ours to choose. The
passport model normalizes them into FPP-S1 tokens at the Verifier, so relying
parties implement exactly one signature algorithm on the hot path.
Post-quantum: confidentiality (harvest-now-decrypt-later of PII and telemetry)
is addressed now via hybrid key exchange. Authenticity of long-lived roots is
hybrid now. Short-lived objects (TTL of seconds to minutes) migrate when
platform and hardware support allows.

## 4. Keys and roles

| Key | Alg | Custody | Lifetime | May sign (`fpp-ctx`) |
|-----|-----|---------|----------|----------------------|
| **Publisher Root** | S1H | Offline HSM, M-of-N ceremony | 10 y | `fpp/1/cert` (intermediates only) |
| **Build Signing** | S1H | HSM, CI-gated | 1 y | `fpp/1/build-manifest` |
| **Policy Signing** | S1H | HSM, two-person | 1 y | `fpp/1/policy` |
| **Verifier AR key** | S1 | Regional HSM | 24 h, certified by Verifier CA | `fpp/1/attestation-result` |
| **Broker SAT key** | S1 | Regional HSM | 24 h | `fpp/1/sat` |
| **Server Liveness key** | S1 | Regional HSM | 24 h | `fpp/1/sar` |
| **Log key** | S1H | HSM | 1 y | `fpp/1/tree-head`, `fpp/1/log-receipt` |
| **Witness key** | S1 (+ML-DSA optional) | Witness operator | 1 y | cosignatures (C2SP tlog-cosignature) |
| **Enforcement key** | S1 | HSM, two-person above thresholds | 90 d | `fpp/1/revocation`, `fpp/1/enforcement-record` |
| **GS instance key** | S1 | Inside GS measured image / CVM, never exported | instance life | `fpp/1/checkpoint`, `fpp/1/host-batch` |
| **GS VRF key** | VRF1 | same as instance key | instance life | VRF proofs only |
| **Device Key** | platform (P-256 or RSA) | TPM / StrongBox / Secure Enclave | device life | evidence only (Verifier) |
| **Session Key** | S1 (P-256 where the hardware requires it) | VBS enclave / TEE / Secure Enclave; software fallback ⇒ tier ≤ D1 | ≤ 1 session | `fpp/1/admit-pop`, `fpp/1/input-commit`, `fpp/1/integrity-report` |

Relying parties learn service keys through a **key bundle** signed by the
Publisher Root chain and fetched per region with a 24 h cache. Rotation overlap
is ≥ 2 × max token TTL.

## 5. Identifiers

| Name | Size | Definition |
|------|------|------------|
| `did` | 32 B | `HMAC-SHA-256(publisher_did_key, hardware_identity)`. `hardware_identity` = TPM EKpub (DER), Android attestation-key chain root-of-trust fields, App Attest key ID, or console device ID. |
| `acct` | 32 B | Pseudonymous account ID for the detection plane |
| `match_id` | 16 B | Random, minted by Broker |
| `slot` | uint16 | Player slot within match |
| `gs_instance_id` | 32 B | `SHA-256(COSE_Key(instance_pub))` |
| `build_id` | 32 B | `SHA-256(build manifest payload)` |
| `policy_ver` | uint | Monotonic per title |
| `epoch` | uint32 | `floor(tick / ticks_per_epoch)` |

## 6. Tokens

### 6.1 Attestation Result (AR): Verifier → IA

EAT profile `tag:fpp,2026:ar/1`. Claim keys: registered CWT/EAT keys where they
exist, private-use keys (< −65536) otherwise.

```cddl
AttestationResult = {
  1 => tstr,                ; iss: verifier id, e.g. "ver.eu-west"
  4 => uint,                ; exp  (≤ iat + 1800)
  6 => uint,                ; iat
  7 => bstr .size 16,       ; cti
  8 => { 1 => COSE_Key },   ; cnf: session public key (RFC 8747)
  10 => bstr .size 32,      ; eat_nonce: echo of Verifier challenge
  265 => "tag:fpp,2026:ar/1", ; eat_profile
  -65601 => bstr .size 32,  ; fpp-did
  -65602 => tier,           ; fpp-tier
  -65603 => features,       ; fpp-features
  -65604 => bstr .size 32,  ; fpp-client-build-id (measured)
  -65605 => tstr,           ; fpp-platform, e.g. "windows", "android"
  -65606 => uint,           ; fpp-policy-ver used for appraisal
  ? -65607 => [* tstr],     ; fpp-warnings (e.g. "os-patch-stale")
}
tier = 0..3                 ; D0..D3
features = {
  ? "secure_boot" => bool, ? "measured_boot" => bool, ? "hvci" => bool,
  ? "vbs" => bool, ? "iommu" => bool, ? "runtime_report" => bool,
  ? "key_in_hw" => bool, ? "os_patch_age_days" => uint,
  ? "strong_integrity" => bool, ? "app_attested" => bool,
}
```

### 6.2 Session Admission Token (SAT): Broker → client

```cddl
SessionAdmissionToken = {
  1 => tstr,                ; iss: broker id
  2 => bstr .size 32,       ; sub: acct
  3 => bstr .size 32,       ; aud: gs_instance_id
  4 => uint,                ; exp (match duration + slack)
  6 => uint,                ; iat
  7 => bstr .size 16,       ; cti
  8 => { 1 => COSE_Key },   ; cnf: same session key as AR
  -65601 => bstr .size 32,  ; did
  -65602 => tier,
  -65620 => bstr .size 16,  ; match_id
  -65621 => uint,           ; slot
  -65622 => tstr,           ; queue
  -65606 => uint,           ; policy_ver
  -65623 => bstr .size 16,  ; ar_cti (links to the AR used)
}
```

### 6.3 Server Attestation Result (SAR): Server Liveness → GS → clients

This is the successor of the prototype's `PlayTicket`. It keeps the hash chain
and the liveness semantics, binds to the TLS key, and says *what* was attested.

```cddl
ServerAttestationResult = {
  1 => tstr,                ; iss: liveness service id
  2 => bstr .size 32,       ; sub: gs_instance_id
  4 => uint,                ; exp (≤ iat + 120)
  6 => uint,                ; iat
  8 => { 1 => COSE_Key },   ; cnf: instance key (signs checkpoints)
  -65640 => bstr .size 32,  ; tls_spki_sha256: TLS leaf SPKI hash
  -65641 => server_class,
  -65642 => bstr .size 32,  ; gs build_id (measured)
  -65643 => tstr,           ; region
  -65644 => uint,           ; seq: strictly increasing per instance
  -65645 => bstr .size 32,  ; prev: SHA-256 of previous SAR payload (chain)
  -65646 => COSE_Key,       ; vrf_pub
}
server_class = &( community: 0, partner: 1, first_party: 2, first_party_cvm: 3 )
```

Clients MUST check: signature chains to the region key bundle; `exp` in the
future (±60 s skew); `tls_spki_sha256` equals the SPKI of the connection's TLS
leaf; `server_class` is allowed by the SAT's queue policy; and `seq`/`prev`
continue the chain on every `SarUpdate`. A gap, fork or expiry means disconnect
(`SAR_LAPSED`).

## 7. Session plane

### 7.1 Connection

- ALPN `fpp/1`. The client MUST validate the GS certificate chain (publisher
  game-server CA) **and** the SAR binding (§6.3). No "insecure" mode exists in
  release builds.
- QUIC transport parameters: `max_datagram_frame_size` ≥ 1200.
- Stream usage:

| Stream | Direction | Content |
|--------|-----------|---------|
| Bidi stream 0 | client-opened | Control messages (§7.2), length-prefixed (QUIC varint) CBOR |
| DATAGRAM | both | `InputFrame` (C→S), `Snapshot` (S→C), title payloads |
| Uni streams | C→S | `InputCommit`, `InputBackfill` |
| Uni streams | S→C | `CheckpointHead` |

Every control message has a hard size cap (default 64 KiB; `IntegrityReport`
256 KiB), enforced **before** allocation.

### 7.2 Control messages

```cddl
ControlMsg = Hello / HelloAck / Admit / Admitted / Reject / SarUpdate /
             IntegrityChallenge / IntegrityReport / BackfillRequest / Kick / Bye

Hello = [ 1, {
  "versions" => [+ uint],            ; supported FPP versions
  "suites"   => [+ tstr],            ; e.g. ["FPP-S1"]
  "features" => uint,                ; feature bits
  "client_build_id" => bstr .size 32,
  "ia_version" => tstr,
} ]

HelloAck = [ 2, {
  "version" => uint, "suite" => tstr, "features" => uint,
  "sar" => COSE_Sign1,               ; current ServerAttestationResult
  "server_nonce" => bstr .size 32,
  "tick_hz" => uint, "ticks_per_epoch" => uint,
} ]

Admit = [ 3, {
  "sat" => COSE_Sign1,               ; SessionAdmissionToken
  "ar"  => COSE_Sign1,               ; AttestationResult (for tier re-check and audit)
  "pop" => COSE_Sign1,               ; by session key, fpp-ctx "fpp/1/admit-pop"
} ]

AdmitPoP = {                         ; payload of "pop"
  "exporter" => bstr .size 32,       ; TLS-Exporter("EXPORTER-fpp-admit", "", 32)
  "hs_hash"  => bstr .size 32,       ; SHA-256(Hello bytes ‖ HelloAck bytes)
  "server_nonce" => bstr .size 32,
  "sat_cti" => bstr .size 16,
}

Admitted = [ 4, { "slot" => uint, "start_tick" => uint } ]
Reject   = [ 5, { "code" => reason, ? "retry_after_s" => uint } ]
SarUpdate = [ 6, { "sar" => COSE_Sign1 } ]      ; at least every exp/2
IntegrityChallenge = [ 7, { "nonce" => bstr .size 32, "types" => uint } ]
IntegrityReport = [ 8, COSE_Sign1 ]             ; payload below; fpp-ctx "fpp/1/integrity-report"
BackfillRequest = [ 9, { "epoch" => uint, "ticks" => [+ uint] } ]
Kick = [ 10, { "code" => reason } ]
Bye  = [ 11, {} ]
```

**GS admission checks (in order, constant-time where relevant):**
1. `sat`: signature (broker key bundle), `aud == own gs_instance_id`,
   `exp`, `match_id` is hosted here, `slot` free.
2. `ar`: signature, `exp`, `cnf` equals `sat.cnf`, `tier ≥` queue minimum
   (re-check, defense in depth), `ar.cti == sat.ar_cti`.
3. `pop`: verify with `cnf`. `exporter` matches this connection. `hs_hash`
   matches this handshake, which provides downgrade protection. `server_nonce`
   matches.
4. Revocation cache: `sat.cti`, `did`, `acct`, `build_id` not revoked.

Failure yields `Reject{code}` and the connection closes. Codes are listed in §11.

### 7.3 Input frames (DATAGRAM)

```text
InputFrame datagram (little-endian, fixed header, not CBOR for size):
  u8   type = 0x01
  u16  slot
  u32  tick            ; the tick this intent is for
  u8   n               ; number of frames (1 + redundancy), n ≤ 8
  n × { u32 tick_i, u16 len_i, len_i bytes payload_i }   ; newest first
```

- The GS accepts at most one payload per `(slot, tick)`, the first to arrive.
  Duplicates with **different** bytes for the same tick are a Signal
  (`INPUT_EQUIVOCATION`).
- Accept window: `[sim_tick − rewind_window, sim_tick + jitter_ticks]`. Frames
  outside it are counted and not applied (AUTH-02).
- Payload semantics are title-defined *intent* (buttons, move axes, view angles
  at input resolution). Never positions or outcomes (AUTH-01).

### 7.4 Input commitments

Once per epoch, the client sends on a uni stream:

```cddl
InputCommit = {                      ; COSE_Sign1 payload, fpp-ctx "fpp/1/input-commit"
  "match_id" => bstr .size 16,
  "slot" => uint,
  "epoch" => uint,
  "first_tick" => uint, "last_tick" => uint,
  "n" => uint,                       ; frames sent in epoch
  "frames_root" => bstr .size 32,    ; MTH over leaves, ascending tick
  "prev" => bstr .size 32,           ; SHA-256 of previous InputCommit (zeros at epoch 0)
}
FrameLeaf = h'00' ‖ u32le(tick) ‖ payload      ; RFC 9162 leaf input
```

The GS recomputes `frames_root` over the frames it received. If ticks are
missing it sends `BackfillRequest` and the client answers with an
`InputBackfill` uni stream carrying the missing `(tick, payload)` pairs. Backfilled
frames are *evidence only*; they are never applied retroactively. A root
mismatch after backfill is a Signal (`COMMIT_MISMATCH`), and both versions are
retained.

This yields **non-repudiation of every input at ~100 bytes/s/player** instead
of a 64-byte signature per packet (the prototype's approach).

### 7.5 Integrity reports

```cddl
IntegrityReportPayload = {           ; fpp-ctx "fpp/1/integrity-report"
  "nonce" => bstr .size 32,          ; from IntegrityChallenge
  "match_id" => bstr .size 16, "slot" => uint,
  "platform_evidence" => bstr,       ; opaque to GS; e.g. Windows runtime report package
  "modules" => [* ModuleResult],
  "ia" => { "version" => tstr, "content_ver" => uint, "uptime_s" => uint },
}
ModuleResult = { "id" => tstr, "ver" => uint, "code" => uint, ? "digest" => bstr .size 32 }
```

- The GS forwards reports to the regional Verifier asynchronously and never
  parses `platform_evidence` (ATT-01).
- **Dual path.** The IA also submits each report directly to the Verifier over
  the control plane. A rogue or buggy GS can therefore delay reports but not
  suppress them. The Verifier notices reports missing on either path.
- Verifier response to the GS: `{slot, verdict: ok | downgrade(tier) | fail, code}`.
  The GS applies the queue policy.

### 7.6 Checkpoint heads

After signing each checkpoint the GS sends `CheckpointHead {match_id, epoch,
digest}` (digest = SHA-256 of the signed Checkpoint) to every client. The IA
keeps the last *N* heads and, after the match, submits a random sample through
`POST /v1/gossip`. The Log answers with an inclusion proof, or with an
equivocation proof if it holds a different checkpoint for the same
`(match_id, epoch)`.

## 8. Evidence plane

### 8.1 Checkpoint

```cddl
Checkpoint = {                        ; COSE_Sign1, GS instance key, fpp-ctx "fpp/1/checkpoint"
  "match_id" => bstr .size 16,
  "gs_instance_id" => bstr .size 32,
  "build_id" => bstr .size 32,
  "policy_ver" => uint,
  "epoch" => uint,
  "ticks" => [uint, uint],            ; inclusive range
  "prev" => bstr .size 32,            ; SHA-256 of previous Checkpoint (zeros at epoch 0)
  "inputs_root" => bstr .size 32,     ; MTH over InputLeaf, ascending slot
  "events_root" => bstr .size 32,     ; MTH over authoritative events, in sim order
  "state_root"  => bstr .size 32,     ; digest of canonical audit-projection state at ticks[1]
  "rng_root"    => bstr .size 32,     ; MTH over VRF proofs issued this epoch
  "roster_root" => bstr .size 32,     ; MTH over (slot, sat_cti, did) admitted
}
InputLeaf = {
  "slot" => uint,
  "commit" => bstr / null,            ; SHA-256 of the client's signed InputCommit, null if absent
  "applied" => bstr,                  ; bitset over ticks: frame applied in time
}
```

- `events_root` leaves are title-defined CBOR events tagged with a registered
  event type (movement resolved, hit confirmed, item granted, and so on).
  Economy events include the Economy Ledger idempotency key (ECO-01).
- `state_root` covers the **audit projection** declared by the title (§7 of
  [03-architecture.md](03-architecture.md)). Large MMO shards MAY use a sparse
  Merkle tree.
- VRF input for roll *k* is
  `"fpp/1/vrf" ‖ match_id ‖ u32le(epoch) ‖ u32le(event_seq) ‖ roll_label`.
  The output drives the roll. The proof becomes a `rng_root` leaf.

### 8.2 Host batch and log

```cddl
HostBatch = {                          ; COSE_Sign1, fpp-ctx "fpp/1/host-batch"
  "host" => bstr .size 32, "seq" => uint, "time" => uint,
  "checkpoints_root" => bstr .size 32, ; MTH over SHA-256(signed Checkpoint), sorted by (match_id, epoch)
  "count" => uint,
}
LogReceipt = {                         ; fpp-ctx "fpp/1/log-receipt"
  "log_id" => bstr .size 32, "leaf_hash" => bstr .size 32,
  "timestamp" => uint, "mmd_s" => uint,
}
```

- The Log is an RFC 9162-style Merkle log served as static tiles (C2SP
  `tlog-tiles`). Tree heads are C2SP `tlog-checkpoint` signed notes, co-signed
  by at least two witnesses (C2SP `tlog-cosignature`), at least one operated
  outside the publisher.
- A `LogReceipt` is a promise of inclusion within `mmd_s`. Failure to include is
  itself provable misbehavior by the log.
- Proof APIs: inclusion (`leaf_hash`, tree size) and consistency (two tree sizes).

### 8.3 Evidence Store

Content-addressed objects keyed by SHA-256: raw frames per `(match, slot,
epoch)`, InputCommits, events, VRF proofs, signed Checkpoints, HostBatches,
LogReceipts. An **Evidence Manifest** per match lists object hashes and is
itself referenced from the last checkpoint's `events_root` (a `match_end`
event). Objects are encrypted per region with envelope keys, and retention is
driven by data class and case holds (PRIV-01, EVD-04).

### 8.4 Audit procedure (normative for Replay Auditor)

For a match, given evidence objects:
1. Verify every Checkpoint signature against the SAR-certified instance key
   that was valid at the time, verify the `prev` chain, verify log inclusion of
   each HostBatch.
2. For each epoch and slot: verify the InputCommit signature (session key from
   the SAT `cnf`), recompute `frames_root`, recompute `InputLeaf`, recompute
   `inputs_root`.
3. Re-simulate from the initial state with *applied* frames only. Recompute
   `events_root`, `state_root`, and verify every VRF proof and output.
4. Any mismatch is emitted as a server Signal with the failing epoch and
   component. Two validly signed, different Checkpoints for one
   `(match_id, epoch)` is an **equivocation proof**, which revokes the instance
   automatically (ENF-02 crypto-proof path).

## 9. Enforcement plane

```cddl
RevocationEvent = {                    ; COSE_Sign1, fpp-ctx "fpp/1/revocation"
  "id" => bstr .size 16,
  "subject" => { "kind" => subject_kind, "id" => bstr },
  "action" => action,
  "scope" => { ? "titles" => [+ tstr], ? "queues" => [+ tstr], ? "regions" => [+ tstr] },
  "effective_at" => uint, ? "expires_at" => uint,
  "reason" => reason,
  "record" => bstr .size 32,           ; hash of enforcement record (in transparency log)
}
subject_kind = &( account: 0, device: 1, session: 2, sat: 3, gs_instance: 4, build: 5 )
action = &( kick: 0, deny_admission: 1, downgrade_tier: 2, segregate: 3,
            suspend: 4, ban: 5, invalidate_match: 6 )
```

- Delivery: regional compacted topic keyed by subject. Brokers and GS keep an
  in-memory exact set for active subjects plus a Bloom filter for fast negative
  checks.
- A GS MUST apply `kick` / `invalidate_match` within 5 s p99 of `effective_at`
  (ENF-03).
- `gs_instance` revocations also go to Server Liveness, which stops SAR renewal.
  Clients drop within one SAR TTL even if the GS ignores the event.

## 10. Control-plane API (summary)

| Endpoint | Caller | Request → Response |
|----------|--------|--------------------|
| `POST /v1/attest/challenge` | IA | `{platform, ia_version}` → `{nonce, exp}` |
| `POST /v1/attest/evidence` | IA | `{nonce, evidence…, session_pub}` → `AttestationResult` |
| `POST /v1/attest/report` | IA (dual path) | `IntegrityReport` → `{ack}` |
| `POST /v1/admission` | client | `{account_token, AR, queue}` → `SAT` + GS endpoint (or queue position) |
| `POST /v1/server/attest` | GS / Host Agent | CVM or measured-boot evidence → `SAR` (then renewed on a stream) |
| `POST /v1/log/add` | Host Agent | `HostBatch` → `LogReceipt` |
| `GET /tile/...`, `/checkpoint` | anyone authorized | C2SP tiles and tree heads |
| `POST /v1/gossip` | IA | sampled `CheckpointHead`s → inclusion or equivocation proofs |

Verifier nonces are single-use (atomic check-and-delete in the regional nonce
store) and expire after 60 s (ATT-02).

## 11. Reason codes (excerpt)

| Code | Name | Meaning |
|------|------|---------|
| 1 | `VERSION_UNSUPPORTED` | No common FPP version |
| 2 | `SAT_INVALID` | Signature, audience, expiry or match mismatch |
| 3 | `AR_INVALID` | AR invalid, expired or `cnf` mismatch |
| 4 | `POP_INVALID` | Proof of possession, exporter or handshake-hash mismatch |
| 5 | `TIER_INSUFFICIENT` | Device tier below queue minimum |
| 6 | `REVOKED` | Subject revoked |
| 7 | `SAR_LAPSED` | Client-side: server liveness expired or chain broken |
| 8 | `INTEGRITY_FAILED` | Runtime attestation failed or missing |
| 9 | `COMMIT_MISMATCH` | InputCommit does not match received frames |
| 10 | `INPUT_EQUIVOCATION` | Conflicting frames for one tick |
| 11 | `POLICY_KICK` | Enforcement action |
| 12 | `SERVER_DRAINING` | Graceful shutdown |

## 12. Versioning and extensibility

- The major version is carried in ALPN (`fpp/1`). Incompatible changes bump ALPN.
- Minor features are negotiated through `features` bits in Hello/HelloAck. The
  negotiated set is covered by `hs_hash` in the PoP, so downgrades are
  detectable.
- Signed objects MAY add fields. Receivers ignore unknown fields **unless** the
  COSE `crit` header lists them.
- Every object carries `fpp-v` in the protected header. Mixed-version
  verification is explicit, never inferred.

## 13. Time

- Tokens use Unix seconds with ±60 s skew tolerance. Services use NTP with
  authenticated sources.
- Inside a match only **ticks** matter. No client-supplied wall-clock value
  enters any validation (AUTH-02). This removes the prototype's `gs_time_ms`
  drift class of bugs.

## 14. Replay and freshness summary

| Object | Replay protection |
|--------|-------------------|
| Evidence | Verifier single-use nonce, 60 s |
| AR | `exp` ≤ 30 min; `cnf`-bound, so useless without the session key |
| SAT | `aud` = one GS instance; `exp`; `cnf`; `cti` revocable |
| Admit PoP | TLS exporter + handshake hash + server nonce: bound to one connection |
| InputFrame | QUIC AEAD + packet numbers; one payload per `(slot, tick)` |
| InputCommit | `(match, slot, epoch)` + `prev` chain |
| IntegrityReport | Challenge nonce |
| SAR | `seq` + `prev` chain + `exp` ≤ 120 s |
| Checkpoint | `(match, epoch)` + `prev` chain + log inclusion |
| RevocationEvent | `id`, idempotent application |

## 15. Security considerations and known limits

1. **Humanness is not attested.** Session keys prove *which attested device*
   produced inputs, not that a human did. Aim assistance through the analog
   hole (T10/T11) is a detection problem (DET-01..03).
2. **Tier D3 attests configuration, not innocence.** Cheats operating inside
   an allowed configuration (same-privilege user-mode tricks, allowed drivers
   with bugs) remain a detection problem. Vulnerable-driver denylists narrow the
   gap.
3. **Rogue host colluding with a cheater** can accept impossible inputs in real
   time. Replay audit (validators run in replay) detects it after the fact, and
   S-Partner hosts are audited 100% for progression-affecting matches.
4. **Log trust** is reduced to "at least one honest witness", as in Certificate
   Transparency.
5. **Metadata privacy.** Checkpoints contain no PII: `did` and `acct` are
   pseudonyms and appear only in `roster_root` leaves, which are stored in the
   regional Evidence Store, not in the public log.
6. **Denial of service.** Every length is capped before allocation; QUIC
   address validation and retry tokens gate GS endpoints; Verifier nonce issuance
   is rate-limited per client address and account.

## Appendix A — Prototype → FPP message mapping

| Prototype (`crates/common/src/proto.rs`) | FPP v1 |
|------------------------------------------|--------|
| `JoinRequest` / `JoinAccept` (GS↔VS) | `POST /v1/server/attest` → `SAR` |
| `PlayTicket` | `ServerAttestationResult` (liveness, chained, TLS-bound) |
| `ClientHello` / `ServerHello` | `Hello` / `HelloAck` + `Admit` / `Admitted` |
| `ClientInput` (signed per input) | `InputFrame` (datagram) + `InputCommit` (signed per epoch) |
| `WorldSnapshot` | title-defined `Snapshot` datagram (interest-managed) |
| `TicketUpdate` | `SarUpdate` (client MUST verify chain) |
| `Heartbeat` + `TranscriptDigest` | `Checkpoint` (single object) |
| `ProtectedReceipt` | `LogReceipt` + witnessed tree head |
| `AuthoritativeEvent` | title events under `events_root` |
| `TpmQuote` (self-nonce) | platform evidence under Verifier nonce → `AttestationResult` |
| `SpendCoins { op_id }` | Economy Ledger mutation with idempotency key; event in `events_root` |
