# 02 — Requirements

Status: Draft v1. Keywords SHALL / SHOULD / MAY per RFC 2119.
Every requirement cites the threats ([01-threat-model.md](01-threat-model.md))
it mitigates. A requirement that mitigates no threat and serves no operational
need does not belong here. The traceability matrix at the end is generated from
these tables.

Verification methods: **R** design/code review · **T** automated test
(unit/integration/property/fuzz) · **P** penetration test / red team ·
**M** production metric with alert · **A** audit (process/legal).

---

## 1. Server authority (AUTH)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| AUTH-01 | The GS SHALL be authoritative for all gameplay state, economy-affecting state and match outcome. Clients send *intents* (input frames), never state. | T01, T05, T23, T24 | R, P |
| AUTH-02 | The server tick SHALL be the only simulation clock. A client may contribute at most one input frame per server tick, plus a bounded jitter buffer (default 4 ticks). Frames for ticks outside `[now − rewind_window, now + jitter]` are dropped and counted as a Signal. | T05, T16 | T |
| AUTH-03 | Lag-compensation rewind SHALL be bounded (title-defined, default ≤ 200 ms), use only server-recorded history, and place the cost of excess latency on the lagging party. | T16 | T |
| AUTH-04 | Titles SHALL declare per-input validation rules (bounds, rates, cooldowns, reachability, line-of-sight for interactions) in the authority kernel. Violations SHALL produce Signals, not only silent drops. | T01, T03, T12 | R, T |
| AUTH-05 | Outcome-affecting randomness (loot, crits, spawns) SHALL be derived with a VRF (RFC 9381) keyed by the GS instance key over protocol-fixed inputs, so auditors can recompute it and hosts cannot grind it. | T20 | T |
| AUTH-06 | Any simulation used for replay auditing SHALL be deterministic: identical inputs and seed yield an identical `state_root` on all supported server platforms. That means ordered collections, fixed-point or controlled floating point with software transcendental functions, and no wall-clock reads. | T20, T36 | T (cross-platform golden replays) |

## 2. Information minimization (INFO)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| INFO-01 | The GS SHALL send an entity's state to a client only if the entity is in that client's potentially-perceivable set (visibility and audibility with a conservative margin for latency), computed server-side. | T02 | T, P |
| INFO-02 | Entities outside direct perception SHOULD be sent with reduced precision or delay. Audio cues SHALL carry only the positional precision a human could perceive. | T02 | R |
| INFO-03 | Spectator and broadcast streams SHALL be delayed by a title-configured interval. | T28 | R |
| INFO-04 | The GS MAY inject honeypot entities that no legitimate rendering path reveals. Player reactions to them produce high-weight Signals. | T02, T03 | T |
| INFO-05 | Client builds SHALL NOT contain server-only data (loot tables, hidden map state, unreleased content keys). | T02 | R |

## 3. Attestation (ATT)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| ATT-01 | Attestation SHALL follow the RATS roles (RFC 9334). Attesters produce Evidence, the Verifier appraises it, and relying parties (Broker, GS) consume only signed Attestation Results in EAT format (RFC 9711). Relying parties SHALL NOT parse raw platform evidence. | T13, T14 | R |
| ATT-02 | Evidence SHALL be bound to a Verifier-issued, single-use nonce (TTL ≤ 60 s) or to a relying-party challenge. The Verifier SHALL reject nonce reuse. | T13 | T, P |
| ATT-03 | Hardware evidence SHALL chain to a platform vendor root: TPM EK certificate to the manufacturer CA (with AK credential activation), the Android attestation root, the Apple App Attest root, the AMD ARK/ASK/VCEK chain, or Intel PCS collateral. The Verifier SHALL consume vendor revocation data. | T14 | T, P |
| ATT-04 | On Windows, appraisal SHALL replay the TCG measured-boot event log against quoted PCRs (not just compare PCR values), and SHALL include `GetRuntimeAttestationReport` driver and code-integrity reports where the OS supports it. | T06, T07, T08, T09 | T |
| ATT-05 | Appraisal policy SHALL include firmware and OS denylists (for example IOMMU pre-boot CVEs), a vulnerable-driver blocklist, and Secure Boot `dbx` currency. | T06, T08, T09 | T, M |
| ATT-06 | Attestation Results SHALL carry a Device Trust Tier (D0–D3) and feature claims, have TTL ≤ 30 min, and be bound (`cnf`) to a session public key held in hardware where available. | T13, T19 | T |
| ATT-07 | Runtime re-attestation SHALL happen at randomized intervals (default 60–180 s) and on server-initiated challenge during a match. Failure SHALL trigger a tier downgrade and the queue's policy action. | T13 | T, M |
| ATT-08 | Game servers outside first-party infrastructure SHALL run in confidential VMs (AMD SEV-SNP or Intel TDX) whose attestation binds the GS instance key. Clients SHALL verify a Server Attestation Result before admission and SHALL disconnect when its liveness lapses. | T20, T21 | T, P |
| ATT-09 | Reference values (build measurements) SHALL come only from the Build Registry: signed, transparency-logged, reproducible where possible, with SLSA Build L3 provenance. | T04, T21, T30 | R, A |
| ATT-10 | The Integrity Agent SHALL measure the game client build identity (code and render-critical assets) and include it in evidence. Unknown builds are rejected for queues at tier D2 and above. | T04, T12 | T |

## 4. Identity (ID)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| ID-01 | Each device SHALL have a non-exportable Device Key generated in hardware (TPM, TEE/StrongBox, Secure Enclave) where available. | T13, T27 | T |
| ID-02 | Device ID SHALL be a keyed pseudonym of the hardware attestation identity, e.g. `DID = HMAC(publisher_key, EK_pub)`. It is stable for bans and unlinkable across publishers. | T27, T32 | R |
| ID-03 | Account↔device bindings SHALL be many-to-many and recorded by the Trust service. Enforcement can target an account, a device, or both. | T27 | R |
| ID-04 | Accounts SHALL support phishing-resistant authentication (passkeys / WebAuthn) and risk-based step-up. High-risk actions (for example trades above a threshold) require step-up. | T26 | T |
| ID-05 | Session keys SHALL be ephemeral per session and bound to the Device Key through the Attestation Result `cnf`. The GS SHALL require proof of possession bound to the TLS exporter. | T19 | T, P |

## 5. Protocol and cryptography (PROTO)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| PROTO-01 | All transport SHALL be QUIC v1 + TLS 1.3 with full certificate validation. "Skip verification" code paths SHALL be compiled out of release builds. | T15, T18 | R, T |
| PROTO-02 | Key exchange SHALL prefer hybrid post-quantum X25519MLKEM768, with classical fallback allowed and counted. | T32 | T, M |
| PROTO-03 | Every signed protocol object SHALL be COSE_Sign1 (RFC 9052) over deterministic CBOR (RFC 8949 §4.2), with a mandatory domain-separation label and protocol version in the protected header. Each key has exactly one purpose. | T13, T36 | R, T |
| PROTO-04 | Bearer tokens SHALL NOT be accepted on the session plane. Tokens are proof-of-possession bound (CWT `cnf`, RFC 8747) and channel-bound. | T19 | T, P |
| PROTO-05 | Version and suite negotiation SHALL be downgrade-protected: negotiated parameters are covered by the admission signature. | T15 | T |
| PROTO-06 | Real-time inputs SHALL use QUIC DATAGRAM frames (RFC 9221) without per-frame signatures. Clients SHALL sign an InputCommit (Merkle root of frames) every epoch (default 1 s). | T20, T36 | T |
| PROTO-07 | Every parser of untrusted input SHALL be memory-safe, check length before allocating, and be fuzzed continuously. | T31, T37 | T (fuzz), R |
| PROTO-08 | Every object SHALL carry algorithm identifiers (crypto agility). Long-lived roots (build signing, log, Verifier CA) SHALL use hybrid Ed25519 + ML-DSA-65 signatures. | T30 | R |

## 6. Evidence and transparency (EVD)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| EVD-01 | Every epoch of every match, the GS SHALL emit a signed Checkpoint containing `inputs_root`, `events_root`, `state_root`, the randomness commitment and the previous checkpoint digest. | T20, T22, T36 | T |
| EVD-02 | Checkpoints, batched per host, SHALL be appended to an append-only Merkle transparency log (RFC 9162 style) with a maximum merge delay (MMD, default 60 s). Tree heads SHALL be co-signed by at least two independent witnesses. | T20, T22, T34, T36 | T, A |
| EVD-03 | Clients SHALL receive checkpoint heads, and the Integrity Agent SHALL submit a random sample to the log for consistency checking. Two conflicting signed checkpoints for the same (match, epoch) are an equivocation proof and SHALL trigger automatic server revocation. | T22 | T |
| EVD-04 | Raw epoch data (input frames, commits, events) SHALL be stored content-addressed in the regional Evidence Store, encrypted at rest, with retention defined per data class. | T36, T32 | R, A |
| EVD-05 | The Replay Auditor SHALL re-simulate 100% of progression-affecting matches on non-first-party hosts, 100% of matches involved in a Case, and a random sample (≥ 1%) of all others. Divergence produces a server Signal. | T20, T23 | M |
| EVD-06 | Every enforcement action and privileged admin operation SHALL be recorded in the transparency log (hash and metadata, no PII). | T34 | A |

## 7. Integrity Agent (IA)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| IA-01 | The IA core SHALL run in user mode. Any kernel component SHALL be optional per title policy, loaded only for the game session and unloaded after it, minimal (no parsing of complex or untrusted formats), and never required for tiers D0–D2. | T31, T32 | R, P |
| IA-02 | Detection content SHALL ship as signed, versioned, sandboxed WebAssembly modules running in a capability-restricted runtime with bounded host APIs (time, memory, calls). | T30, T31 | R, T |
| IA-03 | Content rollout SHALL be staged in rings (0.1% → 1% → 10% → 100%) with automatic rollback on crash or performance regression, and a kill switch per module. | T30 | M |
| IA-04 | The IA SHALL keep its keys in hardware (TPM, VBS enclave, TEE) and sign IntegrityReports. IA integrity is established by attestation, not by self-checks alone. | T13 | P |
| IA-05 | The IA SHALL collect only the data its active modules need. Raw process or module inventories leave the device only on documented high-confidence triggers. | T32 | A |
| IA-06 | IA overhead SHALL stay within ≤ 1% average CPU, ≤ 50 MB RAM, and no frame-time spikes above 1 ms at p99. | — (ops) | M |

## 8. Detection (DET)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| DET-01 | Detection SHALL combine multiple sources: server validators, information-use analysis, aim/input kinematics models, IA signals, economy/graph analytics, player reports, honeypots and threat intelligence. | T02, T03, T10, T11, T25, T28 | R |
| DET-02 | The GS SHALL compute per-player information-use features, such as engagement with entities outside the perceivable set and pre-aiming at occluded targets. | T02 | T |
| DET-03 | Aim and input kinematics models SHALL be trained on labeled data (reviewer verdicts, confirmed cheats), run server-side only, and be proven in shadow mode before they may drive enforcement. | T03, T10, T11, T35 | M |
| DET-04 | Every model and rule SHALL have a registered owner, a version, an evaluation report (precision at the operating point, sliced by region, platform and input device) and drift monitoring. | T33 | A, M |
| DET-05 | Economy analytics SHALL run on the ledger: graph features, velocity, circular trades, bot periodicity. | T24, T25 | M |

## 9. Enforcement (ENF)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| ENF-01 | Enforcement subjects SHALL be: account, device, session, server instance, build. Actions SHALL be: warn, trust-tier downgrade, pool segregation, match invalidation, suspension, ban, device ban, asset rollback. | T25, T27 | R |
| ENF-02 | Automated permanent bans SHALL require at least two independent signal families *or* one cryptographic proof (for example an attested cheat driver, or checkpoint equivocation). Anything else goes to human review. | T33 | R, M |
| ENF-03 | Revocations SHALL reach every GS and broker in the region within 5 s p99 by push, and are bounded by credential TTL even without push. | T20, T37 | M |
| ENF-04 | Enforcement timing SHALL be policy-driven per detection vector: immediate in-match mitigation for blatant cheats, delayed waves for signature detections. | T35 | R |
| ENF-05 | Appeals SHALL be supported with an evidence package that verifies against the transparency log. | T33, T36 | A |
| ENF-06 | Privileged enforcement and grant operations above thresholds SHALL require two-person approval and be logged per EVD-06. | T34 | A |

## 10. Economy (ECO)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| ECO-01 | Economy mutations SHALL execute in a transactional double-entry ledger service, never in GS memory. Every mutation has an idempotency key and provenance (match, epoch, event). | T23, T24 | T |
| ECO-02 | Only first-party servers, or partner servers under 100% replay audit, may request economy mutations. Community servers never may. | T20 | R |
| ECO-03 | Provenance SHALL allow clawback of assets derived from an exploit or cheat. | T24, T25 | T |

## 11. Network abuse (NET)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| NET-01 | Player IP addresses SHALL never be exposed to other players. P2P and voice traffic goes through relays. | T17 | P |
| NET-02 | GS endpoints SHALL sit behind DDoS scrubbing / anycast and use QUIC address validation with stateless retry tokens. Admission is token-gated. | T17, T37 | P |

## 12. Security of the anti-cheat system itself (SEC)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| SEC-01 | All AC code SHALL be memory-safe by default (Rust). Non-memory-safe code is limited to the exception surfaces listed in [ADR-001](06-adr-001-language.md), each size-capped, with extra review, fuzzing and static analysis. | T31 | R |
| SEC-02 | Builds SHALL be reproducible where possible, with SLSA L3 provenance. Binaries and content are signed, and signatures and manifests go into the transparency log. | T21, T30 | A |
| SEC-03 | Signing keys SHALL live in HSMs, roots offline, with documented key ceremonies and a rotation schedule. | T30, T34 | A |
| SEC-04 | A public bug bounty SHALL cover the Integrity Agent and the protocol. | T31 | A |

## 13. Privacy and compliance (PRIV)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| PRIV-01 | A data inventory SHALL record purpose, legal basis and retention per data class, with a DPIA per title and region. | T32 | A |
| PRIV-02 | Telemetry and evidence SHALL stay in the player's region. Only aggregated or pseudonymous features cross regions. | T32 | A |
| PRIV-03 | The detection pipeline SHALL use pseudonymous identifiers. Re-identification happens only inside access-controlled case management. | T32, T34 | R |
| PRIV-04 | What the IA collects and when it runs SHALL be publicly documented. Any kernel component runs only during play. | T32 | A |
| PRIV-05 | Minors: the applicable age-appropriate design codes SHALL be followed, with no collection beyond necessity. | T32 | A |

## 14. Operations and scale (OPS)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| OPS-01 | Each regional cell SHALL be self-sufficient for admission, verification, logging and ingestion. A regional failure does not affect other regions. | T37 | P (game days) |
| OPS-02 | No external call SHALL occur in the per-tick path. Admission adds ≤ 1 RTT to the regional broker, and the Attestation Result cache hit rate is ≥ 95%. | — (ops) | M |
| OPS-03 | Fail modes SHALL be per-queue policy: `fail_closed` (ranked, tournament) or `fail_open_degraded` (casual: admit at D0 into a segregated pool). Never silently fail open. | T37 | T, R |
| OPS-04 | Availability SHALL be: Verifier and Broker 99.99% per region; log append 99.9% with local buffering ≥ 2 × MMD; enforcement feed 99.95%. | T37 | M |
| OPS-05 | The capacity design point SHALL be 10 M CCU globally and 10 k admissions/s peak, with linear scale-out. | — (ops) | T (load) |
| OPS-06 | Every Signal, Detection and Action SHALL be traceable to evidence IDs. | T33, T36 | R |

## 15. Platforms (PLAT)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| PLAT-01 | Windows, macOS, Linux/Steam Deck, Android, iOS, consoles and cloud gaming SHALL be supported through per-platform attestation adapters that produce the *same* Attestation Result format. | T13, T14 | T |
| PLAT-02 | Each queue SHALL declare a minimum device tier per platform. Players below the tier are matched into segregated pools rather than excluded, unless title policy excludes them. | T02, T06, T08, T33 | R |
| PLAT-03 | The SDK SHALL be engine-agnostic, exposed through a stable C ABI plus thin engine plugins (Unreal, Unity, Godot, custom). | — (ops) | T |

## 16. Governance (GOV)

| ID | Requirement | Threats | Verify |
|----|-------------|---------|--------|
| GOV-01 | Each automated action type SHALL have a false-positive budget approved by its policy owner (initial target for automated permanent bans: ≤ 1 per 100 k actions), measured through appeal outcomes and audit samples. | T33 | M, A |
| GOV-02 | Known assistive tools and devices SHALL be evaluated before detections that could affect them ship. | T33 | A |
| GOV-03 | Access to detection logic SHALL be need-to-know. Server-side models never ship to clients. | T34, T35 | A |

---

## 17. Non-functional targets (summary)

| Dimension | Target | Source |
|-----------|--------|--------|
| In-match added latency from anti-cheat | 0 RTT (nothing external in the tick path) | OPS-02 |
| Admission overhead | ≤ 1 RTT to regional broker; AR cache hit ≥ 95% | OPS-02 |
| Revocation → kick | ≤ 5 s p99 (push), ≤ AR/SAR TTL worst case | ENF-03 |
| Evidence finality | Checkpoint in log ≤ MMD (60 s) | EVD-02 |
| Client overhead | ≤ 1% CPU, ≤ 50 MB, ≤ 1 ms p99 frame spike | IA-06 |
| GS overhead (validation + checkpointing) | ≤ 5% CPU per match | budget, see [03](03-architecture.md) |
| Bandwidth overhead (commits, reports) | ≤ 2% of game traffic | PROTO-06 |
| Automated permanent-ban FP | ≤ 1 / 100 k (initial) | GOV-01 |

## 18. Traceability matrix (threat → requirements)

Generated from the tables above. A threat with no requirement is a gap. T29 is
out of scope, and T01/T05 are closed mostly by AUTH-01/02.

<!-- TRACE-MATRIX:BEGIN -->
| Threat | Name | Requirements |
|--------|------|--------------|
| T01 | Memory write | AUTH-01, AUTH-04 |
| T02 | Memory read | INFO-01, INFO-02, INFO-04, INFO-05, DET-01, DET-02, PLAT-02 |
| T03 | Aimbot / triggerbot | AUTH-04, INFO-04, DET-01, DET-03 |
| T04 | Code injection, hooking, modified binaries or assets | ATT-09, ATT-10 |
| T05 | Speedhack / time manipulation | AUTH-01, AUTH-02 |
| T06 | Kernel-mode cheats | ATT-04, ATT-05, PLAT-02 |
| T07 | Hypervisor / VM-based cheats | ATT-04 |
| T08 | DMA cheats, including pre-boot DMA | ATT-04, ATT-05, PLAT-02 |
| T09 | Boot / firmware cheats | ATT-04, ATT-05 |
| T10 | External computer-vision aimbots | DET-01, DET-03 |
| T11 | Input device spoofing / emulation | DET-01, DET-03 |
| T12 | Headless clients / protocol bots | AUTH-04, ATT-10 |
| T13 | AC tampering | ATT-01, ATT-02, ATT-06, ATT-07, ID-01, PROTO-03, IA-04, PLAT-01 |
| T14 | Emulated attestation | ATT-01, ATT-03, PLAT-01 |
| T15 | Packet tampering, injection, replay | PROTO-01, PROTO-05 |
| T16 | Lag switching / selective delay to exploit lag compensation or desync | AUTH-02, AUTH-03 |
| T17 | DDoS against game servers or players | NET-01, NET-02 |
| T18 | MITM / fake server / local proxy cheats | PROTO-01 |
| T19 | Token theft / session hijack / relay | ATT-06, ID-05, PROTO-04 |
| T20 | Rogue GS | AUTH-05, AUTH-06, ATT-08, PROTO-06, EVD-01, EVD-02, EVD-05, ENF-03, ECO-02 |
| T21 | Compromised GS binary or build pipeline | ATT-08, ATT-09, SEC-02 |
| T22 | Split view | EVD-01, EVD-02, EVD-03 |
| T23 | Server logic exploits | AUTH-01, EVD-05, ECO-01 |
| T24 | Duplication via replay, race, or failed idempotency | AUTH-01, DET-05, ECO-01, ECO-03 |
| T25 | Botting, gold farming, RMT | DET-01, DET-05, ENF-01, ECO-03 |
| T26 | Account takeover, account trading, smurfing, boosting | ID-04 |
| T27 | Ban evasion | ID-01, ID-02, ID-03, ENF-01 |
| T28 | Collusion | INFO-03, DET-01 |
| T29 | Payment fraud / chargebacks | **GAP** |
| T30 | Supply-chain attack on AC updates or detection content | ATT-09, PROTO-08, IA-02, IA-03, SEC-02, SEC-03 |
| T31 | Vulnerability in a privileged AC component used for privilege escalation | PROTO-07, IA-01, IA-02, SEC-01, SEC-04 |
| T32 | Privacy harm, over-collection, legal non-compliance | ID-02, PROTO-02, EVD-04, IA-01, IA-05, PRIV-01, PRIV-02, PRIV-03, PRIV-04, PRIV-05 |
| T33 | False positives / mass false bans | DET-04, ENF-02, ENF-05, OPS-06, PLAT-02, GOV-01, GOV-02 |
| T34 | Insider abuse | EVD-02, EVD-06, ENF-06, SEC-03, PRIV-03, GOV-03 |
| T35 | Detection feedback loop | DET-03, ENF-04, GOV-03 |
| T36 | Evidence tampering or repudiation | AUTH-06, PROTO-03, PROTO-06, EVD-01, EVD-02, EVD-04, ENF-05, OPS-06 |
| T37 | DoS on AC backend to force fail-open | PROTO-07, ENF-03, NET-02, OPS-01, OPS-03, OPS-04 |
<!-- TRACE-MATRIX:END -->
