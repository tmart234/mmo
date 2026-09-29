# Anti-Cheat System Design

A threat-driven design for a production anti-cheat **protocol, framework and
system** covering all online titles and platforms, worldwide. Written against
the current prototype in this repo, and meant to replace its ontology while
keeping its best ideas.

| # | Document | Answers |
|---|----------|---------|
| 01 | [Threat model](01-threat-model.md) | Who attacks us, how, and where each attack can be stopped |
| 02 | [Requirements](02-requirements.md) | What the system must do, each requirement traced to threats |
| 03 | [Architecture](03-architecture.md) | Components, planes, trust tiers, flows, deployment, failure modes, capacity |
| 04 | [Protocol (FPP v1)](04-protocol.md) | Wire-level spec: encoding, crypto suites, keys, tokens, messages, checkpoints, revocation |
| 05 | [Ontology review and proposal](05-ontology.md) | *Is the ontology good?* What to keep, what is wrong, the replacement vocabulary |
| 06 | [ADR-001: Language](06-adr-001-language.md) | *Rust or C/C++?* |
| 07 | [Gap analysis and roadmap](07-gap-analysis-and-roadmap.md) | Security findings in current code, coverage, phased plan |
| 08 | [Reference title: Halo: CE](08-reference-title-halo.md) | Using the Halo decompilation port as the first real game: netcode security review, FPP hook points, staged plan |
| 09 | [ADR-002: Transport per plane](09-adr-002-transport.md) | *Is QUIC the most efficient transport?* Encrypted UDP for native game data, QUIC for browsers and the control plane |

## Executive summary

**The threat analysis drives everything.** Across genres and platforms the
damage comes mostly from (a) information cheats (ESP/wallhack), (b) aim
assistance, including hardware and computer-vision aimbots that no on-device
software can see, (c) bots and economy abuse in MMOs, and (d) ban evasion.
Cheating is a business, so the design targets its economics: expensive
identities, durable bans and a slow feedback loop for cheat developers.

**Five layers, strongest first:**
1. **Don't trust, don't send.** Server authority for all state, and
   interest management so hidden enemies never reach the client.
2. **Attest the platform, not the agent.** Hardware- and OS-rooted evidence
   (TPM 2.0, Windows runtime attestation with HVCI/VBS/IOMMU, Play Integrity,
   App Attest, console platforms, SEV-SNP/TDX for servers) is appraised by one
   Verifier and turned into short-lived signed results with device trust tiers.
3. **Detect behavior everywhere.** Server-side behavioral and
   information-use detection is the only layer that works on every platform and
   against the analog hole.
4. **Make every claim verifiable.** Client-signed input commitments, signed
   per-epoch Merkle checkpoints, and a witnessed transparency log. This holds up
   against rogue hosts, lying players and insiders.
5. **Enforce correctly, then quickly.** Multi-signal verdicts, human review,
   delayed waves where they protect detection, appeals backed by evidence.

**What is new relative to 2020-era anti-cheat:** attestation-first (Windows
`GetRuntimeAttestationReport`, required configurations like Secure Boot + TPM
2.0 + HVCI + IOMMU, firmware CVE policy after the 2025 pre-boot DMA findings),
kernel components optional and on-demand, detection content as sandboxed
WebAssembly (containing the blast radius of a bad push), transparency logs and
equivocation proofs borrowed from Certificate Transparency, VRF-verifiable
randomness, hybrid post-quantum transport, and confidential-VM game servers for
third-party hosting.

**Is the ontology good?** Good mechanisms, immature ontology. Keep liveness
tickets, ephemeral keys, signed inputs, notarized transcripts and idempotency
keys. Replace the single "VS" god object, the split Heartbeat/TranscriptDigest
commitment and the self-reported attestation model, and add the missing domain
(accounts, devices, tiers, signals, cases, verdicts, actions). Details in
[05](05-ontology.md).

**Rust or C/C++?** Rust for everything we own (about 90–95%). C/C++ only where
a platform forces it: engine plugin glue, an *optional* Windows kernel
component and the VBS enclave (both until Rust driver/enclave tooling is
production-supported), and console SDK shims. Details in
[ADR-001](06-adr-001-language.md).

**Most urgent code fixes:** disabled TLS verification (F01), GS not pinning
the VS key (F02) and clients not re-verifying ticket updates (F03). Together
they allow a revoked server to keep serving. See [07](07-gap-analysis-and-roadmap.md) §1.

## References

Standards: RFC 9334 (RATS architecture), RFC 9711 (EAT), RFC 8392 (CWT),
RFC 8747 (CWT proof-of-possession), RFC 9052 (COSE), RFC 8949 (CBOR),
RFC 8610 (CDDL), RFC 9162 (Certificate Transparency v2), RFC 9221 (QUIC
DATAGRAM), RFC 9381 (VRF), RFC 8446 (TLS 1.3), FIPS 204 (ML-DSA), C2SP
`tlog-tiles` / `tlog-checkpoint` / `tlog-cosignature`, SLSA v1.

Platform and industry facts used in the threat model and ADR (checked September 2026):
- Windows runtime attestation API: [GetRuntimeAttestationReport (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getruntimeattestationreport)
- VBS enclaves for third-party apps: [Microsoft Tech Community](https://techcommunity.microsoft.com/blog/windowsosplatform/securely-design-your-applications-and-protect-your-sensitive-data-with-vbs-encla/4179543)
- Pre-boot DMA / IOMMU firmware flaw (CVE-2025-11901, -14302, -14303, -14304): [Riot Games](https://www.riotgames.com/en/news/vanguard-security-update-motherboard), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-uefi-flaw-enables-pre-boot-attacks-on-motherboards-from-gigabyte-msi-asus-asrock/)
- Vanguard on-demand loading and runtime attestation on Windows 11 25H2: [FinalBoss.io](https://finalboss.io/valorant-s-anti-cheat-finally-chills-out-but)
- TPM 2.0 + Secure Boot requirements: [Activision Ricochet (BO7)](https://www.callofduty.com/blog/2025/09/call-of-duty-black-ops-7-beta-ricochet-anti-cheat-update), [Battlefield 6 / Javelin (Tom's Hardware)](https://www.tomshardware.com/video-games/battlefield-6s-javelin-anti-cheat-secure-boot-requirement-could-kill-its-steam-deck-support)
- Kernel-driver direction: [Driver Quality Initiative, May 2026 (The Register)](https://www.theregister.com/oses/2026/05/15/microsoft-puts-stability-in-the-drivers-seat-with-new-initiative/5241381), [Windows Resiliency Initiative (Cybersecurity Dive)](https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/)
- Rust Windows drivers status: [microsoft/windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs), [field guide (2026)](https://paragmali.com/blog/rust-in-the-windows-kernel-a-field-guide-to-the-2024-2026-me/)
- Play Integrity hardware-backed verdicts (May 2025): [Android Developers Blog](https://android-developers.googleblog.com/2025/10/stronger-threat-detection-simpler.html), [verdicts](https://developer.android.com/google/play/integrity/verdicts)
- rustls post-quantum key exchange: [docs.rs/rustls](https://docs.rs/rustls)
