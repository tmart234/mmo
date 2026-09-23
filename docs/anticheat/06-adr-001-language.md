# ADR-001 — Implementation language: Rust by default, C/C++ only at forced boundaries

- **Status:** Proposed
- **Date:** 2026-09-23
- **Question:** *"Should the whole codebase be Rust, or do we need any C/C++?"*

## Decision (one paragraph)

Write **everything we own in Rust**: every backend service, the Game Server
authority kernel, the protocol and crypto core, the Integrity Agent core, the
detection-module sandbox, the SDK core and all tooling. Use **C/C++ only where
a platform forces it**, as thin, size-capped adapters with extra controls: engine
plugin glue, the *optional* Windows kernel component (today), the VBS enclave
(today), and console SDK shims under NDA. Each such surface has an explicit exit
criterion for moving to Rust. Kotlin and Swift are used for mobile attestation
APIs, and Python only for offline ML training. Expected split: **≈ 90–95% Rust
by lines of code**, the rest glue.

## Context

What makes anti-cheat unusual when choosing a language:

1. **It runs privileged, on millions of machines, and parses hostile input.**
   Packets, attestation evidence (ASN.1, TPM structures, TCG logs), replays and
   content updates all come from adversaries or cross trust boundaries.
2. **The anti-cheat is itself a prime target** (T30, T31). A memory-corruption
   bug in an AC component is a privilege-escalation primitive for malware:
   - In 2022 ransomware operators loaded a legitimately signed anti-cheat driver
     (`mhyprot2.sys`) to kill security software.
   - In July 2024 an out-of-bounds read in a kernel-mode security product's
     content interpreter, triggered by a content update, crashed roughly 8.5 M
     Windows machines. That is our architecture too: privileged agent plus
     frequently pushed content.
3. **Memory safety is the dominant bug class** in systems code. Microsoft and
   the Chromium project have both reported that about 70% of their serious
   security bugs are memory-safety issues.
4. **Signer and verifier must agree byte-for-byte** on canonical encodings for
   every signed object (tokens, commits, checkpoints). Two implementations in
   two languages is how signature-mismatch bugs happen.
5. **It must integrate with C++ engines (Unreal, custom), C# (Unity) and NDA
   console toolchains**, and run on Windows, macOS, Linux, Android, iOS and
   consoles.
6. **The hot path has hard deadlines** (tick budgets), so no GC pauses.
7. **The existing prototype and team are already Rust** (quinn, rustls,
   ed25519-dalek, Bevy).

## Per-component decision

| Component | Language | Notes |
|-----------|----------|-------|
| Verifier, Broker, Server Liveness, Log, Auditor, Ingest, Scorers, Case, Enforcement, Ledger | **Rust** | Evidence parsers are the highest-risk code in the system. Rust plus continuous fuzzing. |
| Game Server authority kernel + Host Agent | **Rust** | Title gameplay code may be any language behind the `AuthorityRules` trait / C ABI. The audit projection must be deterministic. |
| Protocol (`fpp-*` crates): CBOR/COSE, tokens, Merkle, suites | **Rust** | One implementation, compiled into client SDK, GS and services. |
| Integrity Agent core (user mode) | **Rust** | Exposed through a C ABI (`extern "C"`, headers generated with cbindgen). |
| Detection modules | **Rust → WebAssembly** | Run in wasmtime (itself Rust), capability-restricted. Sandboxing, not language, is what contains a bad content push. |
| Engine plugins | **C++ (Unreal)**, **C# (Unity)**, GDExtension (Godot) | Glue only, ≤ ~2 k LOC per engine, over the C ABI. |
| Windows kernel component (optional, per title) | **C** today → Rust later | See exception E2. |
| VBS enclave (session-key custody, report signing) | **C++** today → Rust later | See exception E3. |
| Android attestation adapter | **Kotlin** | Play Integrity and Keystore key attestation are Java/Kotlin APIs. Bridged to Rust with UniFFI/JNI. |
| Apple attestation adapter | **Swift** | App Attest, Secure Enclave. Bridged to Rust with UniFFI. |
| Console adapters | **C/C++** (NDA toolchains) | See exception E4. |
| ML training and research | **Python** | Offline only, never in a runtime trust path. Models export to ONNX; server-side inference runs in Rust. |
| Reference client (`client-bevy`) | **Rust** | Test harness and reference only. The AC SDK must not depend on Bevy. |

## Exceptions (forced C/C++ surfaces)

Each exception gets: a size cap, mandatory extra review, static analysis,
fuzzing of its interface, and an **exit criterion**.

| ID | Surface | Why not Rust today | Cap | Controls | Exit criterion |
|----|---------|--------------------|-----|----------|----------------|
| **E1** | Engine plugin glue (Unreal C++, Unity C#) | Engines' extension APIs are C++/C# | ~2 k LOC per engine | Generated bindings, no logic beyond marshalling | n/a (permanent, by design) |
| **E2** | Windows kernel component (optional) | As of 2026 `windows-drivers-rs` is described as *not yet recommended for production*, the kernel Rust target is not in upstream Rust, and no third-party Rust driver is known to have shipped through WHCP | ~5 k LOC, C (not C++) | WDK + SAL annotations, CodeQL driver queries, Static Driver Verifier, Driver Verifier, IOCTL fuzzing. **No parsing of complex or untrusted formats in kernel.** | Rust driver target and tooling supported for third-party WHCP submission. Re-evaluate every 6 months. |
| **E3** | VBS enclave DLL | Microsoft's VBS enclave tooling and samples are C++ | ~3 k LOC | Same as E2 plus enclave attestation tests | Supported Rust (`no_std`) enclave target |
| **E4** | Console platform shims | NDA SDKs are C/C++. Rust is not a first-class, platform-holder-supported language on every console. | adapter only | Platform-holder cert requirements, shared C ABI to the Rust core where the toolchain allows | Per platform, confirmed with each platform holder under NDA |
| **E5** | Consumed C/C++ libraries (aws-lc for FIPS crypto, tpm2-tss via `tss-esapi`, ONNX Runtime if chosen) | Mature, certified, or vendor-standard | n/a (not authored by us) | Pinned versions, SBOM, `cargo-deny`/`cargo-vet`, fuzz our wrappers | Adopt pure-Rust equivalents when mature, e.g. pure-Rust TPM command marshalling, or tract/candle for inference |

The kernel component itself is **optional by architecture** (see
[03-architecture.md](03-architecture.md) §6). On D3 Windows the OS attests
kernel integrity (`GetRuntimeAttestationReport`: signed by the Secure Kernel,
driver + code-integrity reports, requires TPM 2.0, Secure Boot, VBS, HVCI and
IOMMU). Most titles should never ship E2 at all, which removes the largest
C surface entirely.

## Things that do *not* justify C/C++

| Claim | Why it does not hold |
|-------|----------------------|
| "Engines are C++, so the SDK must be C++." | A C ABI is the universal boundary. C++ and C# wrappers are generated. |
| "Obfuscation / anti-tamper tools need C++." | Binary-level protectors (virtualization, packing) operate on compiled PE/ELF and are language-agnostic. LLVM-IR obfuscation passes can be applied to Rust via a custom toolchain. Our security does not depend on obfuscation anyway: attestation, server authority and protocol cryptography do the real work. |
| "Memory scanning needs C." | Rust reads raw memory in narrow, audited `unsafe` modules. WASM modules get it through host functions. |
| "C++ is faster." | Performance parity in practice, no GC, and zero-cost FFI. Tick-path hot loops are equally optimizable. |
| "Easier hiring." | Real, but mitigated: engine teams keep writing gameplay in C++/C#; the AC/protocol team is small and already Rust. |

## Engineering rules that come with this decision

1. `#![forbid(unsafe_code)]` in every crate except designated `*-sys` / `*-ffi`
   / `ia-platform-*` crates. Those need `unsafe` review sign-off, and Miri
   where applicable.
2. Supply chain: `cargo-deny` (licenses, advisories, sources), `cargo-vet`
   (audited deps), `cargo-audit` in CI as a **failing** gate. Today's CI runs
   it with `|| true`.
3. Fuzzing: `cargo-fuzz` targets for every parser of untrusted input (CBOR/COSE
   decoding, evidence formats, datagram decoding), run continuously.
   Property tests (proptest) for Merkle/proof code. Model checking (Kani) for
   size and bounds logic in decoders.
4. Crypto provider: move rustls/quinn from `ring` to **aws-lc-rs**. That enables
   `X25519MLKEM768` (preferred when `prefer-post-quantum` is on) and gives a
   FIPS-validated build option.
5. Deterministic simulation code (audit projection) forbids `HashMap` iteration,
   wall-clock reads and platform-dependent float intrinsics (lint + CI golden
   replays across x86-64 and aarch64).
6. The C ABI is versioned (`fpp_sdk_v1_*` symbols), with an ABI-compat CI job.

## Consequences

**Positive:** one language across the trust-critical path, a structurally
eliminated memory-safety bug class in the highest-risk code (evidence parsers,
protocol decoders, content sandbox), one canonical-encoding implementation,
and it continues the existing investment.

**Negative / costs:** cross-compilation matrix complexity (Windows, macOS,
Linux, Android via cargo-ndk, iOS via xcframework, consoles); FFI boundary
design discipline; the kernel and enclave exceptions remain C/C++ until
tooling matures; a training ramp for engine-side integrators (mitigated by
the C ABI).

**Review triggers:** WHCP accepts third-party Rust drivers; Microsoft ships a
user-mode anti-tamper/handle-protection API that makes E2 unnecessary;
console platform holders publish official Rust support.
