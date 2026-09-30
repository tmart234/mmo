# 08 — Reference Title: Halo: CE (decompilation port)

Status: Draft v1 · Reviewed sources: [bnunu/halo-1](https://github.com/bnunu/halo-1)
(`93f8ec8`) and [bnunu/halo-ce-universal](https://github.com/bnunu/halo-ce-universal)
(`3ba97dd`), both shallow clones read on 2026-09-29.

**Why a reference title?** The framework needs a real game to prove itself
against. The Halo: CE decompilation and its native port are an unusually good
fit:

| Property of the port | Why it matters for this framework |
|----------------------|-----------------------------------|
| **Full C source** (decompiled Xbox build 2342, ~405 k lines) plus a native port for Linux, Windows and Android | No reverse engineering or binary hooking. Integration is ordinary C code calling our SDK through its C ABI (ADR-001, exception E1). |
| **Player-hosted, serverless internet play**: invite links, public MQTT signalling, UDP hole punching, up to 128 players (`port/linux/src/p2p.c`) | The host *is a player*. That is the prototype's original **rogue-host** scenario (T20–T22) in its purest form. |
| **Deterministic engine**: the Xbox game ran in lockstep, and the port keeps identical math on every platform (`musl-math`, `port/include/halo_math.h`) | The **Replay Auditor** (AUTH-06, EVD-05) is feasible without rewriting the simulation. |
| **Two netcodes**: original lockstep and the new "distributed" model (`port/linux/NETCODE.md`) | We can study both the classic and the modern (client-predicted, host-authoritative, shooter's-hits) threat surfaces. |
| **Built-in test harness**: `debug.network_test`, scripted bots (`debug.test_input`), latency and loss simulation, per-second state logs | Reproducible red-team tests and false-positive soak tests. |
| **Existing hooks**: machine blacklist rejection code, join tokens, saved films | Natural attachment points for enforcement and evidence. |

It is a shooter, which effectively answers open question 1 in
[07](07-gap-analysis-and-roadmap.md) §5: shooter-first. Its player hosting
answers question 2: rogue hosts are a primary threat, not a later phase.

---

## 1. Evaluating the pasted analysis

The analysis you pasted gets the big picture right: the protocol is not a
drop-in, and game integration is greenfield. Several specifics are outdated or
point in the wrong direction, measured against the code and the design in
[03](03-architecture.md) / [04](04-protocol.md).

| Claim in the analysis | Assessment |
|-----------------------|------------|
| "It is written in Rust, not C++" | ✓ Correct for `mmo`. The *game* is C, so integration needs a C ABI (ADR-001 E1). |
| "`client_binding` is a placeholder of zeros" | ✓ Correct (`vs/src/streams.rs:47,58`, finding F10). FPP replaces it with PoP-bound SATs. |
| "Game integration and client-side work is essentially greenfield" | ✓ Correct. |
| "The VS currently does not verify TPM quotes — it only accepts them" | ✗ **Outdated.** That is what `TPM_GUIDE.md` says, but `vs/src/admission.rs:115` *does* call `verify_quote`. The problem is that it verifies the wrong things: an attester-chosen nonce, no EK chain, and Ed25519-only AKs, so real TPM quotes can never pass (F04, F05). That is worse than "not implemented", because it *looks* implemented. |
| "The protocol and attestation logic are the most mature parts" | ✗ The QUIC plumbing and hash chaining are solid. The protocol itself has a revocation-bypass chain (F01 + F02 + F03), and attestation is self-reported (F06). Neither is ready to wrap a real game until P0/P1 of the roadmap. |
| "Wrap game traffic (positions, inputs, world state) in the PlayTicket/heartbeat envelope" | ✗ **Wrong layering.** Tickets are *server-liveness* credentials, not a per-packet envelope. Per-message signatures on 30 Hz traffic are what FPP replaces with unsigned datagram frames plus signed per-epoch **InputCommits** (04 §7.3–7.4). The port already tunnels its whole system-link protocol, so integration belongs at the **tunnel** and **evidence** layers, not inside every game message. |
| "Tune the VS speed check for Halo's movement model" | ✗ The trust root must not know game physics (05 §2.3). In Halo the host already has the authoritative position. The check belongs in the host (and is currently too permissive, see H01), with the Replay Auditor after the fact. |
| "Port Halo's rendering into Bevy, or hook the client by reverse engineering" | ✗ Neither is needed: the decomp and port give full source. `client-bevy` stays the framework's own reference client. |
| "Implement `HardwareTpm` with tpm2-tss for real hardware trust" | ◐ Direction is off. Halo hosts are players' PCs, so a TPM on "the GS" is not the lever. What matters is (a) device attestation for *verified* playlists through the Verifier (Windows runtime report + TPM, Android Play Integrity; Linux stays D0), and (b) accountability for hosts through evidence and replay. |
| "Heartbeats with `session_id, gs_counter, receipt_tip, sw_hash` in the game loop" | ✗ Superseded: FPP v1 uses a single signed **Checkpoint** per epoch (04 §8.1). |
| "Key distribution, rotation, revocation" | ✓ Needed. Specified in 04 §4. |
| "Prometheus monitoring of heartbeats and revocations" | ◐ Fine for services. For P2P Halo the equivalent is host and client **Signals** into detection. |
| *(missing)* | ✗ It misses the biggest issues: the port is **serverless** (no trust root exists), **both netcodes send every player's state to every machine** (ESP), the distributed netcode **accepts client positions and hit reports** with loose checks, and **the internet-play tunnel keying lets any invite holder read and impersonate other players**. See §2. |

### 1.1 The second analysis (server authority and thin clients)

A later analysis argued that the simulation must be taken out of the client
and run on a dedicated Game Server, so that the client becomes a thin
renderer that sends signed inputs. It gets the principle right. Some of its
mechanics are outdated, and some point in the wrong direction:

| Claim | Assessment |
|-------|------------|
| "Server authority for all state; the client sends inputs, not state" | ✓ Correct, and it is layer 1 of the design ("don't trust, don't send"). In the port, the gap is H01: the host already runs every player from their input, and then snaps them to the client's reported position. The fix is to stop accepting reports, not to rewrite the netcode. ✅ Done in the fork: `network.authority = "host"` (§5, H2). |
| "Extract the simulation from the client; the client becomes a thin renderer" | ◐ The client keeps its simulation, because it needs it to predict. What it loses is *authority*. The Halo client still simulates the whole world, but the host's word overrides it. |
| "Prediction and reconciliation" | ✓ Correct. The fork's client keeps 64 ticks of predicted positions, compares the host's state with its prediction for the same input tick, and moves by the difference. |
| "The client must refuse a GS without a valid, fresh PlayTicket" | ✓ Correct in principle. PlayTickets are now **SARs** (04 §6.3), and `client-core` already enforces the SAR chain. The same check goes into the Halo client with the dedicated host (H5). |
| "The VS receives heartbeats with `receipt_tip` and world positions and revokes a GS on impossible speed" | ✗ **Superseded** (F13). The VS no longer sees positions or game physics (05 §2.3). The GS enforces movement (now H01's fix), signs one Checkpoint per epoch, and the Replay Auditor checks it after the fact. |
| "Signed InputCommits make inputs undeniable; the GS rejects impossible inputs" | ✓ Correct. The C SDK has them (M1). Wiring them into the port is M3. |
| "TPM / Windows runtime attestation is the defense against memory editing" | ◐ It is the strongest *client* layer on Windows and Android (P3). Linux clients stay D0. It does not stop hardware or vision aimbots, so server-side detection stays necessary. |
| *(missing)* | Server authority does not fix **ESP** (H06): the host still sends every player's state to every client. That is H6/M6 (relevance filtering). ◐ Done in the fork for players and the vehicles they ride (`network.relevance`, §5 H6). |

## 2. Security review of the port's multiplayer

Scope: what a player, or anyone holding an invite, can do against a match.
Ratings are relative to competitive play. The port's own docs are candid about
the design trade-offs. These findings are what an anti-cheat has to close.

| ID | Sev | Finding | Location | Direction |
|----|-----|---------|----------|-----------|
| **H01** | **High** (✅ fixed in the fork under `network.authority = "host"`, the default) | **Client-owned movement with an accumulating tolerance.** Each tick (30 Hz) a client sends its own player's position, and the host accepts it if it is within 3.5 world units of the host's current copy, then snaps to it. The copy is the last accepted report, so a modified client can gain up to 3.5 wu per tick beyond what physics allows (≈ 105 wu/s), and step through walls: there is no collision test on the reported position. | `port/linux/game/network_distributed.c:101` (tolerance), `:465` (accept), `:810` (sent every client tick) | Non-accumulating budget (a correction-distance token bucket per second), swept collision test from last accepted to reported position, and a Signal on repeated edge-riding (AUTH-04) |
| **H02** | **High** (✅ path check in the fork) | **Shooter's-hits with no path check.** Clients report their own hits ("what the shooter saw hit, hits"). The host checks the player, the weapon (now or within 10 s), the fire rate, the target within 3.0 wu of where the host has it and the impact within 2.0 wu of the target. I found no check that the path from shooter to impact is unobstructed, so shots through walls are likely accepted, and aim assistance is invisible to these checks by construction. | `port/linux/game/network_damage.c:91,93` (tolerances), `:675-677` (impact check) | Host-side obstruction raycast from the host-known eye position with bounded rewind (AUTH-03), per-target report rate limits, and report geometry fed to aim-kinematics features (DET-03) |
| **H03** | **High** (internet play; ✅ fixed in the fork, H3) | **Tunnel keys are readable by every invite holder.** The host sends each joiner a random tunnel key inside an ACCEPT sealed with a key derived *only from the invite token*, on a public MQTT topic whose name any invite holder can compute. Every player in the game holds the invite, so any of them can recover every other player's tunnel key, decrypt that traffic and forge packets as that player. There is no key agreement and no forward secrecy. | `port/linux/src/p2p_signal.c:454-470` (key generated, sealed with `host_key`), `:767`, `:783` (`host_key`/`join_key` = `derive(token, "seal")`) | Authenticated key exchange per pair (Noise IK/XX, or QUIC/TLS 1.3 through the FPP SDK) with the host's static public-key fingerprint in the invite link. The invite then authorizes but no longer encrypts. |
| **H04** | Medium (✅ fixed in the fork, H3) | **No replay protection, and roaming on any valid packet.** Tunnel packets use random nonces with no replay window. A packet that opens correctly from a *new* address moves the peer's endpoint once the old address has been silent for 3 s. An on-path attacker can replay captured packets; after briefly silencing a victim (for example with a DoS) they can redirect the victim's traffic. Combined with H03, a malicious player can take over another player's session. | `port/linux/src/p2p.c:1366-1368` (open, then `peer_heard`), `:594-600` (endpoint switch) | Counter nonces with a sliding replay window; path validation (challenge-response) before switching endpoints, as QUIC does |
| **H05** | Medium (◐ tunnel on the SDK; signalling, which carries only addresses, still hand-rolled) | **Hand-rolled cryptography.** SHA-256, HMAC, ChaCha20 and Poly1305 are implemented by hand. They look straightforward but are unaudited, and the construction around them (H03, H04) is the real problem. | `port/linux/src/p2p_crypto.c` | Use a vetted library (the FPP SDK's rustls/aws-lc-rs, or libsodium / mbedTLS, which the port already vendors) |
| **H06** | High (by design) | **Everyone receives everything (ESP).** Lockstep delivers every player's input to every machine by definition. The distributed netcode still relays every player's per-tick input and sends every unit's state to every client. A memory reader gets a perfect radar and wallhack (T02). | `port/linux/NETCODE.md` stages 1–4; `network_distributed.c` `distributed_send_unit_states(TRUE)` | Per-client relevance filtering on the host (INFO-01). Distributed mode already sends per-client corrections, so this is feasible there; lockstep cannot support it. |
| **H07** | Low | **Self-reported build identity.** The join token mixes in the tag-data checksum and compile time: fine for version matching, but trivially spoofable by a modified client. | `source/networking/network_server_manager.c` (join-token generation, `tag_groups_checksum`) | Measured client build in Attestation Results for verified playlists (ATT-10) |
| **H08** | Low | **Bans cannot stick.** A machine-blacklist rejection code exists, but machine identity is self-asserted. | `source/networking/network_client_manager.c:2383` | Hardware-rooted Device ID for verified playlists (ID-02) |
| **H09** | — (inherent) | **The host is omnipotent.** In distributed mode the host alone decides damage, deaths, spawns, pickups and scores. A cheating host can give itself immunity, deny kills or spawn items. | `port/linux/NETCODE.md` "Host authoritative" | Cannot be prevented on a player-hosted game. It can be **detected and proven** with client-signed InputCommits, host Checkpoints and deterministic replay (§3). Dedicated hosts remove it for verified playlists. |

## 3. How FPP maps onto Halo

The tier model in [03](03-architecture.md) §4 applies directly:

| Halo mode | Server class | Device tier | What we can guarantee |
|-----------|--------------|-------------|------------------------|
| Invite-link / LAN game hosted by a player | **S-Community** | D0–D1 (no backend involved) | Transport security (H03–H05 fixed), host validation (H01/H02 fixed), and *evidence*: every player can later prove what the host did, and replay can verify it. No ranked credit. |
| **Verified playlist** on a dedicated host (headless port in a first-party or confidential VM) | S-FirstParty / S-FirstParty-CVM | Windows D2/D3, Android D2, Linux D0 in a segregated pool | Full FPP: Verifier, Broker, SAR liveness, transparency log, replay audit, detection, enforcement |

Hook points (file names from the port):

| FPP element | Where it attaches in Halo | Notes |
|-------------|---------------------------|-------|
| Session transport + admission (04 §7.7; §7.1–7.2 in verified mode) | `port/linux/src/p2p.c`, `p2p_signal.c`: replace the tunnel's keying and sealing with `fpp_p2p_host_*` / `fpp_p2p_joiner_*` over the existing UDP socket. The invite carries the host's static public key and an invite secret. Verified mode adds SAT + PoP. | Fixes H03–H05. The game still sees a LAN (keep the `xnet.c` stand-ins). |
| Input frames (04 §7.3) | The existing per-tick `_message_client_game_update` (`source/networking/network_game_globals.c:665` in the port, `:596` in the decomp) plus distributed predictions and hit reports | Title payload stays as is. |
| **InputCommit** (04 §7.4) | Client branch of `network_distributed_tick()` (`network_distributed.c`): Merkle root per epoch over the client's own actions, position reports and hit reports, signed with the session key | ≈ 100 B/s per player |
| **Checkpoint** (04 §8.1) | Host branch of `network_distributed_tick()`: `inputs_root` over everything the host accepted, `events_root` over damage/deaths/pickups/scores it decided, `state_root` over the unit states it sends, randomness from `get_random_seed()` | Signed by the host's instance or session key |
| Checkpoint heads / gossip (04 §7.6) | Host → clients, reliable message; clients keep them with their own commits | Lets any player prove host equivocation |
| **Replay Auditor** (04 §8.4) | Headless build of the port that loads the map and re-simulates host decisions from the evidence bundle. The saved-films code (`source/saved films/`) is the natural starting point. | Needs a determinism check of distributed mode (§5, H4) |
| Validators → Signals | `distributed_handle_predictions()`, `network_damage.c` report checks, and the port's existing "pickup the host does not have" log | Emit structured Signals instead of silently dropping |
| Detection features | Host side: view-angle deltas from the relayed per-tick actions, hit-report geometry, information-use (engaging players outside line of sight) | Server-side only (GOV-03) |
| Enforcement | `_rejection_code_blacklisted_machine` path, keyed by `did` in verified mode | |
| Integrity Agent (verified playlists) | SDK linked into the port: Windows TPM + `GetRuntimeAttestationReport`, Android Play Integrity (Kotlin adapter in `port/android/app`) | Linux: D0 |

### Build and repo boundaries

```text
tmart234/mmo (this repo, Rust, no Halo code)
  crates/fpp-sdk        → staticlib + cbindgen header (fpp_sdk_v1_*)
     targets: i686-unknown-linux-gnu, i686-pc-windows-msvc, aarch64-linux-android
                                  │   (pinned version, generated header)
                                  ▼
<your fork>/halo-ce-universal (C, the game)
  port/linux/src/fpp_glue.c     ≤ ~2 k lines of glue: transport, commits,
                                checkpoints, signals (ADR-001 E1)
  tools/linux_build.py          links libfpp_sdk.a
```

The fork pins one commit of this repository (`COMMIT` in its
`tools/fpp_sdk.py`), with that commit's `fpp.h` vendored, so every build of
the game says exactly which SDK it carries. Nobody raises the pin by hand:
the fork's "Update the fpp SDK" workflow runs `tools/fpp_sdk.py bump` every
six hours, and at once when this repository's CI passes on main (the
`dependents.yml` workflow here, given a `HALO_DISPATCH_TOKEN` secret). It
takes the new commit only if the SDK's source changed, builds and tests
every port with it, and merges when they pass. When they fail, the pull
request stays open for a person, because the C ABI changed in a way the
glue must follow.

The port's game code assumes 32-bit pointers (Xbox heritage), so the desktop
builds are 32-bit x86. Rust supports `i686-unknown-linux-gnu` and
`i686-pc-windows-msvc` at Tier 1, so this is no obstacle.

## 4. Legal and IP guardrails

Not legal advice, but these boundaries keep the framework safe to own and ship:

- Halo: CE is Microsoft's intellectual property. The decompilation is derived
  from Microsoft's binary, so its CC0 notice cannot grant rights its authors
  do not hold. Treat any Halo work as **non-commercial research**.
- **Never commit game data** (disc images, `maps/`, extracted tags) to any
  repository, and never distribute builds bundled with it. The port already
  requires players to supply their own disc image; keep it that way.
- **Keep `mmo` free of Halo code.** The dependency points one way: the Halo
  fork links `mmo`'s SDK. `mmo` stays independently licensable, and if you
  ever build a product the same SDK drops into an original or licensed game.

## 5. Staged plan

Stages are ordered so each is useful on its own. The right column lists what
each needs from the `mmo` roadmap ([07](07-gap-analysis-and-roadmap.md) §4).

| Stage | Work | Exit criterion | Needs from `mmo` |
|-------|------|----------------|------------------|
| **H0 Run it** | Build the port. You supply your own disc image. Play a two-machine LAN or invite match; run `debug.network_test` with scripted bots. | Two machines, one match, both logs agree | — |
| **H1 Red-team clients** | In the fork, behind a debug-only flag: a client that exploits H01 (movement steps), H02 (unobstructed-path gap), and H06 (reads relayed state as a radar); plus a cheating host (H09) | Each attack reproducibly works against the stock netcode | ✅ Code done (debug builds only): `debug.cheat_movement_step`, `debug.cheat_wall_hits`, `debug.cheat_radar` (logs occluded players from relayed state), `debug.cheat_host_immunity` (host drops checked hits on its own player). `tools/network_soak.py` runs each as a scenario; the runs need game data |
| **H2 Host hardening** | Fix H01 and H02; turn every host rejection into a structured Signal (JSON log first) | H1 attacks rejected and flagged; no false rejects in a scripted-bot soak under `debug.network_latency` / `debug.network_loss` | ◐ Code done: H01 fixed by host authority with client reconciliation and a host input buffer; H02 by a structure ray from the shooter's recent positions to the hit; every rejection is a JSON Signal in `signals.jsonl` (network version 5, `port/linux/NETCODE.md`). ✅ Soak runner: `tools/network_soak.py` (honest bots under latency and loss must produce no Signal; H1 movement and wall-hit clients must be flagged/rejected), verdicts unit-tested. Open: running it with game data (needs a disc image) |
| **H3 Transport** | Replace tunnel keying and sealing (H03–H05) with the SDK's P2P session (Noise IK); host static key in invites | An invite holder can no longer decrypt or impersonate another player (test) | ✅ Done on Linux and Windows: the fork's tunnel runs `fpp_p2p_*` sessions; the invite carries the host's X25519 key; signalling carries addresses only; hole punching by unauthenticated probes; identifier = hash of the session key, checked by the host. `tools/fpp_sdk.py` builds libfpp from a pinned commit of this repo. `tools/p2p_loopback_test.py` (CI) shows a forged host key gets no session. Android: no SDK target, internet play off. H05 remainder: signalling still uses the port's own SHA-256/ChaCha20 (addresses only) |
| **H4 Evidence and audit** | InputCommits, host Checkpoints and a local evidence bundle; headless replay auditor; a determinism check of the distributed netcode across Linux, Windows and Android | The auditor flags the H1 cheating host; identical replays across platforms | ◐ Evidence recording done in the fork (halo-ce-pi #6): each client signs an InputCommit per 150-tick epoch over its hit reports with its session key; the host signs a Checkpoint per epoch with its instance key, acknowledging each commit, marking which frames it applied and listing an outcome per reported unit; each machine writes an evidence bundle (04 §8.5). ✅ `fpp-audit` (this repo) checks a bundle's signatures, chains, roots, acknowledgements and accounting, and finds a host that signed two Checkpoints for one epoch across players' bundles: the `debug.cheat_host_immunity` host's dropped hits show up as unaccounted units (tested with synthetic evidence through the fork's P2P loopback). Open: a re-simulating replay auditor and the determinism check (need game data) |
| **H5 Verified playlists** | Dedicated headless host mode, Verifier + Broker + SAR from `mmo`, device tiers, segregated pools. Home-lab target: Pi 5 GS + Pi Zero 2 W VS (§8) | Tiered matchmaking in a staging deployment | P2, P3. ✅ VS for the Pi Zero 2 W (`make pi-vs`, `deploy/pi/`); ✅ SDK for aarch64 (`make ffi-c-test-aarch64`); ✅ trust admission in the fork: joiners present an Attestation Result bound to their P2P session key, the host admits by `network.minimum_tier` and refuses mixed tiers (`fpp_ar_verify`). Open: headless host mode with map rotation, SAR issuance for the GS |
| **H6 Anti-ESP** | Host-side relevance filtering in the distributed netcode | The radar client from H1 loses occluded players, with no visible pop-in at normal latency | ◐ Done in the fork (halo-ce-pi #7, `network.relevance`): each client is sent only the players its own could perceive (PVS clusters, 32-unit motion-tracker radius, teammates, objective carriers, the dead) with a 15-tick linger; a withheld player gets one hidden state with no position and no relayed input; ridden vehicles are filtered per client. Soak scenarios `radar` (the host withheld players) and `radar_open` (the attack works with the filter off). Residual: last position before withholding, players within 32 units or in PVS-visible clusters. Open: the in-game run (needs game data), a per-pair line test |

H0–H2 need nothing from `mmo` and give immediate, visible wins. H3 is where
the framework first runs inside a real game. It depends on the roadmap's P0
fixes and P1 protocol core, which is the right order anyway: the prototype
protocol should not be embedded in a game before F01–F03 are fixed.

## 6. Build check (2026-09-29)

Stage H0's build half was verified in a clean Ubuntu 24.04 container, from
`bnunu/halo-ce-universal` at `3ba97dd`:

| Step | Result |
|------|--------|
| Toolchain | Ubuntu clang 18.1.3 (no PGO: the committed profiles need clang ≥ 22), `gcc-multilib`, `libc6-dev-i386` |
| SDL3 | Ubuntu 24.04 ships no 32-bit SDL3, so SDL `release-3.2.x` was built for `i686-linux-gnu` (console-only: `-DSDL_UNIX_CONSOLE_BUILD=ON`) and installed to `/usr/lib/i386-linux-gnu` |
| `python configure.py --portable --pgo=off && ninja linux` | 643 build steps in ≈ 70 s; `build/linux/halo` is an ELF 32-bit i386 executable |
| `pytest tools/test_linux_port.py` | 11 passed. These cover build tooling (XDK header generation, link checks), not gameplay. |
| Launch without game data | Starts, runs its renderer without a window (no video device in this SDL build), reports `no maps/ folder found`, and exits cleanly |

To go further you need your own Xbox disc image (the game extracts `maps/`
from it) and a machine with a display, or a full SDL3 build with video. For
two-machine tests, `debug.network_test` and `debug.test_input` drive scripted
bots without menus.

Reproduce (Ubuntu 24.04):

```bash
sudo apt-get update && sudo apt-get install -y gcc-multilib libc6-dev-i386 cmake ninja-build clang lld
git clone --depth 1 --branch release-3.2.x https://github.com/libsdl-org/SDL
cmake -S SDL -B SDL/build-i686 -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang -DCMAKE_C_COMPILER_TARGET=i686-linux-gnu -DCMAKE_C_FLAGS=-m32 \
  -DSDL_TESTS=OFF -DSDL_STATIC=OFF -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_LIBDIR=lib/i386-linux-gnu
# (drop -DSDL_UNIX_CONSOLE_BUILD for a desktop with X11/Wayland 32-bit dev packages)
ninja -C SDL/build-i686 && sudo ninja -C SDL/build-i686 install
git clone --depth 1 https://github.com/bnunu/halo-ce-universal && cd halo-ce-universal
python3 configure.py --portable --pgo=off && ninja linux
LD_LIBRARY_PATH=/usr/lib/i386-linux-gnu build/linux/halo
```

On a desktop, the port's own route is simpler: Arch Linux's `lib32-sdl3`
package (what its CI uses), or the prebuilt releases linked from its README.

## 7. The security multiplayer mod

Goal: a Halo: CE mod, and later equivalents for other classic C/C++ games,
that makes player-hosted and dedicated multiplayer speak FPP. The mod is C
code in a fork of the port. All protocol logic stays in `mmo` and reaches the
game only through the C SDK `crates/fpp-ffi` (`include/fpp.h` +
`libfpp.a`). The same SDK serves every classic, since their game code is
C/C++ (ADR-001 E1).

```text
halo-ce-universal fork                         mmo
┌──────────────────────────────────────┐       ┌──────────────────────────────┐
│ game code (decomp, unchanged logic)  │       │ fpp-ffi   C ABI, i686/x86_64 │
│  network_distributed.c  ─┐           │       │  ├ keys, digests             │
│  network_damage.c       ─┼─ hooks ──►│ glue  │  ├ InputCommit builder/verify│
│  p2p.c / p2p_signal.c   ─┘           │ (C)  ─┼─►├ Checkpoint builder/verify │
│ host validators (H01/H02 fixes, C)   │       │  └ fpp_p2p_* secure session  │
│ evidence bundle on disk              │       │ fpp-wire / fpp-crypto / merkle│
└──────────────────────────────────────┘       └──────────────────────────────┘
```

What the glue does with the SDK (distributed netcode, player-hosted):

| Where | When | SDK calls |
|-------|------|-----------|
| Host start | Once per match | `fpp_p2p_keypair_generate` (or a saved key + `fpp_p2p_public_key`); put the public key and a random invite secret in the invite; `fpp_p2p_host_new` |
| Client join | Once per match | `fpp_signer_generate` (session key); `fpp_p2p_joiner_new` with the invite's host key and secret, the session key, and the device's AR if it has one. The host learns the session key from `FPP_P2P_EVENT_KIND_PEER_JOINED` |
| Both, socket I/O | Every datagram | `fpp_p2p_*_recv` on each received datagram; `fpp_p2p_*_send` for game packets; drain `fpp_p2p_*_poll_transmit` into `sendto` and `fpp_p2p_*_poll_event`; joiner calls `fpp_p2p_joiner_retry` every ~500 ms until connected |
| Both, game tick | Every tick | `fpp_p2p_*_tick(now_ms)` (acks and retransmissions for the reliable channel), then drain transmits |
| Client, `network_distributed_tick()` | Every tick | `fpp_input_commit_add_frame(tick, bytes)` with the tick's action update, own-position report and hit reports |
| Client, epoch end | Every `ticks_per_epoch` | `fpp_input_commit_sign`; send with `fpp_p2p_joiner_send_reliable`; keep `fpp_object_digest` as the next `prev` |
| Host, per slot | Every tick | Its own builder over the frames it *received*; at epoch end `fpp_verify_input_commit` (player's key) and compare `frames_root` with `fpp_input_commit_frames_root`; a mismatch is a Signal |
| Host, epoch end | Every epoch | `fpp_checkpoint_begin`; `add_input` per slot (commit digest, applied bitset); `add_event` for damage, deaths, pickups and scores it decided; `add_roster`; `fpp_checkpoint_sign` with the host instance key; send the digest to every client |
| Everyone | Match end | Write the evidence bundle (frames, commits, checkpoints) to disk; clients `fpp_verify_checkpoint` the host's objects. Any player can later prove what the host did (H09). |

Milestones (each builds on the previous; M1 is done):

| # | Milestone | Status / exit |
|---|-----------|---------------|
| **M1** | C SDK for evidence primitives (`fpp-ffi`), 32- and 64-bit | ✅ The C conformance program (`make ffi-c-test`, `ffi-c-test-i686`) signs objects byte-identical to the golden vectors, verified by the independent Python implementation. Linked statically into a local build of the 32-bit port, it runs at start-up: `fpp-probe: SDK ABI 1, signed a 312-byte InputCommit for 30 ticks, verify: ok`. |
| **M2** | Secure P2P session in the SDK: authenticated key exchange with the host's static key in the invite, per-packet counters with a replay window, path validation before endpoint changes | ✅ `crates/fpp-session` + `fpp_p2p_*` (04 §7.7): `Noise_IK_25519_ChaChaPoly_SHA256` over the port's existing UDP socket, session key bound by a signed AdmitPop, 2048-packet replay window, challenge-response path validation, AR slot for tiered lobbies. Attack tests (invite holder cannot read or forge, replay, raced-packet redirect, NAT rebinding) pass in Rust and through the C ABI on x86_64 and i686. Wiring it into `p2p.c` is part of M3. |
| **M3** | Fork + glue: evidence recording as in the table above; host validators fixing H01/H02 emit structured Signals | Red-team clients from H1 are rejected or flagged; each match leaves a verifiable evidence bundle. ✅ H01/H02 closed with Signals; forged damage reports (scale, multiplier, instant kill, bullets as explosions, melee reach) rejected; the P2P session wired into `p2p.c` (H3); InputCommits, Checkpoints and the evidence bundle recorded (H4, halo-ce-pi #6), verified end to end by `fpp-audit` |
| **M4** | Headless replay auditor built from the port | Re-simulates host decisions from a bundle; flags a cheating host; identical results on Linux, Windows and Android | ◐ The accounting audit is done: `fpp-audit` (`crates/fpp-audit`, 04 §8.5) verifies bundles without the game and flags a host that leaves hits unaccounted, ignores a commit, denies a frame, or equivocates. Re-simulating the host's decisions (was each rejection right?) needs a headless build of the port and game data |
| **M5** | Verified playlists: dedicated host mode, Verifier/Broker/SAR from `mmo`, device tiers (Windows, Android) | Needs roadmap P2 and P3 |
| **M6** | Anti-ESP relevance filtering in the distributed netcode | Radar client loses occluded players |

Linking notes, learned from the probe: link the static archive explicitly
(`-l:libfpp.a` or its full path), because with `-lfpp` the linker prefers
`libfpp.so` when both are present. Add `-ldl -lgcc_s` to the game's link line.
The SDK uses no libm symbols, so it coexists with the port's `musl-math`.

## 8. Hardware deployment: Pi 5 game server, Pi Zero 2 W VS

The home-lab target for H5: a Raspberry Pi 5 runs the dedicated Halo host
(the GS), a Raspberry Pi Zero 2 W runs the VS, and players join from PCs and
phones.

```text
 players (Linux/Windows/Android port)          Pi 5 (GS)                         Pi Zero 2 W (VS)
 ┌─────────────────────────┐  fpp-session  ┌──────────────────────────────┐ QUIC ┌───────────────────┐
 │ predicts own player      │◄────────────►│ headless Halo host            │◄────►│ vs (aarch64)      │
 │ reconciles to the host   │  UDP, Noise  │  host authority (H2)          │ TLS  │ admission, SARs,  │
 │ checks the SAR chain     │              │  libfpp.a (aarch64) in loader │ 1.3  │ Checkpoints,      │
 │ signs InputCommits       │              │  Checkpoint per epoch         │      │ Verifier+Broker   │
 └─────────────────────────┘              └──────────────────────────────┘      └───────────────────┘
```

### 8.1 VS on the Pi Zero 2 W ✅

The VS cross-builds for `aarch64-unknown-linux-gnu` with clang, lld and the
Debian aarch64 sysroot (`make pi-vs`). `make pi-vs-smoke` runs the full
smoke test (both passes, including the simulated TPM) with that VS under
`qemu-aarch64-static`, against the native `gs-sim` and `client-sim`: it
passes. The binary is about 7 MB. `deploy/pi/` has the install steps and a
hardened systemd unit. It waits for NTP, because the board has no real-time
clock and SARs expire 10 s after issue. The GS dials the VS by IP address
with the TLS name `vs.dev`, so the dev certificates need no change.

### 8.2 Halo host on the Pi 5 (next)

The game assumes 32-bit pointers, and the Pi 5 is a 64-bit ARM machine. The
Android port has already solved this: it compiles the game as ILP32 AArch64
code (a *guest* image linked below 4 GB, with a subset of musl) and runs it
inside an ordinary 64-bit process (a *host* loader of about 2,300 lines,
`port/android/host`). The Pi 5 build reuses the guest image unchanged and
adds a Linux host:

| Piece | Work |
|-------|------|
| Host loader | `port/linux-arm64/host`: the Android host's loader, memory, thread and syscall files, without JNI, and with no GL, audio or input (a dedicated host draws nothing). Linux and Android share the aarch64 syscall numbers. |
| Page size | The Android host hard-codes 4 KB pages (`host_memory.c`), but Raspberry Pi OS's default Pi 5 kernel (`kernel_2712.img`) uses 16 KB pages. First step: boot `kernel=kernel8.img` (4 KB pages). Later: take the page size from `sysconf(_SC_PAGESIZE)`. |
| Dedicated host mode | Host a game from config with no local player (as `debug.network_test` hosts one without menus), keep the map rotation, and restart on game end. The engine has always had a host player, so a host without one needs testing. |
| SDK | `libfpp.a` for aarch64 links into the LP64 host, not the ILP32 guest. The guest calls it through new host imports (`host_imports.list`), as it calls SDL on Android. `make ffi-c-test-aarch64` already passes the C conformance and P2P attack tests on this target. |
| GS control link | A new `fpp_gs_*` API in `fpp-ffi` that wraps what `gs-sim` does (JoinRequest, SAR chain, Checkpoint per epoch) for C callers. The Halo host shows its SAR to joining clients, and the clients check the chain (§1.1). |
| Attestation | A TPM 2.0 HAT on the Pi 5 (for example Infineon SLB 9672) gives the GS a real TPM for the join quote and re-attestation. That makes the VS's TPM appraisal findings (F04, F05) the next VS work. Without a HAT the GS stays at the simulated TPM, with no hardware assurance. |

A Pi 5 has far more CPU than the Xbox the game was written for (a 733 MHz
Pentium III), so a dedicated host for 16 players should not be
CPU-bound. Measure it with `tools/system_link_bots.py` once the host runs.
