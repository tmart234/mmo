# Raspberry Pi deployment

The home-lab topology for the Halo reference title
([docs/anticheat/08](../../docs/anticheat/08-reference-title-halo.md) §8):

| Board | Role | Runs |
|-------|------|------|
| Raspberry Pi Zero 2 W (quad Cortex-A53, 512 MB) | **VS**: the trust plane (GS admission, SAR chain, Checkpoint intake, stub Verifier and Broker) | `vs` from this repo, aarch64 |
| Raspberry Pi 5 | **GS**: the dedicated Halo host (stage H5, not built yet) | the Halo port as a headless host, linked with `libfpp.a` for aarch64 |
| Players' PCs, phones | **Clients** | the Halo port |

This page installs the VS. The Pi 5 host is the next build target of the
Halo fork. Until it exists, `gs-sim` stands in for it (below).

## 1. Build (on a Linux PC)

Cross-build from x86-64 with clang and the Debian/Ubuntu aarch64 sysroot:

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install clang lld llvm libc6-dev-arm64-cross libgcc-13-dev-arm64-cross qemu-user-static
make pi-vs            # target/aarch64-unknown-linux-gnu/release/{vs,gen_keys}
make pi-vs-smoke      # the full smoke test with this VS, under qemu
```

`make ffi-c-test-aarch64` checks the C SDK for the Pi 5 host in the same way.

## 2. Keys

The VS and every GS must share one dev CA and the VS's public key. Generate
them once, on the PC, and copy them to each board. Never commit them.

```bash
cargo run -p tools --bin gen_keys     # writes keys/
```

| File | VS (Pi Zero 2 W) | GS (Pi 5, or gs-sim) |
|------|------------------|----------------------|
| `vs_ed25519.pk8`, `vs_ed25519.pub` | ✔ (the seed stays only here) | `vs_ed25519.pub` only |
| `vs_tls.der`, `vs_tls.key.der` | ✔ | |
| `dev_ca.der` | ✔ | ✔ |
| `gs_ed25519.pk8`, `gs_ed25519.pub`, `gs_tls.der`, `gs_tls.key.der` | | ✔ |
| `fpp_key_bundle.json` | written by the VS at start | copy from the VS after its first start |

The GS dials the VS by IP address and checks the certificate for the TLS
name `vs.dev`, so the dev certificate works on any address.

## 3. Install on the Pi Zero 2 W

Use Raspberry Pi OS Lite (64-bit). Then:

```bash
# from the PC
scp target/aarch64-unknown-linux-gnu/release/vs pi@vs.local:/tmp/fpp-vs
scp keys/vs_ed25519.pk8 keys/vs_ed25519.pub keys/vs_tls.der keys/vs_tls.key.der keys/dev_ca.der \
    pi@vs.local:/tmp/
scp deploy/pi/fpp-vs.service pi@vs.local:/tmp/

# on the Pi
sudo install -m 0755 /tmp/fpp-vs /usr/local/bin/fpp-vs
sudo useradd --system --home /var/lib/fpp-vs --shell /usr/sbin/nologin fpp-vs
sudo install -d -o fpp-vs -g fpp-vs -m 0700 /var/lib/fpp-vs /var/lib/fpp-vs/keys
sudo install -o fpp-vs -g fpp-vs -m 0600 /tmp/vs_ed25519.pk8 /tmp/vs_tls.key.der /var/lib/fpp-vs/keys/
sudo install -o fpp-vs -g fpp-vs -m 0644 /tmp/vs_ed25519.pub /tmp/vs_tls.der /tmp/dev_ca.der /var/lib/fpp-vs/keys/
sudo install -m 0644 /tmp/fpp-vs.service /etc/systemd/system/
sudo systemctl enable --now systemd-time-wait-sync.service   # no RTC: wait for NTP
sudo systemctl enable --now fpp-vs
journalctl -u fpp-vs -f
```

The VS listens on UDP 4444 (QUIC). Give the board a fixed address (DHCP
reservation) and open UDP 4444 to the GS only.

Notes for this board:

- **Clock.** SARs expire 10 s after issue. The Zero 2 W has no real-time
  clock, so the unit waits for `time-sync.target`. Keep NTP on.
- **Memory.** The unit caps the VS at 256 MB (`MemoryMax`). One VS serves a
  few home game servers easily.
- **SD card.** Checkpoint evidence goes to `/var/lib/fpp-vs/evidence/`, one
  small file per epoch per game server. Move it to a USB drive, or prune it,
  for long runs. P2's Evidence Store replaces local files.
- **Wi-Fi.** The Zero 2 W has 2.4 GHz Wi-Fi only. The VS link is not
  latency-critical (a SAR every 2 s, a Checkpoint per epoch), so Wi-Fi is
  fine. Players never talk to the VS during a match.

## 4. Try it with gs-sim before the Halo host exists

On any Linux machine with the GS keys from §2 and `keys/fpp_key_bundle.json`
copied from the VS:

```bash
# the game server; --game-addr is the address the Broker gives clients, so use the machine's LAN IP
cargo run -p gs-sim -- --vs <vs-ip>:4444 --game-addr <gs-ip>:50000
# a client, anywhere on the LAN, with dev_ca.der and fpp_key_bundle.json in keys/
cargo run -p client-core --bin client-sim -- --vs <vs-ip>:4444 --smoke-test
```

When the VS stops issuing SARs (stop the service), the GS kicks its players
and clients drop on their own within three issue intervals.
