# Raspberry Pi deployment

The home-lab topology for the Halo reference title
([docs/anticheat/08](../../docs/anticheat/08-reference-title-halo.md) §8):

| Board | Role | Runs |
|-------|------|------|
| Raspberry Pi Zero 2 W (quad Cortex-A53, 512 MB) | **The cell**: the Transparency Log and a witness, the Revocation Feed, the Evidence Store, Server Liveness (GS admission, SAR chain, Checkpoints), the Verifier and the Broker, one process and one user each; Enforcement (`fpp-enforce`) and auditors (`fpp-evidence`) as users of their own | `svc-log`, `svc-witness`, `svc-revocation`, `svc-evidence`, `svc-liveness`, `svc-verifier`, `svc-broker`, `fpp-enforce`, `fpp-evidence` from this repo, aarch64 |
| Raspberry Pi 5 | **GS**: the dedicated Halo host (stage H5, not built yet) | the Halo port as a headless host, linked with `libfpp.a` for aarch64 |
| Players' PCs, phones | **Clients** | the Halo port |

This page installs the cell. The Pi 5 host is the next build target of the
Halo fork. Until it exists, `gs-sim` stands in for it (below). To run the
cell on a PC instead, use containers (`deploy/cell`).

## 1. Build (on a Linux PC)

Cross-build from x86-64 with clang and the Debian/Ubuntu aarch64 sysroot:

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install clang lld llvm libc6-dev-arm64-cross libgcc-13-dev-arm64-cross qemu-user-static
make pi-cell          # target/aarch64-unknown-linux-gnu/release/{svc-*,fpp-cell,fpp-enforce}
make pi-cell-smoke    # the full smoke test with these services, under qemu
```

`make ffi-c-test-aarch64` checks the C SDK for the Pi 5 host in the same way.

## 2. Keys

Generate the dev PKI and the cell once, on the PC. Never commit them.

```bash
cargo run -p tools --bin gen_keys     # keys/ and cell/
```

| Files | Goes to |
|-------|---------|
| `cell/ca.der` | the Pi, readable by all three services |
| `cell/<service>/` (`tls.der`, `tls.key.der`), and for log, liveness, verifier and broker `keys/<service>_tls.der`, `keys/<service>_tls.key.der` | the Pi, readable only by that service's user (as `public_tls.*` in its directory) |
| `cell/enforcement/`, `cell/audit/` | the Pi, readable only by `fpp-enforcement`, `fpp-audit` |
| `keys/dev_ca.der` | every GS and client |
| `keys/gs_tls.der`, `keys/gs_tls.key.der` | the GS |
| `keys/fpp_key_bundle.json` | every GS and client: gather it on the Pi after the first start (§3) |

Each service makes its own signing key in its own directory on first start
(`ed25519.seed`); it never leaves the board. Game servers and clients dial
the services by IP address and check the certificates for the names
`liveness.dev`, `verifier.dev`, `broker.dev` and `log.dev`, so the dev certificates
work on any address.

## 3. Install on the Pi Zero 2 W

Use Raspberry Pi OS Lite (64-bit). Then:

```bash
# from the PC
R=target/aarch64-unknown-linux-gnu/release
scp $R/svc-* $R/fpp-cell $R/fpp-enforce $R/fpp-evidence pi@cell.local:/tmp/
scp -r cell keys deploy/pi pi@cell.local:/tmp/

# on the Pi
sudo install -m 0755 /tmp/svc-* /tmp/fpp-cell /tmp/fpp-enforce /tmp/fpp-evidence /usr/local/bin/
sudo groupadd --system fpp
sudo install -d -m 0755 /var/lib/fpp /var/lib/fpp/cell /var/lib/fpp/work /etc/fpp
sudo install -d -g fpp -m 0775 /var/lib/fpp/cell/public
sudo install -m 0644 /tmp/cell/ca.der /var/lib/fpp/cell/
for s in log witness revocation evidence liveness verifier broker enforcement audit; do
  sudo useradd --system --gid fpp --home /var/lib/fpp/work/$s --shell /usr/sbin/nologin fpp-$s
  sudo install -d -o fpp-$s -g fpp -m 0700 /var/lib/fpp/cell/$s /var/lib/fpp/work/$s
  sudo install -o fpp-$s -g fpp -m 0600 /tmp/cell/$s/tls.der /tmp/cell/$s/tls.key.der /var/lib/fpp/cell/$s/
done
for s in log liveness verifier broker; do
  sudo install -o fpp-$s -g fpp -m 0600 /tmp/keys/${s}_tls.der /var/lib/fpp/cell/$s/public_tls.der
  sudo install -o fpp-$s -g fpp -m 0600 /tmp/keys/${s}_tls.key.der /var/lib/fpp/cell/$s/public_tls.key.der
done
for s in log witness revocation evidence liveness verifier broker; do sudo install -m 0644 /tmp/pi/$s.env /etc/fpp/; done
sudo install -m 0644 /tmp/pi/fpp@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now systemd-time-wait-sync.service   # no RTC: wait for NTP
sudo -u fpp-enforcement fpp-enforce --cell /var/lib/fpp/cell init
sudo systemctl enable --now fpp@log fpp@witness fpp@revocation fpp@evidence fpp@liveness fpp@verifier fpp@broker
journalctl -u 'fpp@*' -f

# the key bundle for game servers and clients
fpp-cell bundle /var/lib/fpp/cell /tmp/fpp_key_bundle.json
```

Acting as Enforcement (the record goes into the Transparency Log, the
event to the feed, and within seconds to every game server):

```bash
sudo -u fpp-enforcement fpp-enforce --cell /var/lib/fpp/cell --log 127.0.0.1:7201 \
  kick session:<hex of the player's session key> --note "why"
sudo -u fpp-enforcement fpp-enforce --cell /var/lib/fpp/cell --log 127.0.0.1:7201 \
  kick gs:<hex of a game server instance>    # its SARs stop too
```

The services listen on UDP 4444 (Server Liveness, for game servers), 4445
(Verifier), 4446 (Broker) and 4447 (the Transparency Log, for players'
checks of their game server's Checkpoints), QUIC; inside the board, the Broker reaches
Server Liveness on 127.0.0.1:4454, both follow the Revocation Feed on
127.0.0.1:4460, Server Liveness stores Checkpoints in the Evidence Store
on 127.0.0.1:4470, and the feed, Enforcement and Server Liveness write to the
Transparency Log on 127.0.0.1:7201, where the witness cosigns it (here on
the same board, for development: in production a witness is run by someone
else). Give the board a fixed address (DHCP reservation), open
4444 to the GS and 4445–4447 to players.

Notes for this board:

- **Clock.** SARs expire 10 s after issue. The Zero 2 W has no real-time
  clock, so the units wait for `time-sync.target`. Keep NTP on.
- **Memory.** Each service is capped at 96 MB (`MemoryMax`). One cell
  serves a few home game servers easily.
- **SD card.** The Evidence Store keeps one small object per epoch per game
  server in `/var/lib/fpp/cell/evidence/data/`. Put that on a USB drive for
  long runs. Read it as an auditor with
  `sudo -u fpp-audit fpp-evidence --cell /var/lib/fpp/cell list <match hex>`.
- **Wi-Fi.** The Zero 2 W has 2.4 GHz Wi-Fi only. The links are not
  latency-critical (a SAR every 2 s, a Checkpoint per epoch, admission once
  per match, a log check per Checkpoint after it), so Wi-Fi is fine.
  Players never talk to the cell during a match.

## 4. Try it with gs-sim before the Halo host exists

On any Linux machine with `keys/dev_ca.der`, the GS keys from §2 and the
key bundle from §3 in `keys/`:

```bash
# the game server; --game-addr is the address the Broker gives clients, so use the machine's LAN IP
cargo run -p gs-sim -- --liveness <pi-ip>:4444 --game-addr <gs-ip>:50000
# a client, anywhere on the LAN, with dev_ca.der and fpp_key_bundle.json in keys/
cargo run -p client-core --bin client-sim -- --verifier <pi-ip>:4445 --broker <pi-ip>:4446 \
  --log <pi-ip>:4447 --liveness <pi-ip>:4444 --smoke-test --check-log 30
```

When Server Liveness stops issuing SARs (`systemctl stop fpp@liveness`),
the GS kicks its players and clients drop on their own within three issue
intervals; the Verifier and the Broker keep answering, and the Broker
refuses new players until Server Liveness is back.
