# Running `fppd` on a Raspberry Pi (aarch64)

The entire Fair-Play Protocol v1 trust plane runs as one lean static binary (`fppd`) on a Raspberry Pi Zero 2 W (well inside 512 MB RAM, port `4444/tcp`, zero X.509 PKI ceremony).

## Cross-build

```bash
make pi-cell          # builds target/aarch64-unknown-linux-gnu/release/fppd
make pi-cell-smoke    # runs the smoke test against aarch64 fppd under qemu-aarch64-static
```

## Install on the Pi

```bash
sudo useradd --system --home /var/lib/fpp --shell /usr/sbin/nologin fpp
sudo install -d -o fpp -g fpp -m 0700 /var/lib/fpp /var/lib/fpp/cell /var/lib/fpp/keys
sudo install -m 0755 fppd /usr/local/bin/fppd
sudo install -D -m 0644 fppd.env /etc/fpp/fppd.env
sudo install -m 0644 fppd.service /etc/systemd/system/fppd.service
sudo systemctl daemon-reload
sudo systemctl enable --now fppd
```

Distribute `/var/lib/fpp/keys/fpp_key_bundle.json` (public keys + pinned Noise X25519 transport public key) to game servers and clients. Private signing keys remain isolated under `/var/lib/fpp/cell/` (`0600`).
