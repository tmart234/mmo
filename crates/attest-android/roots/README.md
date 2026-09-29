# Google hardware attestation roots

`google_hardware_attestation_roots.pem` is the list Google publishes at
<https://android.googleapis.com/attestation/root> (fetched 2026-09-29): the
2022 RSA root (serial `f92009e853b6b045`) and the ECDSA root "Key
Attestation CA1". Refresh it from that URL when Google adds a root.

The revocation list is not vendored: it changes daily. The Verifier loads
it from a file (`vs --android-status`), refreshed from
<https://android.googleapis.com/attestation/status>.
