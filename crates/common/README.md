# common

What the prototype's processes share:

- `proto`: messages on the public links (QUIC, bincode-framed): the GS to
  Server Liveness, clients to the Verifier and the Broker;
- `admission`: the challenge every public link opens with, and serving it;
- `framing`: length-prefixed frames with size limits;
- `pki`: the dev CA, each public service's TLS identity, and TLS 1.3 /
  QUIC configs (FPP-T1);
- `keys`: the public key bundle relying parties trust;
- `crypto`: signing helpers and time;
- `tpm`: the join-quote nonce.
