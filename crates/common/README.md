# common

What the prototype's processes share:

- `proto`: control-link messages (QUIC, bincode-framed);
- `framing`: length-prefixed frames with size limits;
- `pki`: the dev CA, TLS identities, and TLS 1.3 / QUIC configs (FPP-T1);
- `keys`: service keys and the public key bundle;
- `crypto`: signing helpers and time;
- `config`: the VS's configuration;
- `tpm`: the join-quote nonce.
