
# `attested-tls-proxy`

This is a work-in-progress crate designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy).

It has three commands:
- `server` - run a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- `client` - run a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.
- `get-tls-cert` - connects to a proxy-server, verify the attestation, and if successful write the server's PEM-encoded TLS certificate chain to standard out. This can be used to make subsequent connections to services using this certificate over regular TLS.

Unlike `cvm-reverse-proxy`, this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.

However attestation generation and verification is not yet implemented - there is a trait provided and mock attestation for testing purposes.

This shares some code with [ameba23/attested-channels](https://github.com/ameba23/attested-channels) and may eventually be merged with that crate.

