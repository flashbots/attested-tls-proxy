
# `attested-tls-proxy`

This is a work-in-progress crate designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy).

It has three commands:
- `server` - run a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- `client` - run a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.
- `get-tls-cert` - connects to a proxy-server, verify the attestation, and if successful write the server's PEM-encoded TLS certificate chain to standard out. This can be used to make subsequent connections to services using this certificate over regular TLS.

Unlike `cvm-reverse-proxy`, this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.

This repo shares some code with [ameba23/attested-channels](https://github.com/ameba23/attested-channels) and may eventually be merged with that crate.

## Measurement headers

When attestation is validated successfully, the following values are injected into the request / response headers:

Header name: `X-Flashbots-Measurement`

Header value:
```json
{
  "0": "48 byte MRTD value encoded as hex",
  "1": "48 byte RTMR0 value encoded as hex",
  "2": "48 byte RTMR1 value encoded as hex",
  "3": "48 byte RTMR2 value encoded as hex",
  "4": "48 byte RTMR3 value encoded as hex",
}
```

Header name: `X-Flashbots-Attestation-Type`

Header value:

One of `none`, `dummy`, `azure-tdx`, `qemu-tdx`, `gcp-tdx`.

These aim to match the header formatting used by `cvm-reverse-proxy`.

