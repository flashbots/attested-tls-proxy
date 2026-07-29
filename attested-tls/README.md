# attested-tls

This is a remote-attested TLS protocol and library which uses a post-handshake attestation exchange.

It is designed to provide a secure channel for communicating with confidential virtual machine based services.

A normal TLS 1.3 handshake takes place, followed by an attestation exchange sent as normal application data. If the attestation was successful the session is used for normal application traffic.

This means normal CA-signed TLS certificates can be used, and there is nothing special about the TLS implementation, or any special handshake message extensions or certificate extensions.

The only special TLS configuration is that the protocol name is specified in ALPN protocol negotiation.

It uses session binding through exported key material from the TLS session. This means the attestation is guaranteed to be fresh, and is authenticated with ephemeral secrets unique to the session. 

Attestation may be provided by either the server, or the client, or both.

## Protocol Specification

A TLS 1.3 handshake is made between server and client. The protocol name `flashbots-ratls/1` is included in ALPN. Future versions of the protocol may add additional protocol names which increment the number given after the slash, but backwards compatibility will be provided through also specifying `flashbots-ratls/1`.

### Attestation Exchange

Immediately after the TLS handshake, an attestation exchange is made. The server first provides an attestation message (even if it has the `none` attestation type). The client verifies, if verification is successful it also provides an attestation message and otherwise closes the connection. If the server cannot verify the client's attestation, it closes the connection.

Attestation exchange messages are formatted as follows:
- A 4 byte length prefix - a big endian encoded unsigned 32 bit integer
- A SCALE (Simple Concatenated Aggregate Little-Endian) encoded [struct](./src/attestation/mod.rs) with the following fields:
  - `attestation_type` - a string with one of the attestation types (described above) including `none`.
  - `attestation` - the actual attestation data. In the case of DCAP this is a binary quote report. In the case of `none` this is an empty byte array.

SCALE is used by parity/substrate and was chosen because it is simple and actually matches the formatting used in TDX quotes. So it was already used as a dependency (via the [`dcap-qvl`](https://docs.rs/dcap-qvl) crate).

### Attestation Generation and Verification

Attestation input takes the form of a 64 byte array.

The first 32 bytes are the SHA256 hash of the encoded public key from the TLS leaf certificate of the party providing the attestation, DER encoded exactly as given in the certificate.

The remaining 32 bytes are exported key material ([RFC5705](https://www.rfc-editor.org/rfc/rfc5705)) from the TLS session. This must have the exporter label `EXPORTER-Channel-Binding` and no context data.

In the case of attestation types `dcap-tdx` and `gcp-tdx`, a standard DCAP attestation is generated using the `configfs-tsm` Linux filesystem interface. This means that this binary must be run with access to `/sys/kernel/config/tsm/report`, which on many systems requires elevated privileges.

When verifying DCAP attestations, the Intel PCS is used to retrieve collateral unless a PCCS url is provided via a command line argument. If expired TCB collateral is provided, the quote will fail to verify.

### Accepted Measurement Policies

These are specified in the `attestation` crate documentation:

- [Attestation types](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#attestation-types)
- [Measurements file format](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#measurements-file)
- [Portable measurement policies](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#portable-measurement-policies)
