# attested-tls

This is a remote-attested TLS protocol and library which uses a post-handshake attestation exchange.

It is designed to provide a secure channel for communicating with confidential virtual machine based services.

A normal TLS 1.3 handshake takes place, followed by an attestation exchange sent as normal application data. If the attestation was successful the session is used for normal application traffic.

This means normal CA-signed TLS certificates can be used, and there is nothing special about the TLS implementation, or any special handshake message extensions or certificate extensions.

The only special TLS configuration is that the protocol name is specified in ALPN protocol negotiation.

It uses session binding through exported key material from the TLS session. This means the attestation is guaranteed to be fresh, and is authenticated with ephemeral secrets unique to the session. 

Attestation may be provided by either the server, or the client, or both.

## Optional features

No features are enabled by default. Enable `ws` for the `websockets` module or
`rpc` for the `attested_rpc` module in your Cargo dependency:

```toml
attested-tls = { path = "../attested-tls", features = ["ws", "rpc"] }
```

## Protocol Specification

A TLS 1.3 handshake is made between server and client. Both peers advertise
`flashbots-ratls/2` followed by `flashbots-ratls/1` in ALPN. Application protocols
are appended with `+`, for example `flashbots-ratls/2+h2` or
`flashbots-ratls/2+tcp-tunnel`. The negotiated version selects the exchange
encoding. A v1-only peer continues to use the original format.

### Attestation Exchange

The exchange has two messages, followed immediately by application traffic:

1. The server sends its attestation, including when it presents no evidence.
2. The client verifies the server's attestation and sends its own attestation.
3. The server verifies the client's attestation. There is no final acknowledgement;
   server-side verification failures close the connection.

Each message has a four-byte big-endian unsigned length prefix, followed by at
most 64 KiB of SCALE-encoded payload:

- **V1:** `AttestationExchangeMessage`, unchanged. The message contains
  `attestation_evidence: Option<AttestationEvidence>`; `None` means no attestation.
- **V2:** `Result<AttestationExchangeMessage, AttestationExchangeError>`.
  `Ok` contains the same attestation message. `Err` replaces that peer's normal
  attestation message and always terminates the exchange, even if verification
  policy allows no attestation.

`AttestationExchangeError` is defined in `attested-tls`, separately from the
attestation dependency's local error type. Its SCALE variants have fixed indexes:

- `GenerationFailed(String)` (index 0): the server or client could not generate
  its attestation, including failure of the generation task.
- `VerificationFailed(String)` (index 1): the client rejected the server's
  attestation. This occupies the client's existing reply slot.

The SCALE `Result` tag is 0 for `Ok` and 1 for `Err`. Error strings contain the
local error's display text, truncated at a UTF-8 boundary to at most 2 KiB.
Received error strings over this limit and malformed v2 payloads are rejected.
A received error surfaces as `AttestedTlsError::RemoteAttestation`; it does not
trigger another error reply.

Error transmission and flushing are best-effort, with a one-second deadline.
The failing endpoint retains its original local error if reporting fails or
expires. Enclosing setup deadlines still apply. V1 failures retain the original
behavior of returning the local error and closing the connection.

SCALE is used by parity/substrate and was chosen because it is simple and
already used by attestation dependencies.

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
