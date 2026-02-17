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

In the case of attestation types `dcap-tdx`, `gcp-tdx`, and `qemu-tdx`, a standard DCAP attestation is generated using the `configfs-tsm` linux filesystem interface. This means that this binary must be run with access to `/sys/kernel/config/tsm/report` which on many systems requires sudo.

When verifying DCAP attestations, the Intel PCS is used to retrieve collateral unless a PCCS url is provided via a command line argument. If expired TCB collateral is provided, the quote will fail to verify.

### Attestation Types

These are the attestation type names used in the measurements file.

- `none` - No attestation provided
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `azure-tdx` - TDX on Azure, with vTPM attestation 
- `qemu-tdx` - TDX on Qemu (no cloud platform)
- `dcap-tdx` - DCAP TDX (platform not specified)

Local attestation types can be automatically detected.

## Measurements File

Accepted measurements for the remote party can be specified in a JSON file containing an array of objects, each of which specifies an accepted attestation type and set of measurements.

This aims to match the formatting used by `cvm-reverse-proxy`.

These objects have the following fields:
- `measurement_id` - a name used to describe the entry. For example the name and version of the CVM OS image that these measurements correspond to.
- `attestation_type` - a string containing one of the attestation types (confidential computing platforms) described below.
- `measurements` - an object with fields referring to the five measurement registers. Field names are the same as for the measurement headers (see below).

Each measurement register entry supports two mutually exclusive fields:
- `expected_any` - **(recommended)** an array of hex-encoded measurement values. The attestation is accepted if the actual measurement matches **any** value in the list (OR semantics).
- `expected` - **(deprecated)** a single hex-encoded measurement value. Retained for backwards compatibility but `expected_any` should be preferred.

Example using `expected_any` (recommended):

```JSON
[
    {
        "measurement_id": "dcap-tdx-example",
        "attestation_type": "dcap-tdx",
        "measurements": {
            "0": {
                "expected_any": [
                    "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"
                ]
            },
            "1": {
                "expected_any": [
                    "da6e07866635cb34a9ffcdc26ec6622f289e625c42c39b320f29cdf1dc84390b4f89dd0b073be52ac38ca7b0a0f375bb"
                ]
            },
            "2": {
                "expected_any": [
                    "a7157e7c5f932e9babac9209d4527ec9ed837b8e335a931517677fa746db51ee56062e3324e266e3f39ec26a516f4f71"
                ]
            },
            "3": {
                "expected_any": [
                    "e63560e50830e22fbc9b06cdce8afe784bf111e4251256cf104050f1347cd4ad9f30da408475066575145da0b098a124"
                ]
            },
            "4": {
                "expected_any": [
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ]
            }
        }
    }
]
```

The `expected_any` field is useful when multiple measurement values should be accepted for a register (e.g., for different versions of the firmware):

```JSON
{
    "0": {
        "expected_any": [
            "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323",
            "abc123def456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ]
    }
}
```

<details>
<summary>Legacy format using deprecated <code>expected</code> field</summary>

The `expected` field is deprecated but still supported for backwards compatibility:

```JSON
[
    {
        "measurement_id": "dcap-tdx-example",
        "attestation_type": "dcap-tdx",
        "measurements": {
            "0": {
                "expected": "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"
            }
        }
    }
]
```

</details>

The only mandatory field is `attestation_type`. If an attestation type is specified, but no measurements, *any* measurements will be accepted for this attestation type. The measurements can still be checked up-stream by the source client or target service using header injection described below. But it is then up to these external programs to reject unacceptable measurements.

