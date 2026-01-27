# attested-tls

### Measurements File

Accepted measurements for the remote party can be specified in a JSON file containing an array of objects, each of which specifies an accepted attestation type and set of measurements.

This aims to match the formatting used by `cvm-reverse-proxy`.

These objects have the following fields:
- `measurement_id` - a name used to describe the entry. For example the name and version of the CVM OS image that these measurements correspond to.
- `attestation_type` - a string containing one of the attestation types (confidential computing platforms) described below. 
- `measurements` - an object with fields referring to the five measurement registers. Field names are the same as for the measurement headers (see below).

Example:

```JSON
[
    {
        "measurement_id": "dcap-tdx-example",
        "attestation_type": "dcap-tdx",
        "measurements": {
            "0": {
                "expected": "47a1cc074b914df8596bad0ed13d50d561ad1effc7f7cc530ab86da7ea49ffc03e57e7da829f8cba9c629c3970505323"
            },
            "1": {
                "expected": "da6e07866635cb34a9ffcdc26ec6622f289e625c42c39b320f29cdf1dc84390b4f89dd0b073be52ac38ca7b0a0f375bb"
            },
            "2": {
                "expected": "a7157e7c5f932e9babac9209d4527ec9ed837b8e335a931517677fa746db51ee56062e3324e266e3f39ec26a516f4f71"
            },
            "3": {
                "expected": "e63560e50830e22fbc9b06cdce8afe784bf111e4251256cf104050f1347cd4ad9f30da408475066575145da0b098a124"
            },
            "4": {
                "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            }
        }
    }
]
```

The only mandatory field is `attestation_type`. If an attestation type is specified, but no measurements, *any* measurements will be accepted for this attestation type. The measurements can still be checked up-stream by the source client or target service using header injection described below. But it is then up to these external programs to reject unacceptable measurements. 

If a measurements file is not provided, a single allowed attestation type **must** be specified using the `--allowed-remote-attestation-type` option. This may be `none` for cases where the remote party is not running in a CVM, but that must be explicitly specified. 

### Attestation Types

These are the attestation type names used in the HTTP headers, and the measurements file, and when specifying a local attestation type with the `--client-attestation-type` or `--server-attestation-type` command line options.

- `auto` - detect attestation type (used only when specifying the local attestation type as a command-line argument)
- `none` - No attestation provided
- `dummy` - Forwards the attestation to a remote service (for testing purposes, not yet supported)
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `azure-tdx` - TDX on Azure, with MAA (not yet supported)
- `qemu-tdx` - TDX on Qemu (no cloud platform)
- `dcap-tdx` - DCAP TDX (platform not specified)

## Protocol Specification

This is based on TLS 1.3.

The protocol name `flashbots-ratls/1` must be given in the TLS configuration for ALPN protocol negotiation during the TLS handshake. Future versions of this protocol will use incrementing version numbers, eg: `flashbots-ratls/2`.

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

## Dependencies and feature flags

The `azure` feature, for Microsoft Azure attestation requires [tpm2](https://tpm2-software.github.io) to be installed. On Debian-based systems this is provided by [`libtss2-dev`](https://packages.debian.org/trixie/libtss2-dev), and on nix `tpm2-tss`.

This feature is enabled by default. For non-azure deployments you can compile without this requirement by specifying `--no-default-features`. But note that this is will disable both generation and verification of azure attestations.
