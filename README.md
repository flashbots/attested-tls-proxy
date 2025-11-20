
# `attested-tls-proxy`

This is a work-in-progress crate designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy).

It has three subcommands:
- `attested-tls-proxy server` - run a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- `attested-tls-proxy client` - run a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.
- `attested-tls-proxy get-tls-cert` - connects to a proxy-server, verify the attestation, and if successful write the server's PEM-encoded TLS certificate chain to standard out. This can be used to make subsequent connections to services using this certificate over regular TLS.

Unlike `cvm-reverse-proxy`, this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.


### Overview

This is a reverse HTTP proxy allowing a normal HTTP client to communicate with a normal HTTP server over a remote-attested TLS channel, by tunneling requests through a proxy-client and proxy-server.

This works as follows:
1. The source HTTP client (eg: curl or a web browser) makes an HTTP request to a proxy-client instance running locally.
2. The proxy-client forwards the request to a proxy-server instance over a remote-attested TLS channel.
3. The proxy-server forwards the request to the target service over regular HTTP.
4. The response from the target service is sent back to the source client, via the proxy-server and proxy-client.

One or both of the proxy-client and proxy-server may be running in a confidential environment and provide attestations which will be verified by the remote party. Verification is configured by a measurements file, and attestation generation is configured by specifying an attestation type when starting the proxy client or server.

### Measurements File

Accepted measurements for the remote party are specified in a JSON file containing an array of objects, each of which specifies an accepted attestation type and set of measurements.

These object have the following fields:
- `measurement_id` - a name used to describe the entry. For example the name and version of the CVM OS image that these measurements correspond to.
- `attestation_type` - one of the attestation types (confidential computing platforms) described below. 
- `measurements` - an object with fields referring to the five measurement registers.

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

### Measurement Headers

When attestation is validated successfully, the following values are injected into the request / response headers making them available to the source client and/or target service:

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

## Protocol Specification
