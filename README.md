# `attested-tls-proxy`

This is a reverse HTTP proxy allowing a normal HTTP client to communicate with a normal HTTP server over a remote-attested TLS channel, by tunneling requests through a proxy-client and proxy-server which handle attestation generation and verification.

This is designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy). Unlike `cvm-reverse-proxy`, this can use a regular PKI certificate on an outer TLS session while carrying attestation on an inner attested TLS session.

The protocol primitives now live in the external [`flashbots/attested-tls`](https://github.com/flashbots/attested-tls) repository:

- [`attested-tls`](https://github.com/flashbots/attested-tls/tree/main/crates/attested-tls) for attested TLS certificate handling
- [`nested-tls`](https://github.com/flashbots/attested-tls/tree/main/crates/nested-tls) for the optional outer TLS session
- [`attestation`](https://github.com/flashbots/attested-tls/tree/main/crates/attestation) for attestation generation, verification, and measurement policies

It has four main subcommands:

- `attested-tls-proxy server` - run a proxy server that exposes an inner attested TLS listener and optionally an outer nested-TLS listener, then forwards traffic to a target service.
- `attested-tls-proxy client` - run a proxy client that accepts local HTTP connections and forwards them to the proxy server over nested TLS or directly to the inner attested TLS listener.
- `attested-tls-proxy get-tls-cert` - connect to a proxy server, verify the remote attestation, and write the inner PEM-encoded TLS certificate chain to standard output.
- `attested-tls-proxy attested-get` - perform a single GET request through the attested channel and print the response body.

## How It Works

This works as follows:

1. A source HTTP client such as `curl` or a web browser makes an HTTP request to a local proxy-client instance.
2. The proxy-client connects to the proxy-server over either:
   - nested TLS: outer PKI TLS plus inner attested TLS, or
   - inner-only mode: direct connection to the inner attested TLS listener with `--inner-session-only`.
3. The proxy server verifies the client attestation when configured to require it, extracts remote attestation from the peer certificate on the inner session, and forwards the HTTP request to the target service.
4. The target service response is returned through the proxy server and proxy client to the source client.

One or both of the proxy client and proxy server may run in a confidential environment and provide attestations which are verified by the remote party. Verification is configured by a measurements file or by allowing a single remote attestation type.

## Measurements File

Accepted measurements for the remote party can be specified in a JSON file containing an array of policy entries. Each entry specifies an accepted attestation type and a set of measurements.

This aims to match the formatting used by `cvm-reverse-proxy`.

The canonical format is documented in the upstream [`attestation` crate README](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#measurements-file). That document is the source of truth for:

- current attestation type names
- preferred measurement field names
- legacy field names still accepted for compatibility
- `expected_any` versus legacy `expected`

If a measurements file is not provided, a single allowed attestation type **must** be specified using `--allowed-remote-attestation-type`. This may be `none` when the remote party is not running in a CVM, but it must be stated explicitly.

## Measurement Headers

When attestation is validated successfully, the following headers are injected into the HTTP request or response, making them available to the source client and target service.

These aim to match the header formatting used by `cvm-reverse-proxy`.

Header name: `X-Flashbots-Measurement`

Header value:

```json
{
  "0": "48 byte MRTD value encoded as hex",
  "1": "48 byte RTMR0 value encoded as hex",
  "2": "48 byte RTMR1 value encoded as hex",
  "3": "48 byte RTMR2 value encoded as hex",
  "4": "48 byte RTMR3 value encoded as hex"
}
```

Header name: `X-Flashbots-Attestation-Type`

Header value: an attestation type string such as `none`, `gcp-tdx`, `azure-tdx`, `qemu-tdx`, or `dcap-tdx`.

## Connection Model

Proxy-client to proxy-server connections use TLS 1.3. The server can expose two different listeners:

- `--inner-listen-addr` exposes the inner attested TLS listener.
- `--outer-listen-addr` exposes an optional outer nested-TLS listener that wraps the inner session with a regular PKI TLS session.

At least one of these listeners must be configured. If TLS certificate and key files are provided, they apply only to the outer listener, and `--outer-listen-addr` is required.

When the server runs without an outer listener, the inner attested certificate still needs a DNS identity. In that case, use `--inner-certificate-name` to control the certificate name embedded into the inner attested certificate. If an outer certificate is present, the server derives that identity from the outer certificate instead.

On the client side:

- default mode connects to the server's outer listener and verifies the outer PKI certificate before entering the inner attested TLS session
- `--inner-session-only` connects directly to the inner attested TLS listener

In both modes, attestation is taken from the peer certificate on the inner TLS session, then enforced against the configured measurement policy.

## Dependencies and Feature Flags

The `azure` feature for Microsoft Azure attestation requires [tpm2](https://tpm2-software.github.io) to be installed. On Debian-based systems this is provided by [`libtss2-dev`](https://packages.debian.org/trixie/libtss2-dev), and on nix by `tpm2-tss`. This dependency is currently not packaged for MacOS, so it is not currently possible to compile or run with the `azure` feature on MacOS.

This feature is disabled by default. Without it, verification of Azure attestations is not possible and Azure attestations will be rejected with an error.

## Trying It Out Locally

This example uses nested TLS on the outer session and `none` for attestation on both sides.

1. Generate a local certificate authority and a TLS certificate for `localhost`.

This requires `openssl` to be installed.

```bash
./scripts/generate-cert.sh localhost 127.0.0.1
```

2. Start a local HTTP server on `127.0.0.1:8000`.

This requires `python3` to be installed.

```bash
python3 -m http.server 8000
```

3. Start the proxy server with both an inner and outer listener.

```bash
cargo run -- server \
  --outer-listen-addr 127.0.0.1:7000 \
  --inner-listen-addr 127.0.0.1:7001 \
  --server-attestation-type none \
  --allowed-remote-attestation-type none \
  --tls-private-key-path server.key \
  --tls-certificate-path server.crt \
  127.0.0.1:8000
```

The final positional argument is the target address, in this case the Python server from step 2.

4. Start a proxy client that connects through the outer nested-TLS listener.

```bash
cargo run -- client \
  --listen-addr 127.0.0.1:6000 \
  --client-attestation-type none \
  --allowed-remote-attestation-type none \
  --tls-ca-certificate ca.crt \
  localhost:7000
```

The final positional argument is the hostname and port of the proxy server's outer listener. `--tls-ca-certificate` is only used in nested-TLS mode.

5. Make an HTTP request to the proxy client.

```bash
curl http://127.0.0.1:6000/README.md
```

Assuming you started the Python HTTP server in the repository root, this should print this README.

For a single request, `attested-get` is simpler:

```bash
cargo run -- attested-get \
  --url-path README.md \
  --tls-ca-certificate ca.crt \
  --allowed-remote-attestation-type none \
  localhost:7000
```

This should also print the README file.

### Inner-Only Example

If you want to connect directly to the inner attested TLS listener instead of nested TLS:

```bash
cargo run -- server \
  --inner-listen-addr 127.0.0.1:7001 \
  --inner-certificate-name localhost \
  --server-attestation-type none \
  --allowed-remote-attestation-type none \
  127.0.0.1:8000
```

```bash
cargo run -- client \
  --listen-addr 127.0.0.1:6000 \
  --inner-session-only \
  --client-attestation-type none \
  --allowed-remote-attestation-type none \
  localhost:7001
```

In inner-only mode the client does not accept `--tls-ca-certificate`, `--tls-private-key-path`, or `--tls-certificate-path`.

## CLI Differences from `cvm-reverse-proxy`

This aims to have a similar command line interface to `cvm-reverse-proxy`, but there are some differences:

- The measurements file path is specified with `--measurements-file` rather than `--server-measurements` or `--client-measurements`.
- If no measurements file is specified, `--allowed-remote-attestation-type` must be given.
- The server splits listener configuration into `--inner-listen-addr` and optional `--outer-listen-addr`.
- `--log-dcap-quote` logs remote DCAP quotes into `quotes/`.

## Docker

### Building the Image

```bash
docker build -t attested-tls-proxy .

# With custom features, for example without Azure/TPM support:
docker build --build-arg FEATURES="" -t attested-tls-proxy .
```

**Note for Apple Silicon (M1-M4) Mac users:** When building on ARM Macs, the Docker build automatically compiles without Azure/TPM features (`--no-default-features`) because the TPM libraries cannot be cross-compiled. For production builds with full Azure support, use an x86_64 system.

### Running

The same image supports all subcommands:

```bash
# Show help
docker run --rm attested-tls-proxy --help

# Run as server in nested-TLS mode
docker run --rm attested-tls-proxy server \
  --outer-listen-addr 0.0.0.0:443 \
  --inner-listen-addr 0.0.0.0:7443 \
  --tls-private-key-path /path/to/key.pem \
  --tls-certificate-path /path/to/cert.pem \
  --allowed-remote-attestation-type none \
  127.0.0.1:8080

# Run as client
docker run --rm attested-tls-proxy client \
  --listen-addr 0.0.0.0:8080 \
  --allowed-remote-attestation-type none \
  target-server:443
```

### Testing with Docker Compose

A `docker-compose.yml` is provided to test the full proxy chain in nested-TLS mode.

1. Generate test certificates:

```bash
mkdir -p certs && cd certs
../scripts/generate-cert.sh proxy-server 127.0.0.1
# Convert key to PKCS#8 format, required by the proxy
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server.key -out server.pkcs8.key
mv server.pkcs8.key server.key
```

2. Start all services:

```bash
docker compose up --build
```

3. Test the proxy:

```bash
# HTTP through proxy-client
curl http://localhost:8080

# Outer TLS directly to proxy-server
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt -servername proxy-server
```

The `openssl s_client` command should show `Verify return code: 0 (ok)`.
