
# `attested-tls-proxy`

This is a reverse HTTP proxy allowing a normal HTTP client to communicate with a normal HTTP server over a remote-attested TLS channel, by tunneling requests through a proxy-client and proxy-server which handle attestation generation and verification.

This is designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy). Unlike `cvm-reverse-proxy` this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.

Details of the remote-attested TLS protocol are in [attested-tls/README.md](attested-tls/README.md).  This is provided as a separate crate for other uses than HTTP proxying.

The proxy-client, on starting, immediately connects to the proxy-server and an attestation-verification exchange is made. This attested-TLS channel is then re-used for all requests from that proxy-client instance.

It has three subcommands:
- `attested-tls-proxy server` - run a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- `attested-tls-proxy client` - run a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.
- `attested-tls-proxy get-tls-cert` - connects to a proxy-server, verify the attestation, and if successful write the server's PEM-encoded TLS certificate chain to standard out. This can be used to make subsequent connections to services using this certificate over regular TLS.

### How it works

This works as follows:
1. The source HTTP client (eg: curl or a web browser) makes an HTTP request to a proxy-client instance running locally.
2. The proxy-client forwards the request to a proxy-server instance over a remote-attested TLS channel.
3. The proxy-server forwards the request to the target service over regular HTTP.
4. The response from the target service is sent back to the source client, via the proxy-server and proxy-client.

One or both of the proxy-client and proxy-server may be running in a confidential environment and provide attestations which will be verified by the remote party. Verification is configured by a measurements file, and attestation generation is configured by specifying an attestation type when starting the proxy client or server.

### Measurements File

Accepted measurements for the remote party can be specified in a JSON file containing an array of objects, each of which specifies an accepted attestation type and set of measurements.

This aims to match the formatting used by `cvm-reverse-proxy`.

Details and examples of the measurements file format are [in the attested-tls documentation](attested-tls/README.md#measurements-file).

If a measurements file is not provided, a single allowed attestation type **must** be specified using the `--allowed-remote-attestation-type` option. This may be `none` for cases where the remote party is not running in a CVM, but that must be explicitly specified.

### Measurement Headers

When attestation is validated successfully, the following headers are injected into the HTTP request / response making them available to the source client and/or target service.

These aim to match the header formatting used by `cvm-reverse-proxy`.

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

Header value: an attestation type given as a string as described below.

### Attestation Types

These are the attestation type names used in the HTTP headers, and the measurements file, and when specifying a local attestation type with the `--client-attestation-type` or `--server-attestation-type` command line options.

- `auto` - detect attestation type (used only when specifying the local attestation type as a command-line argument)
- `none` - No attestation provided
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `azure-tdx` - TDX on Azure, with vTPM attestation 
- `qemu-tdx` - TDX on Qemu (no cloud platform)
- `dcap-tdx` - DCAP TDX (platform not specified)

## Protocol Specification

A proxy-client client will immediately attempt to connect to the given proxy-server.

Proxy-client to proxy-server connections use TLS 1.3.

The protocol name `flashbots-ratls/1` must be given in the TLS configuration for ALPN protocol negotiation during the TLS handshake. Future versions of this protocol will use incrementing version numbers, eg: `flashbots-ratls/2`.

Immediately after the TLS handshake, an attestation exchange is made. Details of how this works are in the [attested-tls protocol spepcification](attested-tls/README.md#protocol-specification).

Following a successful attestation exchange, the client can make HTTP requests, and the server will forward them to the target service.

As described above, the server will inject measurement data into the request headers before forwarding them to the target service, and the client will inject measurement data into the response headers before forwarding them to the source client.

<!-- TODO describe HTTP version negotiation details -->

## Dependencies and feature flags

The `azure` feature, for Microsoft Azure attestation requires [tpm2](https://tpm2-software.github.io) to be installed. On Debian-based systems this is provided by [`libtss2-dev`](https://packages.debian.org/trixie/libtss2-dev), and on nix `tpm2-tss`. This dependency is currently not packaged for MacOS, meaning currently it is not possible to compile or run with the `azure` feature on MacOS. 

This feature is disabled by default. Note that without this feature, verification of azure attestations is not possible and azure attestations will be rejected with an error.

## Trying it out locally (without CVM attestation)

This might help give an understanding of how it works.

1. Run the helper script to generate a mock certifcate authority and a TLS certificate for localhost signed by it.

This requires `openssl` to be installed.

```
./scripts/generate-cert.sh localhost 127.0.0.1
```

2. Start a http server to try this out with, on 127.0.01:8000

This requires `python3` to be installed.

```
python3 -m http.server 8000
```

3. Start a proxy-server:

```
cargo run -- server \
  --listen-addr 127.0.0.1:7000 \
  --server-attestation-type none \
  --allowed-remote-attestation-type none \
  --tls-private-key-path server.key \
  --tls-certificate-path server.crt \
  127.0.0.1:8000
```

The final positional argument is the target address - in this case the python server we started in step 3.
Note that you must specify that you accept 'none' as the remote attestation type.

4. Start a proxy-client:

```
cargo run -- client \
  --listen-addr 127.0.0.1:6000 \
  --client-attestation-type none \
  --allowed-remote-attestation-type none \
  --tls-ca-certificate ca.crt \
  localhost:7000
```

The final positional argument is the hostname and port of the proxy-server.
Note that we specified a CA root of trust. If you use a standard certificate authority you do not need this argument.

5. Make a HTTP request to the proxy-client:

```
curl 127.0.0.1:6000/README.md
```

Assuming you started the python http server in the directory of this repository, this should print the contents of this README.

Since we just wanted to make a single GET request here, we can make this process simpler but using the `attested-get` command:

```
cargo run -- attested-get \
  --url-path README.md
  --tls-ca-certificate ca.crt \
  --allowed-remote-attestation-type none \
  localhost:7000
```

This should also print the README file. This should work even if the proxy-client from step 5 is not running.

## CLI differences from `cvm-reverse-proxy`

This aims to have a similar command line interface to `cvm-reverse-proxy` but there are some differences:

- The measurements file path is specified with `--measurements-file` rather than `--server-measurements` or `--client-measurements`.
- If no measurements file is specified, `--allowed-remote-attestation-type` must be given.
- `--log-dcap-quote` logs all attestation data (not only DCAP), but [currently] only remote attestation data, not locally-generated data.


## Docker

### Building the Image

```bash
docker build -t attested-tls-proxy .

# With custom features (e.g., without azure/TPM):
docker build --build-arg FEATURES="" -t attested-tls-proxy .
```

**Note for Apple Silicon (M1-M4) Mac users:** When building on ARM Macs, the Docker build will automatically compile without Azure/TPM features (`--no-default-features`) because the TPM libraries cannot be cross-compiled. For production builds with full Azure support, use an x86_64 system.

### Running

The same image supports all subcommands (server, client, get-tls-cert, etc.):

```bash
# Show help
docker run --rm attested-tls-proxy --help

# Run as server
docker run --rm attested-tls-proxy server \
  --listen-addr 0.0.0.0:443 \
  --target-addr 127.0.0.1:8080 \
  --tls-private-key-path /path/to/key.pem \
  --tls-certificate-path /path/to/cert.pem \
  --allowed-remote-attestation-type none

# Run as client
docker run --rm attested-tls-proxy client \
  --listen-addr 0.0.0.0:8080 \
  target-server:443 \
  --allowed-remote-attestation-type none
```

### Testing with Docker Compose

A `docker-compose.yml` is provided to test the full proxy chain:

1. **Generate test certificates:**
   ```bash
   mkdir -p certs && cd certs
   ../scripts/generate-cert.sh proxy-server 127.0.0.1
   # Convert key to PKCS#8 format (required by the proxy)
   openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in server.key -out server.pkcs8.key
   mv server.pkcs8.key server.key
   ```

2. **Start all services:**
   ```bash
   docker compose up --build
   ```

3. **Test the proxy:**
   ```bash
   # Test via proxy-client (HTTP)
   curl http://localhost:8080
   # Should return the nginx welcome page

   # Test TLS directly to proxy-server
   openssl s_client -connect localhost:8443 -CAfile certs/ca.crt -servername proxy-server
   # Should show "Verify return code: 0 (ok)"
   ```
