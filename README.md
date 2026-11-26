
# `attested-tls-proxy`

This is a reverse HTTP proxy allowing a normal HTTP client to communicate with a normal HTTP server over a remote-attested TLS channel, by tunneling requests through a proxy-client and proxy-server which handle attestation generation and verification.

This is designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy). Unlike `cvm-reverse-proxy` this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.

Details of the remote-attested TLS protocol are in [crates/attested-tls/README.md](crates/attested-tls/README.md).  This is provided as a separate crate for other uses than HTTP proxying.

The proxy-client, on starting, immediately connects to the proxy-server and an attestation-verification exchange is made. This attested-TLS channel is then re-used for requests from that proxy-client instance. If the channel is lost, the client reconnects automatically and repeats the attestation exchange before forwarding subsequent requests.

It has seven subcommands:

- `attested-tls-proxy server` - run a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- `attested-tls-proxy client` - run a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.
- `attested-tls-proxy get-tls-cert` - connect to a proxy server, verify its attestation, and, if successful, write its PEM-encoded TLS certificate chain to standard output. This can be used to make subsequent connections to services using this certificate over regular TLS.
- `attested-tls-proxy attested-file-server` - serve files from a local filesystem path over an attested TLS channel.
- `attested-tls-proxy attested-get` - connect to a proxy server, verify its attestation, make a single HTTP GET request, and write the response body to standard output.
- `attested-tls-proxy tcp-tunnel-client` - forward local TCP connections through an attested tunnel.
- `attested-tls-proxy tcp-tunnel-server` - accept attested tunnels and forward each to a fixed TCP target.

For opaque TCP forwarding, see [the TCP tunnel](crates/attested-tls-proxy/TCP_TUNNEL.md). The `tcp-tunnel-client` and `tcp-tunnel-server` commands and the `attested_tls_proxy::tcp_tunnel` library module provide one attested connection per source TCP connection, including support for gRPC.

All commands log at info level to stderr by default. Use `--log-debug` for debug logs and `--log-json` for structured logs. Command output, such as HTTP response bodies and certificates, is written to stdout.

### How it works

This works as follows:
1. The source HTTP client (eg: curl or a web browser) makes an HTTP request to a proxy-client instance running locally.
2. The proxy-client forwards the request to a proxy-server instance over a remote-attested TLS channel.
3. The proxy-server forwards the request to the target service over regular HTTP.
4. The response from the target service is sent back to the source client, via the proxy-server and proxy-client.

One or both of the proxy-client and proxy-server may be running in a confidential environment and provide attestations which will be verified by the remote party. Verification is configured by a measurements file, and attestation generation is configured by specifying an attestation type when starting the proxy client or server.

Each HTTP proxy connection setup attempt has a 60-second deadline covering TCP connection, TLS, attestation, and HTTP setup. A startup timeout returns an error and reconnection attempts that time out retry with exponential backoff. The HTTP proxy server also closes incoming connections whose TLS handshake and attestation exchange do not complete within 60 seconds. These setup deadlines do not limit the lifetime of established connections.

### Measurements File

Accepted measurements for the remote party can be specified in a JSON document loaded from a local file or URL. It contains an array of objects, each of which specifies an accepted attestation type and set of measurement values or OS image hashes.

This aims to be compatible with the formatting used by `cvm-reverse-proxy`.

Details and examples of the measurements file format are [in the `attestation` crate documentation](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#measurements-file).

Provide exactly one of `--measurements-file` and `--allowed-remote-attestation-type`.
The latter accepts `dcap-tdx` or `tdx` for both generic DCAP and GCP TDX,
`gcp-tdx` for GCP TDX only, or `none` to explicitly allow an unattested peer.

As an alternative to specifying measurement values, OS image hashes can be specified. See [portable measurement policies](https://github.com/flashbots/attested-tls/tree/main/crates/attestation#portable-measurement-policies) for details.

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
  "4": "48 byte RTMR3 value encoded as hex"
}
```

Header name: `X-Flashbots-Attestation-Type`

Header value: an attestation type given as a string as described below.

### Attestation Types

The HTTP headers and measurements file use the following attestation types. The
`--client-attestation-type` and `--server-attestation-type` options also accept
`auto` for local platform detection.

- `none` - No attestation provided
- `gcp-tdx` - DCAP TDX on Google Cloud Platform
- `dcap-tdx` - DCAP TDX (platform not specified)

The HTTP and TCP tunnel client/server commands default to `auto` when the local
attestation type is omitted. Without a provider, startup fails if no supported
attestation platform is detected. With a provider socket, the provider supplies
the attestation and its type. To run without local attestation, explicitly pass
`--client-attestation-type none` or `--server-attestation-type none` (or set the
corresponding `CLIENT_ATTESTATION_TYPE` / `SERVER_ATTESTATION_TYPE` environment
variable to `none`). This is separate from the remote verification policy.

### Upgrading from Azure attestation

Azure attestation generation and verification have been removed. Remove every
`azure-tdx` record from measurements files before upgrading, including files
that also contain DCAP or GCP records. A file with any Azure record will fail to
load. Update any `azure-tdx` CLI or environment settings to match the deployed
platform. Remove the `--override-azure-outdated-tcb` flag,
`OVERRIDE_AZURE_OUTDATED_TCB` environment variable, and `azure` Cargo feature
from deployment and build settings. For Docker builds that pass `FEATURES=auto`,
omit the argument to use the new default.

### Attestation Provider

`client`, `server`, `tcp-tunnel-client`, `tcp-tunnel-server`, and
`attested-file-server` accept `--attestation-provider-socket <PATH>` (or
`ATTESTATION_PROVIDER_SOCKET`) to delegate quote generation and platform metadata
collection to the local attestation provider service. Use an absolute Unix socket
path. When the local attestation type is omitted or set to `auto`, the proxy
requests evidence from the provider and uses the type carried in that evidence.
The connection fails if the provider returns evidence for an unsupported platform.

For example, with a provider running locally:

```sh
attested-tls-proxy server 127.0.0.1:8000 \
  --listen-addr 0.0.0.0:8443 \
  --attestation-provider-socket /run/attestation-provider/attestation.sock \
  --allowed-remote-attestation-type none
```

The flag takes precedence over the environment variable. When the socket option
is unset, attestation generation runs in the proxy process. `attested-file-server`
defaults to `none` without a provider and uses the provider when a socket is set.
Explicit `none` disables local attestation, including when a socket is set.
Provider connections are made when generating evidence, so socket access and
generation errors surface during connection setup.

The service creates its socket with mode `0660`. Give the proxy access through
the socket's group and provision the socket directory with that group and mode
`2750`. For containers, bind-mount the provider directory at the configured path
and make its group available to the proxy user. See the
[provider documentation](https://github.com/flashbots/attested-tls/tree/main/crates/attestation-provider-server)
for the directory ownership and permissions required by the service.

This option replaces `--dev-dummy-dcap`; migrate existing HTTP provider URLs to
the Unix socket service.

GitHub releases include standalone `attested-tls-proxy` and
`attestation-provider-server` binaries and one `attested-tls-proxy` Debian package
containing both binaries. `sha256sums.txt` covers both binaries and the package.
The provider is built from the exact upstream
revision pinned by the `attestation` dependency, using upstream's `Cargo.lock`.
It reports its upstream Git revision with `--version`.

Both binaries use the same Docker builder, Rust toolchain, reproducible profile,
build flags, and commit timestamp. To build the provider locally, run
`make build-attestation-provider`
(Python 3.11 or newer is required for checkout and profile preparation). Make
invokes Cargo directly for both binaries. To rebuild twice and compare artifact hashes,
run `scripts/check-reproducibility.sh`; pass `provider-artifacts` to check only
the provider binary. To build the combined package locally, run
`make build build-attestation-provider` followed by `make build-deb`. Set
`VERSION` to use the same `1~<version>` package version as a release.
Packaging uses the pinned cargo-deb version and commit timestamp and preserves
both compiled binaries without rebuilding or stripping them. The package installs
both binaries in `/usr/bin`, declares their native library dependencies, and
includes the provider's full upstream license and documentation under
`/usr/share/doc/attested-tls-proxy/attestation-provider-server/`.
It replaces the former standalone `attestation-provider-server` package on upgrade.
The proxy and provider continue to run as separate processes with independently
configured permissions.
`RUST_TOOLCHAIN`, `RUST_IMAGE`, `FEATURES`, `SOURCE_DATE`, and `VERSION`
can be set to reproduce a particular release's build inputs. The release workflow
records the Rust version, immutable builder image digest, and timestamp in its job summary.

### Client key allowlist

On `server`, `tcp-tunnel-server`, and `attested-file-server`, use
`--client-key-allowlist <FILE>` to authenticate clients by Ed25519 public key
during the TLS 1.3 handshake. This option is mutually exclusive with
`--client-auth`, which verifies client certificates against public CA roots.

Use a regular file of at most 64 KiB. Put one raw 32-byte Ed25519 public key
per line, encoded as exactly 64 lowercase hex digits. Blank lines and
whole-line `#` comments are allowed. An empty list, a malformed line anywhere
in the file, or a read error denies all clients. **Replace the file atomically** by writing
the complete new list to a temporary file in the same directory and renaming it
over the configured path.

While the file exists, a client must present a certificate containing a listed
key and prove possession of its private key. On `client` or `tcp-tunnel-client`,
pass the PEM private key with `--tls-private-key-path` and a PEM self-signed
certificate over that same Ed25519 key with `--tls-certificate-path`.

With `--client-key-allowlist-when-missing closed` (the default), a missing file
refuses every handshake. With `open`, a missing file permits anonymous TLS
until the running server first observes the allowlist path, even if the file is
malformed or unreadable. During that initial open period the server sends no
certificate request, even to a client configured to send its own attestation.
Once the server has seen the path, removing it denies access until a valid
list is restored or the process restarts.

The server checks the allowlist during the TLS handshake, at the start of each
HTTP/1 or HTTP/2 request, and every five seconds on open HTTP connections. A
failed check closes the connection and cuts off any uploads or responses still
streaming. The TCP tunnel server checks at tunnel start and every five seconds
while forwarding. Revocation can take up to five seconds to stop traffic,
including when the allowlist changes as the tunnel starts.

On Unix the server caches parsed keys by
device, inode, modification time, and length. Rustls handshake callbacks perform
synchronous file checks with reads bounded to 64 KiB plus one byte to detect
growth. HTTP and tunnel rechecks run on blocking workers.

### Other CLI Options

- `--pccs-url` selects the PCCS used to retrieve collateral when verifying DCAP attestations. It defaults to Intel PCS.
- `--intel-pcs-subscription-key <KEY>` (or `INTEL_PCS_SUBSCRIPTION_KEY`) supplies an API key for Intel PCS when verifying DCAP attestations. The CLI flag takes precedence over the environment variable. This global option is mutually exclusive with `--pccs-url`.
- `client`, `get-tls-cert`, and `attested-get` accept `--allow-self-signed` to permit a self-signed remote TLS certificate.
- `client` and `server` accept `--listen-addr-healthcheck` to start a separate HTTP health-check listener.
- `client --request-timeout-secs` sets the deadline from receipt of request headers through queueing, upload, and receipt of response headers (default: 60 seconds). Expired requests receive HTTP 504 and are not retried. If a response has already started, an unfinished upload is canceled at the deadline; its response status cannot be changed. Response bodies can continue streaming after that deadline once the upload completes.
- `client --response-body-idle-timeout-secs` closes a source connection if its active response body makes no socket write progress for this interval (default: 60 seconds). This covers silent backends and clients that stop reading, even when body polling is blocked. The affected request releases its capacity; HTTP/1.1 reconnects upstream, while other HTTP/2 streams remain usable. Responses already started are truncated rather than replaced with a 504. Streams that keep making progress may continue indefinitely.
- `client --max-in-flight-requests` limits admitted requests, including streaming responses (default: 64). HTTP/2 requests run concurrently; HTTP/1.1 uses one request at a time and reconnects after a timeout or cancellation. Requests waiting for capacity are subject to the same deadline.
- `get-tls-cert --out-measurements <PATH>` writes the verified remote measurements as JSON in addition to writing the certificate chain to standard output.
- `attested-get` does not follow HTTP redirects and exits with an error on 3xx responses. Its library API returns the original response for inspection. The loopback request ignores environment proxy settings.
- If `server` is started without `--tls-private-key-path` and `--tls-certificate-path`, it generates a self-signed certificate for its listening IP address.

These limits also apply to library callers: `ProxyClient::new*` defaults to a 60-second request deadline, a 60-second response-body idle timeout, and 64 in-flight requests. Set `ProxyClientOptions` with `with_request_options` before accepting connections to adjust them, including for long-polling services or streams with long gaps between messages. The idle timeout is inactive while waiting for response headers or between requests on a keep-alive connection.

## Protocol Specification

A proxy-client will immediately attempt to connect to the given proxy-server.

Proxy-client to proxy-server connections use TLS 1.3.

The protocol name `flashbots-ratls/1` must be given in the TLS configuration for ALPN protocol negotiation during the TLS handshake. Future versions of this protocol will use incrementing version numbers, eg: `flashbots-ratls/2`.

Immediately after the TLS handshake, an attestation exchange is made. Details of how this works are in the [attested-tls protocol specification](crates/attested-tls/README.md#protocol-specification).

Following a successful attestation exchange, the client can make HTTP requests, and the server will forward them to the target service.

As described above, the server will inject measurement data into the request headers before forwarding them to the target service, and the client will inject measurement data into the response headers before forwarding them to the source client.

The proxy client and proxy server support HTTP/2 and HTTP/1.1 over their attested-TLS channel, with HTTP/2 preferred. The HTTP protocol is combined with the attested-TLS protocol version in ALPN, producing `flashbots-ratls/1+h2` or `flashbots-ratls/1+http/1.1`. A negotiated `flashbots-ratls/1` value without an HTTP suffix falls back to HTTP/1.1.

The proxy preserves an upstream HTTP `Date` and fills in a missing one from the current system clock so the header reflects backward clock steps immediately. Hyper still sets the `Date` on responses it sends before a request reaches a handler, such as HTTP/1 parse errors.

## Repository layout and development

- `crates/attested-tls`: the attested TLS protocol library.
- `crates/attested-tls-proxy`: the HTTP proxy library and CLI. HTTP forwarding
  lives in `src/http`; its public API is also re-exported at the crate root.

Run the commands below from the repository root. The proxy is the default
workspace member, so existing `cargo run -- ...` commands still work. Build
artifacts remain in the root `target/` directory.

```sh
cargo build -p attested-tls-proxy --locked
cargo test --workspace --features attested-tls/ws,attested-tls/rpc --all-targets --locked
cargo clippy --workspace --features attested-tls/ws,attested-tls/rpc --locked -- -D warnings
cargo fmt --all -- --check
```

To install from a local checkout, use `cargo install --path crates/attested-tls-proxy --locked`.
Docker and Compose commands also run from the repository root.

The `attested-tls` library's `ws` and `rpc` features are opt-in and included in
the test and lint commands above.

## Trying it out locally (without CVM attestation)

This might help give an understanding of how it works.

1. Run the helper script to generate a mock certificate authority and a TLS certificate for localhost signed by it.

This requires `openssl` to be installed.

```
./scripts/generate-cert.sh localhost 127.0.0.1
```

2. Start an HTTP server to try this out with, on 127.0.0.1:8000.

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

The final positional argument is the target address - in this case the Python server we started in step 2.
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

Since we just wanted to make a single GET request here, we can make this process simpler by using the `attested-get` command:

```
cargo run -- attested-get \
  --url-path README.md \
  --tls-ca-certificate ca.crt \
  --allowed-remote-attestation-type none \
  localhost:7000
```

This should also print the README file. This works even if the proxy-client from step 4 is not running.

## CLI differences from `cvm-reverse-proxy`

This aims to have a similar command line interface to `cvm-reverse-proxy` but there are some differences:

- The measurements file path is specified with `--measurements-file` rather than `--server-measurements` or `--client-measurements`.
- If no measurements file is specified, `--allowed-remote-attestation-type` must be given.
- `--log-dcap-quote` logs all attestation data (not only DCAP), but [currently] only remote attestation data, not locally-generated data.


## Docker

### Building the Image

```bash
docker build -t attested-tls-proxy .
```

The optional `FEATURES` build argument takes a space-delimited list of Cargo
features and defaults to an empty list on every architecture.

### Running

The same image supports all subcommands (server, client, get-tls-cert, etc.):

```bash
# Show help
docker run --rm attested-tls-proxy --help

# Run as server, forwarding to a service on port 8080 of the Docker host
docker run --rm \
  --mount type=bind,source=/path/to/certs,target=/certs,readonly \
  --add-host host.docker.internal:host-gateway \
  -p 8443:443 \
  attested-tls-proxy server \
  --listen-addr 0.0.0.0:443 \
  --tls-private-key-path /certs/server.key \
  --tls-certificate-path /certs/server.crt \
  --server-attestation-type none \
  --allowed-remote-attestation-type none \
  host.docker.internal:8080

# Run as client
docker run --rm attested-tls-proxy client \
  --listen-addr 0.0.0.0:8080 \
  target-server:443 \
  --client-attestation-type none \
  --allowed-remote-attestation-type none
```

Replace `/path/to/certs` with the host directory containing `server.key` and `server.crt`.
When the target service is another container, attach both containers to the same Docker network and
use the target container's name instead of `host.docker.internal`.

### Testing with Docker Compose

A `docker-compose.yml` is provided for local testing of the full proxy chain.
It uses test certificates and explicitly disables local attestation on both
proxies, testing TLS forwarding without attestation. For a CVM deployment,
configure local attestation and remote verification policies for your platform.

1. **Generate test certificates:**
   ```bash
   mkdir -p certs
   (cd certs && ../scripts/generate-cert.sh proxy-server 127.0.0.1)
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
