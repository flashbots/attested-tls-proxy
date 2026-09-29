# attested-tls-tcp-tunnel

An attested-TLS TCP tunnel with a `client` and `server` CLI and library.
It forwards bytes without parsing any application protocol:

```text
source <-- TCP --> tunnel client <-- attested TLS TCP --> tunnel server <-- TCP --> target
```

Each source TCP connection opens a dedicated attested-TLS connection and target
TCP connection. Separate source connections get separate tunnels; no connections are
pooled. The server forwards to one configured target, which may itself dispatch
requests to a pool of workers.

## Local example

Build the executable:

```sh
cargo build -p attested-tls-tcp-tunnel
```

For a quick round trip, start a local HTTP service in one terminal:

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Start the tunnel server in another terminal. With no certificate/key arguments,
it generates a self-signed certificate. This example explicitly disables local
attestation and accepts a client with no attestation:

```sh
target/debug/attested-tls-tcp-tunnel server \
  --listen-addr 127.0.0.1:7000 \
  --server-attestation-type none \
  --allowed-remote-attestation-type none \
  127.0.0.1:8000
```

Start the tunnel client in another terminal:

```sh
target/debug/attested-tls-tcp-tunnel client \
  --listen-addr 127.0.0.1:6000 \
  --client-attestation-type none \
  --allowed-remote-attestation-type none \
  --allow-self-signed \
  127.0.0.1:7000
```

Then `curl http://127.0.0.1:6000/` reaches the target. These `none` policies are for
demonstrating transport without a CVM. For attested deployments, select the local
attestation type (or leave automatic detection enabled) and configure accepted
remote measurements using `--measurements-file`.

For gRPC, point the tunnel server at your gRPC service instead of port 8000 and
configure the gRPC client to use plaintext HTTP/2 at `127.0.0.1:6000`. Unary and all
streaming RPC types use the same forwarding path. RPC metadata, trailers,
cancellation, PINGs, and GOAWAY travel between the actual gRPC endpoints.

Application TLS also works: configure TLS in the gRPC client and target as usual.
The inner TLS session passes through unchanged. Configure the application's
server name/authority for its real service identity rather than the local tunnel
address. The tunnel's `--tls-*` settings configure only the outer attested TLS.

## Configuration

Both commands require exactly one of `--measurements-file <PATH_OR_URL>` and
`--allowed-remote-attestation-type <TYPE>`. Measurement policy and attestation
settings follow the [HTTP proxy CLI](../README.md#measurements-file).

| Option | Default / behavior |
|---|---|
| `--listen-addr`, `-l` (`LISTEN_ADDR`) | Client `127.0.0.1:0`; server `0.0.0.0:0`. The actual bound address is logged. |
| Positional target | Client `host[:port]`, default port 443; server `host:port` with required port. IPv6 literals use brackets. |
| `--setup-timeout-secs` | 60; includes DNS, connect, TLS, attestation, and the server's target connect. Applied independently at each endpoint. |
| `--max-connections` | 256 per listener, including connections still establishing; excess arrivals are immediately closed. |
| `--shutdown-grace-secs` | 30; stop accepting, drain, then close remaining tunnels. Zero closes immediately. |
| `--tls-private-key-path`, `--tls-certificate-path` | Must be supplied together; accept PKCS#8, RSA PKCS#1, and P-256 SEC1 PEM keys. |
| Client `--tls-ca-certificate` | Trust the first PEM certificate instead of public roots. |
| Client `--allow-self-signed` | Accept a self-signed server certificate; still verify attestation. Cannot combine with `--tls-ca-certificate`. Preserves any supplied client identity. |
| Server `--client-auth` | Require a TLS client certificate authenticated against public roots. Private client CAs can be configured through the Rust API. |
| `--client-attestation-type` / `--server-attestation-type` | Automatic local detection when omitted. |
| `--pccs-url`, `--dev-dummy-dcap` | Same meaning as in the HTTP proxy. |
| `--log-debug`, `--log-json`, `--log-dcap-quote` | Debug logs, structured logs, or DCAP quote dumps in `quotes/`. Payload bytes are never logged. |
| `--override-azure-outdated-tcb` | Same Azure verification override as in the HTTP proxy. |

The existing environment names are supported: `MEASUREMENTS_FILE`,
`TLS_PRIVATE_KEY_PATH`, `TLS_CERTIFICATE_PATH`, `CLIENT_ATTESTATION_TYPE`,
`SERVER_ATTESTATION_TYPE`, and `OVERRIDE_AZURE_OUTDATED_TCB`.

Enable Azure support with `--features azure`; this requires the same TPM system
dependencies as the HTTP proxy. There is no health-check listener in this version.

## Lifecycle and trust

Startup binds the listener without contacting the remote service. Each accepted
connection gets one setup attempt. Failures close that connection and are logged
with the endpoint and phase; the tunnel does not send HTTP/gRPC error messages.
It does not retry, reconnect an established stream, or replay application data.
gRPC channels and applications own reconnection, retries, and stream recovery.

The client verifies the remote server before forwarding source bytes. The server
verifies the client and application protocol before connecting to its target.
The negotiated ALPN must be `flashbots-ratls/1+tcp-tunnel`; the base transport's
bare ALPN fallback is rejected. An HTTP proxy is not a compatible tunnel peer.
After the existing attestation exchange, there is no additional tunnel framing
or readiness acknowledgement. Client-side setup completion does not confirm
that the remote target has connected; a subsequent failure closes the stream.

The local TCP legs rely on their deployment's trust boundary unless the
application supplies its own TLS. Attestation is checked once per new tunnel;
it does not continuously re-attest a long-lived connection or identify each
application sharing a local proxy. The target sees the tunnel server's IP and
receives no injected attestation metadata.

Forwarding uses bounded buffers and preserves half-closes: a sender may finish
its upload while still receiving a response. There is no established-stream
idle timeout or lifetime limit. Configure RPC deadlines and keepalive in gRPC.
A transport error closes the affected tunnel, including its concurrent RPCs.

SIGINT/Ctrl-C and SIGTERM stop acceptance and trigger bounded draining. An opaque
tunnel cannot generate gRPC GOAWAY or drain individual RPCs. Long-lived streams
are interrupted if still active when the grace period expires. Blocking quote
generation cannot be canceled by dropping its async task; the executable uses
bounded runtime shutdown after draining sockets. The connection cap bounds live
connections, not quote-generation work that outlives a setup timeout.

## Rust API

`TunnelClient` and `TunnelServer` offer `new`, `new_with_tls_config`, `local_addr`,
and `serve_until`. `TunnelOptions` contains setup timeout, connection count, and
shutdown grace. The custom constructors accept Rustls configurations alongside
attestation generators/verifiers and matching certificate chains. They replace
ALPN with the tunnel protocol. Initialize a Rustls crypto provider before use.

```rust,no_run
use attested_tls::attestation::{AttestationGenerator, AttestationVerifier};
use attested_tls_tcp_tunnel::{TunnelClient, TunnelOptions};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
let client = TunnelClient::new(
    "127.0.0.1:6000",
    "tunnel.example.com:443".into(),
    None, // optional client TLS identity
    AttestationGenerator::with_no_attestation(),
    AttestationVerifier::expect_none(), // replace with your measurement policy
    None, // use public CA roots
    TunnelOptions::default(),
).await?;
client.serve_until(async {
    let _ = tokio::signal::ctrl_c().await;
}).await?;
# Ok(())
# }
```

Dropping a `serve_until` future aborts its connection tasks. For graceful shutdown,
resolve the supplied shutdown future and await completion instead. Embedding
applications own runtime shutdown, including outstanding blocking attestation
work. The `tls` module provides TLS configuration helpers, including self-signed
verification that retains client credentials.

## Validation

```sh
cargo check -p attested-tls-tcp-tunnel
cargo test -p attested-tls-tcp-tunnel --all-targets
```

Tests use mock attestation only as a development dependency. The HTTP/2 fixture
tests gRPC message framing, metadata and status trailers, multiplexed streaming,
and cancellation under response flow control without a protobuf compiler.
