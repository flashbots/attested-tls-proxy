//! One TCP connection per attested TLS tunnel, with bounded buffering and no
//! application-protocol interpretation. Install a Rustls crypto provider before
//! constructing tunnels. Serving futures own their connections: dropping one
//! aborts its connection tasks. Blocking attestation generation cannot itself be
//! canceled; embedding applications remain responsible for runtime shutdown.
pub mod tls;

use std::{future::Future, io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use attested_tls::{
    AttestedTlsClient, AttestedTlsError, AttestedTlsServer, SUPPORTED_ALPN_PROTOCOL_VERSIONS,
    TlsCertAndKey,
    attestation::{AttestationGenerator, AttestationVerifier},
};
use tokio::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_rustls::rustls::{ClientConfig, ServerConfig, pki_types::CertificateDer};
use tracing::Instrument;

const APPLICATION_PROTOCOL: &[u8] = b"tcp-tunnel";

/// Limits shared by the client and server. No limit applies to the lifetime or
/// inactivity of an established tunnel.
#[derive(Clone, Copy, Debug)]
pub struct TunnelOptions {
    pub setup_timeout: Duration,
    /// Counts both connections being established and established connections.
    pub max_connections: NonZeroUsize,
    pub shutdown_grace: Duration,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self {
            setup_timeout: Duration::from_secs(60),
            max_connections: NonZeroUsize::new(256).unwrap(),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

impl TunnelOptions {
    fn validate(self) -> Result<Self, TunnelError> {
        if self.setup_timeout.is_zero() {
            return Err(TunnelError::Configuration("setup timeout must be positive"));
        }
        if self.max_connections.get() > Semaphore::MAX_PERMITS {
            return Err(TunnelError::Configuration(
                "connection limit exceeds Tokio's maximum",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("{phase}: {source}")]
    Io {
        phase: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("TLS/attestation: {0}")]
    Attestation(#[from] AttestedTlsError),
    #[error("connection setup timed out")]
    SetupTimeout,
    #[error("protocol validation: peer did not negotiate an attested TCP tunnel")]
    ProtocolMismatch,
    #[error("configuration: {0}")]
    Configuration(&'static str),
}

fn io_error(phase: &'static str) -> impl FnOnce(io::Error) -> TunnelError {
    move |source| TunnelError::Io { phase, source }
}

/// Accepts local TCP connections and opens a dedicated attested connection for
/// each. Construction only binds the listener; it does not contact the server.
pub struct TunnelClient(Tunnel);

impl TunnelClient {
    pub async fn new(
        listen: impl ToSocketAddrs,
        target: String,
        identity: Option<TlsCertAndKey>,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        remote_certificate: Option<CertificateDer<'static>>,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        let config = tls::client_config(identity.as_ref(), remote_certificate, false)?;
        Self::new_with_tls_config(
            listen,
            target,
            config,
            generator,
            verifier,
            identity.map(|i| i.cert_chain),
            options,
        )
        .await
    }

    /// Uses the supplied certificate validation and client identity settings.
    /// ALPN is replaced with the tunnel protocol. `cert_chain` must match the
    /// client identity in `config`, if present, for attestation session binding.
    pub async fn new_with_tls_config(
        listen: impl ToSocketAddrs,
        target: String,
        mut config: ClientConfig,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
        let inner =
            AttestedTlsClient::new_with_tls_config(config, generator, verifier, cert_chain)?;
        Ok(Self(
            Tunnel::bind(
                listen,
                normalize_target(&target, Some(443))?,
                Endpoint::Client(inner),
                options,
            )
            .await?,
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.listener.local_addr()
    }

    /// Serve until shutdown resolves, then stop accepting and drain existing
    /// connections for `shutdown_grace`. Individual connection failures are logged.
    pub async fn serve_until(self, shutdown: impl Future<Output = ()>) -> Result<(), TunnelError> {
        self.0.serve_until(shutdown).await
    }
}

/// Accepts attested TLS connections, verifies peers, and connects each to a fixed
/// TCP target. The target can speak any byte-stream protocol.
pub struct TunnelServer(Tunnel);

impl TunnelServer {
    pub async fn new(
        listen: impl ToSocketAddrs,
        target: String,
        identity: TlsCertAndKey,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        client_auth: bool,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        let config = tls::server_config(&identity, client_auth)?;
        Self::new_with_tls_config(
            listen,
            target,
            config,
            generator,
            verifier,
            identity.cert_chain,
            options,
        )
        .await
    }

    /// Uses custom TLS settings, including private client CA policies. ALPN is
    /// replaced with the tunnel protocol. `cert_chain` must match `config`.
    pub async fn new_with_tls_config(
        listen: impl ToSocketAddrs,
        target: String,
        mut config: ServerConfig,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        cert_chain: Vec<CertificateDer<'static>>,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
        let inner =
            AttestedTlsServer::new_with_tls_config(cert_chain, config, generator, verifier)?;
        Ok(Self(
            Tunnel::bind(
                listen,
                normalize_target(&target, None)?,
                Endpoint::Server(inner),
                options,
            )
            .await?,
        ))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.listener.local_addr()
    }

    pub async fn serve_until(self, shutdown: impl Future<Output = ()>) -> Result<(), TunnelError> {
        self.0.serve_until(shutdown).await
    }
}

#[derive(Clone)]
enum Endpoint {
    Client(AttestedTlsClient),
    Server(AttestedTlsServer),
}

impl Endpoint {
    async fn setup(
        &self,
        inbound: TcpStream,
        target: &str,
    ) -> Result<(TcpStream, tokio_rustls::TlsStream<TcpStream>), TunnelError> {
        inbound
            .set_nodelay(true)
            .map_err(io_error("configure inbound TCP"))?;
        match self {
            Self::Client(client) => {
                let outbound = TcpStream::connect(target)
                    .await
                    .map_err(io_error("connect tunnel server"))?;
                outbound
                    .set_nodelay(true)
                    .map_err(io_error("configure outbound TCP"))?;
                let (stream, _, _) = client.connect(target, outbound).await?;
                require_tunnel_protocol(stream.get_ref().1.alpn_protocol())?;
                Ok((inbound, stream.into()))
            }
            Self::Server(server) => {
                let (stream, _, _) = server.handle_connection(inbound).await?;
                require_tunnel_protocol(stream.get_ref().1.alpn_protocol())?;
                // Never contact the target until peer attestation AND the
                // negotiated application protocol have been checked.
                let target = TcpStream::connect(target)
                    .await
                    .map_err(io_error("connect target"))?;
                target
                    .set_nodelay(true)
                    .map_err(io_error("configure target TCP"))?;
                Ok((target, stream.into()))
            }
        }
    }
}

fn require_tunnel_protocol(protocol: Option<&[u8]>) -> Result<(), TunnelError> {
    let valid = SUPPORTED_ALPN_PROTOCOL_VERSIONS.iter().any(|version| {
        protocol == Some([*version, b"+", APPLICATION_PROTOCOL].concat().as_slice())
    });
    if valid {
        Ok(())
    } else {
        Err(TunnelError::ProtocolMismatch)
    }
}

struct Tunnel {
    listener: TcpListener,
    target: String,
    endpoint: Endpoint,
    options: TunnelOptions,
}

impl Tunnel {
    async fn bind(
        listen: impl ToSocketAddrs,
        target: String,
        endpoint: Endpoint,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        let options = options.validate()?;
        let listener = TcpListener::bind(listen)
            .await
            .map_err(io_error("bind listener"))?;
        Ok(Self {
            listener,
            target,
            endpoint,
            options,
        })
    }

    async fn serve_until(self, shutdown: impl Future<Output = ()>) -> Result<(), TunnelError> {
        let Self {
            listener,
            target,
            endpoint,
            options,
        } = self;
        let slots = Arc::new(Semaphore::new(options.max_connections.get()));
        // JoinSet aborts all children when this serving future is dropped.
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::warn!(%error, "Tunnel task failed");
                    }
                }
                incoming = listener.accept() => {
                    let (inbound, peer) = incoming.map_err(io_error("accept"))?;
                    let Ok(permit) = slots.clone().try_acquire_owned() else {
                        tracing::debug!(%peer, "Connection limit reached; closing new connection");
                        continue;
                    };
                    let endpoint = endpoint.clone();
                    let target = target.clone();
                    let span = tracing::info_span!("tunnel", %peer, %target);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let result = async {
                            let (mut local, mut remote) = tokio::time::timeout(
                                options.setup_timeout, endpoint.setup(inbound, &target),
                            ).await.map_err(|_| TunnelError::SetupTimeout)??;
                            tracing::debug!("Tunnel established");
                            let (sent, received) = tokio::io::copy_bidirectional(&mut local, &mut remote)
                                .await.map_err(io_error("forwarding"))?;
                            tracing::debug!(sent, received, "Tunnel closed");
                            Ok::<(), TunnelError>(())
                        }.await;
                        if let Err(error) = result {
                            tracing::warn!(%error, "Tunnel connection failed");
                        }
                    }.instrument(span));
                }
            }
        }
        drop(listener);
        tracing::info!(connections = tasks.len(), "Draining tunnels");
        if tokio::time::timeout(options.shutdown_grace, async {
            while let Some(result) = tasks.join_next().await {
                if let Err(error) = result {
                    tracing::warn!(%error, "Tunnel task failed while draining");
                }
            }
        })
        .await
        .is_err()
        {
            tasks.shutdown().await;
        }
        Ok(())
    }
}

fn normalize_target(target: &str, default_port: Option<u16>) -> Result<String, TunnelError> {
    let invalid = || {
        TunnelError::Configuration(
            "target must be a hostname, IPv4 address, or bracketed IPv6 address with a valid port",
        )
    };
    let (host, port) = if target.starts_with('[') {
        let end = target.find(']').ok_or_else(invalid)?;
        target[1..end]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid())?;
        let tail = &target[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or_else(invalid)?)
        };
        (&target[..=end], port)
    } else {
        match target.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (target, None),
        }
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(invalid());
    }
    let port = match port {
        Some(port) => port.parse::<u16>().map_err(|_| invalid())?,
        None => default_port.ok_or_else(invalid)?,
    };
    if port == 0 {
        return Err(invalid());
    }
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_and_protocols_are_unambiguous() {
        for (input, expected) in [
            ("example.com", "example.com:443"),
            ("127.0.0.1:42", "127.0.0.1:42"),
            ("[::1]", "[::1]:443"),
            ("[::1]:42", "[::1]:42"),
        ] {
            assert_eq!(normalize_target(input, Some(443)).unwrap(), expected);
        }
        for input in [
            "",
            "host:0",
            "host:65536",
            "host:",
            "host/path",
            "::1",
            "[oops]:443",
            "[::1]oops",
            "user@host:443",
        ] {
            assert!(normalize_target(input, Some(443)).is_err(), "{input}");
        }
        assert!(normalize_target("host", None).is_err());
        assert!(require_tunnel_protocol(Some(b"flashbots-ratls/1+tcp-tunnel")).is_ok());
        for protocol in [
            None,
            Some(b"flashbots-ratls/1".as_slice()),
            Some(b"flashbots-ratls/1+h2".as_slice()),
            Some(b"untrusted+tcp-tunnel".as_slice()),
        ] {
            assert!(require_tunnel_protocol(protocol).is_err());
        }
    }
}
