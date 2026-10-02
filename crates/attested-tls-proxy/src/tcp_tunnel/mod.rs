//! Tunnel a TCP connection over remote attested TLS.
//!
//! This is a proxy which accepts TCP connections and does TLS handshake followed
//! by an attestation exchange.  The TLS session byte-stream is then handed back to
//! the calling application.
//!
//! Assumes a Rustls crypto provider is already installed.
use crate::tls;

use crate::target::{InvalidTarget, normalize_target};

mod pool;
pub use pool::WarmPoolOptions;

use std::{future::Future, io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use attested_tls::{
    AttestedTlsClient, AttestedTlsError, AttestedTlsServer, SUPPORTED_ALPN_PROTOCOL_VERSIONS,
    TlsCertAndKey,
    attestation::{AttestationGenerator, AttestationVerifier},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
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
    /// Timeout for connections establishment, TLS handshake and attestation exchange
    pub setup_timeout: Duration,
    /// Counts establishing, established, and unused pooled connections.
    pub max_connections: NonZeroUsize,
    /// Timeout for closing connections during graceful shutdown.
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

/// Accepts local TCP connections and opens a dedicated attested connection for
/// each. Constructors contact the server only when `startup_check` is enabled.
pub struct TunnelClient(Tunnel);

impl TunnelClient {
    /// Configure background preparation of unused connections. No connections
    /// are opened until serving starts; zero retains on-demand-only behavior.
    pub fn with_pool(mut self, options: WarmPoolOptions) -> Result<Self, TunnelError> {
        if options.size > self.0.options.max_connections.get() {
            return Err(TunnelError::Configuration(
                "pool size must not exceed the connection limit",
            ));
        }
        if options.max_age.is_zero() {
            return Err(TunnelError::Configuration(
                "pool maximum age must be positive",
            ));
        }
        self.0.pool_options = options;
        Ok(self)
    }

    /// If `startup_check` is true, verify an upstream connection within
    /// `options.setup_timeout` and close it before returning. This checks TLS,
    /// attestation, and ALPN, not final target reachability. The server may open
    /// an empty target connection. On failure the local listener is dropped.
    #[allow(clippy::too_many_arguments)] // Keep the startup check explicit in the constructor.
    pub async fn new(
        listen: impl ToSocketAddrs,
        target: String,
        identity: Option<TlsCertAndKey>,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        remote_certificate: Option<CertificateDer<'static>>,
        startup_check: bool,
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
            startup_check,
            options,
        )
        .await
    }

    /// Uses the supplied certificate validation and client identity settings.
    /// ALPN is replaced with the tunnel protocol. `cert_chain` must match the
    /// client identity in `config`, if present, for attestation session binding.
    /// `startup_check` has the same behavior as in [`Self::new`].
    #[allow(clippy::too_many_arguments)] // Mirrors new with caller-supplied TLS settings.
    pub async fn new_with_tls_config(
        listen: impl ToSocketAddrs,
        target: String,
        mut config: ClientConfig,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        startup_check: bool,
        options: TunnelOptions,
    ) -> Result<Self, TunnelError> {
        config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
        let inner =
            AttestedTlsClient::new_with_tls_config(config, generator, verifier, cert_chain)?;
        let tunnel = Tunnel::bind(
            listen,
            normalize_target(&target, Some(443))?,
            Endpoint::Client(inner.clone()),
            options,
        )
        .await?;
        if startup_check {
            tokio::time::timeout(options.setup_timeout, async {
                let mut stream = connect_upstream(&inner, &tunnel.target).await?;
                stream
                    .shutdown()
                    .await
                    .map_err(io_error("close startup check"))?;
                Ok::<(), TunnelError>(())
            })
            .await
            .map_err(|_| TunnelError::SetupTimeout)??;
        }
        Ok(Self(tunnel))
    }

    /// Return local address of the underlying listener
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

    /// Return local address of the underlying listener
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.listener.local_addr()
    }

    /// Serve until shutdown resolves, then stop accepting and drain existing
    /// connections for `shutdown_grace`. Individual connection failures are logged.
    pub async fn serve_until(self, shutdown: impl Future<Output = ()>) -> Result<(), TunnelError> {
        self.0.serve_until(shutdown).await
    }
}

/// Attested TLS client or server
#[derive(Clone)]
enum Endpoint {
    Client(AttestedTlsClient),
    Server(AttestedTlsServer),
}

impl Endpoint {
    /// Common method for attested TLS connection setup for both client and server
    async fn setup(
        &self,
        inbound: TcpStream,
        target: &str,
    ) -> Result<(TcpStream, tokio_rustls::TlsStream<TcpStream>), TunnelError> {
        // Disable Nagle's algorithm to reduce latency
        inbound
            .set_nodelay(true)
            .map_err(io_error("configure inbound TCP"))?;

        match self {
            Self::Client(client) => {
                let stream = connect_upstream(client, target).await?;
                Ok((inbound, stream.into()))
            }
            Self::Server(server) => {
                // Do TLS handshake and attestation exchange on inbound connection
                let (stream, _, _) = server.handle_connection(inbound).await?;

                // Ensure correct negotiated application protocol
                require_tunnel_protocol(stream.get_ref().1.alpn_protocol())?;

                // Open connection to target service
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

/// Shared by startup checks and real tunnels so both enforce the same policy.
async fn connect_upstream(
    client: &AttestedTlsClient,
    target: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TunnelError> {
    let outbound = TcpStream::connect(target)
        .await
        .map_err(io_error("connect tunnel server"))?;

    outbound
        .set_nodelay(true)
        .map_err(io_error("configure outbound TCP"))?;

    // Do TLS handshake and attestation exchange
    let (stream, _, _) = client.connect(target, outbound).await?;

    // Check application protocol was negotiated
    require_tunnel_protocol(stream.get_ref().1.alpn_protocol())?;

    Ok(stream)
}

/// Check negotiated application protocol
fn require_tunnel_protocol(protocol: Option<&[u8]>) -> Result<(), TunnelError> {
    if SUPPORTED_ALPN_PROTOCOL_VERSIONS
        .iter()
        .any(|version| protocol == Some([*version, b"+", APPLICATION_PROTOCOL].concat().as_slice()))
    {
        Ok(())
    } else {
        Err(TunnelError::ProtocolMismatch)
    }
}

struct Tunnel {
    /// Listener for source client (for client) or proxy client (for server)
    listener: TcpListener,
    /// The proxy-server address (for client) or target server address (for server)
    target: String,
    /// Attested TLS client or server
    endpoint: Endpoint,
    options: TunnelOptions,
    pool_options: WarmPoolOptions,
}

impl Tunnel {
    /// Setup listener and check configuration
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
            pool_options: WarmPoolOptions::default(),
        })
    }

    /// Run until told to shut down
    async fn serve_until(self, shutdown: impl Future<Output = ()>) -> Result<(), TunnelError> {
        let Self {
            listener,
            target,
            endpoint,
            options,
            pool_options,
        } = self;

        let slots = Arc::new(Semaphore::new(options.max_connections.get()));

        let mut pool = match &endpoint {
            Endpoint::Client(client) if pool_options.size > 0 => {
                let client = client.clone();
                let target = target.clone();
                Some(pool::Pool::new(
                    pool_options,
                    options.setup_timeout,
                    slots.clone(),
                    move || {
                        let client = client.clone();
                        let target = target.clone();
                        async move {
                            let mut stream = connect_upstream(&client, &target).await?;
                            stream
                                .flush()
                                .await
                                .map_err(io_error("flush prepared tunnel"))?;
                            Ok::<_, TunnelError>(stream)
                        }
                    },
                ))
            }
            _ => None,
        };

        // JoinSet aborts all children when this serving future is dropped.
        let mut tasks = JoinSet::new();

        let mut next_accept = tokio::time::Instant::now();

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
                incoming = async {
                    tokio::time::sleep_until(next_accept).await;
                    listener.accept().await
                } => {
                    let (inbound, peer) = match incoming {
                        Ok(connection) => connection,
                        Err(error) => {
                            // Resource exhaustion and per-connection errors must
                            // not tear down established tunnels. Delay only this
                            // branch so shutdown and task reaping remain responsive.
                            tracing::warn!(%error, "Accept failed; retrying");
                            next_accept = tokio::time::Instant::now() + Duration::from_secs(1);
                            continue;
                        }
                    };

                    let accepted_at = tokio::time::Instant::now();
                    let (acquisition, permit) = match &mut pool {
                        Some(pool) => match pool.acquire().await {
                            Some(acquisition) => (Some(acquisition), None),
                            None => {
                                tracing::warn!(%peer, "Connection limit reached; closing new connection");
                                continue;
                            }
                        },
                        None => match slots.clone().try_acquire_owned() {
                            Ok(permit) => (None, Some(permit)),
                            Err(_) => {
                                tracing::warn!(%peer, "Connection limit reached; closing new connection");
                                continue;
                            }
                        },
                    };

                    let endpoint = endpoint.clone();
                    let target = target.clone();
                    let span = tracing::info_span!("tunnel", %peer, %target);
                    tasks.spawn(async move {
                        let _permit = permit;
                        let result = async {
                            if let Some(acquisition) = acquisition {
                                inbound.set_nodelay(true).map_err(io_error("configure inbound TCP"))?;
                                let remaining = options.setup_timeout.saturating_sub(accepted_at.elapsed());
                                let remote = tokio::time::timeout(remaining, acquisition.connect())
                                    .await.map_err(|_| TunnelError::SetupTimeout)?
                                    .map_err(|error| match error {
                                        pool::Error::Connect(error) => error,
                                        pool::Error::Timeout => TunnelError::SetupTimeout,
                                    })?;
                                forward(inbound, remote).await
                            } else {
                                let (local, remote) = tokio::time::timeout(
                                    options.setup_timeout, endpoint.setup(inbound, &target),
                                ).await.map_err(|_| TunnelError::SetupTimeout)??;
                                forward(local, remote).await
                            }
                        }.await;

                        if let Err(error) = result {
                            tracing::warn!(%error, "Tunnel connection failed");
                        }
                    }.instrument(span));
                }
                // Source admission has priority over speculative refill.
                _ = async {
                    match &mut pool {
                        Some(pool) => pool.maintain().await,
                        None => std::future::pending().await,
                    }
                } => unreachable!("pool maintenance never completes"),
            }
        }

        drop(listener);
        // Acquisitions already belong to source tasks. Only unassigned work is
        // canceled here; no idle connections linger during graceful draining.
        drop(pool);

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

async fn forward(
    mut local: TcpStream,
    mut remote: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<(), TunnelError> {
    tracing::debug!("Tunnel established");
    let (sent, received) = tokio::io::copy_bidirectional(&mut local, &mut remote)
        .await
        .map_err(io_error("forwarding"))?;
    tracing::debug!(sent, received, "Tunnel closed");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("configuration: {0}")]
    InvalidTarget(#[from] InvalidTarget),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocols_are_unambiguous() {
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
