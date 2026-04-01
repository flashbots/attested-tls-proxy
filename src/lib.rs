//! An attested TLS protocol and HTTPS proxy
pub mod attested_get;
pub mod file_server;
pub mod health_check;
pub mod normalize_pem;

pub use attestation;
pub use attestation::AttestationGenerator;

mod http_version;

#[cfg(test)]
mod test_helpers;

use attestation::{AttestationError, AttestationExchangeMessage, AttestationVerifier};
use attested_tls::{AttestedCertificateResolver, AttestedCertificateVerifier, AttestedTlsError};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{Response, service::service_fn};
use hyper_util::rt::TokioIo;
use nested_tls::server::NestingTlsStream;
use nested_tls::{client::NestingTlsConnector, server::NestingTlsAcceptor};
use std::{net::SocketAddr, num::TryFromIntError, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use tokio_rustls::rustls::{
    self, ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use tracing::{debug, error, warn};

use crate::http_version::{ALPN_H2, ALPN_HTTP11, HttpConnection, HttpSender, HttpVersion};

/// The header name for giving attestation type
const ATTESTATION_TYPE_HEADER: &str = "X-Flashbots-Attestation-Type";

/// The header name for giving measurements
const MEASUREMENT_HEADER: &str = "X-Flashbots-Measurement";

/// The header name for giving the forwarded for IP
static X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// The header name for giving the 'real IP' - in our case that of the client
static X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// The longest time in seconds to wait between reconnection attempts
const SERVER_RECONNECT_MAX_BACKOFF_SECS: u64 = 120;

const KEEP_ALIVE_INTERVAL: u64 = 30;
const KEEP_ALIVE_TIMEOUT: u64 = 10;
type RequestWithResponseSender = (
    http::Request<hyper::body::Incoming>,
    oneshot::Sender<Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>>,
);

type OuterProxySession = (Arc<TcpListener>, NestingTlsAcceptor);
type InnerProxySession = (Arc<TcpListener>, TlsAcceptor);

/// TLS Credentials
pub struct TlsCertAndKey {
    /// Der-encoded TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Der-encoded TLS private key
    pub key: PrivateKeyDer<'static>,
}

/// Configuration for the optional outer nested-TLS listener.
pub struct OuterTlsConfig<A> {
    /// The socket address to bind for the outer listener.
    pub listen_addr: A,
    /// How the outer TLS server configuration should be constructed.
    pub tls: OuterTlsMode,
}

/// TLS configuration sources for the outer nested-TLS listener.
pub enum OuterTlsMode {
    /// Build the outer TLS server config from certificate and key material.
    CertAndKey(TlsCertAndKey),
    /// Use an already-constructed outer TLS server config.
    Preconfigured {
        /// The outer TLS server configuration to expose on the listener.
        server_config: ServerConfig,
        /// The server identity to embed into the inner attested certificate.
        certificate_name: String,
    },
}

impl<A> OuterTlsConfig<A>
where
    A: ToSocketAddrs,
{
    fn certificate_name(&self) -> Result<String, ProxyError> {
        match &self.tls {
            OuterTlsMode::CertAndKey(cert_and_key) => {
                Ok(certificate_identity_from_chain(&cert_and_key.cert_chain)?)
            }
            OuterTlsMode::Preconfigured {
                certificate_name, ..
            } => Ok(certificate_name.clone()),
        }
    }

    async fn into_listener_and_acceptor(
        self,
        inner_server_config: Arc<ServerConfig>,
        client_auth: bool,
    ) -> Result<(Arc<TcpListener>, NestingTlsAcceptor), ProxyError> {
        let listen_addr = self.listen_addr;
        let outer_server_config = match self.tls {
            OuterTlsMode::CertAndKey(cert_and_key) => {
                if client_auth {
                    let root_store =
                        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_single_cert(
                            cert_and_key.cert_chain.clone(),
                            cert_and_key.key.clone_key(),
                        )?
                } else {
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_single_cert(
                            cert_and_key.cert_chain.clone(),
                            cert_and_key.key.clone_key(),
                        )?
                }
            }
            OuterTlsMode::Preconfigured { server_config, .. } => server_config,
        };

        let outer_listener = Arc::new(TcpListener::bind(listen_addr).await?);
        let outer_tls_acceptor =
            NestingTlsAcceptor::new(Arc::new(outer_server_config), inner_server_config);

        Ok((outer_listener, outer_tls_acceptor))
    }
}

/// Adds HTTP 1 and 2 to the list of allowed protocols
fn ensure_proxy_alpn_protocols(alpn_protocols: &mut Vec<Vec<u8>>) {
    for protocol in [ALPN_H2, ALPN_HTTP11] {
        let already_present = alpn_protocols.iter().any(|p| p.as_slice() == protocol);

        if !already_present {
            alpn_protocols.push(protocol.to_vec());
        }
    }
}

/// Retrieve the inner attested remote TLS certificate.
pub async fn get_inner_tls_cert(
    server_name: String,
    attestation_verifier: AttestationVerifier,
    remote_outer_certificate: Option<CertificateDer<'static>>,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let root_store = match remote_outer_certificate.as_ref() {
        Some(remote_certificate) => {
            let mut root_store = RootCertStore::empty();
            root_store.add(remote_certificate.clone())?;
            root_store
        }
        None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };

    let outer_client_config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_no_client_auth();

    get_inner_tls_cert_with_config(server_name, attestation_verifier, outer_client_config).await
}

pub async fn get_inner_tls_cert_with_config(
    server_name: String,
    attestation_verifier: AttestationVerifier,
    outer_client_config: ClientConfig,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let outbound_stream = tokio::net::TcpStream::connect(&server_name).await?;

    let domain = server_name_from_host(&server_name)?;

    let attested_cert_verifier = AttestedCertificateVerifier::new(None, attestation_verifier)?;
    let inner_client_config =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(attested_cert_verifier))
            .with_no_client_auth();

    let nested_tls_connector =
        NestingTlsConnector::new(Arc::new(outer_client_config), Arc::new(inner_client_config));

    let mut tls_stream = nested_tls_connector
        .connect(domain, outbound_stream)
        .await?;
    debug!("[get-tls-cert] Connected to proxy server");

    let (_io, server_connection) = tls_stream.get_ref();

    let remote_cert_chain = server_connection
        .peer_certificates()
        .ok_or(ProxyError::NoCertificate)?
        .to_owned();

    tls_stream.shutdown().await?;

    Ok(remote_cert_chain)
}

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer {
    outer: Option<OuterProxySession>,
    inner: Option<InnerProxySession>,
    /// The address/hostname of the target service we are proxying to
    target: String,
}

impl ProxyServer {
    /// Start with dual listeners. The outer nested-TLS listener is optional.
    pub async fn new<O, I>(
        outer_session: Option<OuterTlsConfig<O>>,
        inner_local: Option<I>,
        target: String,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        client_auth: bool,
    ) -> Result<Self, ProxyError>
    where
        O: ToSocketAddrs,
        I: ToSocketAddrs,
    {
        if outer_session.is_none() && inner_local.is_none() {
            return Err(ProxyError::NoListenersConfigured);
        }

        let certificate_name = outer_session
            .as_ref()
            .map(OuterTlsConfig::certificate_name)
            .transpose()?;
        let inner_server_config = Arc::new(
            build_inner_server_config(
                attestation_generator,
                attestation_verifier,
                client_auth,
                certificate_name,
            )
            .await?,
        );
        let inner = match inner_local {
            Some(inner_local) => {
                let inner_listener = Arc::new(TcpListener::bind(inner_local).await?);
                let inner_tls_acceptor = TlsAcceptor::from(inner_server_config.clone());
                Some((inner_listener, inner_tls_acceptor))
            }
            None => None,
        };

        let outer = match outer_session {
            Some(outer_session) => {
                let (outer_listener, outer_tls_acceptor) = outer_session
                    .into_listener_and_acceptor(inner_server_config.clone(), client_auth)
                    .await?;
                Some((outer_listener, outer_tls_acceptor))
            }
            None => None,
        };

        Ok(Self {
            outer,
            inner,
            target,
        })
    }

    /// Accept an incoming connection and handle it in a seperate task
    ///
    /// Returns the handle for the task handling the connection
    pub async fn accept(&self) -> Result<tokio::task::JoinHandle<()>, ProxyError> {
        let target = self.target.clone();
        let outer = self.outer.clone();
        let inner = self.inner.clone();

        let join_handle = match (outer, inner) {
            (
                Some((outer_listener, outer_tls_acceptor)),
                Some((inner_listener, inner_tls_acceptor)),
            ) => {
                let ((inbound, client_addr), use_outer) = tokio::select! {
                    accepted = outer_listener.accept() => (accepted?, true),
                    accepted = inner_listener.accept() => (accepted?, false),
                };

                tokio::spawn(async move {
                    if use_outer {
                        match outer_tls_acceptor.accept(inbound).await {
                            Ok(tls_stream) => {
                                if let Err(err) =
                                    Self::handle_outer_connection(tls_stream, target, client_addr)
                                        .await
                                {
                                    warn!("Failed to handle outer connection: {err}");
                                }
                            }
                            Err(err) => {
                                warn!("Outer attestation exchange failed: {err}");
                            }
                        }
                    } else {
                        match inner_tls_acceptor.accept(inbound).await {
                            Ok(tls_stream) => {
                                if let Err(err) =
                                    Self::handle_inner_connection(tls_stream, target, client_addr)
                                        .await
                                {
                                    warn!("Failed to handle inner connection: {err}");
                                }
                            }
                            Err(err) => {
                                warn!("Inner attestation exchange failed: {err}");
                            }
                        }
                    }
                })
            }
            (None, Some((inner_listener, inner_tls_acceptor))) => {
                let (inbound, client_addr) = inner_listener.accept().await?;
                tokio::spawn(async move {
                    match inner_tls_acceptor.accept(inbound).await {
                        Ok(tls_stream) => {
                            if let Err(err) =
                                Self::handle_inner_connection(tls_stream, target, client_addr).await
                            {
                                warn!("Failed to handle inner connection: {err}");
                            }
                        }
                        Err(err) => {
                            warn!("Inner attestation exchange failed: {err}");
                        }
                    }
                })
            }
            (Some((outer_listener, outer_tls_acceptor)), None) => {
                let (inbound, client_addr) = outer_listener.accept().await?;
                tokio::spawn(async move {
                    match outer_tls_acceptor.accept(inbound).await {
                        Ok(tls_stream) => {
                            if let Err(err) =
                                Self::handle_outer_connection(tls_stream, target, client_addr).await
                            {
                                warn!("Failed to handle outer connection: {err}");
                            }
                        }
                        Err(err) => {
                            warn!("Outer attestation exchange failed: {err}");
                        }
                    }
                })
            }
            _ => return Err(ProxyError::NoListenersConfigured),
        };

        Ok(join_handle)
    }

    /// Helper to get the socket address of either underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match &self.outer {
            Some((listener, _)) => listener.local_addr(),
            None => self
                .inner
                .as_ref()
                .map(|(listener, _)| listener)
                .ok_or_else(|| std::io::Error::other("no listeners configured"))?
                .local_addr(),
        }
    }

    /// Helper to get the socket address of the underlying outer TCP listener if present
    pub fn outer_local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.outer
            .as_ref()
            .map(|(listener, _)| listener.local_addr())
            .transpose()
    }

    /// Helper to get the socket address of the underlying inner TCP listener if present
    pub fn inner_local_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.inner
            .as_ref()
            .map(|(listener, _)| listener.local_addr())
            .transpose()
    }

    async fn handle_outer_connection(
        tls_stream: NestingTlsStream<tokio::net::TcpStream>,
        target: String,
        client_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        debug!("[proxy-server] accepted connection");

        // Get attestation from the remote certificate from the inner session, if present.
        let attestation = {
            let (_io, server_connection) = tls_stream.get_ref();

            match server_connection.peer_certificates() {
                Some(remote_cert_chain) => remote_cert_chain
                    .first()
                    .and_then(|cert| {
                        match AttestedCertificateVerifier::extract_custom_attestation_from_cert(cert)
                        {
                            Ok(attestation) => Some(attestation),
                            Err(err) => {
                                warn!(
                                    "Failed to extract remote attestation from inner-session certificate: {err}"
                                );
                                None
                            }
                        }
                    }),
                None => None,
            }
        };

        let http_version = HttpVersion::from_negotiated_protocol_server(&tls_stream);
        Self::serve_tls_stream(tls_stream, http_version, target, client_addr, attestation).await
    }

    async fn handle_inner_connection(
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        target: String,
        client_addr: SocketAddr,
    ) -> Result<(), ProxyError> {
        debug!("[proxy-server] accepted inner-only connection");

        // Get attestation from the remote certificate, if present
        let attestation = {
            let (_io, server_connection) = tls_stream.get_ref();

            match server_connection.peer_certificates() {
                Some(remote_cert_chain) => remote_cert_chain.first().and_then(|cert| {
                    match AttestedCertificateVerifier::extract_custom_attestation_from_cert(cert) {
                        Ok(attestation) => Some(attestation),
                        Err(err) => {
                            warn!("Failed to extract remote attestation from certificate: {err}");
                            None
                        }
                    }
                }),
                None => None,
            }
        };

        let http_version = HttpVersion::from_negotiated_protocol_server(&tls_stream);
        Self::serve_tls_stream(tls_stream, http_version, target, client_addr, attestation).await
    }

    async fn serve_tls_stream<IO>(
        tls_stream: IO,
        http_version: HttpVersion,
        target: String,
        client_addr: SocketAddr,
        attestation: Option<AttestationExchangeMessage>,
    ) -> Result<(), ProxyError>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (remote_attestation_type, measurements) = match attestation {
            Some(attestation) => (
                Some(attestation.attestation_type),
                match attestation.get_measurements() {
                    Ok(measurements) => measurements,
                    Err(err) => {
                        warn!("Failed to extract measurements from peer attestation: {err}");
                        None
                    }
                },
            ),
            None => (None, None),
        };

        // Setup a request handler
        let service = service_fn(move |mut req| {
            debug!("[proxy-server] Handling request {req:?}");
            let headers = req.headers_mut();

            // Add or update the HOST header
            let old_value = update_header(headers, &http::header::HOST, &target);
            debug!("Updating Host header - old value: {old_value:?} new value: {target}",);

            // Add the x-real-ip header
            let client_ip = client_addr.ip().to_string();
            update_header(headers, &X_REAL_IP, &client_ip);

            // Add or update the x-forwarded-for header
            let new_x_forwarded_for =
                match headers.get(&X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
                    Some(existing) if !existing.trim().is_empty() => {
                        format!("{}, {}", existing.trim(), client_ip)
                    }
                    _ => client_ip.clone(),
                };

            update_header(headers, &X_FORWARDED_FOR, &new_x_forwarded_for);

            // Strip any caller-provided attestation metadata before injecting authenticated values.
            headers.remove(ATTESTATION_TYPE_HEADER);
            headers.remove(MEASUREMENT_HEADER);

            // If we have measurements, from the remote peer, add them to the request header
            let measurements = measurements.clone();

            if let Some(measurements) = measurements {
                match measurements.to_header_format() {
                    Ok(header_value) => {
                        headers.insert(MEASUREMENT_HEADER, header_value);
                    }
                    Err(e) => {
                        // This error is highly unlikely - that the measurement values fail to
                        // encode to JSON or fit in an HTTP header
                        error!("Failed to encode measurement values: {e}");
                    }
                }
            }

            if let Some(remote_attestation_type) = remote_attestation_type {
                update_header(
                    headers,
                    ATTESTATION_TYPE_HEADER,
                    remote_attestation_type.as_str(),
                );
            }

            let target = target.clone();
            async move {
                match Self::handle_http_request(req, target).await {
                    Ok(res) => {
                        debug!("[proxy-server] Responding {res:?}");
                        Ok::<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>(res)
                    }
                    Err(e) => {
                        warn!("Failed to handle a request from a proxy-client: {e}");
                        let mut resp = Response::new(full(format!("Request failed: {e}")));
                        *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                        Ok(resp)
                    }
                }
            }
        });

        // Serve this connection using the request handler defined above
        let io = TokioIo::new(tls_stream);

        // Setup an HTTP server
        match http_version {
            HttpVersion::Http2 => {
                hyper::server::conn::http2::Builder::new(TokioExecutor)
                    .timer(hyper_util::rt::tokio::TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL)))
                    .keep_alive_timeout(Duration::from_secs(KEEP_ALIVE_TIMEOUT))
                    .serve_connection(io, service)
                    .await?;
            }
            HttpVersion::Http1 => {
                hyper::server::conn::http1::Builder::new()
                    .timer(hyper_util::rt::tokio::TokioTimer::new())
                    .keep_alive(true)
                    .serve_connection(io, service)
                    .await?;
            }
        }

        Ok(())
    }

    // Handle a request from the proxy client to the target server
    async fn handle_http_request(
        req: hyper::Request<hyper::body::Incoming>,
        target: String,
    ) -> Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, ProxyError> {
        // Connect to the target server
        let outbound = TcpStream::connect(target).await?;
        let outbound_io = TokioIo::new(outbound);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, hyper::body::Incoming>(outbound_io)
            .await?;

        // Drive the connection
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Client connection error: {e}");
            }
        });

        // Forward the request from the proxy-client to the target server
        match sender.send_request(req).await {
            Ok(resp) => Ok(resp.map(|b| b.boxed())),
            Err(e) => {
                warn!("send_request error: {e}");
                let mut resp = Response::new(full(format!("Request failed: {e}")));
                *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                Ok(resp)
            }
        }
    }
}

/// Helper to create a binary http body
fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A proxy client which forwards http traffic to a proxy-server
#[derive(Debug)]
pub struct ProxyClient {
    /// The underlying TCP listener
    listener: TcpListener,
    /// A channel for sending requests to the connection to the proxy-server
    requests_tx: mpsc::Sender<RequestWithResponseSender>,
}

impl ProxyClient {
    /// Start with optional TLS client auth
    pub async fn new(
        cert_and_key: Option<TlsCertAndKey>,
        address: impl ToSocketAddrs,
        server_name: String,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        remote_certificate: Option<CertificateDer<'static>>,
    ) -> Result<Self, ProxyError> {
        let root_store = match remote_certificate.as_ref() {
            Some(remote_certificate) => {
                let mut root_store = RootCertStore::empty();
                root_store.add(remote_certificate.clone())?;
                root_store
            }
            None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        };

        let outer_client_config = if let Some(ref cert_and_key) = cert_and_key {
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_client_auth_cert(
                    cert_and_key.cert_chain.clone(),
                    cert_and_key.key.clone_key(),
                )?
        } else {
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        Self::new_with_tls_config(
            outer_client_config,
            address,
            server_name,
            attestation_generator,
            attestation_verifier,
            cert_and_key.map(|cert_and_key| cert_and_key.cert_chain),
        )
        .await
    }

    /// Create a new proxy client with given TLS configuration
    pub async fn new_with_tls_config(
        outer_client_config: ClientConfig,
        address: impl ToSocketAddrs,
        target_name: String,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ProxyError> {
        let outer_has_client_auth = outer_client_config.client_auth_cert_resolver.has_certs();
        let inner_has_client_auth = cert_chain.is_some();

        if outer_has_client_auth != inner_has_client_auth {
            return Err(ProxyError::ClientAuthMisconfigured);
        }

        let attested_cert_verifier = AttestedCertificateVerifier::new(None, attestation_verifier)?;

        let mut inner_client_config = if let Some(cert_chain) = cert_chain.as_ref() {
            let inner_cert_resolver = build_attested_cert_resolver(
                attestation_generator,
                certificate_identity_from_chain(cert_chain)?,
            )
            .await?;
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(attested_cert_verifier))
                .with_client_cert_resolver(Arc::new(inner_cert_resolver))
        } else {
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(attested_cert_verifier))
                .with_no_client_auth()
        };
        ensure_proxy_alpn_protocols(&mut inner_client_config.alpn_protocols);

        let nesting_tls_connector =
            NestingTlsConnector::new(Arc::new(outer_client_config), Arc::new(inner_client_config));

        Self::new_with_inner(address, nesting_tls_connector, &target_name).await
    }

    /// Create a new proxy client with given [AttestedTlsClient]
    pub async fn new_with_inner(
        address: impl ToSocketAddrs,
        nesting_tls_connector: NestingTlsConnector,
        target_name: &str,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(address).await?;

        // Process the hostname / port provided by the user
        let target = host_to_host_with_port(target_name);

        // Channel for getting incoming requests from the source client
        let (requests_tx, mut requests_rx) = mpsc::channel::<(
            http::Request<hyper::body::Incoming>,
            oneshot::Sender<
                Result<http::Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>,
            >,
        )>(1024);

        // used only to signal "initial connect succeeded" or "failed with error"
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), ProxyError>>();

        tokio::spawn(async move {
            let mut first = true;
            let mut ready_tx = Some(ready_tx);
            'reconnect: loop {
                let (mut sender, conn, attestation) =
                    // Connect to the proxy server and provide / verify attestation
                    match Self::setup_connection_with_backoff(&target, &nesting_tls_connector, first)
                        .await
                    {
                        Ok(output) => {
                            if first {
                                if let Some(tx) = ready_tx.take() {
                                    let _ = tx.send(Ok(()));
                                }
                                first = false;
                            }
                            output
                        }
                        Err(err) => {
                            if first {
                                if let Some(tx) = ready_tx.take() {
                                    let _ = tx.send(Err(err));
                                }
                                return;
                            } else {
                                error!("Reconnect setup failed unexpectedly: {err}");
                                continue;
                            }
                        }
                    };

                let (conn_done_tx, mut conn_done_rx) =
                    tokio::sync::watch::channel::<Option<hyper::Error>>(None);

                let remote_attestation_type = attestation.attestation_type;
                let measurements = attestation.get_measurements().ok().flatten();

                tokio::spawn(async move {
                    let res = conn.await;
                    let _ = conn_done_tx.send(res.err());
                });
                loop {
                    tokio::select! {
                        // Read an incoming request from the channel (from the source client)
                        incoming_req_option = requests_rx.recv() => {
                            if let Some((req, response_tx)) = incoming_req_option {
                                debug!("[proxy-client] Read incoming request from source client: {req:?}");
                                // Attempt to forward it to the proxy server
                                let (response, should_reconnect) = match sender.send_request(req).await {
                                    Ok(mut resp) => {
                                        debug!("[proxy-client] Read response from proxy-server: {resp:?}");
                                        let headers = resp.headers_mut();
                                        headers.remove(MEASUREMENT_HEADER);

                                        if let Some(measurements) = measurements.clone() {
                                            match measurements.to_header_format() {
                                                Ok(header_value) => {
                                                    headers.insert(MEASUREMENT_HEADER, header_value);
                                                }
                                                Err(e) => {
                                                    error!("Failed to encode measurement values: {e}");
                                                }
                                            }
                                        }

                                        update_header(
                                            headers,
                                            ATTESTATION_TYPE_HEADER,
                                            remote_attestation_type.as_str(),
                                        );

                                        (Ok(resp.map(|b| b.boxed())), false)
                                    }
                                    Err(e) => {
                                        warn!("Failed to send request to proxy-server: {e}");
                                        let mut resp = Response::new(full(format!("Request failed: {e}")));
                                        *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;

                                        (Ok(resp), true)
                                    }
                                };

                                // Send the response back to the source client
                                if response_tx.send(response).is_err() {
                                    warn!("Failed to forward response to source client, probably they dropped the connection");
                                }

                                if should_reconnect {
                                    // Leave the inner loop and continue on the reconnect loop
                                    warn!("Reconnecting to proxy-server due to failed request");
                                    break;
                                }
                            } else {
                                // The request sender was dropped - so no more incoming requests
                                debug!("Request sender dropped - leaving connection handler loop");
                                break 'reconnect;
                            }
                        }

                        // Connection closed
                        _ = conn_done_rx.changed() => {
                            // Leave the inner loop and continue on the reconnect loop
                            warn!("Connection dropped - reconnecting...");
                            break;
                        }
                    };
                }
            }
        });

        match ready_rx.await {
            Ok(Ok(())) => Ok(Self {
                listener,
                requests_tx,
            }),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e.into()),
        }
    }

    /// Helper to return the local socket address from the underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept an incoming connection and handle it in a separate task
    pub async fn accept(&self) -> io::Result<tokio::task::JoinHandle<()>> {
        let (inbound, _client_addr) = self.listener.accept().await?;

        let requests_tx = self.requests_tx.clone();

        let handle = tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(inbound, requests_tx).await {
                warn!("Failed to handle connection from source client: {err}");
            }
        });

        Ok(handle)
    }

    /// Handle an incoming connection from the source client
    async fn handle_connection(
        inbound: TcpStream,
        requests_tx: mpsc::Sender<RequestWithResponseSender>,
    ) -> Result<(), ProxyError> {
        tracing::debug!("proxy-client accepted connection");

        // Setup http server and handler
        let http = hyper::server::conn::http1::Builder::new();
        let service = service_fn(move |req| {
            let requests_tx = requests_tx.clone();
            async move {
                match Self::handle_http_request(req, requests_tx).await {
                    Ok(res) => {
                        Ok::<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>(res)
                    }
                    Err(e) => {
                        warn!("send_request error: {e}");
                        let mut resp = Response::new(full(format!("Request failed: {e}")));
                        *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                        Ok(resp)
                    }
                }
            }
        });

        let io = TokioIo::new(inbound);
        http.serve_connection(io, service).await?;

        Ok(())
    }

    // Attempt connection and handshake with the proxy-server
    // If it fails retry with a backoff (indefinately)
    async fn setup_connection_with_backoff(
        target: &str,
        nesting_tls_connector: &NestingTlsConnector,
        should_bail: bool,
    ) -> Result<(HttpSender, HttpConnection, AttestationExchangeMessage), ProxyError> {
        let mut delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(SERVER_RECONNECT_MAX_BACKOFF_SECS);

        loop {
            match Self::setup_connection(nesting_tls_connector, target).await {
                Ok(output) => {
                    return Ok(output);
                }
                Err(e) => {
                    if should_retry_setup_error(&e, should_bail) {
                        warn!("Reconnect failed: {e}. Retrying in {:#?}...", delay);
                        tokio::time::sleep(delay).await;

                        // increase delay for next time (exponential), but clamp to max_delay
                        delay = std::cmp::min(delay * 2, max_delay);
                    } else {
                        // If we get a non-IO error and should_bail is true, bail
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Connect to the proxy-server, do TLS handshake and remote attestation
    async fn setup_connection(
        nesting_tls_connector: &NestingTlsConnector,
        target: &str,
    ) -> Result<(HttpSender, HttpConnection, AttestationExchangeMessage), ProxyError> {
        let outbound_stream = tokio::net::TcpStream::connect(target).await?;

        let domain = server_name_from_host(target)?;
        let tls_stream = nesting_tls_connector
            .connect(domain, outbound_stream)
            .await?;

        debug!("[proxy-client] Connected to proxy server");

        let attestation = {
            let (_io, server_connection) = tls_stream.get_ref();

            let remote_cert_chain = server_connection
                .peer_certificates()
                .ok_or(ProxyError::NoCertificate)?;

            AttestedCertificateVerifier::extract_custom_attestation_from_cert(
                remote_cert_chain.first().ok_or(ProxyError::NoCertificate)?,
            )?
        };

        // The attestation exchange is now complete - setup an HTTP client
        let http_version = HttpVersion::from_negotiated_protocol_client(&tls_stream);

        let outbound_io = TokioIo::new(tls_stream);
        let (sender, conn) = match http_version {
            HttpVersion::Http2 => {
                let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor)
                    .timer(hyper_util::rt::tokio::TokioTimer::new())
                    .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_INTERVAL)))
                    .keep_alive_timeout(Duration::from_secs(KEEP_ALIVE_TIMEOUT))
                    .keep_alive_while_idle(true)
                    .handshake::<_, hyper::body::Incoming>(outbound_io)
                    .await?;
                (sender.into(), conn.into())
            }
            HttpVersion::Http1 => {
                let (sender, conn) = hyper::client::conn::http1::Builder::new()
                    .handshake::<_, hyper::body::Incoming>(outbound_io)
                    .await?;
                (sender.into(), conn.into())
            }
        };

        Ok((sender, conn, attestation))
    }

    // Handle a request from the source client to the proxy server
    async fn handle_http_request(
        req: hyper::Request<hyper::body::Incoming>,
        requests_tx: mpsc::Sender<RequestWithResponseSender>,
    ) -> Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, ProxyError> {
        let (response_tx, response_rx) = oneshot::channel();
        requests_tx.send((req, response_tx)).await?;
        Ok(response_rx.await??)
    }
}

fn should_retry_setup_error(error: &ProxyError, should_bail: bool) -> bool {
    if !should_bail {
        return true;
    }

    match error {
        ProxyError::Io(io_error) => matches!(
            io_error.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

/// Update a request/response header if we are able to encode the header value
///
/// This avoids bailing on bad header values - the headers are simply not updated
fn update_header<K>(
    headers: &mut HeaderMap,
    header_name: K,
    header_value: &str,
) -> Option<HeaderValue>
where
    K: http::header::IntoHeaderName + std::fmt::Display,
{
    if let Ok(value) = HeaderValue::from_str(header_value) {
        headers.insert(header_name, value)
    } else {
        error!("Failed to encode {header_name} header value: {header_value}");
        None
    }
}

/// An error when running a proxy client or server
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Failed to get server ceritifcate")]
    NoCertificate,
    #[error("TLS: {0}")]
    Rustls(#[from] tokio_rustls::rustls::Error),
    #[error("Verifier builder: {0}")]
    VerifierBuilder(#[from] VerifierBuilderError),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Attestation: {0}")]
    Attestation(#[from] AttestationError),
    #[error("Integer conversion: {0}")]
    IntConversion(#[from] TryFromIntError),
    #[error("Bad host name: {0}")]
    BadDnsName(#[from] tokio_rustls::rustls::pki_types::InvalidDnsNameError),
    #[error("Invalid certificate encoding")]
    InvalidCertificateEncoding,
    #[error("Missing common name in certificate subject")]
    MissingCertificateName,
    #[error("Certificate common name is not valid UTF-8")]
    InvalidCertificateName,
    #[error("HTTP: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Attested TLS: {0}")]
    AttestedTls(#[from] AttestedTlsError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Could not forward response - sender was dropped")]
    OneShotRecv(#[from] oneshot::error::RecvError),
    #[error("Failed to send request, connection to proxy-server dropped")]
    MpscSend,
    #[error("Client auth must be configured on both the inner and outer TLS sessions")]
    ClientAuthMisconfigured,
    #[error("At least one server listener must be configured")]
    NoListenersConfigured,
}

impl From<mpsc::error::SendError<RequestWithResponseSender>> for ProxyError {
    fn from(_err: mpsc::error::SendError<RequestWithResponseSender>) -> Self {
        Self::MpscSend
    }
}

/// Given a certifcate, get the hostname
fn hostname_from_cert(cert: &CertificateDer<'static>) -> Result<String, ProxyError> {
    let cert = x509_parser::parse_x509_certificate(cert.as_ref())
        .map(|(_, parsed)| parsed)
        .map_err(|_| ProxyError::InvalidCertificateEncoding)?;

    Ok(cert
        .subject()
        .iter_common_name()
        .next()
        .ok_or(ProxyError::MissingCertificateName)?
        .as_str()
        .map_err(|_| ProxyError::InvalidCertificateName)?
        .to_string())
}

fn certificate_identity_from_chain(
    cert_chain: &[CertificateDer<'static>],
) -> Result<String, ProxyError> {
    hostname_from_cert(cert_chain.first().ok_or(ProxyError::NoCertificate)?)
}

async fn build_attested_cert_resolver(
    attestation_generator: AttestationGenerator,
    certificate_name: String,
) -> Result<AttestedCertificateResolver, ProxyError> {
    Ok(
        AttestedCertificateResolver::new(attestation_generator, None, certificate_name, vec![])
            .await?,
    )
}

async fn build_inner_server_config(
    attestation_generator: AttestationGenerator,
    attestation_verifier: AttestationVerifier,
    client_auth: bool,
    certificate_name: Option<String>,
) -> Result<ServerConfig, ProxyError> {
    let inner_cert_resolver = build_attested_cert_resolver(
        attestation_generator,
        certificate_name.unwrap_or_else(|| "localhost".to_string()),
    )
    .await?;

    let mut inner_server_config = if client_auth {
        let attested_cert_verifier = AttestedCertificateVerifier::new(None, attestation_verifier)?;
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(Arc::new(attested_cert_verifier))
            .with_cert_resolver(Arc::new(inner_cert_resolver))
    } else {
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(inner_cert_resolver))
    };

    ensure_proxy_alpn_protocols(&mut inner_server_config.alpn_protocols);

    Ok(inner_server_config)
}

/// If no port was provided, default to 443
pub(crate) fn host_to_host_with_port(host: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    }
}

/// Given a hostname with or without port number, create a TLS [ServerName] with just the host part
fn server_name_from_host(
    host: &str,
) -> Result<ServerName<'static>, tokio_rustls::rustls::pki_types::InvalidDnsNameError> {
    let host_part = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    let host_part = host_part.trim_matches(|c| c == '[' || c == ']');

    ServerName::try_from(host_part.to_string())
}

/// An Executor for hyper that uses the tokio runtime
#[derive(Clone)]
pub(crate) struct TokioExecutor;

// Implement the `hyper::rt::Executor` trait for `TokioExecutor` so that it can be used to spawn
// tasks in the hyper runtime.
impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use attestation::{AttestationType, measurements::MeasurementPolicy};
    use std::collections::HashMap;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio_rustls::TlsConnector;

    use super::*;
    use test_helpers::{
        example_http_service, generate_certificate_chain_for_host, generate_tls_config,
        generate_tls_config_with_client_auth, init_tracing,
    };

    fn expected_mock_measurements() -> HashMap<String, String> {
        let zero_measurement = "0".repeat(96);
        HashMap::from([
            ("0".to_string(), zero_measurement.clone()),
            ("1".to_string(), zero_measurement.clone()),
            ("2".to_string(), zero_measurement.clone()),
            ("3".to_string(), zero_measurement.clone()),
            ("4".to_string(), zero_measurement),
        ])
    }

    fn assert_mock_measurements(body: &str) {
        let parsed: HashMap<String, String> = serde_json::from_str(body).unwrap();
        assert_eq!(parsed, expected_mock_measurements());
    }

    fn assert_mock_measurements_header(headers: &http::HeaderMap) {
        let body = headers
            .get(MEASUREMENT_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert_mock_measurements(body);
    }

    fn assert_attestation_type_header(headers: &http::HeaderMap, expected: &str) {
        assert_eq!(
            headers
                .get(ATTESTATION_TYPE_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(expected)
        );
    }

    fn assert_no_measurements_header(headers: &http::HeaderMap) {
        assert!(headers.get(MEASUREMENT_HEADER).is_none());
    }

    /// Test service that echoes attestation-related request headers as JSON.
    async fn request_header_echo_service() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|headers: http::HeaderMap| async move {
                axum::Json(serde_json::json!({
                    "measurement": headers
                        .get(MEASUREMENT_HEADER)
                        .and_then(|v| v.to_str().ok()),
                    "attestation_type": headers
                        .get(ATTESTATION_TYPE_HEADER)
                        .and_then(|v| v.to_str().ok()),
                }))
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        addr
    }

    /// Test service that deliberately returns a spoofed measurement header.
    async fn spoofed_response_measurement_service() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async move {
                let mut response = http::Response::new("ok".to_string());
                response.headers_mut().insert(
                    MEASUREMENT_HEADER,
                    HeaderValue::from_static("{\"spoofed\":\"value\"}"),
                );
                response
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        addr
    }

    #[test]
    fn proxy_alpn_protocols_prefer_http2() {
        let mut protocols = Vec::new();
        ensure_proxy_alpn_protocols(&mut protocols);

        assert_eq!(protocols, vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()]);
    }

    #[test]
    fn proxy_alpn_protocols_preserve_existing_order_without_duplicates() {
        let mut protocols = vec![ALPN_HTTP11.to_vec(), ALPN_H2.to_vec()];
        ensure_proxy_alpn_protocols(&mut protocols);

        assert_eq!(protocols, vec![ALPN_HTTP11.to_vec(), ALPN_H2.to_vec()]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_server_requires_at_least_one_listener() {
        let result = ProxyServer::new(
            None::<OuterTlsConfig<&str>>,
            None::<&str>,
            "127.0.0.1:1".to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await;

        assert!(matches!(result, Err(ProxyError::NoListenersConfigured)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dual_listener_server_reports_expected_addresses() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let tls_cert_and_key = TlsCertAndKey {
            cert_chain,
            key: private_key,
        };

        let dual_listener_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::CertAndKey(tls_cert_and_key),
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let outer_addr = dual_listener_server.outer_local_addr().unwrap().unwrap();
        let inner_addr = dual_listener_server.inner_local_addr().unwrap().unwrap();
        assert_eq!(dual_listener_server.local_addr().unwrap(), outer_addr);
        assert_ne!(outer_addr, inner_addr);

        let inner_only_server = ProxyServer::new(
            None::<OuterTlsConfig<&str>>,
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let inner_only_addr = inner_only_server.inner_local_addr().unwrap().unwrap();
        assert!(inner_only_server.outer_local_addr().unwrap().is_none());
        assert_eq!(inner_only_server.local_addr().unwrap(), inner_only_addr);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inner_only_listener_negotiates_http2_by_default() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let target_addr = example_http_service().await;

        let proxy_server = ProxyServer::new(
            None::<OuterTlsConfig<&str>>,
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let inner_addr = proxy_server.inner_local_addr().unwrap().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let attested_cert_verifier =
            AttestedCertificateVerifier::new(None, AttestationVerifier::mock()).unwrap();
        let mut client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(attested_cert_verifier))
                .with_no_client_auth();
        ensure_proxy_alpn_protocols(&mut client_config.alpn_protocols);

        let tls_connector = TlsConnector::from(Arc::new(client_config));
        let outbound_stream = TcpStream::connect(inner_addr).await.unwrap();
        let domain = ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = tls_connector
            .connect(domain, outbound_stream)
            .await
            .unwrap();

        assert!(matches!(
            HttpVersion::from_negotiated_protocol_client(&tls_stream),
            HttpVersion::Http2
        ));

        tls_stream.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_negotiates_http2_by_default() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, outer_client_config) =
            generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let attested_cert_verifier =
            AttestedCertificateVerifier::new(None, AttestationVerifier::mock()).unwrap();
        let mut inner_client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(attested_cert_verifier))
                .with_no_client_auth();
        ensure_proxy_alpn_protocols(&mut inner_client_config.alpn_protocols);

        let nesting_tls_connector =
            NestingTlsConnector::new(Arc::new(outer_client_config), Arc::new(inner_client_config));

        let (sender, conn, _attestation) = ProxyClient::setup_connection(
            &nesting_tls_connector,
            &format!("localhost:{}", proxy_addr.port()),
        )
        .await
        .unwrap();

        assert!(matches!(sender, HttpSender::Http2(_)));
        assert!(matches!(conn, HttpConnection::Http2 { .. }));
    }

    // Server has mock DCAP, client has no attestation and no client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_with_server_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }

    // Server has no attestation, client has mock DCAP and client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_client_attestation() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain_for_host("localhost");
        let (client_cert_chain, client_private_key) =
            generate_certificate_chain_for_host("localhost");

        let (
            (_client_tls_server_config, client_tls_client_config),
            (server_tls_server_config, _server_tls_client_config),
        ) = generate_tls_config_with_client_auth(
            client_cert_chain.clone(),
            client_private_key,
            server_cert_chain.clone(),
            server_private_key,
        );

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config: server_tls_server_config,
                    certificate_name: certificate_identity_from_chain(&server_cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            true,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_tls_client_config,
            "127.0.0.1:0",
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            Some(client_cert_chain),
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "none");
        assert_no_measurements_header(res.headers());

        let res_body = res.text().await.unwrap();
        assert_mock_measurements(&res_body);
    }

    // Server has no attestation, client has mock DCAP but no client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_client_attestation_no_client_auth() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) =
            generate_tls_config(server_cert_chain.clone(), server_private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&server_cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept one connection, then finish
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept two connections, then finish
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "none");
        assert_no_measurements_header(res.headers());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_strips_spoofed_request_attestation_headers() {
        let target_addr = request_header_echo_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) =
            generate_tls_config(server_cert_chain.clone(), server_private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&server_cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::Client::new()
            .get(format!("http://{}", proxy_client_addr))
            .header(MEASUREMENT_HEADER, "{\"spoofed\":\"request\"}")
            .header(ATTESTATION_TYPE_HEADER, "dcap-tdx")
            .send()
            .await
            .unwrap();

        let echoed: serde_json::Value = serde_json::from_slice(&res.bytes().await.unwrap()).unwrap();
        assert!(echoed["measurement"].is_null());
        assert!(echoed["attestation_type"].is_null());
    }

    // Server has mock DCAP, client has mock DCAP and client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_mutual_attestation() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain_for_host("localhost");
        let (client_cert_chain, client_private_key) =
            generate_certificate_chain_for_host("localhost");

        let (
            (_client_tls_server_config, client_tls_client_config),
            (server_tls_server_config, _server_tls_client_config),
        ) = generate_tls_config_with_client_auth(
            client_cert_chain.clone(),
            client_private_key,
            server_cert_chain.clone(),
            server_private_key,
        );

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config: server_tls_server_config,
                    certificate_name: certificate_identity_from_chain(&server_cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::mock(),
            true,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_tls_client_config,
            "127.0.0.1:0",
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::mock(),
            Some(client_cert_chain),
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();
        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());
        assert_mock_measurements(&res.text().await.unwrap());

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();
        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());
        assert_mock_measurements(&res.text().await.unwrap());
    }

    // Server has mock DCAP, client no attestation - just get the server certificate
    #[tokio::test(flavor = "multi_thread")]
    async fn test_get_tls_cert() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_server_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let retrieved_chain = get_inner_tls_cert_with_config(
            format!("localhost:{}", proxy_server_addr.port()),
            AttestationVerifier::mock(),
            client_config,
        )
        .await
        .unwrap();

        assert_eq!(retrieved_chain.len(), 1);
        assert_eq!(
            hostname_from_cert(&retrieved_chain[0]).unwrap(),
            "localhost"
        );
        assert_ne!(retrieved_chain, cert_chain);
    }

    // Negative test - server does not provide attestation but client requires it
    // Server has no attestaion, client has no attestation and no client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn fails_on_no_attestation_when_expected() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client_result = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await;

        let err = proxy_client_result.unwrap_err().to_string();
        assert!(err.contains("ApplicationVerificationFailure"), "{err}");
    }

    // Negative test - server does not provide attestation but client requires it
    // Server has no attestaion, client has no attestation and no client auth
    #[tokio::test(flavor = "multi_thread")]
    async fn fails_on_bad_measurements() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let measurement_policy = MeasurementPolicy::from_json_bytes(
            br#"
            [{
                "measurement_id": "test",
                "attestation_type": "dcap-tdx",
                "measurements": {
                    "0": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
                    "1": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
                    "2": { "expected": "010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101" },
                    "3": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" },
                    "4": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" }
                }
            }]
            "#
            .to_vec(),
        )
        .unwrap();

        let attestation_verifier = AttestationVerifier {
            measurement_policy,
            pccs_url: None,
            log_dcap_quote: false,
            override_azure_outdated_tcb: false,
        };

        let proxy_client_result = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            attestation_verifier,
            None,
        )
        .await;

        let err = proxy_client_result.unwrap_err().to_string();
        assert!(err.contains("ApplicationVerificationFailure"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_client_reconnects_on_lost_connection() {
        init_tracing();

        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        // This is used to trigger a dropped connection to the proxy server
        let (connection_breaker_tx, connection_breaker_rx) = oneshot::channel();
        let (reconnected_tx, reconnected_rx) = oneshot::channel();

        tokio::spawn(async move {
            let connection_handle = proxy_server.accept().await.unwrap();

            // Wait for a signal to simulate a dropped connection, then drop the task handling the
            // connection
            connection_breaker_rx.await.unwrap();
            connection_handle.abort();

            // Now accept another connection
            proxy_server.accept().await.unwrap();
            let _ = reconnected_tx.send(());
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let initial_response = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();
        assert_attestation_type_header(initial_response.headers(), "dcap-tdx");
        assert_mock_measurements_header(initial_response.headers());

        // Now break the connection
        connection_breaker_tx.send(()).unwrap();
        reconnected_rx.await.unwrap();

        // Make another request
        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_does_not_retry_failed_request() {
        init_tracing();

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_seen = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let app = axum::Router::new().route(
            "/",
            axum::routing::get({
                let request_count = request_count.clone();
                let request_seen = request_seen.clone();
                let release_rx = release_rx.clone();

                move || {
                    let request_count = request_count.clone();
                    let request_seen = request_seen.clone();
                    let mut release_rx = release_rx.clone();

                    async move {
                        request_count.fetch_add(1, Ordering::SeqCst);
                        request_seen.notify_waiters();

                        if !*release_rx.borrow() {
                            release_rx.changed().await.unwrap();
                        }

                        "ok"
                    }
                }
            }),
        );

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        let (connection_breaker_tx, connection_breaker_rx) = oneshot::channel();
        let (reconnected_tx, reconnected_rx) = oneshot::channel();

        tokio::spawn(async move {
            let connection_handle = proxy_server.accept().await.unwrap();
            connection_breaker_rx.await.unwrap();
            connection_handle.abort();
            proxy_server.accept().await.unwrap();
            let _ = reconnected_tx.send(());
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let request_url = format!("http://{}", proxy_client_addr);
        let failed_request = tokio::spawn(async move { reqwest::get(request_url).await.unwrap() });

        loop {
            if request_count.load(Ordering::SeqCst) > 0 {
                break;
            }

            request_seen.notified().await;
        }

        connection_breaker_tx.send(()).unwrap();
        release_tx.send(true).unwrap();

        let failed_response = failed_request.await.unwrap();
        assert_eq!(failed_response.status(), hyper::StatusCode::BAD_GATEWAY);
        assert_eq!(request_count.load(Ordering::SeqCst), 1);

        reconnected_rx.await.unwrap();

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());
        assert_eq!(res.text().await.unwrap(), "ok");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_strips_spoofed_response_measurement_header() {
        let target_addr = spoofed_response_measurement_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) =
            generate_tls_config(server_cert_chain.clone(), server_private_key);

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&server_cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "none");
        assert_no_measurements_header(res.headers());
        assert_eq!(res.text().await.unwrap(), "ok");
    }

    // Use HTTP 1.1
    #[tokio::test(flavor = "multi_thread")]
    async fn http_proxy_with_http1() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (mut server_config, client_config) =
            generate_tls_config(cert_chain.clone(), private_key);

        server_config.alpn_protocols.push(ALPN_HTTP11.to_vec());

        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: certificate_identity_from_chain(&cert_chain).unwrap(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr))
            .await
            .unwrap();

        assert_attestation_type_header(res.headers(), "dcap-tdx");
        assert_mock_measurements_header(res.headers());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }
}
