pub mod attestation;
pub mod attested_get;
pub mod file_server;
pub mod health_check;

pub use attestation::AttestationGenerator;
use attestation::{measurements::MultiMeasurements, AttestationError, AttestationType};
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{service::service_fn, Response};
use hyper_util::rt::TokioIo;
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use tracing::{error, warn};
use x509_parser::parse_x509_certificate;

#[cfg(test)]
mod test_helpers;

use std::num::TryFromIntError;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{
    rustls::{ClientConfig, ServerConfig},
    TlsAcceptor, TlsConnector,
};

use crate::attestation::{AttestationExchangeMessage, AttestationVerifier};

/// This makes it possible to add breaking protocol changes and provide backwards compatibility.
/// When adding more supported versions, note that ordering is important. ALPN will pick the first
/// protocol which both parties support - so newer supported versions should come first.
pub const SUPPORTED_ALPN_PROTOCOL_VERSIONS: [&[u8]; 1] = [b"flashbots-ratls/1"];

/// The label used when exporting key material from a TLS session
const EXPORTER_LABEL: &[u8; 24] = b"EXPORTER-Channel-Binding";

/// The header name for giving attestation type
const ATTESTATION_TYPE_HEADER: &str = "X-Flashbots-Attestation-Type";

/// The header name for giving measurements
const MEASUREMENT_HEADER: &str = "X-Flashbots-Measurement";

/// The longest time in seconds to wait between reconnection attempts
const SERVER_RECONNECT_MAX_BACKOFF_SECS: u64 = 120;

type RequestWithResponseSender = (
    http::Request<hyper::body::Incoming>,
    oneshot::Sender<Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>>,
);
type Http2Sender = hyper::client::conn::http2::SendRequest<hyper::body::Incoming>;

/// TLS Credentials
pub struct TlsCertAndKey {
    /// Der-encoded TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Der-encoded TLS private key
    pub key: PrivateKeyDer<'static>,
}

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer {
    /// The underlying TCP listener
    listener: TcpListener,
    /// Quote generation type to use (including none)
    attestation_generator: AttestationGenerator,
    /// Verifier for remote attestation (including none)
    attestation_verifier: AttestationVerifier,
    /// The certificate chain
    cert_chain: Vec<CertificateDer<'static>>,
    /// For accepting TLS connections
    acceptor: TlsAcceptor,
    /// The address of the target service we are proxying to
    target: SocketAddr,
}

impl ProxyServer {
    pub async fn new(
        cert_and_key: TlsCertAndKey,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        client_auth: bool,
    ) -> Result<Self, ProxyError> {
        if attestation_verifier.has_remote_attestion() && !client_auth {
            return Err(ProxyError::NoClientAuth);
        }

        let mut server_config = if client_auth {
            let root_store =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_and_key.cert_chain.clone(), cert_and_key.key)?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_and_key.cert_chain.clone(), cert_and_key.key)?
        };

        server_config.alpn_protocols = SUPPORTED_ALPN_PROTOCOL_VERSIONS
            .into_iter()
            .map(|p| p.to_vec())
            .collect();

        Self::new_with_tls_config(
            cert_and_key.cert_chain,
            server_config.into(),
            local,
            target,
            attestation_generator,
            attestation_verifier,
        )
        .await
    }

    /// Start with preconfigured TLS
    ///
    /// This is not public as it allows dangerous configuration
    async fn new_with_tls_config(
        cert_chain: Vec<CertificateDer<'static>>,
        server_config: Arc<ServerConfig>,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, ProxyError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind(local).await?;

        Ok(Self {
            listener,
            attestation_generator,
            attestation_verifier,
            acceptor,
            target,
            cert_chain,
        })
    }

    /// Accept an incoming connection and handle it in a seperate task
    pub async fn accept(&self) -> Result<(), ProxyError> {
        let (inbound, _client_addr) = self.listener.accept().await?;

        let acceptor = self.acceptor.clone();
        let target = self.target;
        let cert_chain = self.cert_chain.clone();
        let attestation_generator = self.attestation_generator.clone();
        let attestation_verifier = self.attestation_verifier.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(
                inbound,
                acceptor,
                target,
                cert_chain,
                attestation_generator,
                attestation_verifier,
            )
            .await
            {
                warn!("Failed to handle connection: {err}");
            }
        });

        Ok(())
    }

    /// Helper to get the socket address of the underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Handle an incoming connection from a proxy-client
    async fn handle_connection(
        inbound: TcpStream,
        acceptor: TlsAcceptor,
        target: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> Result<(), ProxyError> {
        tracing::debug!("proxy-server accepted connection");

        // Do TLS handshake
        let mut tls_stream = acceptor.accept(inbound).await?;
        let (_io, connection) = tls_stream.get_ref();

        // Ensure that we agreed a protocol
        let _negotiated_protocol = connection.alpn_protocol().ok_or(ProxyError::AlpnFailed)?;

        // Compute an exporter unique to the session
        let mut exporter = [0u8; 32];
        connection.export_keying_material(
            &mut exporter,
            EXPORTER_LABEL,
            None, // context
        )?;

        let input_data = compute_report_input(&cert_chain, exporter)?;

        // Get the TLS certficate chain of the client, if there is one
        let remote_cert_chain = connection.peer_certificates().map(|c| c.to_owned());

        // If we are in a CVM, generate an attestation
        let attestation = attestation_generator
            .generate_attestation(input_data)
            .await?
            .encode();

        // Write our attestation to the channel, with length prefix
        let attestation_length_prefix = length_prefix(&attestation);
        tls_stream.write_all(&attestation_length_prefix).await?;
        tls_stream.write_all(&attestation).await?;

        // Now read a length-prefixed attestation from the remote peer
        // In the case of no client attestation this will be zero bytes
        let mut length_bytes = [0; 4];
        tls_stream.read_exact(&mut length_bytes).await?;
        let length: usize = u32::from_be_bytes(length_bytes).try_into()?;

        let mut buf = vec![0; length];
        tls_stream.read_exact(&mut buf).await?;

        let remote_attestation_message = AttestationExchangeMessage::decode(&mut &buf[..])?;
        let remote_attestation_type = remote_attestation_message.attestation_type;

        // If we expect an attestaion from the client, verify it and get measurements
        let measurements = if attestation_verifier.has_remote_attestion() {
            let remote_input_data = compute_report_input(
                &remote_cert_chain.ok_or(ProxyError::NoClientAuth)?,
                exporter,
            )?;

            attestation_verifier
                .verify_attestation(remote_attestation_message, remote_input_data)
                .await?
        } else {
            None
        };

        // Setup an HTTP server
        let http = hyper::server::conn::http2::Builder::new(TokioExecutor);

        // Setup a request handler
        let service = service_fn(move |mut req| {
            // If we have measurements, from the remote peer, add them to the request header
            let measurements = measurements.clone();
            let headers = req.headers_mut();
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
            headers.insert(
                ATTESTATION_TYPE_HEADER,
                HeaderValue::from_str(remote_attestation_type.as_str())
                    .expect("Attestation type should be able to be encoded as a header value"),
            );

            async move {
                match Self::handle_http_request(req, target).await {
                    Ok(res) => {
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
        http.serve_connection(io, service).await?;

        Ok(())
    }

    // Handle a request from the proxy client to the target server
    async fn handle_http_request(
        req: hyper::Request<hyper::body::Incoming>,
        target: SocketAddr,
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
        // If we will provide attestation, we must also use client auth
        if attestation_generator.attestation_type != AttestationType::None && cert_and_key.is_none()
        {
            return Err(ProxyError::NoClientAuth);
        }

        // If a remote CA cert was given, use it as the root store, otherwise use webpki_roots
        let root_store = match remote_certificate {
            Some(remote_certificate) => {
                let mut root_store = RootCertStore::empty();
                root_store.add(remote_certificate)?;
                root_store
            }
            None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        };

        // Setup TLS client configuration, with or without client auth
        let mut client_config = if let Some(ref cert_and_key) = cert_and_key {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(
                    cert_and_key.cert_chain.clone(),
                    cert_and_key.key.clone_key(),
                )?
        } else {
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        client_config.alpn_protocols = SUPPORTED_ALPN_PROTOCOL_VERSIONS
            .into_iter()
            .map(|p| p.to_vec())
            .collect();

        Self::new_with_tls_config(
            client_config.into(),
            address,
            server_name,
            attestation_generator,
            attestation_verifier,
            cert_and_key.map(|c| c.cert_chain),
        )
        .await
    }

    /// Create a new proxy client with given TLS configuration
    ///
    /// This is private as it allows dangerous configuration but is used in tests
    async fn new_with_tls_config(
        client_config: Arc<ClientConfig>,
        local: impl ToSocketAddrs,
        target_name: String,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ProxyError> {
        // Setup TCP server and TLS client
        let listener = TcpListener::bind(local).await?;
        let connector = TlsConnector::from(client_config.clone());

        // Process the hostname / port provided by the user
        let target = host_to_host_with_port(&target_name);

        // Channel for getting incoming requests from the source client
        let (requests_tx, mut requests_rx) = mpsc::channel::<(
            http::Request<hyper::body::Incoming>,
            oneshot::Sender<
                Result<http::Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>,
            >,
        )>(1024);

        // Connect to the proxy server and provide / verify attestation
        let (mut sender, mut measurements, mut remote_attestation_type) = Self::setup_connection(
            connector.clone(),
            target.clone(),
            cert_chain.clone(),
            attestation_generator.clone(),
            attestation_verifier.clone(),
        )
        .await?;

        tokio::spawn(async move {
            // Read an incoming request from the channel (from the source client)
            while let Some((req, response_tx)) = requests_rx.recv().await {
                // Attempt to forward it to the proxy server
                let (response, should_reconnect) = match sender.send_request(req).await {
                    Ok(mut resp) => {
                        // If we have measurements from the proxy-server, inject them into the
                        // response header
                        let headers = resp.headers_mut();
                        if let Some(measurements) = measurements.clone() {
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
                        headers.insert(
                            ATTESTATION_TYPE_HEADER,
                            HeaderValue::from_str(remote_attestation_type.as_str()).expect(
                                "Attestation type should be able to be encoded as a header value",
                            ),
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

                // If the connection to the proxy server failed, reconnect
                if should_reconnect {
                    // Reconnect to the server - retrying indefinately with a backoff
                    (sender, measurements, remote_attestation_type) =
                        Self::setup_connection_with_backoff(
                            connector.clone(),
                            target.clone(),
                            cert_chain.clone(),
                            attestation_generator.clone(),
                            attestation_verifier.clone(),
                        )
                        .await;
                }
            }
        });

        Ok(Self {
            listener,
            requests_tx,
        })
    }

    /// Helper to return the local socket address from the underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept an incoming connection and handle it in a separate task
    pub async fn accept(&self) -> io::Result<()> {
        let (inbound, _client_addr) = self.listener.accept().await?;

        let requests_tx = self.requests_tx.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(inbound, requests_tx).await {
                warn!("Failed to handle connection from source client: {err}");
            }
        });

        Ok(())
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
        connector: TlsConnector,
        target: String,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> (Http2Sender, Option<MultiMeasurements>, AttestationType) {
        let mut delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(SERVER_RECONNECT_MAX_BACKOFF_SECS);

        loop {
            match Self::setup_connection(
                connector.clone(),
                target.clone(),
                cert_chain.clone(),
                attestation_generator.clone(),
                attestation_verifier.clone(),
            )
            .await
            {
                Ok(output) => {
                    return output;
                }
                Err(e) => {
                    warn!("Reconnect failed: {e}. Retrying in {:#?}...", delay);
                    tokio::time::sleep(delay).await;

                    // increase delay for next time (exponential), but clamp to max_delay
                    delay = std::cmp::min(delay * 2, max_delay);
                }
            }
        }
    }

    /// Connect to the proxy-server, do TLS handshake and remote attestation
    async fn setup_connection(
        connector: TlsConnector,
        target: String,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> Result<(Http2Sender, Option<MultiMeasurements>, AttestationType), ProxyError> {
        // Make a TCP client connection and TLS handshake
        let out = TcpStream::connect(&target).await?;
        let mut tls_stream = connector
            .connect(server_name_from_host(&target)?, out)
            .await?;

        let (_io, server_connection) = tls_stream.get_ref();

        // Ensure that we agreed a protocol
        let _negotiated_protocol = server_connection
            .alpn_protocol()
            .ok_or(ProxyError::AlpnFailed)?;

        // Compute an exporter unique to the channel
        let mut exporter = [0u8; 32];
        server_connection.export_keying_material(
            &mut exporter,
            EXPORTER_LABEL,
            None, // context
        )?;

        // Get the TLS certificate chain of the server
        let remote_cert_chain = server_connection
            .peer_certificates()
            .ok_or(ProxyError::NoCertificate)?
            .to_owned();

        let remote_input_data = compute_report_input(&remote_cert_chain, exporter)?;

        // Read a length prefixed attestation from the proxy-server
        let mut length_bytes = [0; 4];
        tls_stream.read_exact(&mut length_bytes).await?;
        let length: usize = u32::from_be_bytes(length_bytes).try_into()?;

        let mut buf = vec![0; length];
        tls_stream.read_exact(&mut buf).await?;

        let remote_attestation_message = AttestationExchangeMessage::decode(&mut &buf[..])?;
        let remote_attestation_type = remote_attestation_message.attestation_type;

        // Verify the remote attestation against our accepted measurements
        let measurements = attestation_verifier
            .verify_attestation(remote_attestation_message, remote_input_data)
            .await?;

        // If we are in a CVM, provide an attestation
        let attestation = if attestation_generator.attestation_type != AttestationType::None {
            let local_input_data =
                compute_report_input(&cert_chain.ok_or(ProxyError::NoClientAuth)?, exporter)?;
            attestation_generator
                .generate_attestation(local_input_data)
                .await?
                .encode()
        } else {
            AttestationExchangeMessage::without_attestation().encode()
        };

        // Send our attestation (or zero bytes) prefixed with length
        let attestation_length_prefix = length_prefix(&attestation);
        tls_stream.write_all(&attestation_length_prefix).await?;
        tls_stream.write_all(&attestation).await?;

        // The attestation exchange is now complete - now setup an HTTP client

        let outbound_io = TokioIo::new(tls_stream);
        let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor)
            .handshake::<_, hyper::body::Incoming>(outbound_io)
            .await?;

        // Drive the connection
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Client connection error: {e}");
            }
        });

        // Return the HTTP client, as well as remote measurements
        Ok((sender, measurements, remote_attestation_type))
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

/// Just get the attested remote certificate, with no client authentication
pub async fn get_tls_cert(
    server_name: String,
    attestation_verifier: AttestationVerifier,
    remote_certificate: Option<CertificateDer<'_>>,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    tracing::debug!("Getting remote TLS cert");
    // If a remote CA cert was given, use it as the root store, otherwise use webpki_roots
    let root_store = match remote_certificate {
        Some(remote_certificate) => {
            let mut root_store = RootCertStore::empty();
            root_store.add(remote_certificate)?;
            root_store
        }
        None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.alpn_protocols = SUPPORTED_ALPN_PROTOCOL_VERSIONS
        .into_iter()
        .map(|p| p.to_vec())
        .collect();

    get_tls_cert_with_config(server_name, attestation_verifier, client_config.into()).await
}

async fn get_tls_cert_with_config(
    server_name: String,
    attestation_verifier: AttestationVerifier,
    client_config: Arc<ClientConfig>,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let connector = TlsConnector::from(client_config);

    let out = TcpStream::connect(host_to_host_with_port(&server_name)).await?;
    let mut tls_stream = connector
        .connect(server_name_from_host(&server_name)?, out)
        .await?;

    let (_io, server_connection) = tls_stream.get_ref();

    let mut exporter = [0u8; 32];
    server_connection.export_keying_material(
        &mut exporter,
        EXPORTER_LABEL,
        None, // context
    )?;

    let remote_cert_chain = server_connection
        .peer_certificates()
        .ok_or(ProxyError::NoCertificate)?
        .to_owned();

    let mut length_bytes = [0; 4];
    tls_stream.read_exact(&mut length_bytes).await?;
    let length: usize = u32::from_be_bytes(length_bytes).try_into()?;

    let mut buf = vec![0; length];
    tls_stream.read_exact(&mut buf).await?;

    let remote_attestation_message = AttestationExchangeMessage::decode(&mut &buf[..])?;

    let remote_input_data = compute_report_input(&remote_cert_chain, exporter)?;

    let _measurements = attestation_verifier
        .verify_attestation(remote_attestation_message, remote_input_data)
        .await?;

    tls_stream.shutdown().await?;

    Ok(remote_cert_chain)
}

/// Given a certificate chain and an exporter (session key material), build the quote input value
/// SHA256(pki) || exporter
pub fn compute_report_input(
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
) -> Result<[u8; 64], AttestationError> {
    let mut quote_input = [0u8; 64];
    let pki_hash = get_pki_hash_from_certificate_chain(cert_chain)?;
    quote_input[..32].copy_from_slice(&pki_hash);
    quote_input[32..].copy_from_slice(&exporter);
    Ok(quote_input)
}

/// Given a certificate chain, get the [Sha256] hash of the public key of the leaf certificate
fn get_pki_hash_from_certificate_chain(
    cert_chain: &[CertificateDer<'_>],
) -> Result<[u8; 32], AttestationError> {
    let leaf_certificate = cert_chain.first().ok_or(AttestationError::NoCertificate)?;
    let (_, cert) = parse_x509_certificate(leaf_certificate.as_ref())?;
    let public_key = &cert.tbs_certificate.subject_pki;
    let key_bytes = public_key.subject_public_key.as_ref();

    let mut hasher = Sha256::new();
    hasher.update(key_bytes);
    Ok(hasher.finalize().into())
}

/// An error when running a proxy client or server
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Client auth is required when the client is running in a CVM")]
    NoClientAuth,
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
    #[error("HTTP: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Could not forward response - sender was dropped")]
    OneShotRecv(#[from] oneshot::error::RecvError),
    #[error("Failed to send request, connection to proxy-server dropped")]
    MpscSend,
    #[error("Serialization: {0}")]
    Serialization(#[from] parity_scale_codec::Error),
    #[error("Protocol negotiation failed - remote peer does not support this protocol")]
    AlpnFailed,
}

impl From<mpsc::error::SendError<RequestWithResponseSender>> for ProxyError {
    fn from(_err: mpsc::error::SendError<RequestWithResponseSender>) -> Self {
        Self::MpscSend
    }
}

/// Given a byte array, encode its length as a 4 byte big endian u32
fn length_prefix(input: &[u8]) -> [u8; 4] {
    let len = input.len() as u32;
    len.to_be_bytes()
}

/// If no port was provided, default to 443
fn host_to_host_with_port(host: &str) -> String {
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
    // If host contains ':', try to split off the port.
    let host_part = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);

    // If the host is an IPv6 literal in brackets like "[::1]:443",
    // remove the brackets for SNI (SNI allows bare IPv6 too).
    let host_part = host_part.trim_matches(|c| c == '[' || c == ']');

    ServerName::try_from(host_part.to_string())
}

/// An Executor for hyper that uses the tokio runtime
#[derive(Clone)]
struct TokioExecutor;

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
    use std::collections::HashMap;

    use crate::attestation::measurements::{
        DcapMeasurementRegister, MeasurementPolicy, MeasurementRecord, MultiMeasurements,
    };

    use super::*;
    use test_helpers::{
        example_http_service, generate_certificate_chain, generate_tls_config,
        generate_tls_config_with_client_auth, mock_dcap_measurements,
    };

    // Server has mock DCAP, client has no attestation and no client auth
    #[tokio::test]
    async fn http_proxy_with_server_attestation() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
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
            proxy_addr.to_string(),
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

        let res = reqwest::get(format!("http://{}", proxy_client_addr.to_string()))
            .await
            .unwrap();

        let headers = res.headers();

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::DcapTdx.as_str());

        let measurements_json = headers.get(MEASUREMENT_HEADER).unwrap().to_str().unwrap();
        let measurements =
            MultiMeasurements::from_header_format(measurements_json, AttestationType::DcapTdx)
                .unwrap();
        assert_eq!(measurements, mock_dcap_measurements());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }

    // Server has no attestation, client has mock DCAP and client auth
    #[tokio::test]
    async fn http_proxy_client_attestation() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (client_cert_chain, client_private_key) =
            generate_certificate_chain("127.0.0.1".parse().unwrap());

        let (
            (_client_tls_server_config, client_tls_client_config),
            (server_tls_server_config, _server_tls_client_config),
        ) = generate_tls_config_with_client_auth(
            client_cert_chain.clone(),
            client_private_key,
            server_cert_chain.clone(),
            server_private_key,
        );

        let proxy_server = ProxyServer::new_with_tls_config(
            server_cert_chain,
            server_tls_server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept one connection, then finish
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_tls_client_config,
            "127.0.0.1:0",
            proxy_addr.to_string(),
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
            Some(client_cert_chain),
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept two connections, then finish
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr.to_string()))
            .await
            .unwrap();

        // We expect no measurements from the server
        let headers = res.headers();
        assert!(headers.get(MEASUREMENT_HEADER).is_none());

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::None.as_str());

        let res_body = res.text().await.unwrap();

        // The response body shows us what was in the request header (as the test http server
        // handler puts them there)
        let measurements =
            MultiMeasurements::from_header_format(&res_body, AttestationType::DcapTdx).unwrap();
        assert_eq!(measurements, mock_dcap_measurements());
    }

    // Server has mock DCAP, client has mock DCAP and client auth
    #[tokio::test]
    async fn http_proxy_mutual_attestation() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (client_cert_chain, client_private_key) =
            generate_certificate_chain("127.0.0.1".parse().unwrap());

        let (
            (_client_tls_server_config, client_tls_client_config),
            (server_tls_server_config, _server_tls_client_config),
        ) = generate_tls_config_with_client_auth(
            client_cert_chain.clone(),
            client_private_key,
            server_cert_chain.clone(),
            server_private_key,
        );

        let proxy_server = ProxyServer::new_with_tls_config(
            server_cert_chain,
            server_tls_server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::mock(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept one connection, then finish
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_tls_client_config,
            "127.0.0.1:0",
            proxy_addr.to_string(),
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::mock(),
            Some(client_cert_chain),
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            // Accept two connections, then finish
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let res = reqwest::get(format!("http://{}", proxy_client_addr.to_string()))
            .await
            .unwrap();

        let headers = res.headers();
        let measurements_json = headers.get(MEASUREMENT_HEADER).unwrap().to_str().unwrap();
        let measurements =
            MultiMeasurements::from_header_format(measurements_json, AttestationType::DcapTdx)
                .unwrap();
        assert_eq!(measurements, mock_dcap_measurements());

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::DcapTdx.as_str());

        let res_body = res.text().await.unwrap();

        // The response body shows us what was in the request header (as the test http server
        // handler puts them there)
        let measurements =
            MultiMeasurements::from_header_format(&res_body, AttestationType::DcapTdx).unwrap();
        assert_eq!(measurements, mock_dcap_measurements());

        // Now do another request - to check that the connection has stayed open
        let res = reqwest::get(format!("http://{}", proxy_client_addr.to_string()))
            .await
            .unwrap();

        let headers = res.headers();
        let measurements_json = headers.get(MEASUREMENT_HEADER).unwrap().to_str().unwrap();
        let measurements =
            MultiMeasurements::from_header_format(measurements_json, AttestationType::DcapTdx)
                .unwrap();
        assert_eq!(measurements, mock_dcap_measurements());

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::DcapTdx.as_str());

        let res_body = res.text().await.unwrap();

        // The response body shows us what was in the request header (as the test http server
        // handler puts them there)
        let measurements =
            MultiMeasurements::from_header_format(&res_body, AttestationType::DcapTdx).unwrap();
        assert_eq!(measurements, mock_dcap_measurements());
    }

    // Server has mock DCAP, client no attestation - just get the server certificate
    #[tokio::test]
    async fn test_get_tls_cert() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain.clone(),
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let proxy_server_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let retrieved_chain = get_tls_cert_with_config(
            proxy_server_addr.to_string(),
            AttestationVerifier::mock(),
            client_config,
        )
        .await
        .unwrap();

        assert_eq!(retrieved_chain, cert_chain);
    }

    // Negative test - server does not provide attestation but client requires it
    // Server has no attestaion, client has no attestation and no client auth
    #[tokio::test]
    async fn fails_on_no_attestation_when_expected() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
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
            proxy_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await;

        assert!(matches!(
            proxy_client_result.unwrap_err(),
            ProxyError::Attestation(AttestationError::AttestationTypeNotAccepted)
        ));
    }

    // Negative test - server does not provide attestation but client requires it
    // Server has no attestaion, client has no attestation and no client auth
    #[tokio::test]
    async fn fails_on_bad_measurements() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let attestation_verifier = AttestationVerifier {
            measurement_policy: MeasurementPolicy {
                accepted_measurements: vec![MeasurementRecord {
                    measurement_id: "test".to_string(),
                    measurements: MultiMeasurements::Dcap(HashMap::from([
                        (DcapMeasurementRegister::MRTD, [0; 48]),
                        (DcapMeasurementRegister::RTMR0, [0; 48]),
                        (DcapMeasurementRegister::RTMR1, [1; 48]), // This differs from the mock measurements
                        (DcapMeasurementRegister::RTMR2, [0; 48]),
                        (DcapMeasurementRegister::RTMR3, [0; 48]),
                    ])),
                }],
            },
            pccs_url: None,
            log_dcap_quote: false,
        };

        let proxy_client_result = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            proxy_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            attestation_verifier,
            None,
        )
        .await;

        assert!(matches!(
            proxy_client_result.unwrap_err(),
            ProxyError::Attestation(AttestationError::MeasurementsNotAccepted)
        ));
    }
}
