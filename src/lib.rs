//! An attested TLS protocol and HTTPS proxy
pub mod attested_get;
pub mod file_server;
pub mod health_check;

pub use attested_tls;
pub use attested_tls::attestation;
pub use attested_tls::attestation::AttestationGenerator;

use bytes::Bytes;
use http::HeaderValue;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{service::service_fn, Response};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls::server::VerifierBuilderError;
use tracing::{error, warn};

#[cfg(test)]
mod test_helpers;

use std::{net::SocketAddr, num::TryFromIntError, sync::Arc, time::Duration};
use tokio::io;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::CertificateDer;

#[cfg(test)]
use tokio_rustls::rustls::{ClientConfig, ServerConfig};

use attested_tls::{
    attestation::{
        measurements::MultiMeasurements, AttestationError, AttestationType, AttestationVerifier,
    },
    AttestedTlsClient, AttestedTlsError, AttestedTlsServer, TlsCertAndKey,
};

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

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer {
    /// The underlying attested TLS server
    attested_tls_server: AttestedTlsServer,
    /// The underlying TCP listener
    listener: Arc<TcpListener>,
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
        let attested_tls_server = AttestedTlsServer::new(
            cert_and_key,
            attestation_generator,
            attestation_verifier,
            client_auth,
        )
        .await?;

        let listener = TcpListener::bind(local).await?;

        Ok(Self {
            attested_tls_server,
            listener: listener.into(),
            target,
        })
    }

    /// Start with preconfigured TLS
    ///
    /// This is not public as it allows dangerous configuration
    #[cfg(test)]
    async fn new_with_tls_config(
        cert_chain: Vec<CertificateDer<'static>>,
        server_config: Arc<ServerConfig>,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, ProxyError> {
        let attested_tls_server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config,
            attestation_generator,
            attestation_verifier,
        )
        .await?;

        let listener = TcpListener::bind(local).await?;

        Ok(Self {
            attested_tls_server,
            listener: listener.into(),
            target,
        })
    }

    /// Accept an incoming connection and handle it in a seperate task
    pub async fn accept(&self) -> Result<(), ProxyError> {
        let target = self.target;
        let (inbound, _client_addr) = self.listener.accept().await?;
        let attested_tls_server = self.attested_tls_server.clone();

        tokio::spawn(async move {
            match attested_tls_server.handle_connection(inbound).await {
                Ok((tls_stream, measurements, attestation_type)) => {
                    if let Err(err) =
                        Self::handle_connection(tls_stream, measurements, attestation_type, target)
                            .await
                    {
                        warn!("Failed to handle connection: {err}");
                    }
                }
                Err(err) => {
                    warn!("Attestation exchange failed: {err}");
                }
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
        tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        measurements: Option<MultiMeasurements>,
        remote_attestation_type: AttestationType,
        target: SocketAddr,
    ) -> Result<(), ProxyError> {
        tracing::debug!("proxy-server accepted connection");

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
        let attested_tls_client = AttestedTlsClient::new(
            cert_and_key,
            attestation_generator,
            attestation_verifier,
            remote_certificate,
        )
        .await?;

        Self::new_with_inner(address, attested_tls_client, &server_name).await
    }

    /// Create a new proxy client with given TLS configuration
    ///
    /// This is private as it allows dangerous configuration but is used in tests
    #[cfg(test)]
    async fn new_with_tls_config(
        client_config: Arc<ClientConfig>,
        address: impl ToSocketAddrs,
        target_name: String,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ProxyError> {
        let attested_tls_client = AttestedTlsClient::new_with_tls_config(
            client_config,
            attestation_generator,
            attestation_verifier,
            cert_chain,
        )
        .await?;

        Self::new_with_inner(address, attested_tls_client, &target_name).await
    }

    /// Create a new proxy client with given [AttestedTlsClient]
    pub async fn new_with_inner(
        address: impl ToSocketAddrs,
        attested_tls_client: AttestedTlsClient,
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

        // Connect to the proxy server and provide / verify attestation
        let (mut sender, mut measurements, mut remote_attestation_type) =
            Self::setup_connection_with_backoff(&target, &attested_tls_client, true).await?;

        let attested_tls_client_clone = attested_tls_client.clone();
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
                            &target,
                            &attested_tls_client_clone,
                            false,
                        )
                        .await
                        .expect("Function will not return an error when should_bail is false");
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
        target: &str,
        attested_tls_client: &AttestedTlsClient,
        should_bail: bool,
    ) -> Result<(Http2Sender, Option<MultiMeasurements>, AttestationType), ProxyError> {
        let mut delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(SERVER_RECONNECT_MAX_BACKOFF_SECS);

        loop {
            match Self::setup_connection(attested_tls_client, target).await {
                Ok(output) => {
                    return Ok(output);
                }
                Err(e) => {
                    if matches!(e, ProxyError::Io(_)) || !should_bail {
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
        inner: &AttestedTlsClient,
        target: &str,
    ) -> Result<(Http2Sender, Option<MultiMeasurements>, AttestationType), ProxyError> {
        let (tls_stream, measurements, remote_attestation_type) = inner.connect_tcp(target).await?;

        // The attestation exchange is now complete - setup an HTTP client

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
    #[error("HTTP: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Could not forward response - sender was dropped")]
    OneShotRecv(#[from] oneshot::error::RecvError),
    #[error("Failed to send request, connection to proxy-server dropped")]
    MpscSend,
    #[error("Attested TLS: {0}")]
    AttestedTls(#[from] AttestedTlsError),
}

impl From<mpsc::error::SendError<RequestWithResponseSender>> for ProxyError {
    fn from(_err: mpsc::error::SendError<RequestWithResponseSender>) -> Self {
        Self::MpscSend
    }
}

/// If no port was provided, default to 443
pub(crate) fn host_to_host_with_port(host: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    }
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
    use crate::{
        attestation::measurements::MultiMeasurements, attested_tls::get_tls_cert_with_config,
    };

    use super::*;
    use test_helpers::{
        example_http_service, generate_certificate_chain, generate_tls_config,
        generate_tls_config_with_client_auth, mock_dcap_measurements,
    };

    // Server has mock DCAP, client has no attestation and no client auth
    #[tokio::test]
    async fn http_proxy_with_server_attestation() {
        let _ = tracing_subscriber::fmt::try_init();
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

    // Server has no attestation, client has mock DCAP but no client auth
    #[tokio::test]
    async fn http_proxy_client_attestation_no_client_auth() {
        let target_addr = example_http_service().await;

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) =
            generate_tls_config(server_cert_chain.clone(), server_private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            server_cert_chain,
            server_config,
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
            client_config,
            "127.0.0.1:0",
            proxy_addr.to_string(),
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
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
            &proxy_server_addr.to_string(),
            AttestationVerifier::mock(),
            client_config,
        )
        .await
        .unwrap();

        assert_eq!(retrieved_chain, cert_chain);
    }
}
