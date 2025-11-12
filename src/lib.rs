pub mod attestation;

use attestation::{AttestationError, AttestationType, Measurements};
pub use attestation::{
    DcapTdxQuoteGenerator, DcapTdxQuoteVerifier, NoQuoteGenerator, NoQuoteVerifier, QuoteGenerator,
    QuoteVerifier,
};
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::server::conn::http1::Builder;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio_rustls::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};

#[cfg(test)]
mod test_helpers;

use std::num::TryFromIntError;
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{
    rustls::{ClientConfig, ServerConfig},
    TlsAcceptor, TlsConnector,
};

/// The label used when exporting key material from a TLS session
const EXPORTER_LABEL: &[u8; 24] = b"EXPORTER-Channel-Binding";

const ATTESTATION_TYPE_HEADER: &str = "X-Flashbots-Attestation-Type";

/// The header name for giving measurements
const MEASUREMENT_HEADER: &str = "X-Flashbots-Measurement";

/// TLS Credentials
pub struct TlsCertAndKey {
    /// Der-encoded TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Der-encoded TLS private key
    pub key: PrivateKeyDer<'static>,
}

/// Inner struct used by [ProxyClient] and [ProxyServer]
struct Proxy<L, R>
where
    L: QuoteGenerator,
    R: QuoteVerifier,
{
    /// The underlying TCP listener
    listener: TcpListener,
    /// Quote generation type to use (including none)
    local_quote_generator: L,
    /// Verifier for remote attestation (including none)
    remote_quote_verifier: R,
}

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer<L, R>
where
    L: QuoteGenerator,
    R: QuoteVerifier,
{
    inner: Proxy<L, R>,
    /// The certificate chain
    cert_chain: Vec<CertificateDer<'static>>,
    /// For accepting TLS connections
    acceptor: TlsAcceptor,
    /// The address of the target service we are proxying to
    target: SocketAddr,
}

impl<L: QuoteGenerator, R: QuoteVerifier> ProxyServer<L, R> {
    pub async fn new(
        cert_and_key: TlsCertAndKey,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        local_quote_generator: L,
        remote_quote_verifier: R,
        client_auth: bool,
    ) -> Result<Self, ProxyError> {
        if remote_quote_verifier.attestation_type() != AttestationType::None && !client_auth {
            return Err(ProxyError::NoClientAuth);
        }

        let server_config = if client_auth {
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

        Self::new_with_tls_config(
            cert_and_key.cert_chain,
            server_config.into(),
            local,
            target,
            local_quote_generator,
            remote_quote_verifier,
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
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<Self, ProxyError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind(local).await?;

        let inner = Proxy {
            listener,
            local_quote_generator,
            remote_quote_verifier,
        };

        Ok(Self {
            acceptor,
            target,
            inner,
            cert_chain,
        })
    }

    /// Accept an incoming connection
    pub async fn accept(&self) -> Result<(), ProxyError> {
        let (inbound, _client_addr) = self.inner.listener.accept().await?;

        let acceptor = self.acceptor.clone();
        let target = self.target;
        let cert_chain = self.cert_chain.clone();
        let local_quote_generator = self.inner.local_quote_generator.clone();
        let remote_quote_verifier = self.inner.remote_quote_verifier.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(
                inbound,
                acceptor,
                target,
                cert_chain,
                local_quote_generator,
                remote_quote_verifier,
            )
            .await
            {
                eprintln!("Failed to handle connection: {err}");
            }
        });

        Ok(())
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.listener.local_addr()
    }

    async fn handle_connection(
        inbound: TcpStream,
        acceptor: TlsAcceptor,
        target: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<(), ProxyError> {
        let mut tls_stream = acceptor.accept(inbound).await?;
        let (_io, connection) = tls_stream.get_ref();

        let mut exporter = [0u8; 32];
        connection.export_keying_material(
            &mut exporter,
            EXPORTER_LABEL,
            None, // context
        )?;

        let remote_cert_chain = connection.peer_certificates().map(|c| c.to_owned());

        let attestation = if local_quote_generator.attestation_type() != AttestationType::None {
            local_quote_generator.create_attestation(&cert_chain, exporter)?
        } else {
            Vec::new()
        };

        let attestation_length_prefix = length_prefix(&attestation);

        tls_stream.write_all(&attestation_length_prefix).await?;

        tls_stream.write_all(&attestation).await?;

        let mut length_bytes = [0; 4];
        tls_stream.read_exact(&mut length_bytes).await?;
        let length: usize = u32::from_be_bytes(length_bytes).try_into()?;

        let mut buf = vec![0; length];
        tls_stream.read_exact(&mut buf).await?;

        let measurements = if remote_quote_verifier.attestation_type() != AttestationType::None {
            remote_quote_verifier
                .verify_attestation(
                    buf,
                    &remote_cert_chain.ok_or(ProxyError::NoClientAuth)?,
                    exporter,
                )
                .await?
        } else {
            None
        };
        let remote_attestation_type = remote_quote_verifier.attestation_type();

        let http = Builder::new();
        let service = service_fn(move |mut req| {
            // If we have measurements, add them to the request header
            let measurements = measurements.clone();
            if let Some(measurements) = measurements {
                let headers = req.headers_mut();

                match measurements.to_header_format() {
                    Ok(header_value) => {
                        headers.insert(MEASUREMENT_HEADER, header_value);
                    }
                    Err(e) => {
                        // This error is highly unlikely - that the measurement values fail to
                        // encode to JSON or fit in an HTTP header
                        eprintln!("Failed to encode measurement values: {e}");
                    }
                }
                headers.insert(
                    ATTESTATION_TYPE_HEADER,
                    HeaderValue::from_str(remote_attestation_type.as_str()).unwrap(),
                );
            }

            async move {
                match Self::handle_http_request(req, target).await {
                    Ok(res) => {
                        Ok::<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>(res)
                    }
                    Err(e) => {
                        eprintln!("send_request error: {e}");
                        let mut resp = Response::new(full(format!("Request failed: {e}")));
                        *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                        Ok(resp)
                    }
                }
            }
        });

        let io = TokioIo::new(tls_stream);
        http.serve_connection(io, service).await?;

        Ok(())
    }

    // Handle a request from the proxy client to the target server
    async fn handle_http_request(
        req: hyper::Request<hyper::body::Incoming>,
        target: SocketAddr,
    ) -> Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, ProxyError> {
        let outbound = TcpStream::connect(target).await?;
        let outbound_io = TokioIo::new(outbound);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, hyper::body::Incoming>(outbound_io)
            .await?;
        // Drive the connection
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Client connection error: {e}");
            }
        });

        match sender.send_request(req).await {
            Ok(resp) => Ok(resp.map(|b| b.boxed())),
            Err(e) => {
                eprintln!("send_request error: {e}");
                let mut resp = Response::new(full(format!("Request failed: {e}")));
                *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                Ok(resp)
            }
        }
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

pub struct ProxyClient<L, R>
where
    L: QuoteGenerator,
    R: QuoteVerifier,
{
    inner: Proxy<L, R>,
    connector: TlsConnector,
    /// The host and port of the proxy server
    target: String,
    /// Certificate chain for client auth
    cert_chain: Option<Vec<CertificateDer<'static>>>,
}

impl<L: QuoteGenerator, R: QuoteVerifier> ProxyClient<L, R> {
    pub async fn new(
        cert_and_key: Option<TlsCertAndKey>,
        address: impl ToSocketAddrs,
        server_name: String,
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<Self, ProxyError> {
        if local_quote_generator.attestation_type() != AttestationType::None
            && cert_and_key.is_none()
        {
            return Err(ProxyError::NoClientAuth);
        }

        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = if let Some(ref cert_and_key) = cert_and_key {
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

        Self::new_with_tls_config(
            client_config.into(),
            address,
            server_name,
            local_quote_generator,
            remote_quote_verifier,
            cert_and_key.map(|c| c.cert_chain),
        )
        .await
    }

    /// Create a new proxy with given TLS configuration
    ///
    /// This is private as it allows dangerous configuration but is used in tests
    async fn new_with_tls_config(
        client_config: Arc<ClientConfig>,
        local: impl ToSocketAddrs,
        target_name: String,
        local_quote_generator: L,
        remote_quote_verifier: R,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(local).await?;
        let connector = TlsConnector::from(client_config.clone());

        let inner = Proxy {
            listener,
            local_quote_generator,
            remote_quote_verifier,
        };

        Ok(Self {
            inner,
            connector,
            target: host_to_host_with_port(&target_name),
            cert_chain,
        })
    }

    /// Accept an incoming connection and handle it
    pub async fn accept(&self) -> io::Result<()> {
        let (inbound, _client_addr) = self.inner.listener.accept().await?;

        let connector = self.connector.clone();
        let target = self.target.clone();
        let local_quote_generator = self.inner.local_quote_generator.clone();
        let remote_quote_verifier = self.inner.remote_quote_verifier.clone();
        let cert_chain = self.cert_chain.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(
                inbound,
                connector,
                target,
                cert_chain,
                local_quote_generator,
                remote_quote_verifier,
            )
            .await
            {
                eprintln!("Failed to handle connection: {err}");
            }
        });

        Ok(())
    }

    /// Helper to return the local socket address from the underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.listener.local_addr()
    }

    /// Handle an incoming connection
    async fn handle_connection(
        inbound: TcpStream,
        connector: TlsConnector,
        target: String,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<(), ProxyError> {
        let http = Builder::new();
        let service = service_fn(move |req| {
            let connector = connector.clone();
            let target = target.clone();
            let cert_chain = cert_chain.clone();
            let local_quote_generator = local_quote_generator.clone();
            let remote_quote_verifier = remote_quote_verifier.clone();
            async move {
                match Self::handle_http_request(
                    req,
                    connector,
                    target,
                    cert_chain,
                    local_quote_generator,
                    remote_quote_verifier,
                )
                .await
                {
                    Ok(res) => {
                        Ok::<Response<BoxBody<bytes::Bytes, hyper::Error>>, hyper::Error>(res)
                    }
                    Err(e) => {
                        eprintln!("send_request error: {e}");
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

    async fn setup_connection(
        connector: TlsConnector,
        target: String,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<
        (
            tokio_rustls::client::TlsStream<TcpStream>,
            Option<Measurements>,
        ),
        ProxyError,
    > {
        let out = TcpStream::connect(&target).await?;
        let mut tls_stream = connector
            .connect(server_name_from_host(&target)?, out)
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

        let measurements = remote_quote_verifier
            .verify_attestation(buf, &remote_cert_chain, exporter)
            .await?;

        let attestation = if local_quote_generator.attestation_type() != AttestationType::None {
            local_quote_generator
                .create_attestation(&cert_chain.ok_or(ProxyError::NoClientAuth)?, exporter)?
        } else {
            Vec::new()
        };

        let attestation_length_prefix = length_prefix(&attestation);

        tls_stream.write_all(&attestation_length_prefix).await?;

        tls_stream.write_all(&attestation).await?;

        Ok((tls_stream, measurements))
    }

    // Handle a request from the source client to the proxy server
    async fn handle_http_request(
        req: hyper::Request<hyper::body::Incoming>,
        connector: TlsConnector,
        target: String,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        local_quote_generator: L,
        remote_quote_verifier: R,
    ) -> Result<Response<BoxBody<bytes::Bytes, hyper::Error>>, ProxyError> {
        let remote_attestation_type = remote_quote_verifier.attestation_type();

        let (tls_stream, measurements) = Self::setup_connection(
            connector,
            target,
            cert_chain,
            local_quote_generator,
            remote_quote_verifier,
        )
        .await?;

        // Now the attestation is done, forward the request to the proxy server
        let outbound_io = TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, hyper::body::Incoming>(outbound_io)
            .await?;

        // Drive the connection
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("Client connection error: {e}");
            }
        });

        match sender.send_request(req).await {
            Ok(mut resp) => {
                if let Some(measurements) = measurements {
                    let headers = resp.headers_mut();
                    match measurements.to_header_format() {
                        Ok(header_value) => {
                            headers.insert(MEASUREMENT_HEADER, header_value);
                        }
                        Err(e) => {
                            // This error is highly unlikely - that the measurement values fail to
                            // encode to JSON or fit in an HTTP header
                            eprintln!("Failed to encode measurement values: {e}");
                        }
                    }
                    headers.insert(
                        ATTESTATION_TYPE_HEADER,
                        HeaderValue::from_str(remote_attestation_type.as_str()).unwrap(),
                    );
                }
                Ok(resp.map(|b| b.boxed()))
            }
            Err(e) => {
                eprintln!("send_request error: {e}");
                let mut resp = Response::new(full(format!("Request failed: {e}")));
                *resp.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                Ok(resp)
            }
        }
    }
}

/// Just get the attested remote certificate, with no client authentication
pub async fn get_tls_cert<R: QuoteVerifier>(
    server_name: String,
    remote_quote_verifier: R,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    get_tls_cert_with_config(server_name, remote_quote_verifier, client_config.into()).await
}

async fn get_tls_cert_with_config<R: QuoteVerifier>(
    server_name: String,
    remote_quote_verifier: R,
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

    let _measurements = remote_quote_verifier
        .verify_attestation(buf, &remote_cert_chain, exporter)
        .await?;

    Ok(remote_cert_chain)
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
}

/// Given a byte array, encode its length as a 4 byte big endian u32
fn length_prefix(input: &[u8]) -> [u8; 4] {
    let len = input.len() as u32;
    len.to_be_bytes()
}

fn host_to_host_with_port(host: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:443")
    }
}

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

#[cfg(test)]
mod tests {
    use crate::attestation::CvmImageMeasurements;

    use super::*;
    use test_helpers::{
        default_measurements, example_http_service, example_service, generate_certificate_chain,
        generate_tls_config, generate_tls_config_with_client_auth,
    };

    #[tokio::test]
    async fn http_proxy() {
        let target_addr = example_http_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            DcapTdxQuoteGenerator {
                attestation_type: AttestationType::Dummy,
            },
            NoQuoteVerifier,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        let quote_verifier = DcapTdxQuoteVerifier {
            attestation_type: AttestationType::Dummy,
            accepted_platform_measurements: None,
            accepted_cvm_image_measurements: vec![CvmImageMeasurements {
                rtmr1: [0u8; 48],
                rtmr2: [0u8; 48],
                rtmr3: [0u8; 48],
            }],
            pccs_url: None,
        };

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            proxy_addr.to_string(),
            NoQuoteGenerator,
            quote_verifier,
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
        let measurements_json = headers.get(MEASUREMENT_HEADER).unwrap().to_str().unwrap();
        let measurements = Measurements::from_header_format(measurements_json).unwrap();
        assert_eq!(measurements, default_measurements());

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::Dummy.as_str());

        let res_body = res.text().await.unwrap();
        assert_eq!(res_body, "No measurements");
    }

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

        let quote_verifier = DcapTdxQuoteVerifier {
            attestation_type: AttestationType::Dummy,
            accepted_platform_measurements: None,
            accepted_cvm_image_measurements: vec![CvmImageMeasurements {
                rtmr1: [0u8; 48],
                rtmr2: [0u8; 48],
                rtmr3: [0u8; 48],
            }],
            pccs_url: None,
        };

        let proxy_server = ProxyServer::new_with_tls_config(
            server_cert_chain,
            server_tls_server_config,
            "127.0.0.1:0",
            target_addr,
            DcapTdxQuoteGenerator {
                attestation_type: AttestationType::Dummy,
            },
            quote_verifier.clone(),
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
            proxy_addr.to_string(),
            DcapTdxQuoteGenerator {
                attestation_type: AttestationType::Dummy,
            },
            quote_verifier,
            Some(client_cert_chain),
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
        let measurements_json = headers.get(MEASUREMENT_HEADER).unwrap().to_str().unwrap();
        let measurements = Measurements::from_header_format(measurements_json).unwrap();
        assert_eq!(measurements, default_measurements());

        let attestation_type = headers
            .get(ATTESTATION_TYPE_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(attestation_type, AttestationType::Dummy.as_str());

        let res_body = res.text().await.unwrap();

        // The response body shows us what was in the request header (as the test http server
        // handler puts them there)
        let measurements = Measurements::from_header_format(&res_body).unwrap();
        assert_eq!(measurements, default_measurements());
    }

    #[tokio::test]
    async fn test_get_tls_cert() {
        let target_addr = example_service().await;

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain.clone(),
            server_config,
            "127.0.0.1:0",
            target_addr,
            DcapTdxQuoteGenerator {
                attestation_type: AttestationType::Dummy,
            },
            NoQuoteVerifier,
        )
        .await
        .unwrap();

        let proxy_server_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let quote_verifier = DcapTdxQuoteVerifier {
            attestation_type: AttestationType::Dummy,
            accepted_platform_measurements: None,
            accepted_cvm_image_measurements: vec![CvmImageMeasurements {
                rtmr1: [0u8; 48],
                rtmr2: [0u8; 48],
                rtmr3: [0u8; 48],
            }],
            pccs_url: None,
        };

        let retrieved_chain =
            get_tls_cert_with_config(proxy_server_addr.to_string(), quote_verifier, client_config)
                .await
                .unwrap();

        assert_eq!(retrieved_chain, cert_chain);
    }
}
