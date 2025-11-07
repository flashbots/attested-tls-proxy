mod attestation;

use attestation::AttestationError;
pub use attestation::{AttestationPlatform, MockAttestation, NoAttestation};
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

pub struct TlsCertAndKey {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

struct Proxy<L, R>
where
    L: AttestationPlatform,
    R: AttestationPlatform,
{
    /// The underlying TCP listener
    listener: TcpListener,
    /// Type of CVM platform we run on (including none)
    local_attestation_platform: L,
    /// Type of CVM platform the remote party runs on (including none)
    remote_attestation_platform: R,
}

/// A TLS over TCP server which provides an attestation before forwarding traffic to a given target address
pub struct ProxyServer<L, R>
where
    L: AttestationPlatform,
    R: AttestationPlatform,
{
    inner: Proxy<L, R>,
    /// The certificate chain
    cert_chain: Vec<CertificateDer<'static>>,
    /// For accepting TLS connections
    acceptor: TlsAcceptor,
    /// The address of the target service we are proxying to
    target: SocketAddr,
}

impl<L: AttestationPlatform, R: AttestationPlatform> ProxyServer<L, R> {
    pub async fn new(
        cert_and_key: TlsCertAndKey,
        local: impl ToSocketAddrs,
        target: SocketAddr,
        local_attestation_platform: L,
        remote_attestation_platform: R,
        client_auth: bool,
    ) -> Result<Self, ProxyError> {
        if remote_attestation_platform.is_cvm() && !client_auth {
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
            local_attestation_platform,
            remote_attestation_platform,
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
        local_attestation_platform: L,
        remote_attestation_platform: R,
    ) -> Result<Self, ProxyError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let listener = TcpListener::bind(local).await?;

        let inner = Proxy {
            listener,
            local_attestation_platform,
            remote_attestation_platform,
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
        let local_attestation_platform = self.inner.local_attestation_platform.clone();
        let remote_attestation_platform = self.inner.remote_attestation_platform.clone();
        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(
                inbound,
                acceptor,
                target,
                cert_chain,
                local_attestation_platform,
                remote_attestation_platform,
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
        local_attestation_platform: L,
        remote_attestation_platform: R,
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

        let attestation = if local_attestation_platform.is_cvm() {
            local_attestation_platform.create_attestation(&cert_chain, exporter)?
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

        if remote_attestation_platform.is_cvm() {
            remote_attestation_platform.verify_attestation(
                buf,
                &remote_cert_chain.ok_or(ProxyError::NoClientAuth)?,
                exporter,
            )?;
        }

        let outbound = TcpStream::connect(target).await?;

        let (mut inbound_reader, mut inbound_writer) = tokio::io::split(tls_stream);
        let (mut outbound_reader, mut outbound_writer) = outbound.into_split();

        let client_to_server = tokio::io::copy(&mut inbound_reader, &mut outbound_writer);
        let server_to_client = tokio::io::copy(&mut outbound_reader, &mut inbound_writer);
        tokio::try_join!(client_to_server, server_to_client)?;
        Ok(())
    }
}

pub struct ProxyClient<L, R>
where
    L: AttestationPlatform,
    R: AttestationPlatform,
{
    inner: Proxy<L, R>,
    connector: TlsConnector,
    /// The address of the proxy server
    target: SocketAddr,
    /// The subject name of the proxy server
    target_name: ServerName<'static>,
    /// Certificate chain for client auth
    cert_chain: Option<Vec<CertificateDer<'static>>>,
}

impl<L: AttestationPlatform, R: AttestationPlatform> ProxyClient<L, R> {
    pub async fn new(
        cert_and_key: Option<TlsCertAndKey>,
        address: impl ToSocketAddrs,
        server_address: SocketAddr,
        server_name: ServerName<'static>,
        local_attestation_platform: L,
        remote_attestation_platform: R,
    ) -> Result<Self, ProxyError> {
        if local_attestation_platform.is_cvm() && cert_and_key.is_none() {
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
            server_address,
            server_name,
            local_attestation_platform,
            remote_attestation_platform,
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
        target: SocketAddr,
        target_name: ServerName<'static>,
        local_attestation_platform: L,
        remote_attestation_platform: R,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(local).await?;
        let connector = TlsConnector::from(client_config.clone());

        let inner = Proxy {
            listener,
            local_attestation_platform,
            remote_attestation_platform,
        };

        Ok(Self {
            inner,
            connector,
            target,
            target_name,
            cert_chain,
        })
    }

    /// Accept an incoming connection and handle it
    pub async fn accept(&self) -> io::Result<()> {
        let (inbound, _client_addr) = self.inner.listener.accept().await?;

        let connector = self.connector.clone();
        let target_name = self.target_name.clone();
        let target = self.target;
        let local_attestation_platform = self.inner.local_attestation_platform.clone();
        let remote_attestation_platform = self.inner.remote_attestation_platform.clone();
        let cert_chain = self.cert_chain.clone();

        tokio::spawn(async move {
            if let Err(err) = Self::handle_connection(
                inbound,
                connector,
                target,
                target_name,
                cert_chain,
                local_attestation_platform,
                remote_attestation_platform,
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
        target: SocketAddr,
        target_name: ServerName<'static>,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
        local_attestation_platform: L,
        remote_attestation_platform: R,
    ) -> Result<(), ProxyError> {
        let out = TcpStream::connect(target).await?;
        let mut tls_stream = connector.connect(target_name, out).await?;

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

        if remote_attestation_platform.is_cvm() {
            remote_attestation_platform.verify_attestation(buf, &remote_cert_chain, exporter)?;
        }

        let attestation = if local_attestation_platform.is_cvm() {
            local_attestation_platform
                .create_attestation(&cert_chain.ok_or(ProxyError::NoClientAuth)?, exporter)?
        } else {
            Vec::new()
        };

        let attestation_length_prefix = length_prefix(&attestation);

        tls_stream.write_all(&attestation_length_prefix).await?;

        tls_stream.write_all(&attestation).await?;

        let (mut inbound_reader, mut inbound_writer) = inbound.into_split();
        let (mut outbound_reader, mut outbound_writer) = tokio::io::split(tls_stream);

        let client_to_server = tokio::io::copy(&mut inbound_reader, &mut outbound_writer);
        let server_to_client = tokio::io::copy(&mut outbound_reader, &mut inbound_writer);
        tokio::try_join!(client_to_server, server_to_client)?;
        Ok(())
    }
}

/// Just get the attested remote certificate, with no client authentication
pub async fn get_tls_cert<R: AttestationPlatform>(
    server_address: SocketAddr,
    server_name: ServerName<'static>,
    remote_attestation_platform: R,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    get_tls_cert_with_config(
        server_address,
        server_name,
        remote_attestation_platform,
        client_config.into(),
    )
    .await
}

async fn get_tls_cert_with_config<R: AttestationPlatform>(
    server_address: SocketAddr,
    server_name: ServerName<'static>,
    remote_attestation_platform: R,
    client_config: Arc<ClientConfig>,
) -> Result<Vec<CertificateDer<'static>>, ProxyError> {
    let connector = TlsConnector::from(client_config);

    let out = TcpStream::connect(server_address).await?;
    let mut tls_stream = connector.connect(server_name, out).await?;

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

    if remote_attestation_platform.is_cvm() {
        remote_attestation_platform.verify_attestation(buf, &remote_cert_chain, exporter)?;
    }

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
}

/// Given a byte array, encode its length as a 4 byte big endian u32
fn length_prefix(input: &[u8]) -> [u8; 4] {
    let len = input.len() as u32;
    len.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_helpers::{
        example_http_service, example_service, generate_certificate_chain, generate_tls_config,
        generate_tls_config_with_client_auth,
    };

    #[tokio::test]
    async fn http_proxy() {
        let target_addr = example_http_service().await;
        let target_name = "name".to_string();

        let (cert_chain, private_key) = generate_certificate_chain(target_name.clone());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            MockAttestation,
            NoAttestation,
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
            proxy_addr,
            target_name.try_into().unwrap(),
            NoAttestation,
            MockAttestation,
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
            .unwrap()
            .text()
            .await
            .unwrap();

        assert_eq!(res, "foobar");
    }

    #[tokio::test]
    async fn http_proxy_mutual_attestation() {
        let target_addr = example_http_service().await;
        let target_name = "name".to_string();

        let (server_cert_chain, server_private_key) =
            generate_certificate_chain(target_name.clone());
        let (client_cert_chain, client_private_key) =
            generate_certificate_chain(target_name.clone());

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
            MockAttestation,
            MockAttestation,
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
            proxy_addr,
            target_name.try_into().unwrap(),
            MockAttestation,
            MockAttestation,
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
            .unwrap()
            .text()
            .await
            .unwrap();

        assert_eq!(res, "foobar");
    }

    #[tokio::test]
    async fn raw_tcp_proxy() {
        let target_addr = example_service().await;
        let target_name = "name".to_string();

        let (cert_chain, private_key) = generate_certificate_chain(target_name.clone());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let local_attestation_platform = MockAttestation;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            local_attestation_platform,
            NoAttestation,
        )
        .await
        .unwrap();

        let proxy_server_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0",
            proxy_server_addr,
            target_name.try_into().unwrap(),
            NoAttestation,
            MockAttestation,
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let mut out = TcpStream::connect(proxy_client_addr).await.unwrap();

        let mut buf = [0; 9];
        out.read(&mut buf).await.unwrap();

        assert_eq!(buf[..], b"some data"[..]);
    }

    #[tokio::test]
    async fn test_get_tls_cert() {
        let target_addr = example_service().await;
        let target_name = "name".to_string();

        let (cert_chain, private_key) = generate_certificate_chain(target_name.clone());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let local_attestation_platform = MockAttestation;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain.clone(),
            server_config,
            "127.0.0.1:0",
            target_addr,
            local_attestation_platform,
            NoAttestation,
        )
        .await
        .unwrap();

        let proxy_server_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let retrieved_chain = get_tls_cert_with_config(
            proxy_server_addr,
            target_name.try_into().unwrap(),
            MockAttestation,
            client_config,
        )
        .await
        .unwrap();

        assert_eq!(retrieved_chain, cert_chain);
    }
}
