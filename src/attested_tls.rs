use crate::{
    attestation::{
        measurements::MultiMeasurements, AttestationError, AttestationExchangeMessage,
        AttestationGenerator, AttestationType, AttestationVerifier,
    },
    host_to_host_with_port,
};
use parity_scale_codec::{Decode, Encode};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use x509_parser::parse_x509_certificate;

use std::num::TryFromIntError;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{
    rustls::{ClientConfig, ServerConfig},
    TlsAcceptor, TlsConnector,
};

/// This makes it possible to add breaking protocol changes and provide backwards compatibility.
/// When adding more supported versions, note that ordering is important. ALPN will pick the first
/// protocol which both parties support - so newer supported versions should come first.
pub const SUPPORTED_ALPN_PROTOCOL_VERSIONS: [&[u8]; 1] = [b"flashbots-ratls/1"];

/// The label used when exporting key material from a TLS session
pub(crate) const EXPORTER_LABEL: &[u8; 24] = b"EXPORTER-Channel-Binding";

/// TLS Credentials
pub struct TlsCertAndKey {
    /// Der-encoded TLS certificate chain
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// Der-encoded TLS private key
    pub key: PrivateKeyDer<'static>,
}

/// A TLS server which makes an attestation exchange following the TLS handshake
#[derive(Clone)]
pub struct AttestedTlsServer {
    /// Quote generation type to use (including none)
    attestation_generator: AttestationGenerator,
    /// Verifier for remote attestation (including none)
    attestation_verifier: AttestationVerifier,
    /// The TLS certificate chain
    cert_chain: Vec<CertificateDer<'static>>,
    /// For accepting TLS connections
    acceptor: TlsAcceptor,
}

impl AttestedTlsServer {
    pub async fn new(
        cert_and_key: TlsCertAndKey,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        client_auth: bool,
    ) -> Result<Self, AttestedTlsError> {
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
            attestation_generator,
            attestation_verifier,
        )
        .await
    }

    /// Start with preconfigured TLS
    ///
    /// This is not fully public as it allows dangerous configuration
    pub(crate) async fn new_with_tls_config(
        cert_chain: Vec<CertificateDer<'static>>,
        server_config: Arc<ServerConfig>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
    ) -> Result<Self, AttestedTlsError> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        Ok(Self {
            attestation_generator,
            attestation_verifier,
            acceptor,
            cert_chain,
        })
    }

    /// Handle an incoming connection from a proxy-client
    ///
    /// This is transport agnostic and will work with any asynchronous stream
    pub async fn handle_connection<IO>(
        &self,
        inbound: IO,
    ) -> Result<
        (
            tokio_rustls::server::TlsStream<IO>,
            Option<MultiMeasurements>,
            AttestationType,
        ),
        AttestedTlsError,
    >
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        tracing::debug!("attested-tls-server accepted connection");

        // Do TLS handshake
        let mut tls_stream = self.acceptor.accept(inbound).await?;
        let (_io, connection) = tls_stream.get_ref();

        // Ensure that we agreed a protocol
        let _negotiated_protocol = connection
            .alpn_protocol()
            .ok_or(AttestedTlsError::AlpnFailed)?;

        // Compute an exporter unique to the session
        let mut exporter = [0u8; 32];
        connection.export_keying_material(
            &mut exporter,
            EXPORTER_LABEL,
            None, // context
        )?;

        let input_data = compute_report_input(Some(&self.cert_chain), exporter)?;

        // Get the TLS certficate chain of the client, if there is one
        let remote_cert_chain = connection.peer_certificates().map(|c| c.to_owned());

        // If we are in a CVM, generate an attestation
        let attestation = self
            .attestation_generator
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
        let measurements = if self.attestation_verifier.has_remote_attestion() {
            let remote_input_data = compute_report_input(remote_cert_chain.as_deref(), exporter)?;

            self.attestation_verifier
                .verify_attestation(remote_attestation_message, remote_input_data)
                .await?
        } else {
            None
        };

        Ok((tls_stream, measurements, remote_attestation_type))
    }
}

/// A proxy client which forwards http traffic to a proxy-server
#[derive(Clone)]
pub struct AttestedTlsClient {
    /// The connector for making TLS connections with out configuration
    connector: TlsConnector,
    /// Quote generation type to use (including none)
    attestation_generator: AttestationGenerator,
    /// Verifier for remote attestation (including none)
    attestation_verifier: AttestationVerifier,
    /// The certificate chain for client auth
    cert_chain: Option<Vec<CertificateDer<'static>>>,
}

impl std::fmt::Debug for AttestedTlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestedTlsClient")
            .field("attestation_verifier", &self.attestation_verifier)
            .field("attestation_generator", &self.attestation_generator)
            .field("cert_chain", &self.cert_chain)
            .finish()
    }
}

impl AttestedTlsClient {
    /// Start with optional TLS client auth
    pub async fn new(
        cert_and_key: Option<TlsCertAndKey>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        remote_certificate: Option<CertificateDer<'static>>,
    ) -> Result<Self, AttestedTlsError> {
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
            attestation_generator,
            attestation_verifier,
            cert_and_key.map(|c| c.cert_chain),
        )
        .await
    }

    /// Create a new proxy client with given TLS configuration
    ///
    /// This not fully public as it allows dangerous configuration but is used in tests
    pub(crate) async fn new_with_tls_config(
        client_config: Arc<ClientConfig>,
        attestation_generator: AttestationGenerator,
        attestation_verifier: AttestationVerifier,
        cert_chain: Option<Vec<CertificateDer<'static>>>,
    ) -> Result<Self, AttestedTlsError> {
        let connector = TlsConnector::from(client_config.clone());

        Ok(Self {
            connector,
            attestation_generator,
            attestation_verifier,
            cert_chain,
        })
    }

    /// Given a connection to an attested TLS server, do a TLS handshake and attestation exchange, and return the TLS
    /// stream together with measurement details
    ///
    /// This is transport agnostic and will work with any asynchronous stream
    pub async fn connect<IO>(
        &self,
        target: &str,
        outbound: IO,
    ) -> Result<
        (
            tokio_rustls::client::TlsStream<IO>,
            Option<MultiMeasurements>,
            AttestationType,
        ),
        AttestedTlsError,
    >
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        // Make a TLS handshake with the given connection
        let mut tls_stream = self
            .connector
            .connect(server_name_from_host(target)?, outbound)
            .await?;

        let (_io, server_connection) = tls_stream.get_ref();

        // Ensure that we agreed a protocol
        let _negotiated_protocol = server_connection
            .alpn_protocol()
            .ok_or(AttestedTlsError::AlpnFailed)?;

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
            .ok_or(AttestedTlsError::NoCertificate)?
            .to_owned();

        let remote_input_data = compute_report_input(Some(&remote_cert_chain), exporter)?;

        // Read a length prefixed attestation from the proxy-server
        let mut length_bytes = [0; 4];
        tls_stream.read_exact(&mut length_bytes).await?;
        let length: usize = u32::from_be_bytes(length_bytes).try_into()?;

        let mut buf = vec![0; length];
        tls_stream.read_exact(&mut buf).await?;

        let remote_attestation_message = AttestationExchangeMessage::decode(&mut &buf[..])?;
        let remote_attestation_type = remote_attestation_message.attestation_type;

        // Verify the remote attestation against our accepted measurements
        let measurements = self
            .attestation_verifier
            .verify_attestation(remote_attestation_message, remote_input_data)
            .await?;

        // If we are in a CVM, provide an attestation
        let attestation = if self.attestation_generator.attestation_type != AttestationType::None {
            let local_input_data = compute_report_input(self.cert_chain.as_deref(), exporter)?;
            self.attestation_generator
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

        Ok((tls_stream, measurements, remote_attestation_type))
    }

    /// Make a TCP connection, do a TLS handshake and attestation exchange, and return the TLS
    /// stream together with measurement details
    pub async fn connect_tcp(
        &self,
        target: &str,
    ) -> Result<
        (
            tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
            Option<MultiMeasurements>,
            AttestationType,
        ),
        AttestedTlsError,
    > {
        let out = tokio::net::TcpStream::connect(&target).await?;
        self.connect(target, out).await
    }

    /// Connect to an attested TLS server using TCP, retrieve the remote TLS certificate and return it
    pub async fn get_tls_cert(
        &self,
        server_name: &str,
    ) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
        let (mut tls_stream, _, _) = self.connect_tcp(server_name).await?;

        let (_io, server_connection) = tls_stream.get_ref();

        let remote_cert_chain = server_connection
            .peer_certificates()
            .ok_or(AttestedTlsError::NoCertificate)?
            .to_owned();

        tls_stream.shutdown().await?;

        Ok(remote_cert_chain)
    }
}

/// A client which just gets the attested remote certificate, with no client authentication
pub async fn get_tls_cert(
    server_name: String,
    attestation_verifier: AttestationVerifier,
    remote_certificate: Option<CertificateDer<'static>>,
) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
    tracing::debug!("Getting remote TLS cert");
    let attested_tls_client = AttestedTlsClient::new(
        None,
        AttestationGenerator::with_no_attestation(),
        attestation_verifier,
        remote_certificate,
    )
    .await?;
    attested_tls_client
        .get_tls_cert(&host_to_host_with_port(&server_name))
        .await
}

/// Helper for testing getting remote certificate
#[cfg(test)]
pub(crate) async fn get_tls_cert_with_config(
    server_name: &str,
    attestation_verifier: AttestationVerifier,
    client_config: Arc<ClientConfig>,
) -> Result<Vec<CertificateDer<'static>>, AttestedTlsError> {
    let attested_tls_client = AttestedTlsClient::new_with_tls_config(
        client_config,
        AttestationGenerator::with_no_attestation(),
        attestation_verifier,
        None,
    )
    .await?;
    attested_tls_client.get_tls_cert(server_name).await
}

/// Given a certificate chain and an exporter (session key material), build the quote input value
/// SHA256(pki) || exporter
pub fn compute_report_input(
    cert_chain: Option<&[CertificateDer<'_>]>,
    exporter: [u8; 32],
) -> Result<[u8; 64], AttestationError> {
    let mut quote_input = [0u8; 64];
    if let Some(cert_chain) = cert_chain {
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain)?;
        quote_input[..32].copy_from_slice(&pki_hash);
    }
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

/// An error when running an attested TLS client or server
#[derive(Error, Debug)]
pub enum AttestedTlsError {
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
    #[error("Serialization: {0}")]
    Serialization(#[from] parity_scale_codec::Error),
    #[error("Protocol negotiation failed - remote peer does not support this protocol")]
    AlpnFailed,
}

/// Given a byte array, encode its length as a 4 byte big endian u32
fn length_prefix(input: &[u8]) -> [u8; 4] {
    let len = input.len() as u32;
    len.to_be_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::{generate_certificate_chain, generate_tls_config};

    #[tokio::test]
    async fn server_attestation() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let (_stream, _measurements, _attestation_type) = server.accept().await.unwrap();
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let (_stream, _measurements, _attestation_type) =
            client.connect(&server_addr.to_string()).await.unwrap();
    }
}
