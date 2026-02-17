use std::{net::IpAddr, sync::Arc};
use tokio_rustls::rustls::{
    self,
    crypto::CryptoProvider,
    pki_types::{self, CertificateDer, PrivatePkcs8KeyDer},
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::attested_tls::{AttestedTlsError, TlsCertAndKey};

/// Generate a self signed certifcate
pub fn generate_self_signed_cert(ip_address: IpAddr) -> Result<TlsCertAndKey, rcgen::Error> {
    let keypair = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(ip_address));

    let cert = params.self_signed(&keypair)?;
    Ok(TlsCertAndKey {
        cert_chain: vec![cert.der().clone()],
        key: PrivatePkcs8KeyDer::from(keypair.serialize_der()).into(),
    })
}

/// Client TLS configuration which accepts self-signed remote certificates
pub fn client_tls_config_allow_self_signed() -> Result<rustls::ClientConfig, AttestedTlsError> {
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new()?)
        .with_no_client_auth())
}

/// Used to allow verification of self-signed certificates
#[derive(Debug, Clone)]
pub struct SkipServerVerification {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    pub fn new() -> Result<Arc<Self>, AttestedTlsError> {
        Ok(Arc::new(Self {
            supported_algs: Arc::new(
                CryptoProvider::get_default().ok_or(AttestedTlsError::NoCryptoProvider)?,
            )
            .clone()
            .signature_verification_algorithms,
        }))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Verify signature
        cert.verify_signature(None).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        })?;

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("No crypto provider installed".into()))?;

        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("No crypto provider installed".into()))?;

        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Used to allow verification of self-signed certificates during client authentication
#[derive(Debug)]
pub struct SkipClientVerification {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipClientVerification {
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            supported_algs: Arc::new(CryptoProvider::get_default().unwrap())
                .clone()
                .signature_verification_algorithms,
        })
    }
}

impl rustls::server::danger::ClientCertVerifier for SkipClientVerification {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Verify signature
        cert.verify_signature(None).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        })?;
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("No crypto provider installed".into()))?;

        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .ok_or_else(|| rustls::Error::General("No crypto provider installed".into()))?;

        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )?;

        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestation::{AttestationType, AttestationVerifier},
        attested_tls::{AttestedTlsClient, AttestedTlsServer},
        test_helpers::{generate_certificate_chain, generate_tls_config},
        AttestationGenerator,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::ServerName;

    #[tokio::test]
    async fn self_signed_server_attestation() {
        let cert_and_key = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                cert_and_key.cert_chain.clone().to_vec(),
                cert_and_key.key.clone_key(),
            )
            .unwrap();

        let server = AttestedTlsServer::new_with_tls_config(
            cert_and_key.cert_chain,
            server_config.into(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            let (_stream, _measurements, _attestation_type) =
                server.handle_connection(tcp_stream).await.unwrap();
        });

        let client_config = client_tls_config_allow_self_signed().unwrap();

        let client = AttestedTlsClient::new_with_tls_config(
            client_config.into(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let (_stream, _measurements, _attestation_type) =
            client.connect_tcp(&server_addr.to_string()).await.unwrap();
    }

    #[tokio::test]
    async fn nested_tls_with_self_signed_server_attestation() {
        // Outer TLS setup
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (outer_server_config, outer_client_config) =
            generate_tls_config(cert_chain.clone(), private_key);

        let outer_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(outer_server_config));
        let outer_connector = tokio_rustls::TlsConnector::from(Arc::new(outer_client_config));

        // Inner TLS setup
        let cert_and_key = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                cert_and_key.cert_chain.clone().to_vec(),
                cert_and_key.key.clone_key(),
            )
            .unwrap();

        let server = AttestedTlsServer::new_with_tls_config(
            cert_and_key.cert_chain,
            server_config.into(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();

            // Do outer TLS handshake
            let tls_stream = outer_acceptor.accept(tcp_stream).await.unwrap();

            // Do inner (attested) TLS
            let (_stream, _measurements, _attestation_type) =
                server.handle_connection(tls_stream).await.unwrap();
        });

        // Inner TLS config
        let client_config = client_tls_config_allow_self_signed().unwrap();

        let client = AttestedTlsClient::new_with_tls_config(
            client_config.into(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let client_tcp_stream = tokio::net::TcpStream::connect(&server_addr).await.unwrap();

        // Outer TLS handshake
        let server_name = ServerName::try_from(server_addr.ip().to_string()).unwrap();
        let tls_stream = outer_connector
            .connect(server_name, client_tcp_stream)
            .await
            .unwrap();

        // Inner (attested) TLS
        let (_stream, _measurements, _attestation_type) = client
            .connect(&server_addr.to_string(), tls_stream)
            .await
            .unwrap();
    }
}
