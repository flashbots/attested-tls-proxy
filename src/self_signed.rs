use rcgen::generate_simple_self_signed;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    crypto::CryptoProvider,
    pki_types::{self, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use x509_parser::prelude::{FromDer, X509Certificate};

pub fn generate_self_signed_cert(
    subject_alt_names: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), rcgen::Error> {
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![subject_alt_names.to_string()])?;

    Ok((
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    ))
}

#[derive(Debug)]
pub struct SkipServerVerification {
    verify_hostname: String,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl SkipServerVerification {
    pub fn new(verify_hostname: &str) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            verify_hostname: verify_hostname.to_string(),
            supported_algs: Arc::new(CryptoProvider::get_default().unwrap())
                .clone()
                .signature_verification_algorithms,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if server_name.to_str() != self.verify_hostname {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }

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
        attested_tls::{AttestedTlsClient, AttestedTlsServer, SUPPORTED_ALPN_PROTOCOL_VERSIONS},
        AttestationGenerator,
    };
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn self_signed_server_attestation() {
        let (cert_chain, private_key) = generate_self_signed_cert("127.0.0.1").unwrap();

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain.clone().to_vec(), private_key.clone_key())
            .unwrap();

        let supported_protocols: Vec<_> = SUPPORTED_ALPN_PROTOCOL_VERSIONS
            .into_iter()
            .map(|p| p.to_vec())
            .collect();

        server_config.alpn_protocols = supported_protocols.clone();

        let server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config.into(),
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
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

        let mut client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new("127.0.0.1"))
            .with_no_client_auth();

        client_config.alpn_protocols = supported_protocols.clone();

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
}
