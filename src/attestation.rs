use crate::AttestationError;
use sha2::{Digest, Sha256};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

pub trait AttestationPlatform: Clone + Send + 'static {
    fn create_attestation(&self, cert_chain: &[CertificateDer<'_>], exporter: [u8; 32]) -> Vec<u8>;

    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> bool;
}

#[derive(Clone)]
pub struct MockAttestation;

impl AttestationPlatform for MockAttestation {
    /// Mocks creating an attestation
    fn create_attestation(&self, cert_chain: &[CertificateDer<'_>], exporter: [u8; 32]) -> Vec<u8> {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain).unwrap();
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);
        quote_input.to_vec()
    }

    /// Mocks verifying an attestation
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> bool {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain).unwrap();
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);

        input == quote_input
    }
}

#[derive(Clone)]
pub struct NoAttestation;

impl AttestationPlatform for NoAttestation {
    /// Mocks creating an attestation
    fn create_attestation(
        &self,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Vec<u8> {
        Vec::new()
    }

    /// Mocks verifying an attestation
    fn verify_attestation(
        &self,
        _input: Vec<u8>,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> bool {
        true
    }
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
