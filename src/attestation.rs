use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

/// Represents a CVM technology with quote generation and verification
pub trait AttestationPlatform: Clone + Send + 'static {
    /// Whether this is CVM attestation. This should always return true except for the [NoAttestation] case.
    ///
    /// When false, allows TLS client to be configured without client authentication
    fn is_cvm(&self) -> bool;

    /// Generate an attestation
    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError>;

    /// Verify the given attestation payload
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<(), AttestationError>;
}

/// For testing
#[derive(Clone)]
pub struct MockAttestation;

impl AttestationPlatform for MockAttestation {
    fn is_cvm(&self) -> bool {
        true
    }

    /// Mocks creating an attestation
    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain)?;
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);
        Ok(quote_input.to_vec())
    }

    /// Mocks verifying an attestation
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<(), AttestationError> {
        let mut quote_input = [0u8; 64];
        let pki_hash = get_pki_hash_from_certificate_chain(cert_chain)?;
        quote_input[..32].copy_from_slice(&pki_hash);
        quote_input[32..].copy_from_slice(&exporter);

        if input != quote_input {
            return Err(AttestationError::InputMismatch);
        }
        Ok(())
    }
}

/// For no CVM platform (eg: for one-sided remote-attested TLS)
#[derive(Clone)]
pub struct NoAttestation;

impl AttestationPlatform for NoAttestation {
    fn is_cvm(&self) -> bool {
        false
    }

    /// Create an empty attestation
    fn create_attestation(
        &self,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        Ok(Vec::new())
    }

    /// Ensure that an empty attestation is given
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Result<(), AttestationError> {
        if input.is_empty() {
            Ok(())
        } else {
            Err(AttestationError::AttestationGivenWhenNoneExpected)
        }
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

/// An error when generating or verifying an attestation
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Certificate chain is empty")]
    NoCertificate,
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("Quote input is not as expected")]
    InputMismatch,
    #[error("Configuration mismatch - expected no remote attestation")]
    AttestationGivenWhenNoneExpected,
}
