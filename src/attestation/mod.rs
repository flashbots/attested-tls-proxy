pub mod azure;
pub mod dcap;
pub mod measurements;

use measurements::Measurements;
use std::{
    fmt::{self, Display, Formatter},
    time::SystemTimeError,
};

use configfs_tsm::QuoteGenerationError;
use dcap_qvl::quote::Report;
use sha2::{Digest, Sha256};
use tdx_quote::QuoteParseError;
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

/// For fetching collateral directly from intel, if no PCCS is specified
const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Type of attestaion used
/// Only supported (or soon-to-be supported) types are given
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationType {
    /// No attestion
    None,
    /// Mock attestion
    Dummy,
    /// TDX on Google Cloud Platform
    GcpTdx,
    /// TDX on Azure, with MAA
    AzureTdx,
    /// TDX on Qemu (no cloud platform)
    QemuTdx,
}

impl AttestationType {
    /// Matches the names used by Constellation aTLS
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationType::None => "none",
            AttestationType::Dummy => "dummy",
            AttestationType::AzureTdx => "azure-tdx",
            AttestationType::QemuTdx => "qemu-tdx",
            AttestationType::GcpTdx => "gcp-tdx",
        }
    }
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Defines how to generate an attestation
pub trait QuoteGenerator: Clone + Send + 'static {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType;

    /// Generate an attestation
    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> impl Future<Output = Result<Vec<u8>, AttestationError>> + Send;
}

/// Defines how to verify a quote
pub trait QuoteVerifier: Clone + Send + 'static {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType;

    /// Verify the given attestation payload
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> impl Future<Output = Result<Option<Measurements>, AttestationError>> + Send;
}

/// Given a [Report] get the input data regardless of report type
fn get_quote_input_data(report: Report) -> [u8; 64] {
    match report {
        Report::TD10(r) => r.report_data,
        Report::TD15(r) => r.base.report_data,
        Report::SgxEnclave(r) => r.report_data,
    }
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

/// For no CVM platform (eg: for one-sided remote-attested TLS)
#[derive(Clone)]
pub struct NoQuoteGenerator;

impl QuoteGenerator for NoQuoteGenerator {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        AttestationType::None
    }

    /// Create an empty attestation
    async fn create_attestation(
        &self,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        Ok(Vec::new())
    }
}

/// For no CVM platform (eg: for one-sided remote-attested TLS)
#[derive(Clone)]
pub struct NoQuoteVerifier;

impl QuoteVerifier for NoQuoteVerifier {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        AttestationType::None
    }

    /// Ensure that an empty attestation is given
    async fn verify_attestation(
        &self,
        input: Vec<u8>,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Result<Option<Measurements>, AttestationError> {
        if input.is_empty() {
            Ok(None)
        } else {
            Err(AttestationError::AttestationGivenWhenNoneExpected)
        }
    }
}

/// Create a mock quote for testing on non-confidential hardware
#[cfg(test)]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    let attestation_key = tdx_quote::SigningKey::random(&mut rand_core::OsRng);
    let provisioning_certification_key = tdx_quote::SigningKey::random(&mut rand_core::OsRng);
    Ok(tdx_quote::Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        input,
        b"Mock cert chain".to_vec(),
    )
    .as_bytes())
}

/// Create a quote
#[cfg(not(test))]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    configfs_tsm::create_quote(input)
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
    #[error("Configfs-tsm quote generation: {0}")]
    QuoteGeneration(#[from] configfs_tsm::QuoteGenerationError),
    #[error("SGX quote given when TDX quote expected")]
    SgxNotSupported,
    #[error("Platform measurements do not match any accepted values")]
    UnacceptablePlatformMeasurements,
    #[error("OS image measurements do not match any accepted values")]
    UnacceptableOsImageMeasurements,
    #[error("System Time: {0}")]
    SystemTime(#[from] SystemTimeError),
    #[error("DCAP quote verification: {0}")]
    DcapQvl(#[from] anyhow::Error),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] QuoteParseError),
}
