use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

const PCS_URL: &str = "https://api.trustedservices.intel.com";

pub trait QuoteGenerator: Clone + Send + 'static {
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
}

pub trait QuoteVerifier: Clone + Send + 'static {
    /// Whether this is CVM attestation. This should always return true except for the [NoAttestation] case.
    ///
    /// When false, allows TLS client to be configured without client authentication
    fn is_cvm(&self) -> bool;

    /// Verify the given attestation payload
    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> impl Future<Output = Result<(), AttestationError>> + Send;
}

// /// Represents a CVM technology with quote generation and verification
// pub trait AttestationPlatform: Clone + Send + 'static {
//     /// Whether this is CVM attestation. This should always return true except for the [NoAttestation] case.
//     ///
//     /// When false, allows TLS client to be configured without client authentication
//     fn is_cvm(&self) -> bool;
//
//     /// Generate an attestation
//     fn create_attestation(
//         &self,
//         cert_chain: &[CertificateDer<'_>],
//         exporter: [u8; 32],
//     ) -> Result<Vec<u8>, AttestationError>;
//
//     /// Verify the given attestation payload
//     fn verify_attestation(
//         &self,
//         input: Vec<u8>,
//         cert_chain: &[CertificateDer<'_>],
//         exporter: [u8; 32],
//     ) -> impl Future<Output = Result<(), AttestationError>> + Send;
// }

#[derive(Clone)]
pub struct DcapTdxQuoteGenerator;

impl QuoteGenerator for DcapTdxQuoteGenerator {
    fn is_cvm(&self) -> bool {
        true
    }

    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        let quote_input = compute_report_input(cert_chain, exporter)?;

        Ok(generate_quote(quote_input)?)
    }
}

#[derive(Clone)]
pub struct DcapTdxQuoteVerifier;

impl QuoteVerifier for DcapTdxQuoteVerifier {
    fn is_cvm(&self) -> bool {
        true
    }

    fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> impl Future<Output = Result<(), AttestationError>> + Send {
        async move {
            let quote_input = compute_report_input(cert_chain, exporter)?;
            // In tests we use mock quotes which will fail to verify
            if cfg!(not(test)) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let quote = Quote::parse(&input).unwrap();
                let ca = quote.ca().unwrap();
                let fmspc = hex::encode_upper(quote.fmspc().unwrap());
                let collateral = get_collateral_for_fmspc(PCS_URL, fmspc, ca, false)
                    .await
                    .unwrap();
                let _verified_report = dcap_qvl::verify::verify(&input, &collateral, now).unwrap();

                let quote = Quote::parse(&input).unwrap();
                if get_quote_input_data(quote.report) != quote_input {
                    return Err(AttestationError::InputMismatch);
                }
            } else {
                let quote = tdx_quote::Quote::from_bytes(&input).unwrap();
                if quote.report_input_data() != quote_input {
                    return Err(AttestationError::InputMismatch);
                }
            }

            Ok(())
        }
    }
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
}

/// For no CVM platform (eg: for one-sided remote-attested TLS)
#[derive(Clone)]
pub struct NoQuoteVerifier;

impl QuoteVerifier for NoQuoteVerifier {
    fn is_cvm(&self) -> bool {
        false
    }
    /// Ensure that an empty attestation is given
    async fn verify_attestation(
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
}
