pub mod measurements;

use measurements::{CvmImageMeasurements, MeasurementRecord, Measurements, PlatformMeasurements};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
    time::SystemTimeError,
};

use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
};
use sha2::{Digest, Sha256};
use tdx_quote::QuoteParseError;
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

/// For fetching collateral directly from intel, if no PCCS is specified
const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// This is the type sent over the channel to provide an attestation
#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationExchangeMessage {
    /// What CVM platform is used (including none)
    pub attestation_type: AttestationType,
    /// The attestation evidence as bytes - in the case of DCAP this is a quote
    pub attestation: Vec<u8>,
}

impl AttestationExchangeMessage {
    /// Given an attestation generator (quote generation function for a specific platform)
    /// return an attestation
    /// This also takes the certificate chain and exporter as they are given as input to the attestation
    pub fn from_attestation_generator(
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
        attesation_generator: Arc<dyn QuoteGenerator>,
    ) -> Result<Self, AttestationError> {
        Ok(Self {
            attestation_type: attesation_generator.attestation_type(),
            attestation: attesation_generator.create_attestation(cert_chain, exporter)?,
        })
    }

    /// Create an empty attestation payload for the case that we are running in a non-confidential
    /// environment
    pub fn without_attestation() -> Self {
        Self {
            attestation_type: AttestationType::None,
            attestation: Vec::new(),
        }
    }
}

/// Type of attestaion used
/// Only supported (or soon-to-be supported) types are given
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    /// No attestion
    None,
    /// Forwards the attestaion to a remote service (for testing purposes)
    Dummy,
    /// TDX on Google Cloud Platform
    GcpTdx,
    /// TDX on Azure, with MAA
    AzureTdx,
    /// TDX on Qemu (no cloud platform)
    QemuTdx,
    /// DCAP TDX
    DcapTdx,
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
            AttestationType::DcapTdx => "dcap-tdx",
        }
    }

    /// Get a quote generator for this type of platform
    pub fn get_quote_generator(&self) -> Result<Arc<dyn QuoteGenerator>, AttestationError> {
        match self {
            AttestationType::None => Ok(Arc::new(NoQuoteGenerator)),
            AttestationType::AzureTdx => Err(AttestationError::AttestationTypeNotSupported),
            AttestationType::Dummy => Err(AttestationError::AttestationTypeNotSupported),
            _ => Ok(Arc::new(DcapTdxQuoteGenerator {
                attestation_type: *self,
            })),
        }
    }
}

/// SCALE encode (used over the wire)
impl Encode for AttestationType {
    fn encode(&self) -> Vec<u8> {
        self.as_str().encode()
    }
}

/// SCALE decode
impl Decode for AttestationType {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let s: String = String::decode(input)?;
        serde_json::from_str(&format!("\"{s}\"")).map_err(|_| "Failed to decode enum".into())
    }
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Defines how to generate a quote
pub trait QuoteGenerator: Send + Sync + 'static {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType;

    /// Generate an attestation
    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError>;
}

/// Allows remote attestations to be verified
#[derive(Clone, Debug)]
pub struct AttestationVerifier {
    /// The measurement values we accept
    ///
    /// If this is empty, anything will be accepted - but measurements are always injected into HTTP
    /// headers, so that they can be verified upstream
    accepted_measurements: Vec<MeasurementRecord>,
    /// A PCCS service to use - defaults to Intel PCS
    pccs_url: Option<String>,
}

impl AttestationVerifier {
    /// Create an [AttestationVerifier] which will allow no remote attestation
    pub fn do_not_verify() -> Self {
        Self {
            accepted_measurements: Vec::new(),
            pccs_url: None,
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            accepted_measurements: vec![MeasurementRecord {
                attestation_type: AttestationType::DcapTdx,
                measurement_id: "test".to_string(),
                measurements: Measurements {
                    platform: PlatformMeasurements {
                        mrtd: [0; 48],
                        rtmr0: [0; 48],
                    },
                    cvm_image: CvmImageMeasurements {
                        rtmr1: [0; 48],
                        rtmr2: [0; 48],
                        rtmr3: [0; 48],
                    },
                },
            }],
            pccs_url: None,
        }
    }

    /// Verify an attestation, and ensure the measurements match one of our accepted measurements
    pub async fn verify_attestation(
        &self,
        attestation_exchange_message: AttestationExchangeMessage,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Option<Measurements>, AttestationError> {
        let attestation_type = attestation_exchange_message.attestation_type;

        let measurements = match attestation_type {
            AttestationType::DcapTdx => {
                verify_dcap_attestation(
                    attestation_exchange_message.attestation,
                    cert_chain,
                    exporter,
                    self.pccs_url.clone(),
                )
                .await?
            }
            AttestationType::None => {
                if attestation_exchange_message.attestation.is_empty() {
                    return Ok(None);
                } else {
                    return Err(AttestationError::AttestationGivenWhenNoneExpected);
                }
            }
            _ => {
                return Err(AttestationError::AttestationTypeNotSupported);
            }
        };

        // look through all our accepted measurements
        self.accepted_measurements
            .iter()
            .find(|a| a.attestation_type == attestation_type && a.measurements == measurements);

        Ok(Some(measurements))
    }

    /// Whether we allow no remote attestation
    pub fn has_remote_attestion(&self) -> bool {
        !self.accepted_measurements.is_empty()
    }
}

/// Quote generation using configfs_tsm
#[derive(Clone)]
pub struct DcapTdxQuoteGenerator {
    pub attestation_type: AttestationType,
}

impl QuoteGenerator for DcapTdxQuoteGenerator {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        self.attestation_type
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

/// Verify DCAP TDX quotes, allowing them if they have one of a given set of platform-specific and
/// OS image specific measurements
async fn verify_dcap_attestation(
    input: Vec<u8>,
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
    pccs_url: Option<String>,
) -> Result<Measurements, AttestationError> {
    let quote_input = compute_report_input(cert_chain, exporter)?;
    let (platform_measurements, image_measurements) = if cfg!(not(test)) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let quote = Quote::parse(&input)?;

        let ca = quote.ca()?;
        let fmspc = hex::encode_upper(quote.fmspc()?);
        let collateral = get_collateral_for_fmspc(
            &pccs_url.clone().unwrap_or(PCS_URL.to_string()),
            fmspc,
            ca,
            false, // Indicates not SGX
        )
        .await?;

        let _verified_report = dcap_qvl::verify::verify(&input, &collateral, now)?;

        let measurements = (
            PlatformMeasurements::from_dcap_qvl_quote(&quote)?,
            CvmImageMeasurements::from_dcap_qvl_quote(&quote)?,
        );
        if get_quote_input_data(quote.report) != quote_input {
            return Err(AttestationError::InputMismatch);
        }
        measurements
    } else {
        // In tests we use mock quotes which will fail to verify
        let quote = tdx_quote::Quote::from_bytes(&input)?;
        if quote.report_input_data() != quote_input {
            return Err(AttestationError::InputMismatch);
        }

        (
            PlatformMeasurements::from_tdx_quote(&quote),
            CvmImageMeasurements::from_tdx_quote(&quote),
        )
    };

    Ok(Measurements {
        platform: platform_measurements,
        cvm_image: image_measurements,
    })
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
    fn create_attestation(
        &self,
        _cert_chain: &[CertificateDer<'_>],
        _exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        Ok(Vec::new())
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
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
}
