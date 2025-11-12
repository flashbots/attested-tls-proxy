use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    time::SystemTimeError,
};

use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
};
use http::{header::InvalidHeaderValue, HeaderValue};
use sha2::{Digest, Sha256};
use tdx_quote::QuoteParseError;
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

/// For fetching collateral directly from intel, if no PCCS is specified
const PCS_URL: &str = "https://api.trustedservices.intel.com";

#[derive(Debug, Clone, PartialEq)]
pub struct Measurements {
    pub platform: PlatformMeasurements,
    pub cvm_image: CvmImageMeasurements,
}

impl Measurements {
    pub fn to_header_format(&self) -> Result<HeaderValue, MeasurementFormatError> {
        let mut measurements_map = HashMap::new();
        measurements_map.insert(0, hex::encode(self.platform.mrtd));
        measurements_map.insert(1, hex::encode(self.platform.rtmr0));
        measurements_map.insert(2, hex::encode(self.cvm_image.rtmr1));
        measurements_map.insert(3, hex::encode(self.cvm_image.rtmr2));
        measurements_map.insert(4, hex::encode(self.cvm_image.rtmr3));
        Ok(HeaderValue::from_str(&serde_json::to_string(
            &measurements_map,
        )?)?)
    }

    pub fn from_header_format(input: &str) -> Result<Self, MeasurementFormatError> {
        let measurements_map: HashMap<u32, String> = serde_json::from_str(input)?;
        let measurements_map: HashMap<u32, [u8; 48]> = measurements_map
            .into_iter()
            .map(|(k, v)| (k, hex::decode(v).unwrap().try_into().unwrap()))
            .collect();

        Ok(Self {
            platform: PlatformMeasurements {
                mrtd: *measurements_map
                    .get(&0)
                    .ok_or(MeasurementFormatError::MissingValue("MRTD".to_string()))?,
                rtmr0: *measurements_map
                    .get(&1)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR0".to_string()))?,
            },
            cvm_image: CvmImageMeasurements {
                rtmr1: *measurements_map
                    .get(&2)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR1".to_string()))?,
                rtmr2: *measurements_map
                    .get(&3)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR2".to_string()))?,
                rtmr3: *measurements_map
                    .get(&4)
                    .ok_or(MeasurementFormatError::MissingValue("RTMR3".to_string()))?,
            },
        })
    }
}

#[derive(Error, Debug)]
pub enum MeasurementFormatError {
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Missing value: {0}")]
    MissingValue(String),
    #[error("Invalid header value: {0}")]
    BadHeaderValue(#[from] InvalidHeaderValue),
}

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

/// Defines how to generate a quote
pub trait QuoteGenerator: Clone + Send + 'static {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType;

    /// Generate an attestation
    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError>;
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

/// Measurements determined by the CVM platform
#[derive(Clone, PartialEq, Debug)]
pub struct PlatformMeasurements {
    pub mrtd: [u8; 48],
    pub rtmr0: [u8; 48],
}

impl PlatformMeasurements {
    fn from_dcap_qvl_quote(quote: &dcap_qvl::quote::Quote) -> Result<Self, AttestationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(AttestationError::SgxNotSupported);
            }
        };
        Ok(Self {
            mrtd: report.mr_td,
            rtmr0: report.rt_mr0,
        })
    }

    fn from_tdx_quote(quote: &tdx_quote::Quote) -> Self {
        Self {
            mrtd: quote.mrtd(),
            rtmr0: quote.rtmr0(),
        }
    }
}

/// Measurements determined by the CVM image
#[derive(Clone, PartialEq, Debug)]
pub struct CvmImageMeasurements {
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

impl CvmImageMeasurements {
    fn from_dcap_qvl_quote(quote: &dcap_qvl::quote::Quote) -> Result<Self, AttestationError> {
        let report = match quote.report {
            Report::TD10(report) => report,
            Report::TD15(report) => report.base,
            Report::SgxEnclave(_) => {
                return Err(AttestationError::SgxNotSupported);
            }
        };
        Ok(Self {
            rtmr1: report.rt_mr1,
            rtmr2: report.rt_mr2,
            rtmr3: report.rt_mr3,
        })
    }

    fn from_tdx_quote(quote: &tdx_quote::Quote) -> Self {
        Self {
            rtmr1: quote.rtmr1(),
            rtmr2: quote.rtmr2(),
            rtmr3: quote.rtmr3(),
        }
    }
}

/// Verify DCAP TDX quotes, allowing them if they have one of a given set of platform-specific and
/// OS image specific measurements
#[derive(Clone)]
pub struct DcapTdxQuoteVerifier {
    pub attestation_type: AttestationType,
    /// Platform specific allowed Measurements
    /// Currently an option as this may be determined internally on a per-platform basis (Eg: GCP)
    pub accepted_platform_measurements: Option<Vec<PlatformMeasurements>>,
    /// OS-image specific allows measurement - this is effectively a list of allowed OS images
    pub accepted_cvm_image_measurements: Vec<CvmImageMeasurements>,
    /// URL of a PCCS (defaults to Intel PCS)
    pub pccs_url: Option<String>,
}

impl QuoteVerifier for DcapTdxQuoteVerifier {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        self.attestation_type
    }

    async fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Option<Measurements>, AttestationError> {
        let quote_input = compute_report_input(cert_chain, exporter)?;
        let (platform_measurements, image_measurements) = if cfg!(not(test)) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let quote = Quote::parse(&input)?;

            let ca = quote.ca()?;
            let fmspc = hex::encode_upper(quote.fmspc()?);
            let collateral = get_collateral_for_fmspc(
                &self.pccs_url.clone().unwrap_or(PCS_URL.to_string()),
                fmspc,
                ca,
                false,
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

        if let Some(accepted_platform_measurements) = &self.accepted_platform_measurements
            && !accepted_platform_measurements.contains(&platform_measurements)
        {
            return Err(AttestationError::UnacceptablePlatformMeasurements);
        }

        if !self
            .accepted_cvm_image_measurements
            .contains(&image_measurements)
        {
            return Err(AttestationError::UnacceptableOsImageMeasurements);
        }

        Ok(Some(Measurements {
            platform: platform_measurements,
            cvm_image: image_measurements,
        }))
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
