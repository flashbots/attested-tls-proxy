pub mod azure;
pub mod dcap;
pub mod measurements;
pub mod nv_index;

use measurements::{MeasurementRecord, Measurements};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    time::SystemTimeError,
};

use sha2::{Digest, Sha256};
use tdx_quote::QuoteParseError;
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::prelude::*;

/// This is the type sent over the channel to provide an attestation
#[derive(Debug, Serialize, Deserialize, Encode, Decode)]
pub struct AttesationPayload {
    /// What CVM platform is used (including none)
    pub attestation_type: AttestationType,
    /// The attestation evidence as bytes - in the case of DCAP this is a quote
    pub attestation: Vec<u8>,
}

impl AttesationPayload {
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

/// Can generate a local attestation based on attestation type
#[derive(Clone)]
pub struct AttestationGenerator {
    pub attestation_type: AttestationType,
}

impl AttestationGenerator {
    /// Generate an attestation exchange message
    pub async fn generate_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<AttesationPayload, AttestationError> {
        Ok(AttesationPayload {
            attestation_type: self.attestation_type,
            attestation: self
                .generate_attestation_bytes(cert_chain, exporter)
                .await?,
        })
    }

    /// Generate attestation evidence bytes based on attestation type
    async fn generate_attestation_bytes(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        match self.attestation_type {
            AttestationType::None => Ok(Vec::new()),
            AttestationType::AzureTdx => {
                Ok(azure::create_azure_attestation(cert_chain, exporter).await?)
            }
            AttestationType::Dummy => Err(AttestationError::AttestationTypeNotSupported),
            _ => dcap::create_dcap_attestation(cert_chain, exporter).await,
        }
    }
}

/// Allows remote attestations to be verified
#[derive(Clone, Debug)]
pub struct AttestationVerifier {
    /// The measurement values we accept
    ///
    /// If this is empty, anything will be accepted - but measurements are always injected into HTTP
    /// headers, so that they can be verified upstream
    pub accepted_measurements: Vec<MeasurementRecord>,
    /// A PCCS service to use - defaults to Intel PCS
    pub pccs_url: Option<String>,
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
                    platform: measurements::PlatformMeasurements {
                        mrtd: [0; 48],
                        rtmr0: [0; 48],
                    },
                    cvm_image: measurements::CvmImageMeasurements {
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
        attestation_payload: AttesationPayload,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Option<Measurements>, AttestationError> {
        let attestation_type = attestation_payload.attestation_type;

        let measurements = match attestation_type {
            AttestationType::None => {
                if self.has_remote_attestion() {
                    return Err(AttestationError::AttestationTypeNotAccepted);
                }
                if attestation_payload.attestation.is_empty() {
                    return Ok(None);
                } else {
                    return Err(AttestationError::AttestationGivenWhenNoneExpected);
                }
            }
            AttestationType::AzureTdx => {
                azure::verify_azure_attestation(
                    attestation_payload.attestation,
                    cert_chain,
                    exporter,
                    self.pccs_url.clone(),
                )
                .await?
            }
            AttestationType::Dummy => {
                return Err(AttestationError::AttestationTypeNotSupported);
            }
            _ => {
                dcap::verify_dcap_attestation(
                    attestation_payload.attestation,
                    cert_chain,
                    exporter,
                    self.pccs_url.clone(),
                )
                .await?
            }
        };

        // look through all our accepted measurements
        self.accepted_measurements
            .iter()
            .find(|a| a.attestation_type == attestation_type && a.measurements == measurements)
            .ok_or(AttestationError::MeasurementsNotAccepted)?;

        Ok(Some(measurements))
    }

    /// Whether we allow no remote attestation
    pub fn has_remote_attestion(&self) -> bool {
        !self.accepted_measurements.is_empty()
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
    #[error("Attestation type not accepted")]
    AttestationTypeNotAccepted,
    #[error("Measurements not accepted")]
    MeasurementsNotAccepted,
    #[error("MAA: {0}")]
    Maa(#[from] azure::MaaError),
}
