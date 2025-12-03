pub mod dcap;
pub mod measurements;

use measurements::Measurements;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use tdx_quote::QuoteParseError;
use thiserror::Error;

use crate::attestation::measurements::MeasurementPolicy;

/// This is the type sent over the channel to provide an attestation
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct AttestationExchangeMessage {
    /// What CVM platform is used (including none)
    pub attestation_type: AttestationType,
    /// The attestation evidence as bytes - in the case of DCAP this is a quote
    pub attestation: Vec<u8>,
}

impl AttestationExchangeMessage {
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
    dummy_dcap_url: Option<String>,
}

impl AttestationGenerator {
    pub fn new(
        attestation_type: AttestationType,
        dummy_dcap_url: Option<String>,
    ) -> Result<Self, AttestationError> {
        match attestation_type {
            AttestationType::Dummy => Self::new_dummy(dummy_dcap_url),
            _ => Self::new_not_dummy(attestation_type),
        }
    }

    pub fn with_no_attestation() -> Self {
        Self {
            attestation_type: AttestationType::None,
            dummy_dcap_url: None,
        }
    }

    pub fn new_not_dummy(attestation_type: AttestationType) -> Result<Self, AttestationError> {
        if attestation_type == AttestationType::Dummy {
            return Err(AttestationError::DummyUrl);
        }

        Ok(Self {
            attestation_type,
            dummy_dcap_url: None,
        })
    }

    pub fn new_dummy(dummy_dcap_url: Option<String>) -> Result<Self, AttestationError> {
        match dummy_dcap_url {
            Some(url) => {
                let url = if url.starts_with("http://") || url.starts_with("https://") {
                    url.to_string()
                } else {
                    format!("http://{}", url.trim_start_matches("http://"))
                };

                let url = url.strip_suffix('/').unwrap_or(&url).to_string();

                Ok(Self {
                    attestation_type: AttestationType::Dummy,
                    dummy_dcap_url: Some(url),
                })
            }
            None => Err(AttestationError::DummyUrl),
        }
    }

    /// Generate an attestation exchange message
    pub async fn generate_attestation(
        &self,
        input_data: [u8; 64],
    ) -> Result<AttestationExchangeMessage, AttestationError> {
        Ok(AttestationExchangeMessage {
            attestation_type: self.attestation_type,
            attestation: self.generate_attestation_bytes(input_data).await?,
        })
    }

    /// Generate attestation evidence bytes based on attestation type
    async fn generate_attestation_bytes(
        &self,
        input_data: [u8; 64],
    ) -> Result<Vec<u8>, AttestationError> {
        match self.attestation_type {
            AttestationType::None => Ok(Vec::new()),
            AttestationType::AzureTdx => Err(AttestationError::AttestationTypeNotSupported),
            AttestationType::Dummy => self.generate_dummy_attestation(input_data).await,
            _ => dcap::create_dcap_attestation(input_data).await,
        }
    }

    async fn generate_dummy_attestation(
        &self,
        input_data: [u8; 64],
    ) -> Result<Vec<u8>, AttestationError> {
        let url = format!(
            "{}/attest/{}",
            self.dummy_dcap_url
                .clone()
                .ok_or(AttestationError::DummyUrl)?,
            hex::encode(input_data)
        );

        Ok(reqwest::get(url)
            .await
            .map_err(|err| AttestationError::DummyServer(err.to_string()))?
            .bytes()
            .await
            .map_err(|err| AttestationError::DummyServer(err.to_string()))?
            .to_vec())
    }
}

/// Allows remote attestations to be verified
#[derive(Clone, Debug)]
pub struct AttestationVerifier {
    /// The measurement policy with accepted values and attestation types
    pub measurement_policy: MeasurementPolicy,
    /// If this is empty, anything will be accepted - but measurements are always injected into HTTP
    /// headers, so that they can be verified upstream
    /// A PCCS service to use - defaults to Intel PCS
    pub pccs_url: Option<String>,
    /// Whether to log quotes to a file
    pub log_dcap_quote: bool,
}

impl AttestationVerifier {
    /// Create an [AttestationVerifier] which will allow no remote attestation
    pub fn expect_none() -> Self {
        Self {
            measurement_policy: MeasurementPolicy::expect_none(),
            pccs_url: None,
            log_dcap_quote: false,
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            measurement_policy: MeasurementPolicy::mock(),
            pccs_url: None,
            log_dcap_quote: false,
        }
    }

    /// Verify an attestation, and ensure the measurements match one of our accepted measurements
    pub async fn verify_attestation(
        &self,
        attestation_exchange_message: AttestationExchangeMessage,
        expected_input_data: [u8; 64],
    ) -> Result<Option<Measurements>, AttestationError> {
        let attestation_type = attestation_exchange_message.attestation_type;
        tracing::debug!("Verifing {attestation_type} attestation");

        if self.log_dcap_quote {
            log_attestation(&attestation_exchange_message).await;
        }

        let measurements = match attestation_type {
            AttestationType::None => {
                if self.has_remote_attestion() {
                    return Err(AttestationError::AttestationTypeNotAccepted);
                }
                if attestation_exchange_message.attestation.is_empty() {
                    return Ok(None);
                } else {
                    return Err(AttestationError::AttestationGivenWhenNoneExpected);
                }
            }
            AttestationType::AzureTdx => {
                return Err(AttestationError::AttestationTypeNotSupported);
            }
            AttestationType::Dummy => {
                // Dummy assumes dummy DCAP
                dcap::verify_dcap_attestation(
                    attestation_exchange_message.attestation,
                    expected_input_data,
                    self.pccs_url.clone(),
                )
                .await?
            }
            _ => {
                dcap::verify_dcap_attestation(
                    attestation_exchange_message.attestation,
                    expected_input_data,
                    self.pccs_url.clone(),
                )
                .await?
            }
        };

        // Do a measurement / attestation type policy check
        self.measurement_policy
            .check_measurement(attestation_type, &measurements)?;

        tracing::debug!("Verification successful");
        Ok(Some(measurements))
    }

    /// Whether we allow no remote attestation
    pub fn has_remote_attestion(&self) -> bool {
        self.measurement_policy.has_remote_attestion()
    }
}

/// Write attestation data to a log file
async fn log_attestation(attestation: &AttestationExchangeMessage) {
    if attestation.attestation_type != AttestationType::None {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos();

        let filename = format!("quotes/{}-{}", attestation.attestation_type, timestamp);
        if let Err(err) = tokio::fs::write(&filename, attestation.attestation.clone()).await {
            tracing::warn!("Failed to write {filename}: {err}");
        }
    }
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
    #[error("Dummy attestation type requires dummy service URL")]
    DummyUrl,
    #[error("Dummy server: {0}")]
    DummyServer(String),
}
