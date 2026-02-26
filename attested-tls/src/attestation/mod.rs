//! CVM attestation generation and verification

#[cfg(feature = "azure")]
pub mod azure;
pub mod dcap;
pub mod measurements;
pub(crate) mod pccs;

use measurements::MultiMeasurements;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;

use crate::attestation::{
    dcap::DcapVerificationError, measurements::MeasurementPolicy, pccs::Pccs,
};

const GCP_METADATA_API: &str =
    "http://metadata.google.internal/computeMetadata/v1/project/project-id";

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
            AttestationType::AzureTdx => "azure-tdx",
            AttestationType::QemuTdx => "qemu-tdx",
            AttestationType::GcpTdx => "gcp-tdx",
            AttestationType::DcapTdx => "dcap-tdx",
        }
    }

    /// Detect what platform we are on by attempting an attestation
    pub async fn detect() -> Result<Self, AttestationError> {
        // First attempt azure, if the feature is present
        #[cfg(feature = "azure")]
        {
            if azure::create_azure_attestation([0; 64]).await.is_ok() {
                return Ok(AttestationType::AzureTdx);
            }
        }
        // Otherwise try DCAP quote - this internally checks that the quote provider is `tdx_guest`
        if configfs_tsm::create_tdx_quote([0; 64]).is_ok() {
            if running_on_gcp().await? {
                return Ok(AttestationType::GcpTdx);
            } else {
                return Ok(AttestationType::DcapTdx);
            }
        }
        Ok(AttestationType::None)
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
#[derive(Debug, Clone)]
pub struct AttestationGenerator {
    pub attestation_type: AttestationType,
    attestation_provider_url: Option<String>,
}

impl AttestationGenerator {
    /// Create an attesation generator with given attestation type
    pub fn new(
        attestation_type: AttestationType,
        attestation_provider_url: Option<String>,
    ) -> Result<Self, AttestationError> {
        // If an attestation provider is given, normalize the URL and check that it looks like a local IP
        let attestation_provider_url = attestation_provider_url
            .map(map_attestation_provider_url)
            .transpose()?;

        Ok(Self {
            attestation_type,
            attestation_provider_url,
        })
    }

    /// Detect what confidential compute platform is present and create the appropriate attestation
    /// generator
    pub async fn detect() -> Result<Self, AttestationError> {
        Self::new_with_detection(None, None).await
    }

    /// Do not generate attestations
    pub fn with_no_attestation() -> Self {
        Self {
            attestation_type: AttestationType::None,
            attestation_provider_url: None,
        }
    }

    /// Create an [AttestationGenerator] detecting the attestation type if it is not given
    pub async fn new_with_detection(
        attestation_type_string: Option<String>,
        attestation_provider_url: Option<String>,
    ) -> Result<Self, AttestationError> {
        if attestation_provider_url.is_some() {
            // If a remote provide is used, dont do detection
            let attestation_type = serde_json::from_value(serde_json::Value::String(
                attestation_type_string.ok_or(AttestationError::AttestationTypeNotGiven)?,
            ))?;
            return Self::new(attestation_type, attestation_provider_url);
        };

        let attestation_type_string = attestation_type_string.unwrap_or_else(|| "auto".to_string());
        let attestation_type = if attestation_type_string == "auto" {
            tracing::info!("Doing attestation type detection...");
            AttestationType::detect().await?
        } else {
            serde_json::from_value(serde_json::Value::String(attestation_type_string))?
        };
        tracing::info!("Local platform: {attestation_type}");

        Self::new(attestation_type, None)
    }

    /// Generate an attestation exchange message with given input data
    pub async fn generate_attestation(
        &self,
        input_data: [u8; 64],
    ) -> Result<AttestationExchangeMessage, AttestationError> {
        if let Some(url) = &self.attestation_provider_url {
            Self::use_attestation_provider(url, self.attestation_type, input_data).await
        } else {
            Ok(AttestationExchangeMessage {
                attestation_type: self.attestation_type,
                attestation: self.generate_attestation_bytes(input_data).await?,
            })
        }
    }

    /// Generate attestation evidence bytes based on attestation type, with given input data
    async fn generate_attestation_bytes(
        &self,
        input_data: [u8; 64],
    ) -> Result<Vec<u8>, AttestationError> {
        match self.attestation_type {
            AttestationType::None => Ok(Vec::new()),
            AttestationType::AzureTdx => {
                #[cfg(feature = "azure")]
                {
                    Ok(azure::create_azure_attestation(input_data).await?)
                }
                #[cfg(not(feature = "azure"))]
                {
                    tracing::error!(
                        "Attempted to generate an azure attestation but the `azure` feature not enabled"
                    );
                    Err(AttestationError::AttestationTypeNotSupported)
                }
            }
            _ => dcap::create_dcap_attestation(input_data).await,
        }
    }

    /// Generate an attestation by using an external service for the attestation generation
    async fn use_attestation_provider(
        url: &str,
        attestation_type: AttestationType,
        input_data: [u8; 64],
    ) -> Result<AttestationExchangeMessage, AttestationError> {
        let url = format!("{}/attest/{}", url, hex::encode(input_data));

        let response = reqwest::get(url)
            .await
            .map_err(|err| AttestationError::AttestationProvider(err.to_string()))?
            .bytes()
            .await
            .map_err(|err| AttestationError::AttestationProvider(err.to_string()))?
            .to_vec();

        // If the response is not already wrapped in an attestation exchange message, wrap it in
        // one
        if let Ok(message) = AttestationExchangeMessage::decode(&mut &response[..]) {
            Ok(message)
        } else {
            Ok(AttestationExchangeMessage {
                attestation_type,
                attestation: response,
            })
        }
    }
}

/// Allows remote attestations to be verified
#[derive(Clone, Debug)]
pub struct AttestationVerifier {
    /// The measurement policy with accepted values and attestation types
    pub measurement_policy: MeasurementPolicy,
    /// Whether to log quotes to a file
    pub log_dcap_quote: bool,
    /// Whether to override outdated TCB when on Azure
    pub override_azure_outdated_tcb: bool,
    /// Internal cache for collateral
    internal_pccs: Pccs,
}

impl AttestationVerifier {
    pub fn new(
        measurement_policy: MeasurementPolicy,
        pccs_url: Option<String>,
        log_dcap_quote: bool,
        override_azure_outdated_tcb: bool,
    ) -> Self {
        Self {
            measurement_policy,
            log_dcap_quote,
            override_azure_outdated_tcb,
            internal_pccs: Pccs::new(pccs_url),
        }
    }

    /// Create an [AttestationVerifier] which will allow no remote attestation
    pub fn expect_none() -> Self {
        Self {
            measurement_policy: MeasurementPolicy::expect_none(),
            log_dcap_quote: false,
            override_azure_outdated_tcb: false,
            internal_pccs: Pccs::new(None),
        }
    }

    /// Expect mock measurements used in tests
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn mock() -> Self {
        Self {
            measurement_policy: MeasurementPolicy::mock(),
            log_dcap_quote: false,
            override_azure_outdated_tcb: false,
            internal_pccs: Pccs::new(None),
        }
    }

    /// Verify an attestation, and ensure the measurements match one of our accepted measurements
    pub async fn verify_attestation(
        &self,
        attestation_exchange_message: AttestationExchangeMessage,
        expected_input_data: [u8; 64],
    ) -> Result<Option<MultiMeasurements>, AttestationError> {
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
                #[cfg(feature = "azure")]
                {
                    azure::verify_azure_attestation(
                        attestation_exchange_message.attestation,
                        expected_input_data,
                        self.internal_pccs.clone(),
                        self.override_azure_outdated_tcb,
                    )
                    .await?
                }
                #[cfg(not(feature = "azure"))]
                {
                    return Err(AttestationError::AttestationTypeNotSupported);
                }
            }
            _ => {
                dcap::verify_dcap_attestation(
                    attestation_exchange_message.attestation,
                    expected_input_data,
                    self.internal_pccs.clone(),
                )
                .await?
            }
        };

        // Do a measurement / attestation type policy check
        self.measurement_policy.check_measurement(&measurements)?;

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

/// Test whether it looks like we are running on GCP by hitting the metadata API
async fn running_on_gcp() -> Result<bool, AttestationError> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "Metadata-Flavor",
        "Google".parse().expect("Cannot parse header"),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .default_headers(headers)
        .build()?;

    let resp = client.get(GCP_METADATA_API).send().await;

    if let Ok(r) = resp {
        return Ok(r.status().is_success()
            && r.headers()
                .get("Metadata-Flavor")
                .map(|v| v == "Google")
                .unwrap_or(false));
    }

    Ok(false)
}

/// If an attestion provider service is used, we ensure that it looks like a local IP
///
/// This is to avoid dangerous configuration where the attestation is provided by a remote machine
///
/// This by no means guarantees a safe configuration
fn map_attestation_provider_url(url: String) -> Result<String, AttestationError> {
    // Fist put it in the format that reqwest expects
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{}", url.trim_start_matches("http://"))
    };

    let url = url.strip_suffix('/').unwrap_or(&url).to_string();

    // If compiled in test mode, skip this check
    if !cfg!(test) {
        let parsed = url
            .parse::<std::net::SocketAddr>()
            .or_else(|_| {
                // Try parsing as a URL to extract host
                let parsed = url.parse::<http::Uri>().map_err(|_| "Invalid URL")?;

                let host = parsed.host().ok_or("URL missing host")?;

                host.parse::<std::net::IpAddr>()
                    .map_err(|_| "Only local IP addresses may be used as attestation provider URL")
                    .map(|ip| std::net::SocketAddr::new(ip, 0))
            })
            .map_err(|e| AttestationError::AttestationProviderUrl(e.to_string()))?;

        if !is_local_ip(parsed.ip()) {
            return Err(AttestationError::AttestationProviderUrl(
                "Given URL does not appear to contain a local IP address".to_string(),
            ));
        }
    }
    Ok(url)
}

/// Check if an IP address looks like it is local
fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
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
    #[error("Configuration mismatch - expected no remote attestation")]
    AttestationGivenWhenNoneExpected,
    #[error("Configfs-tsm quote generation: {0}")]
    QuoteGeneration(#[from] configfs_tsm::QuoteGenerationError),
    #[error("DCAP verification: {0}")]
    DcapVerification(#[from] DcapVerificationError),
    #[error("Attestation type not supported")]
    AttestationTypeNotSupported,
    #[error("Attestation type not accepted")]
    AttestationTypeNotAccepted,
    #[error("Measurements not accepted")]
    MeasurementsNotAccepted,
    #[cfg(feature = "azure")]
    #[error("MAA: {0}")]
    Maa(#[from] azure::MaaError),
    #[error("If using a an attestation provider an attestation type must be given")]
    AttestationTypeNotGiven,
    #[error("Attestation provider server: {0}")]
    AttestationProvider(String),
    #[error("Attestation provider URL: {0}")]
    AttestationProviderUrl(String),
    #[error("JSON: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("HTTP client: {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_test_attestation_provider_server(body: Vec<u8>) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(&body).await;
                let _ = socket.shutdown().await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn attestation_detection_does_not_panic() {
        // We dont enforce what platform the test is run on, only that the function does not panic
        let _ = AttestationGenerator::new_with_detection(None, None).await;
    }

    #[tokio::test]
    async fn running_on_gcp_check_does_not_panic() {
        let _ = running_on_gcp().await;
    }

    #[tokio::test]
    async fn attestation_provider_response_is_wrapped_if_needed() {
        let input_data = [0u8; 64];

        let encoded_message = AttestationExchangeMessage {
            attestation_type: AttestationType::None,
            attestation: vec![1, 2, 3],
        }
        .encode();

        let encoded_addr = spawn_test_attestation_provider_server(encoded_message).await;
        let encoded_url = format!("http://{encoded_addr}");
        let decoded = AttestationGenerator::use_attestation_provider(
            &encoded_url,
            AttestationType::GcpTdx,
            input_data,
        )
        .await
        .unwrap();
        assert_eq!(decoded.attestation_type, AttestationType::None);
        assert_eq!(decoded.attestation, vec![1, 2, 3]);

        let raw_addr = spawn_test_attestation_provider_server(vec![9, 8]).await;
        let raw_url = format!("http://{raw_addr}");
        let wrapped = AttestationGenerator::use_attestation_provider(
            &raw_url,
            AttestationType::DcapTdx,
            input_data,
        )
        .await
        .unwrap();
        assert_eq!(wrapped.attestation_type, AttestationType::DcapTdx);
        assert_eq!(wrapped.attestation, vec![9, 8]);
    }
}
