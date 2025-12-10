//! Data Center Attestation Primitives (DCAP) evidence generation and verification
use crate::attestation::{measurements::MultiMeasurements, AttestationError};

use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
};
use thiserror::Error;

/// For fetching collateral directly from Intel, if no PCCS is specified
pub const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Quote generation using configfs_tsm
pub async fn create_dcap_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    let quote = generate_quote(input_data)?;
    tracing::info!("Generated TDX quote of {} bytes", quote.len());
    Ok(quote)
}

/// Verify a DCAP TDX quote, and return the measurement values
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let measurements = if cfg!(not(test)) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let quote = Quote::parse(&input)?;
        tracing::info!("Verifying DCAP attestation: {quote:?}");

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

        let measurements = MultiMeasurements::from_dcap_qvl_quote(&quote)?;

        if get_quote_input_data(quote.report) != expected_input_data {
            return Err(DcapVerificationError::InputMismatch);
        }
        measurements
    } else {
        // In tests we use mock quotes which will fail to verify
        let quote = tdx_quote::Quote::from_bytes(&input)?;
        if quote.report_input_data() != expected_input_data {
            return Err(DcapVerificationError::InputMismatch);
        }

        MultiMeasurements::from_tdx_quote(&quote)
    };

    Ok(measurements)
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
    configfs_tsm::create_tdx_quote(input)
}

/// Given a [Report] get the input data regardless of report type
pub fn get_quote_input_data(report: Report) -> [u8; 64] {
    match report {
        Report::TD10(r) => r.report_data,
        Report::TD15(r) => r.base.report_data,
        Report::SgxEnclave(r) => r.report_data,
    }
}

/// An error when verifying a DCAP attestation
#[derive(Error, Debug)]
pub enum DcapVerificationError {
    #[error("Quote input is not as expected")]
    InputMismatch,
    #[error("SGX quote given when TDX quote expected")]
    SgxNotSupported,
    #[error("System Time: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("DCAP quote verification: {0}")]
    DcapQvl(#[from] anyhow::Error),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
}
