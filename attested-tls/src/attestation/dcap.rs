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
#[cfg(not(test))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    verify_dcap_attestation_with_given_timestamp(input, expected_input_data, pccs_url, now).await
}

/// Allows the timestamp to be given, making it possible to test with existing attestations
async fn verify_dcap_attestation_with_given_timestamp(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
    now: u64,
) -> Result<MultiMeasurements, DcapVerificationError> {
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

    Ok(measurements)
}

#[cfg(test)]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    _pccs_url: Option<String>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    // In tests we use mock quotes which will fail to verify
    let quote = tdx_quote::Quote::from_bytes(&input)?;
    if quote.report_input_data() != expected_input_data {
        return Err(DcapVerificationError::InputMismatch);
    }
    Ok(MultiMeasurements::from_tdx_quote(&quote))
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
    #[cfg(test)]
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
}

#[cfg(test)]
mod tests {
    use crate::attestation::measurements::MeasurementPolicy;

    use super::*;
    #[tokio::test]
    async fn test_dcap_verify() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../../test-assets/dcap-tdx-1766059550570652607");

        // To avoid this test stopping working when the certificate is no longer valid we pass in a
        // timestamp
        let now = 1764621240;

        let measurements_json = br#"
        [{
            "measurement_id": "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd",
            "attestation_type": "dcap-tdx",
            "measurements": {
            "0": { "expected": "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694"},
            "1": { "expected": "0564ec85d8d7cbaebde0f6cce94f3b15722c656b610426abbfde11a5e14e9a9ee07c752df120b85267bb6c6c743a9301"},
            "2": { "expected": "d6b50192d3c4a98ac0a58e12b1e547edd02d79697c1fb9faa2f6fd0b150553b23f399e6d63612699b208468da7b748f3"},
            "3": { "expected": "b26c7be2db28613938cd75fd4173b963130712acb710f2820f9f0519e93f781dbabd7ba945870f499826d0ed169c5b42"},
            "4": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
            }
        }]
        "#;

        let measurement_policy = MeasurementPolicy::from_json_bytes(measurements_json.to_vec())
            .await
            .unwrap();

        let measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [
                116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80, 227,
                118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139, 161, 136,
                37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85, 245, 114, 33,
                173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
            ],
            None,
            now,
        )
        .await
        .unwrap();

        measurement_policy.check_measurement(&measurements).unwrap();
    }
}
