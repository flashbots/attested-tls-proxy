//! Data Center Attestation Primitives (DCAP) evidence generation and verification
use crate::attestation::{AttestationError, measurements::MultiMeasurements};

use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    QuoteCollateralV3,
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
    tcb_info::TcbInfo,
};
use thiserror::Error;

/// FMSPC with which to override TCB level checks on Azure (not used for GCP or other platforms)
const AZURE_BAD_FMSPC: &str = "90C06F000000";

/// For fetching collateral directly from Intel, if no PCCS is specified
pub const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Quote generation using configfs_tsm
pub async fn create_dcap_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    let quote = generate_quote(input_data)?;
    tracing::info!("Generated TDX quote of {} bytes", quote.len());
    Ok(quote)
}

/// Verify a DCAP TDX quote, and return the measurement values
#[cfg(not(any(test, feature = "mock")))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let override_azure_outdated_tcb = false;
    verify_dcap_attestation_with_given_timestamp(
        input,
        expected_input_data,
        pccs_url,
        None,
        now,
        override_azure_outdated_tcb,
    )
    .await
}

/// Allows the timestamp to be given, making it possible to test with existing attestations
///
/// If collateral is given, it is used instead of contacting PCCS (used in tests)
pub async fn verify_dcap_attestation_with_given_timestamp(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
    collateral: Option<QuoteCollateralV3>,
    now: u64,
    override_azure_outdated_tcb: bool,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let quote = Quote::parse(&input)?;
    tracing::info!("Verifying DCAP attestation: {quote:?}");

    let ca = quote.ca()?;
    let fmspc = hex::encode_upper(quote.fmspc()?);

    // Override outdated TCB only if we are on Azure and the FMSPC is known to be outdated
    let override_outdated_tcb = if override_azure_outdated_tcb {
        |mut tcb_info: TcbInfo| {
            if tcb_info.fmspc == AZURE_BAD_FMSPC {
                for tcb_level in &mut tcb_info.tcb_levels {
                    if tcb_level.tcb.sgx_components[7].svn > 3 {
                        tcb_level.tcb.sgx_components[7].svn = 3
                    }
                }
            }
            tcb_info
        }
    } else {
        |tcb_info: TcbInfo| tcb_info
    };

    let collateral = match collateral {
        Some(c) => c,
        None => {
            get_collateral_for_fmspc(
                &pccs_url.clone().unwrap_or(PCS_URL.to_string()),
                fmspc,
                ca,
                false, // Indicates not SGX
            )
            .await?
        }
    };

    let _verified_report = dcap_qvl::verify::verify_with_tcb_override(
        &input,
        &collateral,
        now,
        override_outdated_tcb,
    )?;

    let measurements = MultiMeasurements::from_dcap_qvl_quote(&quote)?;

    if get_quote_input_data(quote.report) != expected_input_data {
        return Err(DcapVerificationError::InputMismatch);
    }

    Ok(measurements)
}

#[cfg(any(test, feature = "mock"))]
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
#[cfg(any(test, feature = "mock"))]
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
#[cfg(not(any(test, feature = "mock")))]
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
    #[cfg(any(test, feature = "mock"))]
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
        let now = 1769509141;

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

        let collateral_bytes: &'static [u8] =
            include_bytes!("../../test-assets/dcap-quote-collateral-00.json");

        let collateral = serde_json::from_slice(collateral_bytes).unwrap();

        let measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [
                116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80, 227,
                118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139, 161, 136,
                37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85, 245, 114, 33,
                173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
            ],
            None,
            Some(collateral),
            now,
            false,
        )
        .await
        .unwrap();

        measurement_policy.check_measurement(&measurements).unwrap();
    }

    // This specifically tests a quote which has outdated TCB level from Azure
    #[tokio::test]
    async fn test_dcap_verify_azure_override() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../../test-assets/azure_failed_dcap_quote_10.bin");

        // To avoid this test stopping working when the certificate is no longer valid we pass in a
        // timestamp
        let now = 1771414156;

        let collateral_bytes: &'static [u8] =
            include_bytes!("../../test-assets/azure-collateral.json");

        let collateral = serde_json::from_slice(collateral_bytes).unwrap();

        let _measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [
                210, 20, 43, 100, 53, 152, 235, 95, 174, 43, 200, 82, 157, 215, 154, 85, 139, 41,
                248, 104, 204, 187, 101, 49, 203, 40, 218, 185, 220, 228, 119, 40, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            None,
            Some(collateral),
            now,
            true,
        )
        .await
        .unwrap();
    }
}
