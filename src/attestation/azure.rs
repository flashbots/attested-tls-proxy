//! Microsoft Azure Attestation (MAA) evidence generation and verification
use std::string::FromUtf8Error;

use az_tdx_vtpm::{hcl, imds, report, vtpm};
use base64::{engine::general_purpose::URL_SAFE as BASE64_URL_SAFE, Engine as _};
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::attestation::{
    self, compute_report_input,
    measurements::{CvmImageMeasurements, Measurements, PlatformMeasurements},
    nv_index,
};

const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

pub async fn create_azure_attestation(
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
) -> Result<Vec<u8>, MaaError> {
    let input_data = compute_report_input(cert_chain, exporter)
        .map_err(|e| MaaError::InputData(e.to_string()))?;

    let td_report = report::get_report()?;

    // This makes a request to Azure Instance metadata service and gives us a binary response
    let td_quote_bytes = imds::get_td_quote(&td_report)?;

    let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data)?;

    let ak_certificate_der = read_ak_certificate_from_tpm()?;

    let tpm_attestation = TpmAttest {
        ak_certificate_pem: pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::default(),
            &ak_certificate_der,
        )?,
        quote: vtpm::get_quote(&input_data)?,
        event_log: Vec::new(),
        instance_info: None,
    };

    let attestation_document = AttestationDocument {
        tdx_quote_base64: BASE64_URL_SAFE.encode(&td_quote_bytes),
        hcl_report_base64: BASE64_URL_SAFE.encode(&hcl_report_bytes),
        tpm_attestation,
    };

    Ok(serde_json::to_vec(&attestation_document)?)
}

pub async fn verify_azure_attestation(
    input: Vec<u8>,
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
    pccs_url: Option<String>,
) -> Result<super::measurements::Measurements, MaaError> {
    let input_data = compute_report_input(cert_chain, exporter)
        .map_err(|e| MaaError::InputData(e.to_string()))?;

    let attestation_document: AttestationDocument = serde_json::from_slice(&input)?;

    // Verify TDX quote (same as with DCAP) - TODO deduplicate this code
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tdx_quote_bytes = BASE64_URL_SAFE
        .decode(attestation_document.tdx_quote_base64)
        .unwrap();

    let quote = dcap_qvl::quote::Quote::parse(&tdx_quote_bytes).unwrap();

    let ca = quote.ca().unwrap();
    let fmspc = hex::encode_upper(quote.fmspc().unwrap());
    let collateral = dcap_qvl::collateral::get_collateral_for_fmspc(
        &pccs_url
            .clone()
            .unwrap_or(attestation::dcap::PCS_URL.to_string()),
        fmspc,
        ca,
        false, // Indicates not SGX
    )
    .await
    .unwrap();

    let _verified_report = dcap_qvl::verify::verify(&input, &collateral, now).unwrap();

    // Check that hcl_report_bytes (hashed?) matches TDX quote report data
    // if get_quote_input_data(quote.report) != quote_input {
    //     return Err(AttestationError::InputMismatch);
    // }

    let hcl_report_bytes = BASE64_URL_SAFE
        .decode(attestation_document.hcl_report_base64)
        .unwrap();

    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();
    let hcl_ak_pub = hcl_report.ak_pub()?;
    let td_report: az_tdx_vtpm::tdx::TdReport = hcl_report.try_into()?;
    assert!(var_data_hash == td_report.report_mac.reportdata[..32]);

    let vtpm_quote = attestation_document.tpm_attestation.quote;
    let hcl_ak_pub_der = hcl_ak_pub.key.try_to_der().unwrap();
    let pub_key = PKey::public_key_from_der(&hcl_ak_pub_der).unwrap();
    vtpm_quote.verify(&pub_key, &input_data)?;
    let _pcrs = vtpm_quote.pcrs_sha256();

    // TODO parse AK certificate
    // Check that AK public key matches that from TPM quote
    // Verify AK certificate against microsoft root cert

    Ok(Measurements {
        platform: PlatformMeasurements::from_dcap_qvl_quote(&quote).unwrap(),
        cvm_image: CvmImageMeasurements::from_dcap_qvl_quote(&quote).unwrap(),
    })
}

/// The attestation evidence payload that gets sent over the channel
#[derive(Debug, Serialize, Deserialize)]
struct AttestationDocument {
    /// TDX quote from the IMDS
    tdx_quote_base64: String,
    /// Serialized HCL report
    hcl_report_base64: String,
    /// vTPM related evidence
    tpm_attestation: TpmAttest,
}

#[derive(Debug, Serialize, Deserialize)]
struct TpmAttest {
    /// Attestation Key certificate from vTPM
    ak_certificate_pem: String,
    /// vTPM quotes over the selected PCR bank(s).
    quote: vtpm::Quote,
    /// Raw TCG event log bytes (UEFI + IMA)
    ///
    /// `/sys/kernel/security/ima/ascii_runtime_measurements`,
    /// `/sys/kernel/security/tpm0/binary_bios_measurements`,
    event_log: Vec<u8>,
    /// Optional platform / instance metadata used to bind or verify the AK
    instance_info: Option<Vec<u8>>,
}

fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
    let mut context = nv_index::get_session_context()?;
    nv_index::read_nv_index(&mut context, TPM_AK_CERT_IDX)
}

#[derive(Error, Debug)]
pub enum MaaError {
    #[error("Failed to build input data: {0}")]
    InputData(String),
    #[error("Report: {0}")]
    Report(#[from] az_tdx_vtpm::report::ReportError),
    #[error("IMDS: {0}")]
    Imds(#[from] imds::ImdsError),
    #[error("vTPM report: {0}")]
    VtpmReport(#[from] az_tdx_vtpm::vtpm::ReportError),
    #[error("HCL: {0}")]
    Hcl(#[from] hcl::HclError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP Client: {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("MAA provider response: {0} - {1}")]
    MaaProvider(http::StatusCode, String),
    #[error("Token is bad UTF8: {0}")]
    BadUtf8(#[from] FromUtf8Error),
    #[error("vTPM quote: {0}")]
    VtpmQuote(#[from] vtpm::QuoteError),
    #[error("AK public key: {0}")]
    AkPub(#[from] vtpm::AKPubError),
    #[error("vTPM quote could not be verified: {0}")]
    TpmQuoteVerify(#[from] vtpm::VerifyError),
    #[error("vTPM read: {0}")]
    TssEsapi(#[from] tss_esapi::Error),
    #[error("PEM encode: {0}")]
    Pem(#[from] pem_rfc7468::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_decode_hcl() {
        // from cvm-reverse-proxy/internal/attestation/azure/tdx/testdata/hclreport.bin
        let hcl_bytes: &'static [u8] = include_bytes!("../../test-assets/hclreport.bin");

        let hcl_report = hcl::HclReport::new(hcl_bytes.to_vec()).unwrap();
        let hcl_var_data = hcl_report.var_data();
        let var_data_values: serde_json::Value = serde_json::from_slice(&hcl_var_data).unwrap();

        // Check that it contains 64 byte user data
        assert_eq!(
            hex::decode(var_data_values["user-data"].as_str().unwrap())
                .unwrap()
                .len(),
            64
        );
    }
}
