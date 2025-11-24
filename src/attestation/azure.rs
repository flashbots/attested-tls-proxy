//! Microsoft Azure Attestation (MAA) evidence generation and verification
use std::string::FromUtf8Error;

use az_tdx_vtpm::{hcl, imds, report, vtpm};
use tokio_rustls::rustls::pki_types::CertificateDer;
// use openssl::pkey::{PKey, Public};
use base64::{engine::general_purpose::URL_SAFE as BASE64_URL_SAFE, Engine as _};
use reqwest::Client;
use serde::Serialize;
use thiserror::Error;

use crate::attestation::{compute_report_input, AttestationError};

// #[derive(Clone)]
// pub struct MaaGenerator {
// }

pub async fn create_azure_attestation(
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
) -> Result<Vec<u8>, MaaError> {
    let maa_endpoint = "todo".to_string();
    let aad_access_token = "todo".to_string();
    let input_data = compute_report_input(cert_chain, exporter)
        .map_err(|e| MaaError::InputData(e.to_string()))?;

    let td_report = report::get_report()?;

    // let mrtd = td_report.tdinfo.mrtd;
    // let rtmr0 = td_report.tdinfo.rtrm[0];
    // let rtmr1 = td_report.tdinfo.rtrm[1];
    // let rtmr2 = td_report.tdinfo.rtrm[2];
    // let rtmr3 = td_report.tdinfo.rtrm[3];

    // This makes a request to Azure Instance metadata service and gives us a binary response
    let td_quote_bytes = imds::get_td_quote(&td_report)?;

    let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data)?;
    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let hcl_var_data = hcl_report.var_data();

    // let bytes = vtpm::get_report().unwrap();
    // let hcl_report = hcl::HclReport::new(bytes).unwrap();
    // let var_data_hash = hcl_report.var_data_sha256();
    // let _ak_pub = hcl_report.ak_pub().unwrap();
    //
    // let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
    // assert!(var_data_hash == td_report.report_mac.reportdata[..32]);

    // let nonce = "a nonce".as_bytes();
    //
    // let tpm_quote = vtpm::get_quote(nonce).unwrap();
    // let der = ak_pub.key.try_to_der().unwrap();
    // let pub_key = PKey::public_key_from_der(&der).unwrap();
    // tpm_quote.verify(&pub_key, nonce).unwrap();

    let quote_b64 = BASE64_URL_SAFE.encode(&td_quote_bytes);
    let runtime_b64 = BASE64_URL_SAFE.encode(hcl_var_data);

    let body = TdxVmRequest {
        quote: quote_b64,
        runtime_data: Some(RuntimeData {
            data: runtime_b64,
            data_type: "Binary",
        }),
        nonce: Some("my-app-nonce-or-session-id".to_string()),
    };
    let body_bytes = serde_json::to_vec(&body)?;
    let jwt_token = call_tdxvm_attestation(maa_endpoint, aad_access_token, body_bytes).await?;
    Ok(jwt_token.as_bytes().to_vec())
}

/// Get a signed JWT from the azure API
async fn call_tdxvm_attestation(
    maa_endpoint: String,
    aad_access_token: String,
    body_bytes: Vec<u8>,
) -> Result<String, MaaError> {
    let url = format!("{}/attest/TdxVm?api-version=2025-06-01", maa_endpoint);

    let client = Client::new();
    let res = client
        .post(&url)
        .bearer_auth(&aad_access_token)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await?;

    let status = res.status();
    let text = res.text().await?;

    if !status.is_success() {
        return Err(MaaError::MaaProvider(status, text));
    }

    #[derive(serde::Deserialize)]
    struct AttestationResponse {
        token: String,
    }

    let parsed: AttestationResponse = serde_json::from_str(&text)?;
    Ok(parsed.token) // Microsoft-signed JWT
}

pub async fn verify_azure_attestation(
    input: Vec<u8>,
    cert_chain: &[CertificateDer<'_>],
    exporter: [u8; 32],
) -> Result<super::measurements::Measurements, MaaError> {
    let _input_data = compute_report_input(cert_chain, exporter)
        .map_err(|e| MaaError::InputData(e.to_string()))?;
    let token = String::from_utf8(input)?;

    decode_jwt(&token).await.unwrap();

    todo!()
}

async fn decode_jwt(token: &str) -> Result<(), AttestationError> {
    // Parse payload (claims) without verification (TODO this will be swapped out once we have the
    // key-getting logic)
    let parts: Vec<&str> = token.split('.').collect();
    let claims_json = BASE64_URL_SAFE.decode(parts[1]).unwrap();

    let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
    println!("{claims}");
    Ok(())
}

#[derive(Serialize)]
struct RuntimeData<'a> {
    data: String, // base64url of VarData bytes
    #[serde(rename = "dataType")]
    data_type: &'a str, // "Binary" in our case
}

#[derive(Serialize)]
struct TdxVmRequest<'a> {
    quote: String, // base64 (TDX quote)
    #[serde(rename = "runtimeData", skip_serializing_if = "Option::is_none")]
    runtime_data: Option<RuntimeData<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
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
