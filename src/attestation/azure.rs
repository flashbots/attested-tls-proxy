use az_tdx_vtpm::{hcl, imds, report, vtpm};
use tokio_rustls::rustls::pki_types::CertificateDer;
// use openssl::pkey::{PKey, Public};
use base64::{engine::general_purpose::URL_SAFE as BASE64_URL_SAFE, Engine as _};
use reqwest::Client;
use serde::Serialize;

use crate::attestation::{compute_report_input, AttestationError, AttestationType, QuoteGenerator};

use super::QuoteVerifier;

#[derive(Clone)]
pub struct MaaGenerator {
    maa_endpoint: String,
    aad_access_token: String,
}

impl QuoteGenerator for MaaGenerator {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        AttestationType::AzureTdx
    }

    async fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        let input_data = compute_report_input(cert_chain, exporter)?;

        let td_report = report::get_report().unwrap();

        // let mrtd = td_report.tdinfo.mrtd;
        // let rtmr0 = td_report.tdinfo.rtrm[0];
        // let rtmr1 = td_report.tdinfo.rtrm[1];
        // let rtmr2 = td_report.tdinfo.rtrm[2];
        // let rtmr3 = td_report.tdinfo.rtrm[3];

        // This makes a request to Azure Instance metadata service and gives us a binary response
        let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();

        let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data).unwrap();
        let hcl_report = hcl::HclReport::new(hcl_report_bytes).unwrap();
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
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let jwt_token = self.call_tdxvm_attestation(body_bytes).await.unwrap();
        Ok(jwt_token.as_bytes().to_vec())
    }
}

impl MaaGenerator {
    /// Get a signed JWT from the azure API
    async fn call_tdxvm_attestation(
        &self,
        body_bytes: Vec<u8>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/attest/TdxVm?api-version=2025-06-01", self.maa_endpoint);

        let client = Client::new();
        let res = client
            .post(&url)
            .bearer_auth(&self.aad_access_token)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;

        if !status.is_success() {
            return Err(format!("MAA attestation failed: {status} {text}").into());
        }

        #[derive(serde::Deserialize)]
        struct AttestationResponse {
            token: String,
        }

        let parsed: AttestationResponse = serde_json::from_str(&text)?;
        Ok(parsed.token) // Microsoft-signed JWT
    }
}

#[derive(Clone)]
pub struct MaaVerifier;

impl QuoteVerifier for MaaVerifier {
    fn attestation_type(&self) -> AttestationType {
        AttestationType::AzureTdx
    }

    async fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Option<super::measurements::Measurements>, AttestationError> {
        let _input_data = compute_report_input(cert_chain, exporter)?;
        let token = String::from_utf8(input).unwrap();

        self.decode_jwt(&token).await.unwrap();

        todo!()
    }
}

impl MaaVerifier {
    async fn decode_jwt(&self, token: &str) -> Result<(), AttestationError> {
        // Parse payload (claims) without verification (TODO this will be swapped out once we have the
        // key-getting logic)
        let parts: Vec<&str> = token.split('.').collect();
        let claims_json = BASE64_URL_SAFE.decode(parts[1]).unwrap();

        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        println!("{claims}");
        Ok(())
    }
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
