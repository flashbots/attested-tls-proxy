//! Microsoft Azure vTPM attestation evidence generation and verification
mod ak_certificate;
mod nv_index;
use ak_certificate::{read_ak_certificate_from_tpm, verify_ak_cert_with_azure_roots};

use az_tdx_vtpm::{hcl, imds, vtpm};
use base64::{engine::general_purpose::URL_SAFE as BASE64_URL_SAFE, Engine as _};
use dcap_qvl::QuoteCollateralV3;
use num_bigint::BigUint;
use openssl::{error::ErrorStack, pkey::PKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x509_parser::prelude::*;

use crate::attestation::{
    dcap::verify_dcap_attestation_with_given_timestamp, measurements::MultiMeasurements,
};

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

/// TPM related components of the attestation document
#[derive(Debug, Serialize, Deserialize)]
struct TpmAttest {
    /// Attestation Key certificate from vTPM
    ak_certificate_pem: String,
    /// vTPM quote
    quote: vtpm::Quote,
    /// Raw TCG event log bytes (UEFI + IMA) [currently not used]
    ///
    /// `/sys/kernel/security/ima/ascii_runtime_measurements`,
    /// `/sys/kernel/security/tpm0/binary_bios_measurements`,
    event_log: Vec<u8>,
    /// Optional platform / instance metadata used to bind or verify the AK [currently not used]
    instance_info: Option<Vec<u8>>,
}

/// Generate a TDX attestation on Azure
pub async fn create_azure_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, MaaError> {
    let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data)?;

    let hcl = hcl::HclReport::new(hcl_report_bytes.clone())?;

    let td_report_from_hcl = hcl.try_into()?;

    // This makes a request to Azure Instance metadata service and gives us a binary response
    let td_quote_bytes = imds::get_td_quote(&td_report_from_hcl)?;

    let ak_certificate_der = read_ak_certificate_from_tpm()?;

    let tpm_attestation = TpmAttest {
        ak_certificate_pem: pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::default(),
            &ak_certificate_der,
        )?,
        quote: vtpm::get_quote(&input_data[..32])?,
        event_log: Vec::new(),
        instance_info: None,
    };

    let attestation_document = AttestationDocument {
        tdx_quote_base64: BASE64_URL_SAFE.encode(&td_quote_bytes),
        hcl_report_base64: BASE64_URL_SAFE.encode(&hcl_report_bytes),
        tpm_attestation,
    };

    tracing::info!("Successfully generated azure attestation: {attestation_document:?}");
    Ok(serde_json::to_vec(&attestation_document)?)
}

/// Verify a TDX attestation from Azure
pub async fn verify_azure_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
    override_azure_outdated_tcb: bool,
) -> Result<super::measurements::MultiMeasurements, MaaError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    verify_azure_attestation_with_given_timestamp(
        input,
        expected_input_data,
        pccs_url,
        None,
        now,
        override_azure_outdated_tcb,
    )
    .await
}

/// Do the verification, passing in the current time
/// This allows us to test this function without time checks going out of date
async fn verify_azure_attestation_with_given_timestamp(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_url: Option<String>,
    collateral: Option<QuoteCollateralV3>,
    now: u64,
    override_azure_outdated_tcb: bool,
) -> Result<super::measurements::MultiMeasurements, MaaError> {
    let attestation_document: AttestationDocument = serde_json::from_slice(&input)?;
    tracing::info!("Attempting to verifiy azure attestation: {attestation_document:?}");

    let hcl_report_bytes = BASE64_URL_SAFE.decode(attestation_document.hcl_report_base64)?;

    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();

    // Check that HCL var data hash matches TDX quote report data
    let mut expected_tdx_input_data = [0u8; 64];
    expected_tdx_input_data[..32].copy_from_slice(&var_data_hash);

    // Do DCAP verification
    let tdx_quote_bytes = BASE64_URL_SAFE.decode(attestation_document.tdx_quote_base64)?;
    let _dcap_measurements = verify_dcap_attestation_with_given_timestamp(
        tdx_quote_bytes,
        expected_tdx_input_data,
        pccs_url,
        collateral,
        now,
        override_azure_outdated_tcb,
    )
    .await?;

    let hcl_ak_pub = hcl_report.ak_pub()?;

    // Get attestation key from runtime claims
    let ak_from_claims = {
        let runtime_data_raw = hcl_report.var_data();
        let claims: HclRuntimeClaims = serde_json::from_slice(runtime_data_raw)?;

        let ak_jwk = claims
            .keys
            .iter()
            .find(|k| k.kid == "HCLAkPub")
            .ok_or(MaaError::ClaimsMissingHCLAkPub)?;

        RsaPubKey::from_jwk(ak_jwk)?
    };

    // Check that the TD report input data matches the HCL var data hash
    let td_report: az_tdx_vtpm::tdx::TdReport = hcl_report.try_into()?;
    if var_data_hash != td_report.report_mac.reportdata[..32] {
        return Err(MaaError::TdReportInputMismatch);
    }

    // Verify the vTPM quote
    let vtpm_quote = attestation_document.tpm_attestation.quote;
    let hcl_ak_pub_der = hcl_ak_pub
        .key
        .try_to_der()
        .map_err(|_| MaaError::JwkConversion)?;
    let pub_key = PKey::public_key_from_der(&hcl_ak_pub_der)?;
    vtpm_quote.verify(&pub_key, &expected_input_data[..32])?;

    let pcrs = vtpm_quote.pcrs_sha256();

    // Parse AK certificate
    let (_type_label, ak_certificate_der) = pem_rfc7468::decode_vec(
        attestation_document
            .tpm_attestation
            .ak_certificate_pem
            .as_bytes(),
    )?;

    let (remaining_bytes, ak_certificate) = X509Certificate::from_der(&ak_certificate_der)?;

    // Check that AK public key matches that from TPM quote and HCL claims
    let ak_from_certificate = RsaPubKey::from_certificate(&ak_certificate)?;
    let ak_from_hcl = RsaPubKey::from_openssl_pubkey(&pub_key)?;
    if ak_from_claims != ak_from_hcl {
        return Err(MaaError::AkFromClaimsNotEqualAkFromHcl);
    }
    if ak_from_claims != ak_from_certificate {
        return Err(MaaError::AkFromClaimsNotEqualAkFromCertificate);
    }

    // Strip trailing data from AK certificate
    let leaf_len = ak_certificate_der.len() - remaining_bytes.len();
    let ak_certificate_der_without_trailing_data = &ak_certificate_der[..leaf_len];

    // Verify the AK certificate against microsoft root cert
    verify_ak_cert_with_azure_roots(ak_certificate_der_without_trailing_data, now)?;

    Ok(MultiMeasurements::from_pcrs(pcrs))
}

/// JSON Web Key used in [HclRuntimeClaims]
#[derive(Debug, Deserialize)]
struct Jwk {
    #[allow(unused)]
    pub kty: String,
    pub kid: String,
    #[allow(unused)]
    pub n: Option<String>,
    #[allow(unused)]
    pub e: Option<String>,
    // other fields ignored
}

/// The internal data structure for HCL runtime claims
#[derive(Debug, serde::Deserialize)]
struct HclRuntimeClaims {
    keys: Vec<Jwk>,
    #[allow(unused)]
    #[serde(rename = "vm-configuration")]
    vm_config: Option<serde_json::Value>,
    #[allow(unused)]
    #[serde(rename = "user-data")]
    user_data: Option<serde_json::Value>,
}

/// This is only used as a common type to compare public keys with different formats
#[derive(Debug, PartialEq)]
struct RsaPubKey {
    n: BigUint,
    e: BigUint,
}

impl RsaPubKey {
    fn from_jwk(jwk: &Jwk) -> Result<Self, MaaError> {
        if jwk.kty != "RSA" {
            return Err(MaaError::NotRsa);
        }

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n_bytes = URL_SAFE_NO_PAD.decode(jwk.n.clone().ok_or(MaaError::JwkParse)?)?;
        let e_bytes = URL_SAFE_NO_PAD.decode(jwk.e.clone().ok_or(MaaError::JwkParse)?)?;

        Ok(Self {
            n: BigUint::from_bytes_be(&n_bytes),
            e: BigUint::from_bytes_be(&e_bytes),
        })
    }

    fn from_certificate(cert: &X509Certificate) -> Result<Self, MaaError> {
        let spki = cert.public_key();
        let rsa_from_cert = match spki.parsed() {
            Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => rsa,
            _ => return Err(MaaError::NotRsa),
        };

        Ok(Self {
            n: BigUint::from_bytes_be(rsa_from_cert.modulus),
            e: BigUint::from_bytes_be(rsa_from_cert.exponent),
        })
    }

    fn from_openssl_pubkey(key: &PKey<openssl::pkey::Public>) -> Result<Self, MaaError> {
        let rsa_from_pkey = key.rsa()?;

        Ok(Self {
            n: BigUint::from_bytes_be(&rsa_from_pkey.n().to_vec()),
            e: BigUint::from_bytes_be(&rsa_from_pkey.e().to_vec()),
        })
    }
}

/// An error when generating or verifying a Microsoft Azure vTPM attestation
#[derive(Error, Debug)]
pub enum MaaError {
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
    #[error("TD report input does not match hashed HCL var data")]
    TdReportInputMismatch,
    #[error("Base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Attestation Key from HCL runtime claims does not match that from HCL report")]
    AkFromClaimsNotEqualAkFromHcl,
    #[error("Attestation Key from HCL runtime claims does not match that from attestation key certificate")]
    AkFromClaimsNotEqualAkFromCertificate,
    #[error("WebPKI: {0}")]
    WebPki(#[from] webpki::Error),
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("Cannot encode JSON web key as DER")]
    JwkConversion,
    #[error("OpenSSL: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("Cannot extract measurements from quote")]
    CannotExtractMeasurementsFromQuote,
    #[error("Expected AK key to be RSA")]
    NotRsa,
    #[error("JSON web key has missing field")]
    JwkParse,
    #[error("HCL runtime claims is missing HCLAkPub field")]
    ClaimsMissingHCLAkPub,
    #[error("DCAP verification: {0}")]
    DcapVerification(#[from] crate::attestation::dcap::DcapVerificationError),
}

#[cfg(test)]
mod tests {
    use crate::attestation::measurements::MeasurementPolicy;

    use super::*;

    #[tokio::test]
    async fn test_decode_hcl() {
        // From cvm-reverse-proxy/internal/attestation/azure/tdx/testdata/hclreport.bin
        let hcl_bytes: &'static [u8] = include_bytes!("../../../test-assets/hclreport.bin");

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

    /// Verify a stored attestation from a test-deployment on azure
    #[tokio::test]
    async fn test_verify() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../../../test-assets/azure-tdx-1764662251380464271");

        // To avoid this test stopping working when the certificate is no longer valid we pass in a
        // timestamp
        let now = 1771423480;

        let measurements_json = br#"
        [{
            "measurement_id": "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd",
            "attestation_type": "azure-tdx",
            "measurements": {
                "4": {
                    "expected": "c4a25a6d7704629f63db84d20ea8db0e9ce002b2801be9a340091fe7ac588699"
                },
                "9": {
                    "expected": "9f4a5775122ca4703e135a9ae6041edead0064262e399df11ca85182b0f1541d"
                },
                "11": {
                    "expected": "abd7c695ffdb6081e99636ee016d1322919c68d049b698b399d22ae215a121bf"
                }
            }
        }]
        "#;

        let measurement_policy = MeasurementPolicy::from_json_bytes(measurements_json.to_vec())
            .await
            .unwrap();

        let collateral_bytes: &'static [u8] =
            include_bytes!("../../../test-assets/azure-collateral02.json");

        let collateral = serde_json::from_slice(collateral_bytes).unwrap();

        let measurements = verify_azure_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [0; 64], // Input data
            None,
            collateral,
            now,
            false,
        )
        .await
        .unwrap();

        measurement_policy.check_measurement(&measurements).unwrap();
    }
}
