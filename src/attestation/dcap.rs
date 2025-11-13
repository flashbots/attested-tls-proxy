use crate::attestation::{
    compute_report_input, generate_quote, get_quote_input_data,
    measurements::{CvmImageMeasurements, Measurements, PlatformMeasurements},
    AttestationError, AttestationType, QuoteGenerator, QuoteVerifier, PCS_URL,
};

use dcap_qvl::{collateral::get_collateral_for_fmspc, quote::Quote};
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Quote generation using configfs_tsm
#[derive(Clone)]
pub struct DcapTdxQuoteGenerator {
    pub attestation_type: AttestationType,
}

impl QuoteGenerator for DcapTdxQuoteGenerator {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        self.attestation_type
    }

    async fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        let quote_input = compute_report_input(cert_chain, exporter)?;

        Ok(generate_quote(quote_input)?)
    }
}

/// Verify DCAP TDX quotes, allowing them if they have one of a given set of platform-specific and
/// OS image specific measurements
#[derive(Clone)]
pub struct DcapTdxQuoteVerifier {
    pub attestation_type: AttestationType,
    /// Platform specific allowed Measurements
    /// Currently an option as this may be determined internally on a per-platform basis (Eg: GCP)
    pub accepted_platform_measurements: Option<Vec<PlatformMeasurements>>,
    /// OS-image specific allows measurement - this is effectively a list of allowed OS images
    pub accepted_cvm_image_measurements: Vec<CvmImageMeasurements>,
    /// URL of a PCCS (defaults to Intel PCS)
    pub pccs_url: Option<String>,
}

impl QuoteVerifier for DcapTdxQuoteVerifier {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        self.attestation_type
    }

    async fn verify_attestation(
        &self,
        input: Vec<u8>,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Option<Measurements>, AttestationError> {
        let quote_input = compute_report_input(cert_chain, exporter)?;
        let (platform_measurements, image_measurements) = if cfg!(not(test)) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let quote = Quote::parse(&input)?;

            let ca = quote.ca()?;
            let fmspc = hex::encode_upper(quote.fmspc()?);
            let collateral = get_collateral_for_fmspc(
                &self.pccs_url.clone().unwrap_or(PCS_URL.to_string()),
                fmspc,
                ca,
                false,
            )
            .await?;

            let _verified_report = dcap_qvl::verify::verify(&input, &collateral, now)?;

            let measurements = (
                PlatformMeasurements::from_dcap_qvl_quote(&quote)?,
                CvmImageMeasurements::from_dcap_qvl_quote(&quote)?,
            );
            if get_quote_input_data(quote.report) != quote_input {
                return Err(AttestationError::InputMismatch);
            }
            measurements
        } else {
            // In tests we use mock quotes which will fail to verify
            let quote = tdx_quote::Quote::from_bytes(&input)?;
            if quote.report_input_data() != quote_input {
                return Err(AttestationError::InputMismatch);
            }

            (
                PlatformMeasurements::from_tdx_quote(&quote),
                CvmImageMeasurements::from_tdx_quote(&quote),
            )
        };

        if let Some(accepted_platform_measurements) = &self.accepted_platform_measurements
            && !accepted_platform_measurements.contains(&platform_measurements)
        {
            return Err(AttestationError::UnacceptablePlatformMeasurements);
        }

        if !self
            .accepted_cvm_image_measurements
            .contains(&image_measurements)
        {
            return Err(AttestationError::UnacceptableOsImageMeasurements);
        }

        Ok(Some(Measurements {
            platform: platform_measurements,
            cvm_image: image_measurements,
        }))
    }
}
