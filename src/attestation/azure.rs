use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::attestation::{compute_report_input, AttestationError, AttestationType, QuoteGenerator};

#[derive(Clone)]
pub struct MaaQuoteGenerator {}

impl QuoteGenerator for MaaQuoteGenerator {
    /// Type of attestation used
    fn attestation_type(&self) -> AttestationType {
        AttestationType::AzureTdx
    }

    fn create_attestation(
        &self,
        cert_chain: &[CertificateDer<'_>],
        exporter: [u8; 32],
    ) -> Result<Vec<u8>, AttestationError> {
        let quote_input = compute_report_input(cert_chain, exporter)?;

        todo!()
    }
}
