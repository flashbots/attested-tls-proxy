use az_tdx_vtpm::{hcl, imds, report, tdx, vtpm};
use tokio_rustls::rustls::pki_types::CertificateDer;
// use openssl::pkey::{PKey, Public};

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

        let td_report = report::get_report().unwrap();

        // let mrtd = td_report.tdinfo.mrtd;
        // let rtmr0 = td_report.tdinfo.rtrm[0];
        // let rtmr1 = td_report.tdinfo.rtrm[1];
        // let rtmr2 = td_report.tdinfo.rtrm[2];
        // let rtmr3 = td_report.tdinfo.rtrm[3];

        // This makes a request to Azure Instance metadata service and gives us a binary response
        let td_quote_bytes = imds::get_td_quote(&td_report).unwrap();

        let bytes = vtpm::get_report().unwrap();
        let hcl_report = hcl::HclReport::new(bytes).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let ak_pub = hcl_report.ak_pub().unwrap();

        let td_report: tdx::TdReport = hcl_report.try_into().unwrap();
        assert!(var_data_hash == td_report.report_mac.reportdata[..32]);

        // let nonce = "a nonce".as_bytes();
        //
        // let tpm_quote = vtpm::get_quote(nonce).unwrap();
        // let der = ak_pub.key.try_to_der().unwrap();
        // let pub_key = PKey::public_key_from_der(&der).unwrap();
        // tpm_quote.verify(&pub_key, nonce).unwrap();
        todo!()
    }
}
