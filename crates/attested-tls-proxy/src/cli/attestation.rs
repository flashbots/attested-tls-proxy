use anyhow::anyhow;
use attested_tls::attestation::{
    AttestationType, AttestationVerifier, PccsMode, measurements::MeasurementPolicy,
};

pub(super) async fn build_verifier(
    measurements_file: Option<String>,
    allowed_remote_attestation_type: Option<String>,
    pccs_url: Option<String>,
    log_dcap_quote: bool,
    override_azure_outdated_tcb: bool,
) -> anyhow::Result<AttestationVerifier> {
    if log_dcap_quote {
        tokio::fs::create_dir_all("quotes").await?;
    }

    let measurement_policy = match measurements_file {
        Some(server_measurements) => {
            MeasurementPolicy::from_file_or_url(server_measurements).await?
        }
        None => {
            match allowed_remote_attestation_type
                .ok_or(anyhow!(
                    "Either a measurements file or an allowed attestation type must be provided"
                ))?
                .to_lowercase()
                .as_str()
            {
                "tdx" => MeasurementPolicy::tdx(),
                attestation_type => {
                    let allowed_server_attestation_type: AttestationType = serde_json::from_value(
                        serde_json::Value::String(attestation_type.to_string()),
                    )?;
                    MeasurementPolicy::single_attestation_type(allowed_server_attestation_type)
                }
            }
        }
    };

    let mut attestation_verifier_builder = AttestationVerifier::builder(measurement_policy)
        .with_pccs_mode(PccsMode::Lazy)
        .with_dump_dcap_quotes(log_dcap_quote)
        .with_override_azure_outdated_tcb(override_azure_outdated_tcb);
    if let Some(pccs_url) = pccs_url {
        attestation_verifier_builder = attestation_verifier_builder.with_pccs_url(pccs_url);
    }
    Ok(attestation_verifier_builder.build())
}
