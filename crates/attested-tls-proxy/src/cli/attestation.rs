use anyhow::{anyhow, ensure};
use attested_tls::attestation::{
    AttestationGenerator, AttestationType, AttestationVerifier, CachePolicy,
    measurements::MeasurementPolicy,
};

pub(super) async fn build_verifier(
    measurements_file: Option<String>,
    allowed_remote_attestation_type: Option<String>,
    pccs_url: Option<String>,
    intel_pcs_subscription_key: Option<String>,
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
        .with_cache_policy(CachePolicy::OnDemand)
        .with_dump_dcap_quotes(log_dcap_quote)
        .with_override_azure_outdated_tcb(override_azure_outdated_tcb);
    if let Some(pccs_url) = pccs_url {
        attestation_verifier_builder = attestation_verifier_builder.with_pccs_url(pccs_url);
    }
    if let Some(key) = intel_pcs_subscription_key {
        attestation_verifier_builder =
            attestation_verifier_builder.with_intel_pcs_subscription_key(key);
    }
    Ok(attestation_verifier_builder.build())
}

/// Build a local generator, requiring explicit opt-in to run without attestation.
pub(super) fn build_attestation_generator(
    requested_type: Option<String>,
    provider_url: Option<String>,
    type_option: &str,
) -> anyhow::Result<AttestationGenerator> {
    let generator = AttestationGenerator::new_with_detection(requested_type.clone(), provider_url)?;
    validate_platform(
        generator.attestation_type,
        requested_type.as_deref(),
        type_option,
    )?;
    Ok(generator)
}

fn validate_platform(
    platform: AttestationType,
    requested_type: Option<&str>,
    type_option: &str,
) -> anyhow::Result<()> {
    let automatic = matches!(requested_type, None | Some("auto"));
    ensure!(
        !automatic || platform != AttestationType::None,
        "No supported attestation platform detected. To proceed without local attestation, explicitly set {type_option} none."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_detection_requires_an_attested_platform() {
        for option in ["--client-attestation-type", "--server-attestation-type"] {
            for requested in [None, Some("auto")] {
                let error = validate_platform(AttestationType::None, requested, option)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("No supported attestation platform detected"));
                assert!(error.contains(&format!("{option} none")));
                for platform in [
                    AttestationType::DcapTdx,
                    AttestationType::GcpTdx,
                    AttestationType::AzureTdx,
                ] {
                    validate_platform(platform, requested, option).unwrap();
                }
            }
        }
    }

    #[test]
    fn explicit_none_is_supported() {
        let generator =
            build_attestation_generator(Some("none".into()), None, "--client-attestation-type")
                .unwrap();
        assert_eq!(generator.attestation_type, AttestationType::None);
    }

    #[test]
    fn upstream_configuration_errors_propagate() {
        for (requested, provider) in [
            (Some("invalid"), None),
            (None, Some("http://127.0.0.1:1234")),
            (Some("auto"), Some("http://127.0.0.1:1234")),
            (Some("dcap-tdx"), Some("not a URL")),
        ] {
            let requested = requested.map(str::to_owned);
            let provider = provider.map(str::to_owned);
            let expected =
                AttestationGenerator::new_with_detection(requested.clone(), provider.clone())
                    .unwrap_err();
            let actual =
                build_attestation_generator(requested, provider, "--client-attestation-type")
                    .unwrap_err();
            assert_eq!(actual.to_string(), expected.to_string());
        }
    }
}
