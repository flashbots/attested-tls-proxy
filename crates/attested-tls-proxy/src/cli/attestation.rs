use anyhow::{anyhow, ensure};
use attested_tls::attestation::{
    AttestationGenerator, AttestationType, AttestationVerifier, CachePolicy,
    measurements::MeasurementPolicy,
};
use std::path::PathBuf;

pub(super) async fn build_verifier(
    measurements_file: Option<String>,
    allowed_remote_attestation_type: Option<String>,
    pccs_url: Option<String>,
    intel_pcs_subscription_key: Option<String>,
    log_dcap_quote: bool,
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
        .with_dump_dcap_quotes(log_dcap_quote);
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
    provider_socket: Option<PathBuf>,
    type_option: &str,
) -> anyhow::Result<AttestationGenerator> {
    if provider_socket.is_some() && matches!(requested_type.as_deref(), None | Some("auto")) {
        // The pinned provider API needs a non-None type to enable requests.
        // It only uses this value as an on/off switch: the returned evidence
        // supplies the actual platform.
        return Ok(AttestationGenerator::new(
            AttestationType::DcapTdx,
            provider_socket,
        )?);
    }
    let generator =
        AttestationGenerator::new_with_detection(requested_type.clone(), provider_socket)?;
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
                for platform in [AttestationType::DcapTdx, AttestationType::GcpTdx] {
                    validate_platform(platform, requested, option).unwrap();
                }
            }
        }
    }

    #[test]
    fn explicit_none_is_supported() {
        for provider in [
            None,
            Some(PathBuf::from("/run/attestation-provider/attestation.sock")),
        ] {
            let generator = build_attestation_generator(
                Some("none".into()),
                provider,
                "--client-attestation-type",
            )
            .unwrap();
            assert_eq!(generator.attestation_type, AttestationType::None);
            assert!(
                generator
                    .generate_attestation([0; 64])
                    .unwrap()
                    .attestation_evidence
                    .is_none()
            );
        }
    }

    #[test]
    fn provider_configuration_is_lazy_and_generation_errors_propagate() {
        let dir = tempfile::tempdir().unwrap();
        for requested in [None, Some("auto"), Some("dcap-tdx")] {
            let generator = build_attestation_generator(
                requested.map(str::to_owned),
                Some(dir.path().join("missing.sock")),
                "--client-attestation-type",
            )
            .unwrap();
            assert_ne!(generator.attestation_type, AttestationType::None);
            assert!(matches!(
                generator.generate_attestation([42; 64]),
                Err(attested_tls::attestation::AttestationError::AttestationProvider(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn provider_default_preserves_the_returned_attestation_type() {
        use attested_tls::attestation::{
            AttestationEvidence, Encode, mock_platform_metadata, provider::ProviderResponse,
        };
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
            time::Duration,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let cases = [
            (None, AttestationType::GcpTdx),
            (Some("auto"), AttestationType::DcapTdx),
        ];
        let provider = std::thread::spawn(move || {
            for (_, actual_type) in cases {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut input = Vec::new();
                stream.read_to_end(&mut input).unwrap();
                assert_eq!(input, [42; 64]);
                let body = ProviderResponse::Ok(
                    AttestationEvidence {
                        quote: input,
                        platform: mock_platform_metadata(actual_type).unwrap(),
                    }
                    .into(),
                )
                .encode();
                stream
                    .write_all(&(body.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        for (requested, actual_type) in cases {
            let generator = build_attestation_generator(
                requested.map(str::to_owned),
                Some(path.clone()),
                "--client-attestation-type",
            )
            .unwrap();
            let message = generator.generate_attestation([42; 64]).unwrap();
            assert_eq!(message.attestation_type().unwrap(), actual_type);
            assert_eq!(message.attestation_evidence.unwrap().quote, [42; 64]);
        }
        provider.join().unwrap();
    }

    #[test]
    fn upstream_configuration_errors_propagate() {
        for (requested, provider) in [
            (Some("invalid"), None),
            (
                Some("invalid"),
                Some("/run/attestation-provider/attestation.sock"),
            ),
            (Some("dcap-tdx"), Some("relative.sock")),
            (Some("dcap-tdx"), Some("http://127.0.0.1:1234")),
        ] {
            let requested = requested.map(str::to_owned);
            let provider = provider.map(PathBuf::from);
            let expected =
                AttestationGenerator::new_with_detection(requested.clone(), provider.clone())
                    .unwrap_err();
            let actual =
                build_attestation_generator(requested, provider, "--client-attestation-type")
                    .unwrap_err();
            assert_eq!(actual.to_string(), expected.to_string());
        }
    }

    #[tokio::test]
    async fn verifier_rejects_measurements_file_with_azure_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("measurements.json");
        tokio::fs::write(
            &path,
            r#"[{"attestation_type":"dcap-tdx"},{"attestation_type":"azure-tdx"}]"#,
        )
        .await
        .unwrap();

        let result =
            build_verifier(Some(path.to_str().unwrap().into()), None, None, None, false).await;
        let Err(error) = result else {
            panic!("measurements file with an Azure record was accepted");
        };
        assert!(error.to_string().contains("unknown variant `azure-tdx`"));
    }
}
