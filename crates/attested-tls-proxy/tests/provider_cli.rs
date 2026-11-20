use std::process::Command;

const COMMANDS: [&str; 5] = [
    "client",
    "server",
    "tcp-tunnel-client",
    "tcp-tunnel-server",
    "attested-file-server",
];

fn cli(subcommand: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_attested-tls-proxy"));
    for variable in [
        "ATTESTATION_PROVIDER_SOCKET",
        "CLIENT_ATTESTATION_TYPE",
        "SERVER_ATTESTATION_TYPE",
        "TLS_PRIVATE_KEY_PATH",
        "TLS_CERTIFICATE_PATH",
        "MEASUREMENTS_FILE",
    ] {
        command.env_remove(variable);
    }
    command.args([subcommand, "--allowed-remote-attestation-type", "none"]);
    if subcommand == "attested-file-server" {
        command.args([
            ".",
            "--tls-private-key-path",
            "missing-key.pem",
            "--tls-certificate-path",
            "missing-cert.pem",
        ]);
    } else {
        command.arg("127.0.0.1:8000");
    }
    command
}

#[test]
fn socket_from_flag_or_environment_requires_an_explicit_type_before_loading_credentials() {
    for subcommand in COMMANDS {
        let type_flag = if subcommand.ends_with("client") {
            "--client-attestation-type"
        } else {
            "--server-attestation-type"
        };
        for from_env in [false, true] {
            for requested_type in [None, Some("auto")] {
                let mut command = cli(subcommand);
                let path = "/run/attestation-provider/attestation.sock";
                if from_env {
                    command.env("ATTESTATION_PROVIDER_SOCKET", path);
                } else {
                    command.args(["--attestation-provider-socket", path]);
                }
                if let Some(requested_type) = requested_type {
                    command.args([type_flag, requested_type]);
                }
                let output = command.output().unwrap();
                assert!(!output.status.success());
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(
                    stderr.contains(&format!("explicitly set {type_flag}")),
                    "{subcommand}, from_env={from_env}, type={requested_type:?}: {stderr}"
                );
            }
        }
    }
}

#[test]
fn removed_http_provider_option_is_rejected() {
    for subcommand in COMMANDS {
        let output = cli(subcommand)
            .args(["--dev-dummy-dcap", "http://127.0.0.1:1234"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("unexpected argument '--dev-dummy-dcap'"),
            "{stderr}"
        );
    }
}
