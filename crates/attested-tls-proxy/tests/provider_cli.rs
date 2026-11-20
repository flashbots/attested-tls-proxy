use std::{path::Path, process::Command};

const COMMANDS: [&str; 5] = [
    "client",
    "server",
    "tcp-tunnel-client",
    "tcp-tunnel-server",
    "attested-file-server",
];

fn cli(subcommand: &str, credentials: &Path) -> Command {
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
        command.arg(".");
    } else {
        command.arg("127.0.0.1:8000");
    }
    command
        .arg("--tls-private-key-path")
        .arg(credentials)
        .arg("--tls-certificate-path")
        .arg(credentials);
    command
}

#[test]
fn socket_from_flag_or_environment_accepts_omitted_auto_and_none_types() {
    let credentials = tempfile::NamedTempFile::new().unwrap();
    for subcommand in COMMANDS {
        let type_flag = if subcommand.ends_with("client") {
            "--client-attestation-type"
        } else {
            "--server-attestation-type"
        };
        for from_env in [false, true] {
            for requested_type in [None, Some("auto"), Some("none")] {
                let mut command = cli(subcommand, credentials.path());
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
                // Getting as far as loading credentials confirms that provider
                // setup accepted the type without probing the host or socket.
                let expected = if subcommand.starts_with("tcp-tunnel-") {
                    "No certificates in"
                } else {
                    "No private key found in PEM"
                };
                assert!(
                    stderr.contains(expected),
                    "{subcommand}, from_env={from_env}, type={requested_type:?}: {stderr}"
                );
            }
        }
    }
}

#[test]
fn removed_http_provider_option_is_rejected() {
    let credentials = tempfile::NamedTempFile::new().unwrap();
    for subcommand in COMMANDS {
        let output = cli(subcommand, credentials.path())
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
