mod attestation;
mod http;
mod pem;
mod tcp_tunnel;

use anyhow::ensure;
use attested_tls::tls::ClientAuth;
use clap::{Args, Parser, Subcommand, ValueEnum, builder::TypedValueParser};
use std::path::PathBuf;

const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[derive(Parser, Debug, Clone)]
#[command(version = GIT_REV, about, long_about = None)]
pub(crate) struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Path to file, or URL, containing JSON measurements to be enforced on the remote party
    #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
    measurements_file: Option<String>,
    /// Allowed attestation type when no measurements file is specified, or tdx for DCAP and GCP
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// The URL of a PCCS to use when verifying DCAP attestations. Defaults to Intel PCS.
    #[arg(long, global = true)]
    pccs_url: Option<String>,
    /// Intel PCS subscription key to use when verifying DCAP attestations
    #[arg(
        long,
        global = true,
        env = "INTEL_PCS_SUBSCRIPTION_KEY",
        hide_env_values = true,
        value_parser = clap::builder::StringValueParser::new().map(|key| key.trim().to_owned()),
        conflicts_with = "pccs_url"
    )]
    intel_pcs_subscription_key: Option<String>,
    /// Log debug messages
    #[arg(long, global = true)]
    pub(crate) log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    pub(crate) log_json: bool,
    /// Log DCAP quotes to folder `quotes/`
    #[arg(long, global = true)]
    log_dcap_quote: bool,
}

#[derive(Args, Debug, Clone)]
struct ClientAuthArgs {
    /// Require a client TLS certificate authenticated against public roots.
    /// If the client is running in a CVM this must be enabled.
    #[arg(long, conflicts_with = "client_key_allowlist")]
    client_auth: bool,
    /// File of permitted Ed25519 client public keys, read at each TLS handshake
    #[arg(long, value_name = "FILE")]
    client_key_allowlist: Option<PathBuf>,
    /// Missing file policy before the allowlist path is first seen. Later removal always closes access
    #[arg(
        long,
        value_enum,
        default_value = "closed",
        requires = "client_key_allowlist"
    )]
    client_key_allowlist_when_missing: WhenMissing,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum WhenMissing {
    Open,
    Closed,
}

impl From<ClientAuthArgs> for ClientAuth {
    fn from(args: ClientAuthArgs) -> Self {
        match args.client_key_allowlist {
            Some(path) => Self::KeyAllowlist {
                path,
                open_when_missing: matches!(
                    args.client_key_allowlist_when_missing,
                    WhenMissing::Open
                ),
            },
            None => args.client_auth.into(),
        }
    }
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Accept local TCP connections and tunnel each to an attested server
    TcpTunnelClient(tcp_tunnel::ClientArgs),
    /// Accept attested tunnels and forward each to a fixed TCP target
    TcpTunnelServer(tcp_tunnel::ServerArgs),
    /// Run a proxy client
    Client(http::ClientArgs),
    /// Run a proxy server
    Server(http::ServerArgs),
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert(http::GetTlsCertArgs),
    /// Serve a filesystem path over an attested channel
    AttestedFileServer(http::AttestedFileServerArgs),
    /// Start a proxy-client, send a single HTTP GET request to the given path and print the
    /// response to standard output
    AttestedGet(http::AttestedGetArgs),
}

impl Cli {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.allowed_remote_attestation_type.is_some() != self.measurements_file.is_some(),
            "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
        );

        Ok(())
    }

    pub(crate) async fn run(self) -> anyhow::Result<()> {
        let verifier = attestation::build_verifier(
            self.measurements_file,
            self.allowed_remote_attestation_type,
            self.pccs_url,
            self.intel_pcs_subscription_key,
            self.log_dcap_quote,
        )
        .await?;
        match self.command {
            CliCommand::TcpTunnelClient(args) => args.run(verifier).await,
            CliCommand::TcpTunnelServer(args) => args.run(verifier).await,
            CliCommand::Client(args) => args.run(verifier).await,
            CliCommand::Server(args) => args.run(verifier).await,
            CliCommand::GetTlsCert(args) => args.run(verifier).await,
            CliCommand::AttestedFileServer(args) => args.run(verifier).await,
            CliCommand::AttestedGet(args) => args.run(verifier).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_commands_reject_removed_date_flag() {
        for mode in ["client", "server", "attested-get", "attested-file-server"] {
            let err =
                Cli::try_parse_from(["proxy", mode, "target", "--no-date-header"]).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{mode}"
            );
        }
    }

    #[test]
    fn server_client_auth_policies_conflict() {
        for mode in ["server", "tcp-tunnel-server", "attested-file-server"] {
            let args = [
                "proxy",
                mode,
                "target",
                "--tls-private-key-path",
                "key",
                "--tls-certificate-path",
                "cert",
                "--client-key-allowlist",
                "clients",
            ];
            assert!(Cli::try_parse_from(args).is_ok());
            for mode in ["open", "closed"] {
                assert!(
                    Cli::try_parse_from(
                        args.into_iter()
                            .chain(["--client-key-allowlist-when-missing", mode])
                    )
                    .is_ok()
                );
            }
            let err = Cli::try_parse_from(args.into_iter().chain(["--client-auth"])).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }
}
