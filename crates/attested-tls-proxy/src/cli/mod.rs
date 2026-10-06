mod attestation;
mod http;
mod pem;
mod tcp_tunnel;

use anyhow::ensure;
use clap::{Parser, Subcommand};

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
    /// If no measurements file is specified, a single attestion type to allow
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// The URL of a PCCS to use when verifying DCAP attestations. Defaults to Intel PCS.
    #[arg(long, global = true)]
    pccs_url: Option<String>,
    /// Log debug messages
    #[arg(long, global = true)]
    pub(crate) log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    pub(crate) log_json: bool,
    /// Log DCAP quotes to folder `quotes/`
    #[arg(long, global = true)]
    log_dcap_quote: bool,
    /// Overrides Azure outdated TCB info
    #[arg(long, global = true, env = "OVERRIDE_AZURE_OUTDATED_TCB")]
    override_azure_outdated_tcb: bool,
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
        if let CliCommand::TcpTunnelClient(args) = &self.command {
            args.validate()?;
        }
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
            self.log_dcap_quote,
            self.override_azure_outdated_tcb,
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
