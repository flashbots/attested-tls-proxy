use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, anyhow, ensure};
use attested_tls::{
    TlsCertAndKey,
    attestation::{
        AttestationGenerator, AttestationType, AttestationVerifier, PccsMode,
        measurements::MeasurementPolicy,
    },
    self_signed::generate_self_signed_cert,
};
use attested_tls_tcp_tunnel::{TunnelClient, TunnelOptions, TunnelServer, tls};
use clap::{Args, Parser, Subcommand};
use tokio_rustls::rustls::{self, pki_types::CertificateDer};

#[derive(Debug, Parser)]
#[command(version = env!("GIT_REV"), about = "Forward TCP connections through remote-attested TLS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// File or URL containing the remote measurement policy
    #[arg(
        long,
        global = true,
        env = "MEASUREMENTS_FILE",
        conflicts_with = "allowed_remote_attestation_type"
    )]
    measurements_file: Option<String>,
    /// Remote attestation type to accept when no measurements file is given
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// PCCS URL for DCAP verification (defaults to Intel PCS)
    #[arg(long, global = true)]
    pccs_url: Option<String>,
    #[arg(long, global = true)]
    log_debug: bool,
    #[arg(long, global = true)]
    log_json: bool,
    /// Write DCAP quotes to quotes/
    #[arg(long, global = true)]
    log_dcap_quote: bool,
    #[arg(long, global = true, env = "OVERRIDE_AZURE_OUTDATED_TCB")]
    override_azure_outdated_tcb: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Accept local TCP connections and tunnel each to an attested server
    Client {
        /// Tunnel server hostname/IP and optional port (default 443)
        target_addr: String,
        #[arg(short, long, default_value = "127.0.0.1:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        #[command(flatten)]
        limits: Limits,
        #[command(flatten)]
        identity: Identity,
        /// Local attestation type (defaults to automatic detection)
        #[arg(long, env = "CLIENT_ATTESTATION_TYPE")]
        client_attestation_type: Option<String>,
        /// CA certificate to trust instead of public roots
        #[arg(long, conflicts_with = "allow_self_signed")]
        tls_ca_certificate: Option<PathBuf>,
        /// Accept a self-signed server certificate; attestation policy still applies
        #[arg(long)]
        allow_self_signed: bool,
    },
    /// Accept attested tunnels and forward each to a fixed TCP target
    Server {
        /// Target service hostname/IP and required port
        target_addr: String,
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        #[command(flatten)]
        limits: Limits,
        #[command(flatten)]
        identity: Identity,
        /// Local attestation type (defaults to automatic detection)
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// Require a client TLS certificate authenticated against public roots
        #[arg(long)]
        client_auth: bool,
    },
}

#[derive(Debug, Args)]
struct Identity {
    #[arg(long, env = "TLS_PRIVATE_KEY_PATH", requires = "tls_certificate_path")]
    tls_private_key_path: Option<PathBuf>,
    #[arg(long, env = "TLS_CERTIFICATE_PATH", requires = "tls_private_key_path")]
    tls_certificate_path: Option<PathBuf>,
    /// Dummy attestation service URL (requires local attestation type dummy)
    #[arg(long)]
    dev_dummy_dcap: Option<String>,
}

impl Identity {
    fn load(&self) -> anyhow::Result<Option<TlsCertAndKey>> {
        match (&self.tls_certificate_path, &self.tls_private_key_path) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => {
                let cert_chain = load_certs(cert)?;
                let key_file = File::open(key)
                    .with_context(|| format!("Opening private key {}", key.display()))?;
                let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
                    .ok_or_else(|| anyhow!("No private key found in PEM"))?;
                Ok(Some(TlsCertAndKey { cert_chain, key }))
            }
            _ => Err(anyhow!(
                "Certificate chain and private key must be provided together"
            )),
        }
    }
}

#[derive(Debug, Args)]
struct Limits {
    /// Deadline for DNS, connections, TLS, and attestation; not stream lifetime
    #[arg(long, default_value = "60")]
    setup_timeout_secs: NonZeroU64,
    /// Maximum connections including setup; excess arrivals are closed
    #[arg(long, default_value = "256", value_parser = parse_connection_limit)]
    max_connections: NonZeroUsize,
    /// Time to drain connections at shutdown before closing them (0 closes immediately)
    #[arg(long, default_value = "30")]
    shutdown_grace_secs: u64,
}

impl From<Limits> for TunnelOptions {
    fn from(value: Limits) -> Self {
        Self {
            setup_timeout: Duration::from_secs(value.setup_timeout_secs.get()),
            max_connections: value.max_connections,
            shutdown_grace: Duration::from_secs(value.shutdown_grace_secs),
        }
    }
}

fn parse_connection_limit(value: &str) -> Result<NonZeroUsize, String> {
    let value = value.parse::<NonZeroUsize>().map_err(|e| e.to_string())?;
    if value.get() > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(format!(
            "must not exceed {}",
            tokio::sync::Semaphore::MAX_PERMITS
        ));
    }
    Ok(value)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    ensure!(
        cli.measurements_file.is_some() != cli.allowed_remote_attestation_type.is_some(),
        "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install Rustls crypto provider"))?;
    let level = if cli.log_debug { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::new(format!(
        "warn,attested_tls_tcp_tunnel={level},attested_tls={level}"
    ));
    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    // Dropping a #[tokio::main] runtime waits indefinitely for spawn_blocking
    // quote generation. After draining sockets, do not wait for those workers.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run(cli));
    runtime.shutdown_timeout(Duration::ZERO);
    result
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if cli.log_dcap_quote {
        tokio::fs::create_dir_all("quotes").await?;
    }
    let policy = match cli.measurements_file {
        Some(path) => MeasurementPolicy::from_file_or_url(path).await?,
        None => match cli
            .allowed_remote_attestation_type
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .as_str()
        {
            "tdx" => MeasurementPolicy::tdx(),
            name => {
                let kind: AttestationType =
                    serde_json::from_value(serde_json::Value::String(name.to_owned()))?;
                MeasurementPolicy::single_attestation_type(kind)
            }
        },
    };
    let mut verifier = AttestationVerifier::builder(policy)
        .with_pccs_mode(PccsMode::Lazy)
        .with_dump_dcap_quotes(cli.log_dcap_quote)
        .with_override_azure_outdated_tcb(cli.override_azure_outdated_tcb);
    if let Some(url) = cli.pccs_url {
        verifier = verifier.with_pccs_url(url);
    }
    let verifier = verifier.build();
    match cli.command {
        Command::Client {
            target_addr,
            listen_addr,
            limits,
            identity,
            client_attestation_type,
            tls_ca_certificate,
            allow_self_signed,
        } => {
            let credentials = identity.load()?;
            let remote_certificate = tls_ca_certificate
                .as_deref()
                .map(load_certs)
                .transpose()?
                .and_then(|certs| certs.into_iter().next());
            let config =
                tls::client_config(credentials.as_ref(), remote_certificate, allow_self_signed)?;
            let generator = AttestationGenerator::new_with_detection(
                client_attestation_type,
                identity.dev_dummy_dcap,
            )?;
            let client = TunnelClient::new_with_tls_config(
                listen_addr,
                target_addr,
                config,
                generator,
                verifier,
                credentials.map(|c| c.cert_chain),
                limits.into(),
            )
            .await?;
            tracing::info!(address = %client.local_addr()?, "Tunnel client listening");
            client.serve_until(shutdown_signal()).await?;
        }
        Command::Server {
            target_addr,
            listen_addr,
            limits,
            identity,
            server_attestation_type,
            client_auth,
        } => {
            let credentials = match identity.load()? {
                Some(credentials) => credentials,
                None => {
                    tracing::warn!(
                        "No TLS certificate provided; generating self-signed certificate"
                    );
                    generate_self_signed_cert(listen_addr.ip())?
                }
            };
            let generator = AttestationGenerator::new_with_detection(
                server_attestation_type,
                identity.dev_dummy_dcap,
            )?;
            let server = TunnelServer::new(
                listen_addr,
                target_addr,
                credentials,
                generator,
                verifier,
                client_auth,
                limits.into(),
            )
            .await?;
            tracing::info!(address = %server.local_addr()?, "Tunnel server listening");
            server.serve_until(shutdown_signal()).await?;
        }
    }
    Ok(())
}

fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open(path).with_context(|| format!("Opening certificate file {}", path.display()))?,
    ))
    .collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "No certificates in {}", path.display());
    Ok(certs)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result { tracing::error!(%error, "Cannot listen for Ctrl-C; shutting down"); }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => tracing::error!(%error, "Cannot listen for SIGTERM; shutting down"),
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "Cannot listen for Ctrl-C; shutting down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_and_validation() {
        let Cli {
            command:
                Command::Client {
                    listen_addr,
                    limits,
                    ..
                },
            ..
        } = Cli::try_parse_from([
            "tunnel",
            "client",
            "localhost",
            "--allowed-remote-attestation-type",
            "none",
        ])
        .unwrap()
        else {
            panic!("wrong command")
        };
        assert_eq!(listen_addr, "127.0.0.1:0".parse().unwrap());
        assert_eq!(limits.setup_timeout_secs.get(), 60);
        assert_eq!(limits.max_connections.get(), 256);
        assert_eq!(limits.shutdown_grace_secs, 30);
        let Cli {
            command: Command::Server { listen_addr, .. },
            ..
        } = Cli::try_parse_from(["tunnel", "server", "localhost:50051"]).unwrap()
        else {
            panic!("wrong command")
        };
        assert_eq!(listen_addr, "0.0.0.0:0".parse().unwrap());
        for args in [
            vec!["--max-connections", "0"],
            vec!["--setup-timeout-secs", "0"],
            vec!["--tls-private-key-path", "key.pem"],
            vec!["--tls-certificate-path", "cert.pem"],
            vec!["--allow-self-signed", "--tls-ca-certificate", "ca.pem"],
            vec![
                "--measurements-file",
                "policy.json",
                "--allowed-remote-attestation-type",
                "none",
            ],
        ] {
            assert!(
                Cli::try_parse_from(["tunnel", "client", "localhost"].into_iter().chain(args))
                    .is_err()
            );
        }
        assert!(
            parse_connection_limit(&(tokio::sync::Semaphore::MAX_PERMITS + 1).to_string()).is_err()
        );
    }

    #[test]
    fn empty_and_invalid_certificate_files_fail() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(load_certs(file.path()).is_err());
        std::fs::write(
            file.path(),
            "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(load_certs(file.path()).is_err());
    }
}
