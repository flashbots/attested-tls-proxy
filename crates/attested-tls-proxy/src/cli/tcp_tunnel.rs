use anyhow::{anyhow, ensure};
use attested_tls::{
    TlsCertAndKey,
    attestation::{AttestationGenerator, AttestationVerifier},
};
use attested_tls_proxy::self_signed::generate_self_signed_cert;
use attested_tls_proxy::tcp_tunnel::{TunnelClient, TunnelOptions, TunnelServer, tls};
use clap::Args;
use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tokio_rustls::rustls::pki_types::CertificateDer;

#[derive(Debug, Clone, Args)]
pub(super) struct ClientArgs {
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
}

#[derive(Debug, Clone, Args)]
pub(super) struct ServerArgs {
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
}

#[derive(Debug, Clone, Args)]
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
                let key = super::pem::load_private_key_pem(key.clone())?;
                Ok(Some(TlsCertAndKey { cert_chain, key }))
            }
            _ => Err(anyhow!(
                "Certificate chain and private key must be provided together"
            )),
        }
    }
}

#[derive(Debug, Clone, Args)]
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

impl ClientArgs {
    pub(super) async fn run(self, verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            target_addr,
            listen_addr,
            limits,
            identity,
            client_attestation_type,
            tls_ca_certificate,
            allow_self_signed,
        } = self;

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
            false, // No startup check.
            limits.into(),
        )
        .await?;
        tracing::info!(address = %client.local_addr()?, "Tunnel client listening");
        client.serve_until(shutdown_signal()).await?;
        Ok(())
    }
}

impl ServerArgs {
    pub(super) async fn run(self, verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            target_addr,
            listen_addr,
            limits,
            identity,
            server_attestation_type,
            client_auth,
        } = self;

        let credentials = match identity.load()? {
            Some(credentials) => credentials,
            None => {
                tracing::warn!("No TLS certificate provided; generating self-signed certificate");
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
        Ok(())
    }
}

fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = super::pem::load_certs_pem(path.to_owned())?;
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
    use crate::cli::{Cli, CliCommand};
    use clap::Parser;

    #[test]
    fn cli_defaults_and_validation() {
        let Cli {
            command:
                CliCommand::TcpTunnelClient(ClientArgs {
                    listen_addr,
                    limits,
                    ..
                }),
            ..
        } = Cli::try_parse_from([
            "tunnel",
            "tcp-tunnel-client",
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
            command: CliCommand::TcpTunnelServer(ServerArgs { listen_addr, .. }),
            ..
        } = Cli::try_parse_from(["tunnel", "tcp-tunnel-server", "localhost:50051"]).unwrap()
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
        ] {
            assert!(
                Cli::try_parse_from(
                    ["tunnel", "tcp-tunnel-client", "localhost"]
                        .into_iter()
                        .chain(args)
                )
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
