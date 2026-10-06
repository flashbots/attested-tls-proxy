use super::pem::{
    certs_to_pem_string, load_certs_pem, load_tls_cert_and_key, load_tls_cert_and_key_server,
};
use anyhow::{anyhow, ensure};
use attested_tls::attestation::{
    AttestationType, AttestationVerifier, measurements::MultiMeasurements,
};
use attested_tls_proxy::{
    AttestationGenerator, ProxyClient, ProxyClientOptions, ProxyServer,
    attested_get::{attested_get, split_target_and_path},
    file_server::attested_file_server,
    get_tls_cert, health_check,
};
use clap::Args;
use std::{
    net::SocketAddr,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

#[derive(Args, Debug, Clone)]
pub(super) struct ClientArgs {
    /// Socket address to listen on
    #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
    listen_addr: SocketAddr,
    /// The hostname:port or ip:port of the proxy server (port defaults to 443)
    target_addr: String,
    /// Request deadline in seconds, including queueing and waiting for response headers
    #[arg(long, default_value = "60")]
    request_timeout_secs: NonZeroU64,
    /// Close a source connection if its response body makes no write progress for this many seconds
    #[arg(long, default_value = "60")]
    response_body_idle_timeout_secs: NonZeroU64,
    /// Maximum in-flight requests, including streaming responses
    #[arg(long, default_value = "64", value_parser = parse_max_in_flight_requests)]
    max_in_flight_requests: NonZeroUsize,
    /// Type of attestation to present (dafaults to 'auto' for automatic detection)
    /// If other than None, a TLS key and certicate must also be given
    #[arg(long, env = "CLIENT_ATTESTATION_TYPE")]
    client_attestation_type: Option<String>,
    /// The path to a PEM encoded private key for client authentication
    #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
    tls_private_key_path: Option<PathBuf>,
    /// The path to a PEM encoded certificate chain for client authentication
    #[arg(long, env = "TLS_CERTIFICATE_PATH")]
    tls_certificate_path: Option<PathBuf>,
    /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
    #[arg(long)]
    tls_ca_certificate: Option<PathBuf>,
    /// URL of the remote dummy attestation service. Only use with --client-attestation-type
    /// dummy
    #[arg(long)]
    dev_dummy_dcap: Option<String>,
    // Address to listen on for health checks
    #[arg(long)]
    listen_addr_healthcheck: Option<SocketAddr>,
    /// Enables verification of self-signed TLS certificates
    #[arg(long)]
    allow_self_signed: bool,
}

impl ClientArgs {
    pub(super) async fn run(self, attestation_verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            listen_addr,
            target_addr,
            request_timeout_secs,
            response_body_idle_timeout_secs,
            max_in_flight_requests,
            client_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            tls_ca_certificate,
            dev_dummy_dcap,
            listen_addr_healthcheck,
            allow_self_signed,
        } = self;

        let target_addr = target_addr
            .strip_prefix("https://")
            .unwrap_or(&target_addr)
            .to_string();

        if let Some(listen_addr_healthcheck) = listen_addr_healthcheck {
            health_check::server(listen_addr_healthcheck).await?;
        }

        let tls_cert_and_chain = if let Some(private_key) = tls_private_key_path {
            Some(load_tls_cert_and_key(
                tls_certificate_path
                    .ok_or(anyhow!("Private key given but no certificate chain"))?,
                private_key,
            )?)
        } else {
            ensure!(
                tls_certificate_path.is_none(),
                "Certificate chain given but no private key"
            );
            None
        };

        let remote_tls_cert = match tls_ca_certificate {
            Some(remote_cert_filename) => Some(
                load_certs_pem(remote_cert_filename)?
                    .first()
                    .ok_or(anyhow!("Filename given but no ceritificates found"))?
                    .clone(),
            ),
            None => None,
        };

        let client_attestation_generator =
            AttestationGenerator::new_with_detection(client_attestation_type, dev_dummy_dcap)?;

        let client_tls_config = attested_tls::tls::client_config(
            tls_cert_and_chain.as_ref(),
            remote_tls_cert,
            allow_self_signed,
        )?;
        let client = ProxyClient::new_with_tls_config(
            client_tls_config,
            listen_addr,
            target_addr,
            client_attestation_generator,
            attestation_verifier,
            tls_cert_and_chain.map(|identity| identity.cert_chain),
        )
        .await?
        .with_request_options(ProxyClientOptions {
            request_timeout: Duration::from_secs(request_timeout_secs.get()),
            response_body_idle_timeout: Duration::from_secs(response_body_idle_timeout_secs.get()),
            max_in_flight_requests,
        });

        loop {
            if let Err(err) = client.accept().await {
                tracing::error!("Failed to handle connection: {err}");
            }
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(super) struct ServerArgs {
    /// Socket address to listen on
    #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
    listen_addr: SocketAddr,
    /// The hostname:port or ip:port of the target service to forward traffic to
    target_addr: String,
    /// Type of attestation to present (dafaults to 'auto' for automatic detection)
    /// If other than None, a TLS key and certicate must also be given
    #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
    server_attestation_type: Option<String>,
    /// The path to a PEM encoded private key
    #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
    tls_private_key_path: Option<PathBuf>,
    /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
    #[arg(long, env = "TLS_CERTIFICATE_PATH")]
    tls_certificate_path: Option<PathBuf>,
    /// Whether to use client authentication. If the client is running in a CVM this must be
    /// enabled.
    #[arg(long)]
    client_auth: bool,
    /// URL of the remote dummy attestation service. Only use with --server-attestation-type
    /// dummy
    #[arg(long)]
    dev_dummy_dcap: Option<String>,
    // Address to listen on for health checks
    #[arg(long)]
    listen_addr_healthcheck: Option<SocketAddr>,
}

impl ServerArgs {
    pub(super) async fn run(self, attestation_verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            listen_addr,
            target_addr,
            tls_private_key_path,
            tls_certificate_path,
            client_auth,
            server_attestation_type,
            dev_dummy_dcap,
            listen_addr_healthcheck,
        } = self;

        if let Some(listen_addr_healthcheck) = listen_addr_healthcheck {
            health_check::server(listen_addr_healthcheck).await?;
        }

        let tls_cert_and_chain = load_tls_cert_and_key_server(
            tls_certificate_path,
            tls_private_key_path,
            listen_addr.ip(),
        )?;

        let local_attestation_generator =
            AttestationGenerator::new_with_detection(server_attestation_type, dev_dummy_dcap)?;

        let server = ProxyServer::new(
            tls_cert_and_chain,
            listen_addr,
            target_addr,
            local_attestation_generator,
            attestation_verifier,
            client_auth,
        )
        .await?;

        loop {
            if let Err(err) = server.accept().await {
                tracing::error!("Failed to handle connection: {err}");
            }
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(super) struct GetTlsCertArgs {
    /// The hostname:port or ip:port of the proxy server (port defaults to 443)
    server: String,
    /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
    #[arg(long)]
    tls_ca_certificate: Option<PathBuf>,
    /// Enables verification of self-signed TLS certificates
    #[arg(long)]
    allow_self_signed: bool,
    /// Filename to write measurements as JSON to
    #[arg(long)]
    out_measurements: Option<PathBuf>,
}

impl GetTlsCertArgs {
    pub(super) async fn run(self, attestation_verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            server,
            tls_ca_certificate,
            allow_self_signed,
            out_measurements,
        } = self;

        let remote_tls_cert = match tls_ca_certificate {
            Some(remote_cert_filename) => Some(
                load_certs_pem(remote_cert_filename)?
                    .first()
                    .ok_or(anyhow!("Filename given but no ceritificates found"))?
                    .clone(),
            ),
            None => None,
        };
        let (cert_chain, measurements) = get_tls_cert(
            server,
            attestation_verifier,
            remote_tls_cert,
            allow_self_signed,
        )
        .await?;

        // If the user chose to write measurements to a file as JSON
        if let Some(path_to_write_measurements) = out_measurements {
            std::fs::write(
                path_to_write_measurements,
                measurements
                    .unwrap_or(MultiMeasurements::NoAttestation)
                    .to_header_format()?
                    .as_bytes(),
            )?;
        }
        println!("{}", certs_to_pem_string(&cert_chain)?);
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub(super) struct AttestedFileServerArgs {
    /// Filesystem path to statically serve
    path_to_serve: PathBuf,
    /// Socket address to listen on
    #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
    listen_addr: SocketAddr,
    /// Type of attestation to present (dafaults to none)
    /// If other than None, a TLS key and certicate must also be given
    #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
    server_attestation_type: Option<String>,
    /// The path to a PEM encoded private key
    #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
    tls_private_key_path: PathBuf,
    /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
    #[arg(long, env = "TLS_CERTIFICATE_PATH")]
    tls_certificate_path: PathBuf,
    /// URL of the remote dummy attestation service. Only use with --server-attestation-type
    /// dummy
    #[arg(long)]
    dev_dummy_dcap: Option<String>,
}

impl AttestedFileServerArgs {
    pub(super) async fn run(self, attestation_verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            path_to_serve,
            listen_addr,
            server_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            dev_dummy_dcap,
        } = self;

        let tls_cert_and_chain = load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;

        let server_attestation_type: AttestationType = serde_json::from_value(
            serde_json::Value::String(server_attestation_type.unwrap_or("none".to_string())),
        )?;

        let attestation_generator =
            AttestationGenerator::new(server_attestation_type, dev_dummy_dcap)?;

        attested_file_server(
            path_to_serve,
            tls_cert_and_chain,
            listen_addr,
            attestation_generator,
            attestation_verifier,
            false,
        )
        .await?;
        Ok(())
    }
}

#[derive(Args, Debug, Clone)]
pub(super) struct AttestedGetArgs {
    /// The hostname:port or ip:port of the proxy server (port defaults to 443) together
    /// with the URL path to GET from the target service, eg: 127.0.0.1:3000/foobar
    target_addr: String,
    /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
    #[arg(long)]
    tls_ca_certificate: Option<PathBuf>,
    /// Enables verification of self-signed TLS certificates
    #[arg(long)]
    allow_self_signed: bool,
    /// Optional path to GET (defaults to '/') - this takes precedence over giving the path
    /// as part of the target address.
    #[arg(long)]
    url_path: Option<String>,
}

impl AttestedGetArgs {
    pub(super) async fn run(self, attestation_verifier: AttestationVerifier) -> anyhow::Result<()> {
        let Self {
            target_addr,
            url_path,
            tls_ca_certificate,
            allow_self_signed,
        } = self;

        let remote_tls_cert = match tls_ca_certificate {
            Some(remote_cert_filename) => Some(
                load_certs_pem(remote_cert_filename)?
                    .first()
                    .ok_or(anyhow!("Filename given but no ceritificates found"))?
                    .clone(),
            ),
            None => None,
        };

        let (target_addr, embedded_url_path) = split_target_and_path(&target_addr);
        let url_path = url_path.or(embedded_url_path);

        let mut response = attested_get(
            target_addr,
            url_path.as_deref().unwrap_or("/"),
            attestation_verifier,
            remote_tls_cert,
            allow_self_signed,
        )
        .await?;

        ensure!(
            !response.status().is_redirection(),
            "Attested GET returned {}; redirects are not followed because the destination has not been attested",
            response.status()
        );

        // Write response body to standard output
        let mut stdout = tokio::io::stdout();

        while let Some(chunk) = response.chunk().await? {
            stdout.write_all(&chunk).await?;
        }

        stdout.flush().await?;
        Ok(())
    }
}

/// Parses an admission limit within Tokio's supported semaphore range.
fn parse_max_in_flight_requests(value: &str) -> Result<NonZeroUsize, String> {
    let count = value
        .parse::<NonZeroUsize>()
        .map_err(|error| error.to_string())?;
    if count.get() > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(format!(
            "must not exceed {}",
            tokio::sync::Semaphore::MAX_PERMITS,
        ));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, CliCommand};
    use clap::Parser;
    /// Checks that CLI parsing rejects invalid limits before starting the proxy.
    #[test]
    fn max_in_flight_requests_validates_semaphore_limit() {
        for count in [
            0,
            1,
            tokio::sync::Semaphore::MAX_PERMITS,
            tokio::sync::Semaphore::MAX_PERMITS + 1,
        ] {
            let result = Cli::try_parse_from([
                "attested-tls-proxy",
                "client",
                "localhost:443",
                "--max-in-flight-requests",
                &count.to_string(),
            ]);
            if (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&count) {
                let CliCommand::Client(ClientArgs {
                    max_in_flight_requests,
                    ..
                }) = result.unwrap().command
                else {
                    panic!("expected client command");
                };
                assert_eq!(max_in_flight_requests.get(), count);
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    clap::error::ErrorKind::ValueValidation
                );
            }
        }
    }
}
