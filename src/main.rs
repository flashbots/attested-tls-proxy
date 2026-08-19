use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use std::{
    fs::File,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::level_filters::LevelFilter;

use attested_tls_proxy::{
    AttestationGenerator, ProxyClient, ProxyServer,
    attested_get::{attested_get, split_target_and_path},
    attested_tls::{
        TlsCertAndKey,
        attestation::{AttestationType, AttestationVerifier, measurements::MeasurementPolicy},
    },
    file_server::attested_file_server,
    get_tls_cert, health_check,
    normalize_pem::normalize_private_key_pem_to_pkcs8,
};

const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[derive(Parser, Debug, Clone)]
#[command(version = GIT_REV, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Path to file, or URL, containing JSON measurements to be enforced on the remote party
    #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
    measurements_file: Option<String>,
    /// Reload the measurement policy from --measurements-file after a measurement mismatch
    #[arg(long, global = true, requires = "measurements_file")]
    dynamic_measurement_policy: bool,
    /// If no measurements file is specified, a single attestion type to allow
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// The URL of a PCCS to use when verifying DCAP attestations. Defaults to Intel PCS.
    #[arg(long, global = true)]
    pccs_url: Option<String>,
    /// Log debug messages
    #[arg(long, global = true)]
    log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    log_json: bool,
    /// Log DCAP quotes to folder `quotes/`
    #[arg(long, global = true)]
    log_dcap_quote: bool,
    /// Overrides Azure outdated TCB info
    #[arg(long, global = true, env = "OVERRIDE_AZURE_OUTDATED_TCB")]
    override_azure_outdated_tcb: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        target_addr: String,
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
    },
    /// Run a proxy server
    Server {
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
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
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
    },
    /// Serve a filesystem path over an attested channel
    AttestedFileServer {
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
    },
    /// Start a proxy-client, send a single HTTP GET request to the given path and print the
    /// response to standard output
    AttestedGet {
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
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install the default rustls crypto provider"))?;

    let cli = Cli::parse();

    ensure!(
        cli.allowed_remote_attestation_type.is_some() != cli.measurements_file.is_some(),
        "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
    );
    ensure!(
        !cli.dynamic_measurement_policy || cli.measurements_file.is_some(),
        "--dynamic-measurement-policy requires --measurements-file"
    );

    let dynamic_measurements_file_or_url = if cli.dynamic_measurement_policy {
        cli.measurements_file.clone()
    } else {
        None
    };

    let crate_name = env!("CARGO_CRATE_NAME");

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into()) // global default
        .parse_lossy(format!(
            "{crate_name}={}",
            if cli.log_debug { "debug" } else { "warn" }
        ));

    let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(env_filter);

    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.pretty().init();
    }

    if cli.log_dcap_quote {
        tokio::fs::create_dir_all("quotes").await?;
    }

    let measurement_policy = match cli.measurements_file {
        Some(server_measurements) => {
            MeasurementPolicy::from_file_or_url(server_measurements).await?
        }
        None => {
            match cli
                .allowed_remote_attestation_type
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

    let mut attestation_verifier_builder =
        AttestationVerifier::builder(measurement_policy).with_pccs_not_prewarmed();
    if let Some(file_or_url) = dynamic_measurements_file_or_url {
        attestation_verifier_builder =
            attestation_verifier_builder.with_dynamic_measurements_file_or_url(file_or_url);
    }
    if let Some(pccs_url) = cli.pccs_url {
        attestation_verifier_builder = attestation_verifier_builder.pccs_url(pccs_url);
    }
    if cli.log_dcap_quote {
        attestation_verifier_builder = attestation_verifier_builder.dump_dcap_quotes();
    }
    #[cfg(feature = "azure")]
    if cli.override_azure_outdated_tcb {
        attestation_verifier_builder = attestation_verifier_builder.override_azure_outdated_tcb();
    }
    let attestation_verifier = attestation_verifier_builder.build();

    match cli.command {
        CliCommand::Client {
            listen_addr,
            target_addr,
            client_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            tls_ca_certificate,
            dev_dummy_dcap,
            listen_addr_healthcheck,
            allow_self_signed,
        } => {
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

            let client = if allow_self_signed {
                let client_tls_config =
                    attested_tls_proxy::self_signed::client_tls_config_allow_self_signed()?;
                ProxyClient::new_with_tls_config(
                    client_tls_config,
                    listen_addr,
                    target_addr,
                    client_attestation_generator,
                    attestation_verifier,
                    None,
                )
                .await?
            } else {
                ProxyClient::new(
                    tls_cert_and_chain,
                    listen_addr,
                    target_addr,
                    client_attestation_generator,
                    attestation_verifier,
                    remote_tls_cert,
                )
                .await?
            };

            loop {
                if let Err(err) = client.accept().await {
                    tracing::error!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::Server {
            listen_addr,
            target_addr,
            tls_private_key_path,
            tls_certificate_path,
            client_auth,
            server_attestation_type,
            dev_dummy_dcap,
            listen_addr_healthcheck,
        } => {
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
        CliCommand::GetTlsCert {
            server,
            tls_ca_certificate,
            allow_self_signed,
            out_measurements,
        } => {
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
                    measurements.to_header_format()?.as_bytes(),
                )?;
            }
            println!("{}", certs_to_pem_string(&cert_chain)?);
        }
        CliCommand::AttestedFileServer {
            path_to_serve,
            listen_addr,
            server_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            dev_dummy_dcap,
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;

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
        }
        CliCommand::AttestedGet {
            target_addr,
            url_path,
            tls_ca_certificate,
            allow_self_signed,
        } => {
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

            // Write response body to standard output
            let mut stdout = tokio::io::stdout();

            while let Some(chunk) = response.chunk().await? {
                stdout.write_all(&chunk).await?;
            }

            stdout.flush().await?;
        }
    }

    Ok(())
}

fn load_tls_cert_and_key_server(
    cert_chain: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ip: IpAddr,
) -> anyhow::Result<TlsCertAndKey> {
    if let Some(private_key) = private_key {
        load_tls_cert_and_key(
            cert_chain.ok_or(anyhow!("Private key given but no certificate chain"))?,
            private_key,
        )
    } else {
        if cert_chain.is_some() {
            return Err(anyhow!("Certificate chain provided but no private key"));
        }
        tracing::warn!("No TLS ceritifcate provided - generating self-signed");
        Ok(attested_tls_proxy::self_signed::generate_self_signed_cert(
            ip,
        )?)
    }
}

/// Load TLS details from storage
fn load_tls_cert_and_key(
    cert_chain: PathBuf,
    private_key: PathBuf,
) -> anyhow::Result<TlsCertAndKey> {
    let key = load_private_key_pem(private_key)?;
    let cert_chain = load_certs_pem(cert_chain)?;
    Ok(TlsCertAndKey { key, cert_chain })
}

/// load certificates from a PEM-encoded file
fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
}

/// load TLS private key from a PEM-encoded file
fn load_private_key_pem(path: PathBuf) -> anyhow::Result<PrivateKeyDer<'static>> {
    let pem_bytes = std::fs::read(path)?;
    normalize_private_key_pem_to_pkcs8(&pem_bytes)
}

/// Given a certificate chain, convert it to a PEM encoded string
fn certs_to_pem_string(certs: &[CertificateDer<'_>]) -> Result<String, pem_rfc7468::Error> {
    let mut out = String::new();
    for cert in certs {
        let block =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert.as_ref())?;
        out.push_str(&block);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_measurement_policy_requires_measurements_file() {
        let result = Cli::try_parse_from([
            "attested-tls-proxy",
            "--allowed-remote-attestation-type",
            "none",
            "--dynamic-measurement-policy",
            "get-tls-cert",
            "example.com",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn dynamic_measurement_policy_accepts_measurements_file() {
        let cli = Cli::try_parse_from([
            "attested-tls-proxy",
            "--measurements-file",
            "measurements.json",
            "--dynamic-measurement-policy",
            "get-tls-cert",
            "example.com",
        ])
        .unwrap();

        assert!(cli.dynamic_measurement_policy);
        assert_eq!(cli.measurements_file.as_deref(), Some("measurements.json"));
    }
}
