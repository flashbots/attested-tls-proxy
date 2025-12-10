use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::level_filters::LevelFilter;

use attested_tls_proxy::{
    attestation::{measurements::MeasurementPolicy, AttestationType, AttestationVerifier},
    attested_get::attested_get,
    file_server::attested_file_server,
    get_tls_cert, AttestationGenerator, ProxyClient, ProxyServer, TlsCertAndKey,
};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Optional path to file containing JSON measurements to be enforced on the remote party
    #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
    measurements_file: Option<PathBuf>,
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
    },
    /// Run a proxy server
    Server {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// Socket address of the target service to forward traffic to
        target_addr: SocketAddr,
        /// Type of attestation to present (dafaults to 'auto' for automatic detection)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// The path to a PEM encoded private key
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: PathBuf,
        /// The path to a PEM encoded certificate chain
        #[arg(long, env = "TLS_CERTIFICATE_PATH")]
        tls_certificate_path: PathBuf,
        /// Whether to use client authentication. If the client is running in a CVM this must be
        /// enabled.
        #[arg(long)]
        client_auth: bool,
        /// URL of the remote dummy attestation service. Only use with --server-attestation-type
        /// dummy
        #[arg(long)]
        dev_dummy_dcap: Option<String>,
        // TODO missing:
        // Name:    "listen-addr-healthcheck",
        // EnvVars: []string{"LISTEN_ADDR_HEALTHCHECK"},
        // Value:   "",
        // Usage:   "address to listen on for health checks",
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        server: String,
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
        /// The path to a PEM encoded certificate chain
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
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        target_addr: String,
        #[arg(long)]
        /// path to GET (defaults to '/')
        url_path: Option<String>,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long)]
        tls_ca_certificate: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    ensure!(
        cli.allowed_remote_attestation_type.is_some() != cli.measurements_file.is_some(),
        "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
    );

    let crate_name = env!("CARGO_PKG_NAME");

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
        Some(server_measurements) => MeasurementPolicy::from_file(server_measurements).await?,
        None => {
            let allowed_server_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(cli.allowed_remote_attestation_type.ok_or(anyhow!(
                    "Either a measurements file or an allowed attestation type must be provided"
                ))?),
            )?;
            MeasurementPolicy::single_attestation_type(allowed_server_attestation_type)
        }
    };

    let attestation_verifier = AttestationVerifier {
        measurement_policy,
        pccs_url: cli.pccs_url,
        log_dcap_quote: cli.log_dcap_quote,
    };

    match cli.command {
        CliCommand::Client {
            listen_addr,
            target_addr,
            client_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            tls_ca_certificate,
            dev_dummy_dcap,
        } => {
            let target_addr = target_addr
                .strip_prefix("https://")
                .unwrap_or(&target_addr)
                .to_string();

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
                AttestationGenerator::new_with_detection(client_attestation_type, dev_dummy_dcap)
                    .await?;

            let client = ProxyClient::new(
                tls_cert_and_chain,
                listen_addr,
                target_addr,
                client_attestation_generator,
                attestation_verifier,
                remote_tls_cert,
            )
            .await?;

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
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;

            let local_attestation_generator =
                AttestationGenerator::new_with_detection(server_attestation_type, dev_dummy_dcap)
                    .await?;

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
        CliCommand::GetTlsCert { server } => {
            let cert_chain = get_tls_cert(server, attestation_verifier).await?;
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

            let mut response = attested_get(
                target_addr,
                &url_path.unwrap_or_default(),
                attestation_verifier,
                remote_tls_cert,
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
    let mut reader = std::io::BufReader::new(File::open(path)?);

    // Tries to read the key as PKCS#8, PKCS#1, or SEC1
    let pks8_key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .ok_or(anyhow!("No PKS8 Key"))??;

    Ok(PrivateKeyDer::Pkcs8(pks8_key))
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
