use anyhow::{anyhow, ensure};
use attestation::{AttestationType, AttestationVerifier, measurements::MeasurementPolicy};
use clap::{Parser, Subcommand, ValueEnum};
use pccs::Pccs;
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_vsock::VMADDR_CID_ANY;
use tracing::level_filters::LevelFilter;

use attested_tls_proxy::{
    AttestationGenerator, OuterTlsConfig, OuterTlsMode, ProxyClient, ProxyConnectTarget,
    ProxyListenAddr, ProxyServer, TlsCertAndKey,
    attested_get::attested_get,
    file_server::{AttestedFileServerConfig, attested_file_server},
    get_inner_tls_cert, health_check,
    normalize_pem::normalize_private_key_pem_to_pkcs8,
};

const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

/// The crates from which debug messages are logged when the `--log-debug` option is
/// present
const DEBUG_LOG_TARGETS: &[&str] = &[
    "attestation",
    "attested_tls",
    "attested_tls_proxy",
    "nested_tls",
    "pccs",
];

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkTransport {
    Tcp,
    Vsock,
}

#[derive(Parser, Debug, Clone)]
#[command(version = GIT_REV, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Path to file, or URL, containing JSON measurements to be enforced on the remote party
    #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
    measurements_file: Option<String>,
    /// If no measurements file is specified, a single attestion type to allow
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// The URL of a PCCS to use when verifying DCAP attestations. Defaults to an internal PCCS.
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
        /// Network transport to use for the local client listener
        #[arg(long, value_enum, default_value_t = NetworkTransport::Tcp, env = "LISTEN_TRANSPORT")]
        listen_transport: NetworkTransport,
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// Local VSOCK CID to bind when using `--listen-transport vsock`
        #[arg(long, default_value_t = VMADDR_CID_ANY, env = "LISTEN_VSOCK_CID")]
        listen_vsock_cid: u32,
        /// Local VSOCK port to bind when using `--listen-transport vsock`
        #[arg(long, env = "LISTEN_VSOCK_PORT")]
        listen_vsock_port: Option<u32>,
        /// Network transport to use when connecting to the proxy server
        #[arg(long, value_enum, default_value_t = NetworkTransport::Tcp, env = "TARGET_TRANSPORT")]
        target_transport: NetworkTransport,
        /// Remote VSOCK CID for the proxy server when using `--target-transport vsock`
        #[arg(long, env = "TARGET_VSOCK_CID")]
        target_vsock_cid: Option<u32>,
        /// Remote VSOCK port for the proxy server when using `--target-transport vsock`
        #[arg(long, env = "TARGET_VSOCK_PORT")]
        target_vsock_port: Option<u32>,
        /// Connect directly to the server's inner attested TLS listener instead of nested TLS
        #[arg(long)]
        inner_session_only: bool,
        /// The proxy server hostname:port for TCP, or TLS server name for VSOCK
        target_addr: String,
        /// Type of attestation to present (defaults to automatic detection)
        /// Client certificate material enables client authentication.
        #[arg(long, env = "CLIENT_ATTESTATION_TYPE")]
        client_attestation_type: Option<String>,
        /// The path to a PEM encoded private key for outer client authentication in nested-TLS mode
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
    },
    /// Run a proxy server
    Server {
        /// Socket address to listen on for the outer nested-TLS listener, if enabled
        #[arg(long)]
        outer_listen_addr: Option<SocketAddr>,
        /// VSOCK CID to bind for the outer nested-TLS listener
        #[arg(long, default_value_t = VMADDR_CID_ANY, env = "OUTER_VSOCK_CID")]
        outer_vsock_cid: u32,
        /// VSOCK port to bind for the outer nested-TLS listener, if enabled
        #[arg(long, env = "OUTER_VSOCK_PORT")]
        outer_vsock_port: Option<u32>,
        /// Socket address to listen on for the inner-only attested TLS listener
        #[arg(long)]
        inner_listen_addr: Option<SocketAddr>,
        /// VSOCK CID to bind for the inner-only attested TLS listener
        #[arg(long, default_value_t = VMADDR_CID_ANY, env = "INNER_VSOCK_CID")]
        inner_vsock_cid: u32,
        /// VSOCK port to bind for the inner-only attested TLS listener, if enabled
        #[arg(long, env = "INNER_VSOCK_PORT")]
        inner_vsock_port: Option<u32>,
        /// DNS name to embed into the inner attested certificate when no outer listener is used
        #[arg(long)]
        inner_certificate_name: Option<String>,
        /// The hostname:port or ip:port of the target service to forward traffic to
        target_addr: String,
        /// Type of attestation to present (dafaults to 'auto' for automatic detection)
        /// This configures the inner attested TLS listener and does not require outer TLS certs.
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// The path to a PEM encoded private key for the optional outer nested-TLS listener
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: Option<PathBuf>,
        /// PEM certificate chain for the optional outer nested-TLS listener
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
        /// Filename to write measurements as JSON to
        #[arg(long)]
        out_measurements: Option<PathBuf>,
    },
    /// Serve a filesystem path over an attested channel
    AttestedFileServer {
        /// Filesystem path to statically serve
        path_to_serve: PathBuf,
        /// Socket address to listen on for the outer nested-TLS listener, if enabled
        #[arg(long)]
        outer_listen_addr: Option<SocketAddr>,
        /// Socket address to listen on for the inner-only attested TLS listener
        #[arg(long)]
        inner_listen_addr: Option<SocketAddr>,
        /// DNS name to embed into the inner attested certificate when no outer listener is used
        #[arg(long)]
        inner_certificate_name: Option<String>,
        /// Type of attestation to present (dafaults to none)
        /// This configures the inner attested TLS listener and does not require outer TLS certs.
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// The path to a PEM encoded private key for the optional outer nested-TLS listener
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: Option<PathBuf>,
        /// PEM certificate chain for the optional outer nested-TLS listener
        #[arg(long, env = "TLS_CERTIFICATE_PATH")]
        tls_certificate_path: Option<PathBuf>,
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
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    ensure!(
        cli.allowed_remote_attestation_type.is_some() != cli.measurements_file.is_some(),
        "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
    );

    let log_filter = if cli.log_debug {
        DEBUG_LOG_TARGETS
            .iter()
            .map(|target| format!("{target}=debug"))
            .collect::<Vec<_>>()
            .join(",")
    } else {
        format!("{}=warn", env!("CARGO_CRATE_NAME"))
    };
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into()) // global default
        .parse_lossy(log_filter);

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

    let attestation_verifier = AttestationVerifier {
        measurement_policy,
        pccs_url: cli.pccs_url,
        dump_dcap_quotes: cli.log_dcap_quote,
        override_azure_outdated_tcb: cli.override_azure_outdated_tcb,
        internal_pccs: Some(Pccs::new(None)),
    };

    match cli.command {
        CliCommand::Client {
            listen_transport,
            listen_addr,
            listen_vsock_cid,
            listen_vsock_port,
            target_transport,
            target_vsock_cid,
            target_vsock_port,
            inner_session_only,
            target_addr,
            client_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            tls_ca_certificate,
            dev_dummy_dcap,
            listen_addr_healthcheck,
        } => {
            let target_addr = target_addr
                .strip_prefix("https://")
                .unwrap_or(&target_addr)
                .to_string();
            let listen_endpoint = client_listen_endpoint(
                listen_transport,
                listen_addr,
                listen_vsock_cid,
                listen_vsock_port,
            )?;
            let target_endpoint = client_target_endpoint(
                target_transport,
                target_addr.clone(),
                target_vsock_cid,
                target_vsock_port,
            )?;

            if let Some(listen_addr_healthcheck) = listen_addr_healthcheck {
                health_check::server(listen_addr_healthcheck).await?;
            }

            validate_client_args(
                inner_session_only,
                tls_private_key_path.as_ref(),
                tls_certificate_path.as_ref(),
                tls_ca_certificate.as_ref(),
            )?;

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

            let client = if inner_session_only {
                ProxyClient::new_inner_only_with_transport_tls_config(
                    listen_endpoint,
                    target_endpoint,
                    client_attestation_generator,
                    attestation_verifier,
                    tls_cert_and_chain.map(|cert_and_key| cert_and_key.cert_chain),
                )
                .await?
            } else {
                ProxyClient::new_with_transport(
                    tls_cert_and_chain,
                    listen_endpoint,
                    target_endpoint,
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
            outer_listen_addr,
            outer_vsock_cid,
            outer_vsock_port,
            inner_listen_addr,
            inner_vsock_cid,
            inner_vsock_port,
            inner_certificate_name,
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

            let tls_cert_and_chain =
                load_tls_cert_and_key_server(tls_certificate_path, tls_private_key_path)?;
            let outer_listen = optional_listen_endpoint(
                "outer",
                outer_listen_addr,
                outer_vsock_cid,
                outer_vsock_port,
            )?;
            let inner_listen = optional_listen_endpoint(
                "inner",
                inner_listen_addr,
                inner_vsock_cid,
                inner_vsock_port,
            )?;
            validate_listener_args(
                inner_listen.is_some(),
                outer_listen.is_some(),
                tls_cert_and_chain.is_some(),
            )?;

            let local_attestation_generator =
                AttestationGenerator::new_with_detection(server_attestation_type, dev_dummy_dcap)?;

            let server = ProxyServer::new_with_listeners(
                tls_cert_and_chain
                    .zip(outer_listen)
                    .map(|(cert_and_key, listen_addr)| OuterTlsConfig {
                        listen_addr,
                        tls: OuterTlsMode::CertAndKey(cert_and_key),
                    }),
                inner_listen,
                inner_certificate_name,
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
            out_measurements: _, // TODO
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
            let cert_chain =
                get_inner_tls_cert(server, attestation_verifier, remote_tls_cert).await?;

            // // If the user chose to write measurements to a file as JSON
            // if let Some(path_to_write_measurements) = out_measurements {
            //     std::fs::write(
            //         path_to_write_measurements,
            //         measurements
            //             .unwrap_or(MultiMeasurements::NoAttestation)
            //             .to_header_format()?
            //             .as_bytes(),
            //     )?;
            // }
            println!("{}", certs_to_pem_string(&cert_chain)?);
        }
        CliCommand::AttestedFileServer {
            path_to_serve,
            outer_listen_addr,
            inner_listen_addr,
            inner_certificate_name,
            server_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            dev_dummy_dcap,
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key_server(tls_certificate_path, tls_private_key_path)?;
            validate_listener_args(
                inner_listen_addr.is_some(),
                outer_listen_addr.is_some(),
                tls_cert_and_chain.is_some(),
            )?;

            let server_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(server_attestation_type.unwrap_or("none".to_string())),
            )?;

            let attestation_generator =
                AttestationGenerator::new(server_attestation_type, dev_dummy_dcap)?;

            attested_file_server(AttestedFileServerConfig {
                path_to_serve,
                outer_cert_and_key: tls_cert_and_chain,
                outer_listen_addr,
                inner_listen_addr,
                inner_certificate_name,
                attestation_generator,
                attestation_verifier,
                client_auth: false,
            })
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

fn load_tls_cert_and_key_server(
    cert_chain: Option<PathBuf>,
    private_key: Option<PathBuf>,
) -> anyhow::Result<Option<TlsCertAndKey>> {
    match (cert_chain, private_key) {
        (Some(cert_chain), Some(private_key)) => {
            Ok(Some(load_tls_cert_and_key(cert_chain, private_key)?))
        }
        (Some(_), None) => Err(anyhow!("Certificate chain provided but no private key")),
        (None, Some(_)) => Err(anyhow!("Private key given but no certificate chain")),
        (None, None) => Ok(None),
    }
}

fn client_listen_endpoint(
    listen_transport: NetworkTransport,
    listen_addr: SocketAddr,
    listen_vsock_cid: u32,
    listen_vsock_port: Option<u32>,
) -> anyhow::Result<ProxyListenAddr<SocketAddr>> {
    match listen_transport {
        NetworkTransport::Tcp => Ok(ProxyListenAddr::Tcp(listen_addr)),
        NetworkTransport::Vsock => Ok(ProxyListenAddr::Vsock {
            cid: listen_vsock_cid,
            port: listen_vsock_port.ok_or_else(|| {
                anyhow!("--listen-vsock-port is required with --listen-transport vsock")
            })?,
        }),
    }
}

fn client_target_endpoint(
    target_transport: NetworkTransport,
    target_addr: String,
    target_vsock_cid: Option<u32>,
    target_vsock_port: Option<u32>,
) -> anyhow::Result<ProxyConnectTarget<String>> {
    match target_transport {
        NetworkTransport::Tcp => Ok(ProxyConnectTarget::Tcp(target_addr)),
        NetworkTransport::Vsock => Ok(ProxyConnectTarget::Vsock {
            cid: target_vsock_cid.ok_or_else(|| {
                anyhow!("--target-vsock-cid is required with --target-transport vsock")
            })?,
            port: target_vsock_port.ok_or_else(|| {
                anyhow!("--target-vsock-port is required with --target-transport vsock")
            })?,
            server_name: target_addr,
        }),
    }
}

fn optional_listen_endpoint(
    name: &str,
    tcp_addr: Option<SocketAddr>,
    vsock_cid: u32,
    vsock_port: Option<u32>,
) -> anyhow::Result<Option<ProxyListenAddr<SocketAddr>>> {
    match (tcp_addr, vsock_port) {
        (Some(_), Some(_)) => Err(anyhow!(
            "--{name}-listen-addr and --{name}-vsock-port are mutually exclusive"
        )),
        (Some(addr), None) => Ok(Some(ProxyListenAddr::Tcp(addr))),
        (None, Some(port)) => Ok(Some(ProxyListenAddr::Vsock {
            cid: vsock_cid,
            port,
        })),
        (None, None) => Ok(None),
    }
}

fn validate_listener_args(
    inner_listener_configured: bool,
    outer_listener_configured: bool,
    has_outer_tls: bool,
) -> anyhow::Result<()> {
    if !inner_listener_configured && !outer_listener_configured {
        return Err(anyhow!(
            "At least one inner or outer listener must be configured"
        ));
    }

    if has_outer_tls && !outer_listener_configured {
        return Err(anyhow!(
            "An outer listener is required when TLS certificate and key are provided"
        ));
    }

    if !has_outer_tls && outer_listener_configured {
        return Err(anyhow!(
            "An outer listener requires TLS certificate and key"
        ));
    }

    Ok(())
}

fn validate_client_args(
    inner_session_only: bool,
    _tls_private_key_path: Option<&PathBuf>,
    _tls_certificate_path: Option<&PathBuf>,
    tls_ca_certificate: Option<&PathBuf>,
) -> anyhow::Result<()> {
    if inner_session_only && tls_ca_certificate.is_some() {
        return Err(anyhow!(
            "--tls-ca-certificate cannot be used with --inner-session-only"
        ));
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
    fn client_rejects_tls_ca_certificate_in_inner_only_mode() {
        let cert_path = PathBuf::from("ca.pem");
        let err = validate_client_args(true, None, None, Some(&cert_path))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--tls-ca-certificate"));
    }

    #[test]
    fn client_allows_tls_client_auth_in_inner_only_mode() {
        let cert_path = PathBuf::from("client.crt");
        let key_path = PathBuf::from("client.key");
        validate_client_args(true, Some(&key_path), Some(&cert_path), None).unwrap();
    }

    #[test]
    fn client_requires_vsock_listen_port_when_listening_on_vsock() {
        let err = client_listen_endpoint(
            NetworkTransport::Vsock,
            "127.0.0.1:0".parse().unwrap(),
            VMADDR_CID_ANY,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("--listen-vsock-port"));
    }

    #[test]
    fn client_requires_vsock_target_when_connecting_over_vsock() {
        let err = client_target_endpoint(
            NetworkTransport::Vsock,
            "localhost".to_string(),
            Some(3),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("--target-vsock-port"));
    }

    #[test]
    fn server_rejects_tcp_and_vsock_for_same_listener() {
        let err = optional_listen_endpoint(
            "inner",
            Some("127.0.0.1:7001".parse().unwrap()),
            VMADDR_CID_ANY,
            Some(7001),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("mutually exclusive"));
    }
}
