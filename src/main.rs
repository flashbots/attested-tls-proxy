use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use attested_tls_proxy::{
    attestation::{measurements::get_measurements_from_file, AttestationType, AttestationVerifier},
    get_tls_cert, ProxyClient, ProxyServer, TlsCertAndKey,
};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    // TODO missing:
    // Name:  "log-json",
    // Value: false,
    // Usage: "log in JSON format",
    //
    // Name:  "log-debug",
    // Value: true,
    // Usage: "log debug messages",
    //
    // Name:    "log-dcap-quote",
    // EnvVars: []string{"LOG_DCAP_QUOTE"},
    // Value:   false,
    // Usage:   "log dcap quotes to folder quotes/",
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0")]
        listen_addr: SocketAddr,
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        target_addr: String,
        /// The path to a PEM encoded private key for client authentication
        #[arg(long)]
        tls_private_key_path: Option<PathBuf>,
        /// The path to a PEM encoded certificate chain for client authentication
        #[arg(long)]
        tls_certificate_path: Option<PathBuf>,
        /// Type of attestaion to present (dafaults to none)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long)]
        client_attestation_type: Option<String>,
        /// Optional path to file containing JSON measurements to be enforced on the server
        #[arg(long)]
        server_measurements: Option<PathBuf>,
        #[arg(long)]
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        tls_ca_certificate: Option<PathBuf>,
        // TODO missing:
        // Name:    "dev-dummy-dcap",
        // EnvVars: []string{"DEV_DUMMY_DCAP"},
        // Usage:   "URL of the remote dummy DCAP service. Only with --client-attestation-type dummy.",
    },
    /// Run a proxy server
    Server {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0")]
        listen_addr: SocketAddr,
        /// Socket address of the target service to forward traffic to
        target_addr: SocketAddr,
        /// The path to a PEM encoded private key
        #[arg(long)]
        tls_private_key_path: PathBuf,
        /// The path to a PEM encoded certificate chain
        #[arg(long)]
        tls_certificate_path: PathBuf,
        /// Whether to use client authentication. If the client is running in a CVM this must be
        /// enabled.
        #[arg(long)]
        client_auth: bool,
        /// Type of attestaion to present (dafaults to none)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long)]
        server_attestation_type: Option<String>,
        /// Optional path to file containing JSON measurements to be enforced on the client
        #[arg(long)]
        client_measurements: Option<PathBuf>,
        // TODO missing:
        // Name:    "listen-addr-healthcheck",
        // EnvVars: []string{"LISTEN_ADDR_HEALTHCHECK"},
        // Value:   "",
        // Usage:   "address to listen on for health checks",
        //
        // Name:    "dev-dummy-dcap",
        // EnvVars: []string{"DEV_DUMMY_DCAP"},
        // Usage:   "URL of the remote dummy DCAP service. Only with --server-attestation-type dummy.",
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        server: String,
        /// Optional path to file containing JSON measurements to be enforced on the server
        #[arg(long)]
        server_measurements: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Client {
            listen_addr,
            target_addr,
            tls_private_key_path,
            tls_certificate_path,
            client_attestation_type,
            server_measurements,
            tls_ca_certificate,
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

            let attestation_verifier = match server_measurements {
                Some(server_measurements) => {
                    get_measurements_from_file(server_measurements).await?
                }
                None => AttestationVerifier::do_not_verify(),
            };

            let client_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(client_attestation_type.unwrap_or("none".to_string())),
            )?;

            let remote_tls_cert = match tls_ca_certificate {
                Some(remote_cert_filename) => Some(
                    load_certs_pem(remote_cert_filename)?
                        .first()
                        .ok_or(anyhow!("Filename given but no ceritificates found"))?
                        .clone(),
                ),
                None => None,
            };

            let client_attestation_generator = client_attestation_type.get_quote_generator()?;

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
                    eprintln!("Failed to handle connection: {err}");
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
            client_measurements,
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;

            let server_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(server_attestation_type.unwrap_or("none".to_string())),
            )?;

            let local_attestation_generator = server_attestation_type.get_quote_generator()?;

            let attestation_verifier = match client_measurements {
                Some(client_measurements) => {
                    get_measurements_from_file(client_measurements).await?
                }
                None => AttestationVerifier::do_not_verify(),
            };

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
                    eprintln!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::GetTlsCert {
            server,
            server_measurements,
        } => {
            let attestation_verifier = match server_measurements {
                Some(server_measurements) => {
                    get_measurements_from_file(server_measurements).await?
                }
                None => AttestationVerifier::do_not_verify(),
            };
            let cert_chain = get_tls_cert(server, attestation_verifier).await?;
            println!("{}", certs_to_pem_string(&cert_chain)?);
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

fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
}

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
