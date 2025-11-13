use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use attested_tls_proxy::{
    attestation::{AttestationType, CvmImageMeasurements},
    get_tls_cert, DcapTdxQuoteGenerator, DcapTdxQuoteVerifier, NoQuoteGenerator, NoQuoteVerifier,
    ProxyClient, ProxyServer, TlsCertAndKey,
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
        // TODO `cvm-reverse-proxy` accepts with with protocol, eg: `https://localhost:80`
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
        // Value: string(proxy.AttestationNone),
        // TODO missing:
        // Name:  "tls-ca-certificate",
        // Usage: "additional CA certificate to verify against (PEM) [default=no additional TLS certs]. Only valid with --verify-tls.",
        //
        //
        // Name:  "server-measurements",
        // Usage: "optional path to JSON measurements enforced on the server",
        //
        // Name:    "override-azurev6-tcbinfo",
        // Value:   false,
        // EnvVars: []string{"OVERRIDE_AZUREV6_TCBINFO"},
        // Usage:   "Allows Azure's V6 instance outdated SEAM Loader",
        //
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
        // TODO missing:
        // Name:    "listen-addr-healthcheck",
        // EnvVars: []string{"LISTEN_ADDR_HEALTHCHECK"},
        // Value:   "",
        // Usage:   "address to listen on for health checks",
        //
        // Name:    "server-attestation-type",
        // EnvVars: []string{"SERVER_ATTESTATION_TYPE"},
        // Value:   string(proxy.AttestationAuto),
        // Usage:   "type of attestation to present (" + proxy.AvailableAttestationTypes + "). Set to " + string(proxy.AttestationDummy) + " to connect to a remote tdx quote provider. Defaults to automatic detection.",
        //
        // Name:    "client-measurements",
        // EnvVars: []string{"CLIENT_MEASUREMENTS"},
        // Usage:   "optional path to JSON measurements enforced on the client",
        //
        // Name:    "override-azurev6-tcbinfo",
        // Value:   false,
        // EnvVars: []string{"OVERRIDE_AZUREV6_TCBINFO"},
        // Usage:   "Allows Azure's V6 instance outdated SEAM Loader",
        //
        // Name:    "dev-dummy-dcap",
        // EnvVars: []string{"DEV_DUMMY_DCAP"},
        // Usage:   "URL of the remote dummy DCAP service. Only with --server-attestation-type dummy.",
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        server: String,
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
        } => {
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

            // TODO
            let _client_attestation_type = match client_attestation_type {
                Some(_) => AttestationType::QemuTdx,
                None => AttestationType::None,
            };

            let quote_verifier = DcapTdxQuoteVerifier {
                attestation_type: AttestationType::Dummy,
                accepted_platform_measurements: None,
                accepted_cvm_image_measurements: vec![CvmImageMeasurements {
                    rtmr1: [0u8; 48],
                    rtmr2: [0u8; 48],
                    rtmr3: [0u8; 48],
                }],
                pccs_url: None,
            };

            let client = ProxyClient::new(
                tls_cert_and_chain,
                listen_addr,
                target_addr,
                NoQuoteGenerator,
                quote_verifier,
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
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;
            let local_attestation = DcapTdxQuoteGenerator {
                attestation_type: AttestationType::Dummy,
            };
            let remote_attestation = NoQuoteVerifier;

            let server = ProxyServer::new(
                tls_cert_and_chain,
                listen_addr,
                target_addr,
                local_attestation,
                remote_attestation,
                client_auth,
            )
            .await?;

            loop {
                if let Err(err) = server.accept().await {
                    eprintln!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::GetTlsCert { server } => {
            let quote_verifier = DcapTdxQuoteVerifier {
                attestation_type: AttestationType::Dummy,
                accepted_platform_measurements: None,
                accepted_cvm_image_measurements: vec![CvmImageMeasurements {
                    rtmr1: [0u8; 48],
                    rtmr2: [0u8; 48],
                    rtmr3: [0u8; 48],
                }],
                pccs_url: None,
            };
            let cert_chain = get_tls_cert(server, quote_verifier).await?;
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
