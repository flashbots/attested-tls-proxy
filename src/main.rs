use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr, path::PathBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use attested_tls_proxy::{
    get_tls_cert, MockAttestation, NoAttestation, ProxyClient, ProxyServer, TlsCertAndKey,
};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        /// Socket address to listen on
        #[arg(short, long)]
        address: SocketAddr,
        /// The socket address of the proxy server
        #[arg(short, long)]
        server_address: SocketAddr,
        /// The domain name of the proxy server
        #[arg(long)]
        server_name: String,
        /// The path to a PEM encoded private key for client authentication
        #[arg(long)]
        private_key: Option<PathBuf>,
        /// The path to a PEM encoded certificate chain for client authentication
        #[arg(long)]
        cert_chain: Option<PathBuf>,
    },
    /// Run a proxy server
    Server {
        /// Socket address to listen on
        #[arg(short, long)]
        address: SocketAddr,
        /// Socket address of the target service to forward traffic to
        #[arg(short, long)]
        target_address: SocketAddr,
        /// The path to a PEM encoded private key
        #[arg(long)]
        private_key: PathBuf,
        /// The path to a PEM encoded certificate chain
        #[arg(long)]
        cert_chain: PathBuf,
        /// Whether to use client authentication. If the client is running in a CVM this must be
        /// enabled.
        #[arg(long)]
        client_auth: bool,
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
        /// The socket address of the proxy server
        #[arg(short, long)]
        server_address: SocketAddr,
        /// The domain name of the proxy server
        #[arg(long)]
        server_name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Client {
            address,
            server_name,
            server_address,
            private_key,
            cert_chain,
        } => {
            let tls_cert_and_chain = if let Some(private_key) = private_key {
                Some(load_tls_cert_and_key(
                    cert_chain.ok_or(anyhow!("Private key given but no certificate chain"))?,
                    private_key,
                )?)
            } else {
                ensure!(
                    cert_chain.is_none(),
                    "Certificate chain given but no private key"
                );
                None
            };

            let client = ProxyClient::new(
                tls_cert_and_chain,
                address,
                server_address,
                server_name.try_into()?,
                NoAttestation,
                MockAttestation,
            )
            .await?;

            loop {
                if let Err(err) = client.accept().await {
                    eprintln!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::Server {
            address,
            target_address,
            private_key,
            cert_chain,
            client_auth,
        } => {
            let tls_cert_and_chain = load_tls_cert_and_key(cert_chain, private_key)?;
            let local_attestation = MockAttestation;
            let remote_attestation = NoAttestation;

            let server = ProxyServer::new(
                tls_cert_and_chain,
                address,
                target_address,
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
        CliCommand::GetTlsCert {
            server_address,
            server_name,
        } => {
            let cert_chain =
                get_tls_cert(server_address, server_name.try_into()?, MockAttestation).await?;
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
