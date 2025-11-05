use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use attested_tls_proxy::{MockAttestation, NoAttestation, ProxyClient, ProxyServer};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Socket address to listen on
    #[arg(short, long)]
    address: SocketAddr,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        #[arg(short, long)]
        server_address: SocketAddr,
        #[arg(long)]
        server_name: String,
    },
    /// Run a proxy server
    Server {
        #[arg(short, long)]
        client_address: SocketAddr,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Client {
            server_name,
            server_address,
        } => {
            let client = ProxyClient::new(
                cli.address,
                server_address,
                server_name.try_into().unwrap(),
                NoAttestation,
                MockAttestation,
            )
            .await;

            loop {
                client.accept().await.unwrap();
            }
        }
        CliCommand::Server { client_address } => {
            let cert_chain = load_certs_pem("certs.pem").unwrap();
            let key = load_private_key_pem("key.pem");
            let local_attestation = MockAttestation;
            let remote_attestation = NoAttestation;

            let server = ProxyServer::new(
                cert_chain,
                key,
                cli.address,
                client_address,
                local_attestation,
                remote_attestation,
            )
            .await;

            loop {
                server.accept().await.unwrap();
            }
        }
    }
}

pub fn load_certs_pem(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    Ok(
        rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
            .map(|res| res.unwrap())
            .collect(),
    )
}

pub fn load_private_key_pem(path: &str) -> PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(File::open(path).unwrap());

    // Tries to read the key as PKCS#8, PKCS#1, or SEC1
    let pks8_key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .unwrap()
        .unwrap();

    PrivateKeyDer::Pkcs8(pks8_key)
}
