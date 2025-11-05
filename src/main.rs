use clap::{Parser, Subcommand};
use std::{fs::File, net::SocketAddr};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};

use attested_tls_proxy::{ProxyClient, ProxyServer};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Peer to peer filesharing")]
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
            let root_store =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let client_config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let client = ProxyClient::new(
                client_config.into(),
                cli.address,
                server_address,
                server_name.try_into().unwrap(),
            )
            .await;

            loop {
                client.accept().await.unwrap();
            }
        }
        CliCommand::Server { client_address } => {
            let cert_chain = load_certs_pem("certs.pem").unwrap();
            let key = load_private_key_pem("key.pem");
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain.clone(), key)
                .expect("Failed to create rustls server config");

            let server = ProxyServer::new(
                cert_chain,
                server_config.into(),
                cli.address,
                client_address,
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
