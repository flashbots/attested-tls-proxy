use axum::response::IntoResponse;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
    ClientConfig, RootCertStore, ServerConfig,
};

use crate::{
    attestation::measurements::{CvmImageMeasurements, Measurements, PlatformMeasurements},
    MEASUREMENT_HEADER,
};

/// Helper to generate a self-signed certificate for testing
pub fn generate_certificate_chain(
    ip: IpAddr,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ip.to_string());

    let keypair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&keypair).unwrap();

    let certs = vec![CertificateDer::from(cert)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(keypair.serialize_der()));
    (certs, key)
}

/// Helper to generate TLS configuration for testing
///
/// For the server: A given self-signed certificate
/// For the client: A root certificate store with the server's certificate
pub fn generate_tls_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate_chain.clone(), key)
        .expect("Failed to create rustls server config");

    let mut root_store = RootCertStore::empty();
    root_store.add(certificate_chain[0].clone()).unwrap();

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (Arc::new(server_config), Arc::new(client_config))
}

/// Helper to generate a mutual TLS configuration with client authentification for testing
pub fn generate_tls_config_with_client_auth(
    alice_certificate_chain: Vec<CertificateDer<'static>>,
    alice_key: PrivateKeyDer<'static>,
    bob_certificate_chain: Vec<CertificateDer<'static>>,
    bob_key: PrivateKeyDer<'static>,
) -> (
    (Arc<ServerConfig>, Arc<ClientConfig>),
    (Arc<ServerConfig>, Arc<ClientConfig>),
) {
    let (alice_client_verifier, alice_root_store) =
        client_verifier_from_remote_cert(bob_certificate_chain[0].clone());

    let alice_server_config = ServerConfig::builder()
        .with_client_cert_verifier(alice_client_verifier)
        .with_single_cert(alice_certificate_chain.clone(), alice_key.clone_key())
        .expect("Failed to create rustls server config");

    let alice_client_config = ClientConfig::builder()
        .with_root_certificates(alice_root_store)
        .with_client_auth_cert(alice_certificate_chain.clone(), alice_key)
        .unwrap();

    let (bob_client_verifier, bob_root_store) =
        client_verifier_from_remote_cert(alice_certificate_chain[0].clone());

    let bob_server_config = ServerConfig::builder()
        .with_client_cert_verifier(bob_client_verifier)
        .with_single_cert(bob_certificate_chain.clone(), bob_key.clone_key())
        .expect("Failed to create rustls server config");

    let bob_client_config = ClientConfig::builder()
        .with_root_certificates(bob_root_store)
        .with_client_auth_cert(bob_certificate_chain, bob_key)
        .unwrap();

    (
        (Arc::new(alice_server_config), Arc::new(alice_client_config)),
        (Arc::new(bob_server_config), Arc::new(bob_client_config)),
    )
}

fn client_verifier_from_remote_cert(
    cert: CertificateDer<'static>,
) -> (Arc<dyn ClientCertVerifier>, RootCertStore) {
    let mut root_store = RootCertStore::empty();
    root_store.add(cert).unwrap();

    (
        WebPkiClientVerifier::builder(Arc::new(root_store.clone()))
            .build()
            .unwrap(),
        root_store,
    )
}

pub async fn example_http_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = axum::Router::new().route("/", axum::routing::get(get_handler));

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    addr
}

async fn get_handler(headers: http::HeaderMap) -> impl IntoResponse {
    headers
        .get(MEASUREMENT_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("No measurements")
        .to_string()
}

pub async fn example_service() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut inbound, _client_addr) = listener.accept().await.unwrap();
            inbound.write_all(b"some data").await.unwrap();
        }
    });

    addr
}

pub fn default_measurements() -> Measurements {
    Measurements {
        platform: PlatformMeasurements {
            mrtd: [0u8; 48],
            rtmr0: [0u8; 48],
        },
        cvm_image: CvmImageMeasurements {
            rtmr1: [0u8; 48],
            rtmr2: [0u8; 48],
            rtmr3: [0u8; 48],
        },
    }
}
