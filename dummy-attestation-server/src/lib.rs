use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use attested_tls_proxy::{attestation::AttestationExchangeMessage, QuoteGenerator};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use parity_scale_codec::{Decode, Encode};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

#[derive(Clone)]
struct SharedState {
    attestation_generator: Arc<dyn QuoteGenerator>,
}

pub async fn dummy_attestation_server(
    listener: TcpListener,
    attestation_generator: Arc<dyn QuoteGenerator>,
) -> anyhow::Result<SocketAddr> {
    let addr = listener.local_addr()?;

    let app = axum::Router::new()
        .route("/attest/{input_data}", axum::routing::get(get_attest))
        .with_state(SharedState {
            attestation_generator,
        });

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(addr)
}

async fn get_attest(
    State(shared_state): State<SharedState>,
    Path(input_data): Path<String>,
) -> Result<(StatusCode, Vec<u8>), ServerError> {
    let (cert_chain, _) = generate_certificate_chain("0.0.0.0".parse().unwrap());
    let input_data: [u8; 64] = hex::decode(input_data).unwrap().try_into().unwrap();

    let attestation = AttestationExchangeMessage::from_attestation_generator(
        &cert_chain,
        input_data[..32].try_into().unwrap(),
        shared_state.attestation_generator,
    )?
    .encode();

    Ok((StatusCode::OK, attestation))
}

pub async fn dummy_attestation_client(server_addr: SocketAddr) -> anyhow::Result<()> {
    let input_data = [0; 64];
    let response = reqwest::get(format!(
        "http://{server_addr}/attest/{}",
        hex::encode(input_data)
    ))
    .await
    .unwrap()
    .bytes()
    .await
    .unwrap();

    let remote_attestation_message = AttestationExchangeMessage::decode(&mut &response[..])?;
    let remote_attestation_type = remote_attestation_message.attestation_type;
    println!("{remote_attestation_type}");

    // TODO validate the attestation
    Ok(())
}

struct ServerError(pub anyhow::Error);

impl<E> From<E> for ServerError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        ServerError(err.into())
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        eprintln!("{:?}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{:?}", self.0)).into_response()
    }
}

/// Helper to generate a self-signed certificate for testing
fn generate_certificate_chain(
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

#[cfg(test)]
mod tests {

    use attested_tls_proxy::attestation::AttestationType;

    use super::*;

    #[tokio::test]
    async fn test_dummy_server() {
        let attestation_generator = AttestationType::None.get_quote_generator().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        dummy_attestation_server(listener, attestation_generator)
            .await
            .unwrap();
        dummy_attestation_client(server_addr).await.unwrap();
    }
}
