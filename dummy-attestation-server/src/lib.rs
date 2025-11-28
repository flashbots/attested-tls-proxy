use std::net::SocketAddr;

use anyhow::anyhow;
use attested_tls_proxy::attestation::{
    AttestationExchangeMessage, AttestationGenerator, AttestationVerifier,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use parity_scale_codec::{Decode, Encode};
use tokio::net::TcpListener;

#[derive(Clone)]
struct SharedState {
    attestation_generator: AttestationGenerator,
}

/// An HTTP server which produces test attestations
pub async fn dummy_attestation_server(
    listener: TcpListener,
    attestation_generator: AttestationGenerator,
) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route("/attest/{input_data}", axum::routing::get(get_attest))
        .with_state(SharedState {
            attestation_generator,
        });

    axum::serve(listener, app).await?;

    Ok(())
}

/// Handler for the GET `/attest/{input_data}` route
/// Input data should be 64 bytes hex
async fn get_attest(
    State(shared_state): State<SharedState>,
    Path(input_data): Path<String>,
) -> Result<(StatusCode, Vec<u8>), ServerError> {
    let input_data: [u8; 64] = hex::decode(input_data)?
        .try_into()
        .map_err(|_| anyhow!("Input data must be 64 bytes"))?;

    let attestation = shared_state
        .attestation_generator
        .generate_attestation(input_data)
        .await?
        .encode();

    Ok((StatusCode::OK, attestation))
}

/// A client helper which makes a request to `/attest`
pub async fn dummy_attestation_client(
    server_addr: SocketAddr,
    attestation_verifier: AttestationVerifier,
) -> anyhow::Result<AttestationExchangeMessage> {
    let input_data = [0; 64];
    let response = reqwest::get(format!(
        "http://{server_addr}/attest/{}",
        hex::encode(input_data)
    ))
    .await?
    .bytes()
    .await?;

    let remote_attestation_message = AttestationExchangeMessage::decode(&mut &response[..])?;
    let remote_attestation_type = remote_attestation_message.attestation_type;

    println!("Remote attestation type: {remote_attestation_type}");

    attestation_verifier
        .verify_attestation(remote_attestation_message.clone(), input_data)
        .await?;

    Ok(remote_attestation_message)
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

#[cfg(test)]
mod tests {

    use attested_tls_proxy::attestation::AttestationType;

    use super::*;

    #[tokio::test]
    async fn test_dummy_server() {
        let attestation_generator = AttestationGenerator {
            attestation_type: AttestationType::None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            dummy_attestation_server(listener, attestation_generator)
                .await
                .unwrap();
        });
        dummy_attestation_client(server_addr, AttestationVerifier::do_not_verify())
            .await
            .unwrap();
    }
}
