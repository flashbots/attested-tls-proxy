pub use attested_tls_proxy::attestation::AttestationGenerator;
use std::net::SocketAddr;

use attested_tls_proxy::attestation::{
    AttestationError, AttestationExchangeMessage, AttestationVerifier,
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

/// An HTTP server which provides attestations
pub async fn attestation_provider_server(
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
        .map_err(|_| ServerError::InvalidLength)?;

    let attestation = shared_state
        .attestation_generator
        .generate_attestation(input_data)
        .await?
        .encode();

    Ok((StatusCode::OK, attestation))
}

/// A client helper which makes a request to `/attest`
pub async fn attestation_provider_client(
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

#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error(transparent)]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Input data must be 64 bytes")]
    InvalidLength,
    #[error(transparent)]
    AttestationFailed(#[from] AttestationError),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServerError::InvalidHex(_) | ServerError::InvalidLength => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            ServerError::AttestationFailed(_) => {
                tracing::error!("{self:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_provider_server() {
        let attestation_generator = AttestationGenerator::with_no_attestation();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            attestation_provider_server(listener, attestation_generator)
                .await
                .unwrap();
        });
        attestation_provider_client(server_addr, AttestationVerifier::expect_none())
            .await
            .unwrap();
    }
}
