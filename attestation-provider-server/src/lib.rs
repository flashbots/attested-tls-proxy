pub use attested_tls_proxy::attestation::AttestationGenerator;
use std::net::SocketAddr;

use anyhow::anyhow;
use attested_tls_proxy::attestation::{AttestationExchangeMessage, AttestationVerifier};
use axum::serve::Listener;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use parity_scale_codec::{Decode, Encode};
use tokio_vsock::{VsockAddr, VsockStream};

#[derive(Debug, Clone, Copy)]
pub enum AttestationProviderEndpoint {
    Tcp(SocketAddr),
    Vsock { cid: u32, port: u32 },
}

#[derive(Clone)]
struct SharedState {
    attestation_generator: AttestationGenerator,
}

/// An HTTP server which provides attestations
pub async fn attestation_provider_server<L>(
    listener: L,
    attestation_generator: AttestationGenerator,
) -> anyhow::Result<()>
where
    L: Listener,
    L::Addr: std::fmt::Debug,
{
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
        .generate_attestation(input_data)?
        .encode();

    Ok((StatusCode::OK, attestation))
}

/// A client helper which makes a request to `/attest`
pub async fn attestation_provider_client(
    server_endpoint: AttestationProviderEndpoint,
    attestation_verifier: AttestationVerifier,
) -> anyhow::Result<AttestationExchangeMessage> {
    let input_data = [0; 64];
    let response = match server_endpoint {
        AttestationProviderEndpoint::Tcp(server_addr) => reqwest::get(format!(
            "http://{server_addr}/attest/{}",
            hex::encode(input_data)
        ))
        .await?
        .bytes()
        .await?
        .to_vec(),
        AttestationProviderEndpoint::Vsock { cid, port } => {
            let stream = VsockStream::connect(VsockAddr::new(cid, port)).await?;
            let io = TokioIo::new(stream);
            let (mut sender, connection) = http1::handshake(io).await?;

            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    eprintln!("vsock HTTP connection error: {err}");
                }
            });

            let request = Request::builder()
                .method(http::Method::GET)
                .uri(format!("/attest/{}", hex::encode(input_data)))
                .header(http::header::HOST, format!("{cid}:{port}"))
                .body(http_body_util::Empty::<Bytes>::new())?;

            let response = sender.send_request(request).await?;
            response.into_body().collect().await?.to_bytes().to_vec()
        }
    };

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
    use super::*;
    use tokio::net::TcpListener;

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
        attestation_provider_client(
            AttestationProviderEndpoint::Tcp(server_addr),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();
    }
}
