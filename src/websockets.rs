use thiserror::Error;
use tokio_tungstenite::WebSocketStream;

use crate::{
    attestation::{measurements::MultiMeasurements, AttestationType},
    attested_tls::{AttestedTlsClient, AttestedTlsError, AttestedTlsServer},
};

/// Websocket message type re-exported for convenience
pub use tokio_tungstenite::tungstenite::protocol::Message;

// TODO allow setting ws config
pub struct AttestedWsServer {
    inner: AttestedTlsServer,
}

impl AttestedWsServer {
    pub async fn accept(
        &self,
    ) -> Result<
        (
            WebSocketStream<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
            Option<MultiMeasurements>,
            AttestationType,
        ),
        AttestedWsError,
    > {
        let (stream, measurements, attestation_type) = self.inner.accept().await?;
        Ok((
            tokio_tungstenite::accept_async(stream).await.unwrap(),
            measurements,
            attestation_type,
        ))
    }
}

pub struct AttestedWsClient {
    inner: AttestedTlsClient,
}

impl AttestedWsClient {
    pub async fn connect(
        &self,
        server: &str,
    ) -> Result<
        (
            WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
            Option<MultiMeasurements>,
            AttestationType,
        ),
        AttestedWsError,
    > {
        let (stream, measurements, attestation_type) = self.inner.connect(server).await?;
        let (ws_connection, _response) =
            tokio_tungstenite::client_async(format!("wss://{server}"), stream)
                .await
                .unwrap();
        Ok((ws_connection, measurements, attestation_type))
    }
}

#[derive(Error, Debug)]
pub enum AttestedWsError {
    #[error("Attested TLS: {0}")]
    Rustls(#[from] AttestedTlsError),
}

#[cfg(test)]
mod tests {
    use futures_util::{sink::SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::protocol::Message;

    use super::*;
    use crate::{
        attestation::{AttestationGenerator, AttestationType, AttestationVerifier},
        test_helpers::{generate_certificate_chain, generate_tls_config},
    };

    #[tokio::test]
    async fn server_attestation_websocket() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let server_addr = server.local_addr().unwrap();

        let ws_server = AttestedWsServer { inner: server };

        tokio::spawn(async move {
            let (mut ws_connection, _measurements, _attestation_type) =
                ws_server.accept().await.unwrap();

            ws_connection
                .send(Message::Text("foo".into()))
                .await
                .unwrap();
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let ws_client = AttestedWsClient { inner: client };

        let (mut ws_connection, _measurements, _attestation_type) =
            ws_client.connect(&server_addr.to_string()).await.unwrap();

        let message = ws_connection.next().await.unwrap().unwrap();

        assert_eq!(message.to_text().unwrap(), "foo");
    }
}
