use std::{net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio_tungstenite::{tungstenite::protocol::WebSocketConfig, WebSocketStream};

use crate::{
    attestation::{measurements::MultiMeasurements, AttestationType},
    attested_tls::{AttestedTlsClient, AttestedTlsError, AttestedTlsServer},
};

/// Websocket message type re-exported for convenience
pub use tokio_tungstenite::tungstenite::protocol::Message;

/// An attested Websocket server
pub struct AttestedWsServer {
    /// The underlying attested TLS server
    pub inner: AttestedTlsServer,
    /// Optional websocket configuration
    pub websocket_config: Option<WebSocketConfig>,
    listener: Arc<TcpListener>,
}

impl AttestedWsServer {
    pub async fn new(
        addr: impl ToSocketAddrs,
        inner: AttestedTlsServer,
        websocket_config: Option<WebSocketConfig>,
    ) -> Result<Self, AttestedWsError> {
        let listener = TcpListener::bind(addr).await?;

        Ok(Self {
            listener: listener.into(),
            inner,
            websocket_config,
        })
    }

    /// Accept a Websocket connection
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
        let (tcp_stream, _addr) = self.listener.accept().await?;

        let (stream, measurements, attestation_type) =
            self.inner.handle_connection(tcp_stream).await?;
        Ok((
            tokio_tungstenite::accept_async_with_config(stream, self.websocket_config).await?,
            measurements,
            attestation_type,
        ))
    }

    /// Helper to get the socket address of the underlying TCP listener
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

/// An attested Websocket client
pub struct AttestedWsClient {
    /// The underlying attested TLS client
    pub inner: AttestedTlsClient,
    /// Optional websocket configuration
    pub websocket_config: Option<WebSocketConfig>,
}

impl AttestedWsClient {
    /// Make a Websocket connection
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
        let (stream, measurements, attestation_type) = self.inner.connect_tcp(server).await?;
        let (ws_connection, _response) = tokio_tungstenite::client_async_with_config(
            format!("wss://{server}"),
            stream,
            self.websocket_config,
        )
        .await?;

        Ok((ws_connection, measurements, attestation_type))
    }
}

impl From<AttestedTlsClient> for AttestedWsClient {
    fn from(inner: AttestedTlsClient) -> Self {
        Self {
            inner,
            websocket_config: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum AttestedWsError {
    #[error("Attested TLS: {0}")]
    Rustls(#[from] AttestedTlsError),
    #[error("Websockets: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
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
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let ws_server = AttestedWsServer::new("127.0.0.1:0", server, None)
            .await
            .unwrap();

        let server_addr = ws_server.local_addr().unwrap();

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

        let ws_client: AttestedWsClient = client.into();

        let (mut ws_connection, _measurements, _attestation_type) =
            ws_client.connect(&server_addr.to_string()).await.unwrap();

        let message = ws_connection.next().await.unwrap().unwrap();

        assert_eq!(message.to_text().unwrap(), "foo");
    }
}
