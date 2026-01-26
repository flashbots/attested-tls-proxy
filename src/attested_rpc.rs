//! Provides an attested JSON RPC client based on [alloy_rpc_client::RpcClient]
use alloy_rpc_client::RpcClient;
use alloy_transport_http::{Http, HyperClient};
use hyper::{client::conn, Request, Response};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use thiserror::Error;
use tower_service::Service;

use crate::{
    attestation::{measurements::MultiMeasurements, AttestationType},
    attested_tls::{AttestedTlsClient, AttestedTlsError},
    TokioExecutor,
};

/// An attested TLS client which can create RpcClients for attested connections
pub struct AttestedRpcClient {
    /// The underlying attested TLS client
    pub inner: AttestedTlsClient,
}

impl AttestedRpcClient {
    /// Connect to an attested RPC server
    ///
    /// This could be a regular JSON RPC server behind an attested TLS proxy
    ///
    /// `is_local` is passed on to [RpcClient] and represents not whether the connection
    /// leaves the internal network, but whether it is a public RPC or an RPC behind a load
    /// balancer. This gives different client behaviour allowing for less reliable connections.
    pub async fn connect(
        &self,
        server: &str,
        is_local: bool,
    ) -> Result<(RpcClient, Option<MultiMeasurements>, AttestationType), AttestedRpcError> {
        // Make a TCP connection to the attested server, and do TLS handshake and attestation
        // exchange
        let (stream, measurements, attestation_type) = self.inner.connect_tcp(server).await?;

        // Setup HTTP2 client
        let io = TokioIo::new(stream);
        let (sender, conn) = conn::http2::handshake(TokioExecutor, io).await?;

        // Drive the HTTP2 connection for the lifetime of `sender`
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::error!("AttestedRpcClient connection error: {e}");
            }
        });

        let url = url::Url::parse(&format!("http://{server}"))?;
        let rpc_client = Self::make_attested_http2_rpc_client(url, sender, is_local).await?;

        Ok((rpc_client, measurements, attestation_type))
    }

    /// Given an HTTP2 connection, setup RPC client
    async fn make_attested_http2_rpc_client(
        rpc_url: url::Url,
        sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>,
        is_local: bool,
    ) -> Result<RpcClient, AttestedRpcError> {
        let service = Http2ClientConnectionService { sender };

        let hyper_transport =
            HyperClient::<http_body_util::Full<bytes::Bytes>, _>::with_service(service);
        let http = Http::with_client(hyper_transport, rpc_url);

        let rpc_client = RpcClient::new(http, is_local);

        Ok(rpc_client)
    }
}

/// Wrap hyper's HTTP2 client connection so we can implement a tower service for it
#[derive(Debug, Clone)]
struct Http2ClientConnectionService {
    sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
}

impl Service<Request<http_body_util::Full<hyper::body::Bytes>>> for Http2ClientConnectionService {
    type Response = Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, req: Request<http_body_util::Full<hyper::body::Bytes>>) -> Self::Future {
        // Clone so multiple calls can proceed concurrently over the same HTTP2 connection
        let mut sender = self.sender.clone();

        Box::pin(async move {
            // Note: SendRequest docs mention req must have a host header
            sender.send_request(req).await
        })
    }
}

/// An error from attested JSON RPC
#[derive(Error, Debug)]
pub enum AttestedRpcError {
    #[error("Attested TLS: {0}")]
    Rustls(#[from] AttestedTlsError),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Cannot parse URL: {0}")]
    Url(#[from] url::ParseError),
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::{
        attestation::{AttestationGenerator, AttestationType, AttestationVerifier},
        test_helpers::{generate_certificate_chain, generate_tls_config},
        ProxyServer,
    };
    use jsonrpsee::server::{ServerBuilder, ServerHandle};
    use jsonrpsee::RpcModule;

    /// Starts a JSON-RPC HTTP server on a random local port
    async fn spawn_test_rpc_server() -> (SocketAddr, ServerHandle) {
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();

        let addr: SocketAddr = server.local_addr().unwrap();

        let mut module = RpcModule::new(());

        // Mock ethereum-like RPC method
        module
            .register_async_method("eth_chainId", |_params, _ctx, _ext| async move {
                Ok::<_, jsonrpsee::types::ErrorObjectOwned>("0x1")
            })
            .unwrap();

        let handle = server.start(module);

        (addr, handle)
    }

    #[tokio::test]
    async fn server_attestation_rpc_client() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let (target_addr, _handle) = spawn_test_rpc_server().await;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let attested_rpc_client = AttestedRpcClient { inner: client };

        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&proxy_addr.to_string(), true)
            .await
            .unwrap();

        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");
    }

    #[tokio::test]
    async fn server_attestation_rpc_client_drops_connection() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let (target_addr, _handle) = spawn_test_rpc_server().await;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        // This is used to trigger a dropped connection to the proxy server
        let (connection_breaker_tx, connection_breaker_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let connection_handle = proxy_server.accept().await.unwrap();

            // Wait for a signal to simulate a dropped connection, then drop the task handling the
            // connection
            connection_breaker_rx.await.unwrap();
            connection_handle.abort();

            proxy_server.accept().await.unwrap();
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let attested_rpc_client = AttestedRpcClient { inner: client };

        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&proxy_addr.to_string(), true)
            .await
            .unwrap();

        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");

        // Now break the connection
        connection_breaker_tx.send(()).unwrap();

        // Show that the next call fails
        let err = rpc_client
            .request::<(), String>("eth_chainId", ())
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "connection error".to_string());

        // Make another connection
        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&proxy_addr.to_string(), true)
            .await
            .unwrap();

        // Now the call succeeds
        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");
    }
}
