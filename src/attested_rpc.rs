//! Provides an attested JSON RPC client based on [alloy_rpc_client::RpcClient]
use alloy_rpc_client::RpcClient;
use alloy_transport_http::{Http, HyperClient};
use hyper::{client::conn, Request, Response};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use thiserror::Error;
use tower_service::Service;

use crate::{
    attestation::{measurements::MultiMeasurements, AttestationType},
    attested_tls::{AttestedTlsClient, AttestedTlsError},
    TokioExecutor,
};

pub enum HttpVersion {
    Http1,
    Http2,
}

/// An attested TLS client which can create RpcClients for attested connections
pub struct AttestedRpcClient {
    /// The underlying attested TLS client
    pub inner: AttestedTlsClient,
    pub http_version: HttpVersion,
}

impl AttestedRpcClient {
    /// Start an RPC client based on HTTP1.1
    pub fn new_http1(inner: AttestedTlsClient) -> Self {
        Self {
            inner,
            http_version: HttpVersion::Http1,
        }
    }

    /// Start an RPC client based on HTTP2
    pub fn new_http2(inner: AttestedTlsClient) -> Self {
        Self {
            inner,
            http_version: HttpVersion::Http2,
        }
    }

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

        // Setup HTTP client
        let io = TokioIo::new(stream);

        let rpc_client = match self.http_version {
            HttpVersion::Http1 => {
                let (sender, conn) = conn::http1::handshake(io).await?;
                // Drive the connection for the lifetime of `sender`
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::error!("AttestedRpcClient connection error: {e}");
                    }
                });
                let url = url::Url::parse(&format!("http://{server}"))?;
                Self::make_attested_http1_rpc_client(url, sender, is_local).await?
            }
            HttpVersion::Http2 => {
                let (sender, conn) = conn::http2::handshake(TokioExecutor, io).await?;
                // Drive the connection for the lifetime of `sender`
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::error!("AttestedRpcClient connection error: {e}");
                    }
                });
                let url = url::Url::parse(&format!("http://{server}"))?;
                Self::make_attested_http2_rpc_client(url, sender, is_local).await?
            }
        };

        Ok((rpc_client, measurements, attestation_type))
    }

    /// Given an HTTP1 connection, setup RPC client
    async fn make_attested_http1_rpc_client(
        rpc_url: url::Url,
        sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        is_local: bool,
    ) -> Result<RpcClient, AttestedRpcError> {
        let service = Http1ClientConnectionService::new(sender);

        let hyper_transport =
            HyperClient::<http_body_util::Full<bytes::Bytes>, _>::with_service(service);
        let http = Http::with_client(hyper_transport, rpc_url);

        let rpc_client = RpcClient::new(http, is_local);

        Ok(rpc_client)
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

/// Wrap hyper's HTTP1 client connection so we can implement a tower service for it
#[derive(Debug, Clone)]
struct Http1ClientConnectionService {
    sender: Arc<
        tokio::sync::Mutex<
            hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
        >,
    >,
}

impl Http1ClientConnectionService {
    fn new(
        sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    ) -> Self {
        Self {
            sender: tokio::sync::Mutex::new(sender).into(),
        }
    }
}

impl Service<Request<http_body_util::Full<hyper::body::Bytes>>> for Http1ClientConnectionService {
    type Response = Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<http_body_util::Full<hyper::body::Bytes>>) -> Self::Future {
        let sender = self.sender.clone();

        Box::pin(async move {
            let mut sender = sender.lock().await;
            futures_util::future::poll_fn(|cx| sender.poll_ready(cx)).await?;
            sender.send_request(req).await
        })
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
        ProxyServer, ALPN_H2,
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
        let (server_config, mut client_config) =
            generate_tls_config(cert_chain.clone(), private_key);

        let (target_addr, _handle) = spawn_test_rpc_server().await;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr.to_string(),
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });
        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let attested_rpc_client = AttestedRpcClient::new_http2(client);

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
        let (server_config, mut client_config) =
            generate_tls_config(cert_chain.clone(), private_key);

        let (target_addr, _handle) = spawn_test_rpc_server().await;

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr.to_string(),
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

        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let attested_rpc_client = AttestedRpcClient::new_http2(client);

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
