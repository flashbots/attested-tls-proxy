//! Provides an attested JSON RPC client based on [alloy_rpc_client::RpcClient]
use alloy_rpc_client::RpcClient;
use alloy_transport_http::{Http, HyperClient};
use hyper::{Request, Response, client::conn};
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
    AttestedTlsClient, AttestedTlsError,
    attestation::{AttestationType, measurements::MultiMeasurements},
};

/// Supported HTTP versions for RPC connection bootstrapping
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
    /// This could be a regular JSON RPC server behind an attested TLS proxy.
    pub async fn connect(
        &self,
        server: &str,
        is_local: bool,
    ) -> Result<(RpcClient, Option<MultiMeasurements>, AttestationType), AttestedRpcError> {
        let (stream, measurements, attestation_type) = self.inner.connect_tcp(server).await?;
        let io = TokioIo::new(stream);

        let rpc_client = match self.http_version {
            HttpVersion::Http1 => {
                let (sender, conn) = conn::http1::handshake(io).await?;
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

    async fn make_attested_http1_rpc_client(
        rpc_url: url::Url,
        sender: hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        is_local: bool,
    ) -> Result<RpcClient, AttestedRpcError> {
        let service = Http1ClientConnectionService::new(sender);
        let hyper_transport =
            HyperClient::<http_body_util::Full<bytes::Bytes>, _>::with_service(service);
        let http = Http::with_client(hyper_transport, rpc_url);
        Ok(RpcClient::new(http, is_local))
    }

    async fn make_attested_http2_rpc_client(
        rpc_url: url::Url,
        sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>,
        is_local: bool,
    ) -> Result<RpcClient, AttestedRpcError> {
        let service = Http2ClientConnectionService { sender };
        let hyper_transport =
            HyperClient::<http_body_util::Full<bytes::Bytes>, _>::with_service(service);
        let http = Http::with_client(hyper_transport, rpc_url);
        Ok(RpcClient::new(http, is_local))
    }
}

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
        let mut sender = self.sender.clone();
        Box::pin(async move { sender.send_request(req).await })
    }
}

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

#[derive(Clone)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, sync::Arc};

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::{Value, json};
    use tokio::net::TcpListener;

    use super::AttestedRpcClient;

    use crate::{
        AttestedTlsClient, AttestedTlsServer,
        attestation::{AttestationGenerator, AttestationType, AttestationVerifier},
        test_helpers::{generate_certificate_chain, generate_tls_config},
    };

    async fn simple_json_rpc_service(
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let id = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(Value::Null);

        let response_body = json!({
            "jsonrpc": "2.0",
            "result": "0x1",
            "id": id,
        })
        .to_string();

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(response_body)))
            .unwrap())
    }

    async fn serve_json_rpc_connection(
        server: Arc<AttestedTlsServer>,
        tcp_stream: tokio::net::TcpStream,
    ) {
        let (tls_stream, _measurements, _attestation_type) =
            server.handle_connection(tcp_stream).await.unwrap();
        let io = TokioIo::new(tls_stream);
        let service = service_fn(simple_json_rpc_service);

        hyper::server::conn::http2::Builder::new(hyper_util::rt::tokio::TokioExecutor::new())
            .serve_connection(io, service)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn server_attestation_rpc_client() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = Arc::new(server);

        tokio::spawn(async move {
            let (tcp_stream, _) = listener.accept().await.unwrap();
            serve_json_rpc_connection(server, tcp_stream).await;
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .unwrap();

        let attested_rpc_client = AttestedRpcClient::new_http2(client);

        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&server_addr.to_string(), true)
            .await
            .unwrap();

        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");
    }

    #[tokio::test]
    async fn server_attestation_rpc_client_drops_connection() {
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let server = AttestedTlsServer::new_with_tls_config(
            cert_chain,
            server_config,
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = Arc::new(server);

        let (connection_breaker_tx, connection_breaker_rx) = tokio::sync::oneshot::channel();
        let (connection_closed_tx, connection_closed_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (tcp_stream_1, _) = listener.accept().await.unwrap();
            let first_conn_handle =
                tokio::spawn(serve_json_rpc_connection(server.clone(), tcp_stream_1));

            connection_breaker_rx.await.unwrap();
            first_conn_handle.abort();
            let _ = first_conn_handle.await;
            let _ = connection_closed_tx.send(());

            let (tcp_stream_2, _) = listener.accept().await.unwrap();
            serve_json_rpc_connection(server, tcp_stream_2).await;
        });

        let client = AttestedTlsClient::new_with_tls_config(
            client_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .unwrap();

        let attested_rpc_client = AttestedRpcClient::new_http2(client);

        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&server_addr.to_string(), true)
            .await
            .unwrap();

        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");

        connection_breaker_tx.send(()).unwrap();
        connection_closed_rx.await.unwrap();

        let err = rpc_client
            .request::<(), String>("eth_chainId", ())
            .await
            .unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("connection error") || err_msg.contains("operation was canceled"),
            "unexpected error: {err_msg}"
        );

        let (rpc_client, _measurements, _attestation_type) = attested_rpc_client
            .connect(&server_addr.to_string(), true)
            .await
            .unwrap();

        let response: String = rpc_client.request("eth_chainId", ()).await.unwrap();
        assert_eq!(response, "0x1");
    }
}
