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

#[derive(Clone)]
pub struct SingleH2Service {
    sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
}

impl SingleH2Service {
    pub fn new(
        sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<hyper::body::Bytes>>,
    ) -> Self {
        Self { sender }
    }
}

impl Service<Request<http_body_util::Full<hyper::body::Bytes>>> for SingleH2Service {
    type Response = Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // hyper’s SendRequest has readiness APIs; this is the most correct place to use them.
        self.sender.poll_ready(cx)
    }

    fn call(&mut self, req: Request<http_body_util::Full<hyper::body::Bytes>>) -> Self::Future {
        // Clone so multiple calls can proceed concurrently over the same H2 connection. :contentReference[oaicite:5]{index=5}
        let mut sender = self.sender.clone();

        Box::pin(async move {
            // Note: SendRequest docs mention req must have a Host header. :contentReference[oaicite:6]{index=6}
            sender.send_request(req).await
        })
    }
}

pub async fn make_rpc_client_attested_h2(
    rpc_url: url::Url,
    sender: hyper::client::conn::http2::SendRequest<http_body_util::Full<bytes::Bytes>>,
) -> Result<RpcClient, Box<dyn std::error::Error + Send + Sync>> {
    let service = SingleH2Service::new(sender);

    let hyper_transport =
        HyperClient::<http_body_util::Full<bytes::Bytes>, _>::with_service(service);
    let http = Http::with_client(hyper_transport, rpc_url);
    let rpc_client = RpcClient::new(http, true);

    Ok(rpc_client)
}

pub struct AttestedRpcClient {
    /// The underlying attested TLS client
    pub inner: AttestedTlsClient,
}

impl AttestedRpcClient {
    pub async fn connect(
        &self,
        server: &str,
    ) -> Result<(RpcClient, Option<MultiMeasurements>, AttestationType), AttestedRpcError> {
        let (stream, measurements, attestation_type) = self.inner.connect_tcp(server).await?;

        let io = TokioIo::new(stream);
        let (sender, conn) = conn::http2::handshake(TokioExecutor, io).await?;

        // Drive the h2 connection for the lifetime of `sender`.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("attested h2 connection error: {e}");
            }
        });

        let rpc_client = make_rpc_client_attested_h2(server.try_into().unwrap(), sender)
            .await
            .unwrap();

        Ok((rpc_client, measurements, attestation_type))
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
}
