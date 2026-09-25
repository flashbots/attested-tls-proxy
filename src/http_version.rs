//! HTTP Version support and negotiation
use crate::client_request::RequestBody;
use crate::{
    ProxyError,
    client_request::{ProxyResponse, http2},
};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::pin::Pin;
use std::task::{Context, Poll};

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Supported HTTP versions
#[derive(Debug)]
pub enum HttpVersion {
    /// HTTP 1.1
    Http1,
    /// HTTP 2
    Http2,
}

impl HttpVersion {
    /// Given a server TLS stream, choose an HTTP version to use
    pub fn from_negotiated_protocol_server<IO>(tls: &tokio_rustls::server::TlsStream<IO>) -> Self {
        let (_io, conn) = tls.get_ref();

        let negotiated_alpn = conn.alpn_protocol();
        let chosen_protocol = Self::from_alpn_bytes(negotiated_alpn);
        tracing::debug!(
            "[server] Negotiated ALPN {:?}, chosen protocol {chosen_protocol:?}",
            negotiated_alpn.map(String::from_utf8_lossy)
        );
        chosen_protocol
    }

    /// Given a client TLS stream, choose an HTTP version to use
    pub fn from_negotiated_protocol_client<IO>(tls: &tokio_rustls::client::TlsStream<IO>) -> Self {
        let (_io, conn) = tls.get_ref();

        let negotiated_alpn = conn.alpn_protocol();
        let chosen_protocol = Self::from_alpn_bytes(negotiated_alpn);
        tracing::debug!(
            "[client] Negotiated ALPN {:?}, chosen protocol {chosen_protocol:?}",
            negotiated_alpn.map(String::from_utf8_lossy)
        );
        chosen_protocol
    }

    fn from_alpn_bytes(chosen_protocol: Option<&[u8]>) -> Self {
        match chosen_protocol {
            Some(p) if p.ends_with(ALPN_H2) => HttpVersion::Http2,
            Some(p) if p.ends_with(ALPN_HTTP11) => HttpVersion::Http1,
            _ => HttpVersion::Http1,
        }
    }
}

type Http1Sender = hyper::client::conn::http1::SendRequest<RequestBody>;
type Http2Sender = http2::Sender;

type Http1Connection = hyper::client::conn::http1::Connection<
    TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    RequestBody,
>;

type Http2Connection = http2::Connection;

/// A protocol version agnostic HTTP sender
pub enum HttpSender {
    Http1(Http1Sender),
    Http2(Http2Sender),
}

impl From<Http1Sender> for HttpSender {
    fn from(inner: Http1Sender) -> Self {
        Self::Http1(inner)
    }
}

impl From<Http2Sender> for HttpSender {
    fn from(inner: Http2Sender) -> Self {
        Self::Http2(inner)
    }
}

impl HttpSender {
    pub async fn ready(&mut self) -> Result<(), ProxyError> {
        match self {
            Self::Http1(sender) => sender.ready().await.map_err(Into::into),
            Self::Http2(sender) => sender.ready().await,
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Self::Http1(sender) => sender.is_closed(),
            Self::Http2(sender) => sender.is_closed(),
        }
    }

    pub async fn send_request(
        &mut self,
        request: http::Request<RequestBody>,
    ) -> Result<ProxyResponse, ProxyError> {
        match self {
            Self::Http1(sender) => sender
                .send_request(request)
                .await
                .map(|response| response.map(|body| body.map_err(Into::into).boxed()))
                .map_err(Into::into),
            Self::Http2(sender) => sender.send_request(request).await,
        }
    }
}

pin_project_lite::pin_project! {
    /// A protocol version agnostic HTTP connection
    #[project = HttpConnectionProj]
    pub enum HttpConnection {
        Http1 { #[pin] inner: Http1Connection },
        Http2 { #[pin] inner: Http2Connection },
    }
}

impl From<Http1Connection> for HttpConnection {
    fn from(inner: Http1Connection) -> Self {
        Self::Http1 { inner }
    }
}

impl From<Http2Connection> for HttpConnection {
    fn from(inner: Http2Connection) -> Self {
        Self::Http2 { inner }
    }
}

impl Future for HttpConnection {
    type Output = Result<(), ProxyError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            HttpConnectionProj::Http1 { inner } => inner.poll(cx).map_err(Into::into),
            HttpConnectionProj::Http2 { inner } => inner.poll(cx),
        }
    }
}
