//! HTTP Version support and negotiation
use hyper::Response;
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

        let chosen_protocol = Self::from_alpn_bytes(conn.alpn_protocol());
        tracing::debug!("[server] Chosen protocol {chosen_protocol:?}",);
        chosen_protocol
    }

    /// Given a client TLS stream, choose an HTTP version to use
    pub fn from_negotiated_protocol_client<IO>(tls: &tokio_rustls::client::TlsStream<IO>) -> Self {
        let (_io, conn) = tls.get_ref();

        let chosen_protocol = Self::from_alpn_bytes(conn.alpn_protocol());
        tracing::debug!("[client] Chosen protocol {chosen_protocol:?}",);
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

type Http1Sender = hyper::client::conn::http1::SendRequest<hyper::body::Incoming>;
type Http2Sender = hyper::client::conn::http2::SendRequest<hyper::body::Incoming>;

type Http1Connection = hyper::client::conn::http1::Connection<
    TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    hyper::body::Incoming,
>;

type Http2Connection = hyper::client::conn::http2::Connection<
    TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    hyper::body::Incoming,
    crate::TokioExecutor,
>;

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
    pub async fn send_request(
        &mut self,
        request: http::Request<hyper::body::Incoming>,
    ) -> Result<Response<hyper::body::Incoming>, hyper::Error> {
        match self {
            Self::Http1(sender) => sender.send_request(request).await,
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
    type Output = Result<(), hyper::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            HttpConnectionProj::Http1 { inner } => inner.poll(cx),
            HttpConnectionProj::Http2 { inner } => inner.poll(cx),
        }
    }
}
