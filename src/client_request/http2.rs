//! HTTP/2 forwarding with an explicit reset handle for each request upload.
//! Hyper's client hides this handle after returning response headers, so a body
//! waiting for send capacity cannot otherwise be canceled through its Body API.
use std::{
    future::poll_fn,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{BoxError, ProxyResponse, RequestBody};
use crate::ProxyError;

pub(crate) type Connection = Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send>>;

#[derive(Clone)]
pub(crate) struct Sender {
    inner: h2::client::SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
}

pub(crate) async fn handshake<T>(io: T) -> Result<(Sender, Connection), ProxyError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (inner, mut connection) = h2::client::Builder::new()
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(5 * 1024 * 1024)
        .max_header_list_size(16 * 1024)
        .enable_push(false)
        .handshake(io)
        .await?;
    let ping = connection.ping_pong().expect("ping handle available once");
    let closed = Arc::new(AtomicBool::new(false));
    let sender = Sender {
        inner,
        closed: closed.clone(),
    };
    // Mark the sender closed on completion, cancellation, or a keep-alive failure.
    struct Closed(Arc<AtomicBool>);
    impl Drop for Closed {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let closed = Closed(closed);
    let connection = Box::pin(async move {
        let _closed = closed;
        tokio::select! {
            result = &mut connection => result.map_err(Into::into),
            result = keep_alive(ping) => result,
        }
    });
    Ok((sender, connection))
}

async fn keep_alive(mut ping: h2::PingPong) -> Result<(), ProxyError> {
    loop {
        tokio::time::sleep(Duration::from_secs(crate::KEEP_ALIVE_INTERVAL)).await;
        tokio::time::timeout(
            Duration::from_secs(crate::KEEP_ALIVE_TIMEOUT),
            ping.ping(h2::Ping::opaque()),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP/2 keep-alive timed out")
        })??;
    }
}

impl Sender {
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub(crate) async fn ready(&mut self) -> Result<(), ProxyError> {
        poll_fn(|cx| self.inner.poll_ready(cx))
            .await
            .map_err(|error| {
                self.closed.store(true, Ordering::Release);
                error.into()
            })
    }

    pub(crate) async fn send_request(
        &mut self,
        request: http::Request<RequestBody>,
    ) -> Result<ProxyResponse, ProxyError> {
        let (mut parts, body) = request.into_parts();
        strip_connection_headers(&mut parts.headers);
        if let Some(length) = body.size_hint().exact()
            && (length != 0
                || matches!(
                    parts.method,
                    http::Method::POST | http::Method::PUT | http::Method::PATCH
                ))
        {
            parts
                .headers
                .entry(http::header::CONTENT_LENGTH)
                .or_insert(length.into());
        }
        let end = body.is_end_stream();
        let (response, stream) = self
            .inner
            .send_request(http::Request::from_parts(parts, ()), end)?;
        if !end {
            body.send_http2(stream);
        }
        let response = response.await?;
        Ok(response.map(|inner| {
            ResponseBody {
                inner,
                data_done: false,
            }
            .boxed()
        }))
    }
}

fn strip_connection_headers(headers: &mut http::HeaderMap) {
    let connection_headers: Vec<http::header::HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| name.trim().parse().ok())
        .collect();
    headers.remove(http::header::CONNECTION);
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    if headers
        .get(http::header::TE)
        .is_some_and(|value| value != "trailers")
    {
        headers.remove(http::header::TE);
    }
}

struct ResponseBody {
    inner: h2::RecvStream,
    data_done: bool,
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if !self.data_done {
            match std::task::ready!(self.inner.poll_data(cx)) {
                Some(Ok(data)) => {
                    if let Err(error) = self.inner.flow_control().release_capacity(data.len()) {
                        return Poll::Ready(Some(Err(error.into())));
                    }
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Some(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
                None => self.data_done = true,
            }
        }
        self.inner.poll_trailers(cx).map(|result| match result {
            Ok(trailers) => trailers.map(|trailers| Ok(Frame::trailers(trailers))),
            Err(error) => Some(Err(error.into())),
        })
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::strip_connection_headers;

    /// Removes headers nominated by every Connection field, including comma-separated names.
    #[test]
    fn strips_all_connection_header_values() {
        let mut headers = http::HeaderMap::new();
        headers.append("connection", "x-first, connection".parse().unwrap());
        headers.append("connection", " X-Second, x-third ".parse().unwrap());
        for name in ["x-first", "x-second", "x-third", "x-end-to-end"] {
            headers.insert(name, "value".parse().unwrap());
        }
        headers.insert("te", "trailers".parse().unwrap());

        strip_connection_headers(&mut headers);

        for name in ["connection", "x-first", "x-second", "x-third"] {
            assert!(!headers.contains_key(name), "unexpected header: {name}");
        }
        assert_eq!(headers["x-end-to-end"], "value");
        assert_eq!(headers["te"], "trailers");
    }
}
