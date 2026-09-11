//! Watch response progress outside Hyper's body polling. A blocked source socket
//! must still time out even when Hyper has stopped asking for body frames.
use super::ProxyResponse;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    time::Instant,
};

#[derive(Clone)]
pub(crate) struct ResponseActivity(watch::Sender<Option<Instant>>);

pub(crate) fn new(
    stream: TcpStream,
    timeout: Duration,
) -> (IdleIo, ResponseActivity, impl Future<Output = ()>) {
    let (tx, rx) = watch::channel(None);
    let activity = ResponseActivity(tx);
    (
        IdleIo {
            stream,
            activity: activity.clone(),
        },
        activity,
        wait_for_idle(rx, timeout),
    )
}

async fn wait_for_idle(mut activity: watch::Receiver<Option<Instant>>, timeout: Duration) {
    loop {
        let last_write = *activity.borrow_and_update();
        if let Some(last_write) = last_write {
            tokio::select! {
                result = activity.changed() => { if result.is_err() { return; } }
                _ = tokio::time::sleep_until(last_write + timeout) => {
                    // A write may race with timer expiry. Check the latest value.
                    if activity.borrow().is_some_and(|at| Instant::now() >= at + timeout) {
                        return;
                    }
                }
            }
        } else if activity.changed().await.is_err() {
            return;
        }
    }
}

impl ResponseActivity {
    pub(crate) fn track(&self, response: ProxyResponse) -> ProxyResponse {
        self.0.send_replace(Some(Instant::now()));
        response.map(|inner| {
            let mut body = IdleBody {
                inner,
                activity: Some(self.clone()),
            };
            if body.inner.is_end_stream() {
                body.finish();
            }
            body.boxed()
        })
    }

    fn wrote_bytes(&self, result: &Poll<io::Result<usize>>) {
        if matches!(result, Poll::Ready(Ok(n)) if *n > 0) {
            self.0.send_if_modified(|at| {
                if at.is_some() {
                    *at = Some(Instant::now());
                    true
                } else {
                    false
                }
            });
        }
    }
}

pub(crate) struct IdleIo {
    stream: TcpStream,
    activity: ResponseActivity,
}

impl AsyncRead for IdleIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for IdleIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        self.activity.wrote_bytes(&result);
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        self.activity.wrote_bytes(&result);
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct IdleBody {
    inner: http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>,
    activity: Option<ResponseActivity>,
}

impl IdleBody {
    fn finish(&mut self) {
        if let Some(activity) = self.activity.take() {
            activity.0.send_replace(None);
        }
    }
}

impl Drop for IdleBody {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Body for IdleBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
            || self.inner.is_end_stream()
        {
            self.finish();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
