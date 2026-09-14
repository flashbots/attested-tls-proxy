//! Upload cancellation must work while waiting for HTTP/2 capacity, without
//! polling the body. Shared state lets the forwarding task reset the
//! HTTP/2 stream and drop the source body independently.
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::sync::{OwnedSemaphorePermit, oneshot};

struct UploadState {
    inner: Option<Incoming>,
    finished: Option<oneshot::Sender<()>>,
    complete: bool,
    waker: Option<Waker>,
    // Retain both the wire reset and local task cancellation handles because
    // Body::poll_frame cannot interrupt a flow-control capacity wait.
    http2: Option<Arc<Mutex<h2::SendStream<bytes::Bytes>>>>,
    upload_task: Option<tokio::task::AbortHandle>,
    canceled: bool,
}

impl UploadState {
    fn finish(&mut self) {
        self.inner.take();
        self.complete = true;
        self.waker.take();
        if self.http2.is_none()
            && let Some(finished) = self.finished.take()
        {
            let _ = finished.send(());
        }
    }
}

fn cancel(state: &Mutex<UploadState>) {
    let waker = {
        let mut state = state.lock().unwrap();
        state.canceled = true;
        if let Some(stream) = state.http2.take() {
            stream.lock().unwrap().send_reset(h2::Reason::CANCEL);
        }
        // A local reset need not wake our own capacity waiter. Abort the task
        // as well, so it drops its body and permit without any peer progress.
        if let Some(task) = state.upload_task.take() {
            task.abort();
        }
        state.inner.take();
        state.finished.take();
        state.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

pub(super) struct UploadGuard(Arc<Mutex<UploadState>>);

impl Drop for UploadGuard {
    fn drop(&mut self) {
        cancel(&self.0);
    }
}

/// Uploads run independently of response futures. Keep the permit until the
/// upload finishes or its canceled task drops the body.
pub(crate) struct RequestBody {
    state: Arc<Mutex<UploadState>>,
    permit: Option<Arc<OwnedSemaphorePermit>>,
}

impl RequestBody {
    pub(super) fn new(
        inner: Incoming,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> (Self, UploadGuard, oneshot::Receiver<()>) {
        let (finished, receiver) = oneshot::channel();
        let mut state = UploadState {
            inner: Some(inner),
            finished: Some(finished),
            complete: false,
            waker: None,
            http2: None,
            upload_task: None,
            canceled: false,
        };
        if state.inner.as_ref().unwrap().is_end_stream() {
            state.finish();
        }
        let state = Arc::new(Mutex::new(state));
        (
            Self {
                state: state.clone(),
                permit: Some(permit),
            },
            UploadGuard(state),
            receiver,
        )
    }

    pub(crate) fn send_http2(mut self, stream: h2::SendStream<bytes::Bytes>) {
        use http_body_util::BodyExt;
        use std::future::poll_fn;

        let stream = Arc::new(Mutex::new(stream));
        {
            let mut state = self.state.lock().unwrap();
            if state.canceled {
                stream.lock().unwrap().send_reset(h2::Reason::CANCEL);
                return;
            }
            state.http2 = Some(stream.clone());
        }
        let state = self.state.clone();
        let task = tokio::spawn(async move {
            let result: Result<(), super::BoxError> = async {
                loop {
                    let frame = tokio::select! {
                        biased;
                        reset = poll_fn(|cx| stream.lock().unwrap().poll_reset(cx)) => {
                            return Err(reset.map(h2::Error::from).unwrap_or_else(|error| error).into());
                        }
                        frame = self.frame() => frame,
                    };
                    let Some(frame) = frame else { break; };
                    let frame = frame?;
                    match frame.into_data() {
                        Ok(mut data) => {
                            while !data.is_empty() {
                                stream.lock().unwrap().reserve_capacity(data.len());
                                let capacity =
                                    poll_fn(|cx| stream.lock().unwrap().poll_capacity(cx))
                                        .await
                                        .ok_or_else(|| {
                                            io::Error::new(
                                                io::ErrorKind::BrokenPipe,
                                                "HTTP/2 upload closed",
                                            )
                                        })??;
                                if capacity == 0 {
                                    continue;
                                }
                                let chunk = data.split_to(capacity.min(data.len()));
                                stream.lock().unwrap().send_data(chunk, false)?;
                            }
                        }
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                stream.lock().unwrap().send_trailers(trailers)?;
                                return Ok(());
                            }
                        }
                    }
                }
                stream
                    .lock()
                    .unwrap()
                    .send_data(bytes::Bytes::new(), true)?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "HTTP/2 request upload failed");
            } else {
                let mut state = self.state.lock().unwrap();
                state.http2.take();
                state.upload_task.take();
                if let Some(finished) = state.finished.take() {
                    let _ = finished.send(());
                }
            }
            // On failure, Drop resets the stream and closes upload_finished.
        });
        let mut state = state.lock().unwrap();
        if state.canceled {
            task.abort();
        } else if state.http2.is_some() {
            state.upload_task = Some(task.abort_handle());
        }
    }
}

impl Drop for RequestBody {
    fn drop(&mut self) {
        cancel(&self.state);
    }
}

impl Body for RequestBody {
    type Data = bytes::Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let frame = {
            let mut state = self.state.lock().unwrap();
            if state.complete {
                Poll::Ready(None)
            } else if let Some(inner) = state.inner.as_mut() {
                let frame = Pin::new(&mut *inner).poll_frame(cx);
                if matches!(frame, Poll::Ready(Some(Err(_)))) {
                    state.inner.take();
                    state.finished.take();
                } else if matches!(frame, Poll::Ready(None)) || inner.is_end_stream() {
                    state.finish();
                } else {
                    state.waker = Some(cx.waker().clone());
                }
                frame.map(|frame| frame.map(|frame| frame.map_err(io::Error::other)))
            } else {
                Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "request upload canceled",
                ))))
            }
        };
        let http2 = self.state.lock().unwrap().http2.is_some();
        if !http2
            && (matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
                || self.is_end_stream())
        {
            self.permit.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.state.lock().unwrap().complete
    }

    fn size_hint(&self) -> SizeHint {
        self.state
            .lock()
            .unwrap()
            .inner
            .as_ref()
            .map(Body::size_hint)
            .unwrap_or_default()
    }
}
