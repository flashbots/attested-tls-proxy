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
        // Cleanup must also work during unwinding after a panic under this lock.
        // Recover the guard only to discard the upload, never to resume it.
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.canceled = true;
        if let Some(stream) = state.http2.take() {
            stream
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .send_reset(h2::Reason::CANCEL);
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

/// Locks a stream for normal operation, rejecting poisoned state.
fn lock_stream(
    stream: &Mutex<h2::SendStream<bytes::Bytes>>,
) -> io::Result<std::sync::MutexGuard<'_, h2::SendStream<bytes::Bytes>>> {
    stream
        .lock()
        .map_err(|_| io::Error::other("HTTP/2 upload stream poisoned"))
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
            let Ok(mut state) = self.state.lock() else {
                stream
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .send_reset(h2::Reason::CANCEL);
                return;
            };
            if state.canceled {
                stream
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .send_reset(h2::Reason::CANCEL);
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
                        reset = poll_fn(|cx| match lock_stream(&stream) {
                            Ok(mut stream) => stream.poll_reset(cx).map_err(super::BoxError::from),
                            Err(error) => Poll::Ready(Err(error.into())),
                        }) => {
                            return Err(reset.map(|reason| super::BoxError::from(h2::Error::from(reason))).unwrap_or_else(|error| error));
                        }
                        frame = self.frame() => frame,
                    };
                    let Some(frame) = frame else { break; };
                    let frame = frame?;
                    match frame.into_data() {
                        Ok(mut data) => {
                            while !data.is_empty() {
                                lock_stream(&stream)?.reserve_capacity(data.len());
                                let capacity =
                                    poll_fn(|cx| match lock_stream(&stream) {
                                        Ok(mut stream) => stream.poll_capacity(cx).map(|capacity| capacity.transpose().map_err(super::BoxError::from)),
                                        Err(error) => Poll::Ready(Err(error.into())),
                                    })
                                        .await?
                                        .ok_or_else(|| {
                                            io::Error::new(
                                                io::ErrorKind::BrokenPipe,
                                                "HTTP/2 upload closed",
                                            )
                                        })?;
                                if capacity == 0 {
                                    continue;
                                }
                                let chunk = data.split_to(capacity.min(data.len()));
                                lock_stream(&stream)?.send_data(chunk, false)?;
                            }
                        }
                        Err(frame) => {
                            if let Ok(trailers) = frame.into_trailers() {
                                lock_stream(&stream)?.send_trailers(trailers)?;
                                return Ok(());
                            }
                        }
                    }
                }
                lock_stream(&stream)?.send_data(bytes::Bytes::new(), true)?;
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%error, "HTTP/2 request upload failed");
            } else {
                let Ok(mut state) = self.state.lock() else {
                    return;
                };
                state.http2.take();
                state.upload_task.take();
                if let Some(finished) = state.finished.take() {
                    let _ = finished.send(());
                }
            }
            // On failure, Drop resets the stream and closes upload_finished.
        });
        let Ok(mut state) = state.lock() else {
            task.abort();
            cancel(&state);
            return;
        };
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
        let frame = match self.state.lock() {
            Err(_) => Poll::Ready(Some(Err(io::Error::other("request upload state poisoned")))),
            Ok(mut state) => {
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
            }
        };
        if matches!(frame, Poll::Ready(Some(Err(_)))) {
            cancel(&self.state);
        }
        let http2 = self
            .state
            .lock()
            .map(|state| state.http2.is_some())
            .unwrap_or(false);
        if !http2
            && (matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
                || self.is_end_stream())
        {
            self.permit.take();
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.complete)
            .unwrap_or(false)
    }

    fn size_hint(&self) -> SizeHint {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.inner.as_ref().map(Body::size_hint))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// Checks that poisoned upload state returns an error and releases its capacity.
    #[tokio::test]
    async fn poisoned_upload_state_releases_capacity() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let (finished, receiver) = oneshot::channel();
        let state = Arc::new(Mutex::new(UploadState {
            inner: None,
            finished: Some(finished),
            complete: false,
            waker: None,
            http2: None,
            upload_task: None,
            canceled: false,
        }));
        let mut body = RequestBody {
            state: state.clone(),
            permit: Some(Arc::new(slots.clone().acquire_owned().await.unwrap())),
        };
        let guard = UploadGuard(state.clone());
        let _ = std::panic::catch_unwind(|| {
            let _lock = state.lock().unwrap();
            panic!("poison upload state");
        });
        assert!(body.frame().await.unwrap().is_err());
        assert!(receiver.await.is_err());
        drop(body);
        drop(guard);
        assert_eq!(slots.available_permits(), 1);
    }
}
