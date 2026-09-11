//! Upload cancellation must work even when Hyper is waiting for HTTP/2 capacity
//! and is not polling the body. Shared state lets the forwarding task drop the
//! source body independently.
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
}

impl UploadState {
    fn finish(&mut self) {
        self.inner.take();
        self.complete = true;
        self.waker.take();
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
    }
}

fn cancel(state: &Mutex<UploadState>) {
    let waker = {
        let mut state = state.lock().unwrap();
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

/// Hyper sends uploads independently of response futures. Keep the permit until
/// the upload finishes or Hyper drops the canceled stream.
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
        if matches!(frame, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) || self.is_end_stream() {
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
