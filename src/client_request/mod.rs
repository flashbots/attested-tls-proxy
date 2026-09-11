//! Per-request forwarding, deadlines, and response lifetime tracking.
#[cfg(test)]
mod tests;
mod upload;
use std::{
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
pub(crate) use upload::RequestBody;

use http_body_util::BodyExt;
use hyper::{
    Response,
    body::{Body, Frame, Incoming, SizeHint},
};
use tokio::{
    sync::{OwnedSemaphorePermit, oneshot},
    time::Instant,
};

use crate::{
    ATTESTATION_TYPE_HEADER, MEASUREMENT_HEADER,
    attestation::{AttestationType, measurements::MultiMeasurements},
    full,
    http_version::HttpSender,
    update_header,
};

/// Limits for requests accepted by a proxy client.
#[derive(Clone, Copy, Debug)]
pub struct ProxyClientOptions {
    /// Deadline covering queueing, request upload, and waiting for response headers.
    /// Response bodies may continue streaming after this deadline.
    pub request_timeout: Duration,
    /// Maximum admitted requests, including responses whose bodies are still streaming.
    /// HTTP/1.1 forwards one request at a time on its shared connection.
    pub max_in_flight_requests: NonZeroUsize,
}

impl Default for ProxyClientOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            max_in_flight_requests: NonZeroUsize::new(64).unwrap(),
        }
    }
}

pub(crate) type ProxyResponse =
    Response<http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>>;

pub(crate) struct PendingRequest {
    pub request: http::Request<Incoming>,
    pub response_tx: oneshot::Sender<ProxyResponse>,
    pub deadline: Instant,
    pub permit: OwnedSemaphorePermit,
}

pub(crate) fn gateway_timeout() -> ProxyResponse {
    let mut response = Response::new(full("Request deadline exceeded"));
    *response.status_mut() = http::StatusCode::GATEWAY_TIMEOUT;
    response
}

pub(crate) struct ForwardResult {
    pub sender: HttpSender,
    pub reconnect: bool,
}

pub(crate) async fn forward(
    mut sender: HttpSender,
    pending: PendingRequest,
    measurements: Option<MultiMeasurements>,
    attestation_type: AttestationType,
) -> ForwardResult {
    let PendingRequest {
        request,
        mut response_tx,
        deadline,
        permit,
    } = pending;
    let http1 = matches!(sender, HttpSender::Http1(_));
    // Expired or canceled queued requests must never be sent to the backend.
    if response_tx.is_closed() || Instant::now() >= deadline {
        let _ = response_tx.send(gateway_timeout());
        return ForwardResult {
            sender,
            reconnect: false,
        };
    }

    let permit = Arc::new(permit);
    let (parts, body) = request.into_parts();
    let (body, upload_guard, mut upload_finished) = RequestBody::new(body, permit.clone());
    let request = http::Request::from_parts(parts, body);

    let response = tokio::select! {
        biased;
        _ = response_tx.closed() => None,
        _ = tokio::time::sleep_until(deadline) => {
            let _ = response_tx.send(gateway_timeout());
            return ForwardResult { reconnect: http1 || sender.is_closed(), sender };
        }
        result = async {
            sender.ready().await?;
            sender.send_request(request).await
        } => Some(result),
    };
    let mut response = match response {
        Some(Ok(response)) => response,
        failure => {
            if let Some(Err(error)) = failure {
                tracing::warn!("Failed to send request to proxy-server: {error}");
                let mut response = Response::new(full(format!("Request failed: {error}")));
                *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                let _ = response_tx.send(response);
            }
            // HTTP/2 stream failures/cancellations must not interrupt other streams.
            return ForwardResult {
                reconnect: http1 || sender.is_closed(),
                sender,
            };
        }
    };

    // These measurements belong to the connection used for this request.
    let headers = response.headers_mut();
    if let Some(measurements) = measurements {
        match measurements.to_header_format() {
            Ok(value) => {
                headers.insert(MEASUREMENT_HEADER, value);
            }
            Err(error) => tracing::error!("Failed to encode measurement values: {error}"),
        }
    }
    update_header(headers, ATTESTATION_TYPE_HEADER, attestation_type.as_str());

    let (finished_tx, mut finished_rx) = oneshot::channel();
    let response = response.map(|inner| {
        let mut body = TrackedBody {
            inner,
            permit: Some(permit.clone()),
            finished: Some(finished_tx),
        };
        if body.inner.is_end_stream() {
            body.finish();
        }
        body.boxed()
    });
    let _ = response_tx.send(response);

    // Early response headers do not mean that the upload has finished. Keep its
    // deadline and the shared permit alive until both directions have completed.
    let mut uploaded = false;
    let mut responded = false;
    let mut upload_ok = true;
    while !uploaded || !responded {
        tokio::select! {
            biased;
            result = &mut upload_finished, if !uploaded => {
                uploaded = true;
                upload_ok = result.is_ok();
            }
            result = &mut finished_rx, if !responded => {
                responded = true;
                if result.is_err() {
                    // Dropping this guard stops an upload still owned by Hyper.
                    drop(upload_guard);
                    return ForwardResult { reconnect: http1 || sender.is_closed(), sender };
                }
            }
            _ = tokio::time::sleep_until(deadline), if !uploaded => {
                // Headers may already have reached the caller, so a 504 can no
                // longer replace them. Cancel the upload instead.
                drop(upload_guard);
                return ForwardResult { reconnect: http1 || sender.is_closed(), sender };
            }
        }
    }
    ForwardResult {
        sender,
        reconnect: http1 && !upload_ok,
    }
}

pin_project_lite::pin_project! {
    struct TrackedBody {
        #[pin]
        inner: Incoming,
        permit: Option<Arc<OwnedSemaphorePermit>>,
        finished: Option<oneshot::Sender<()>>,
    }
}

impl TrackedBody {
    fn finish(&mut self) {
        self.permit.take();
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
    }
}

impl Body for TrackedBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let frame = this.inner.as_mut().poll_frame(cx);
        if matches!(frame, Poll::Ready(Some(Err(_)))) {
            this.permit.take();
            this.finished.take();
        } else if matches!(frame, Poll::Ready(None)) || this.inner.is_end_stream() {
            this.permit.take();
            if let Some(finished) = this.finished.take() {
                let _ = finished.send(());
            }
        }
        frame
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
