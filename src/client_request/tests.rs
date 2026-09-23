use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    routing::{get, post},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinSet,
    time::timeout,
};

use super::ProxyClientOptions;
use crate::{
    AttestationGenerator, AttestationVerifier, ProxyClient, ProxyServer,
    http_version::{ALPN_H2, ALPN_HTTP11},
    test_helpers::{generate_certificate_chain, generate_tls_config},
};

struct Fixture {
    url: String,
    addr: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    _tasks: JoinSet<()>,
}

async fn proxy(app: Router, protocol: &[u8], slots: usize, request_timeout: Duration) -> Fixture {
    proxy_with_idle_timeout(
        app,
        protocol,
        slots,
        request_timeout,
        Duration::from_secs(60),
    )
    .await
}

async fn proxy_with_idle_timeout(
    app: Router,
    protocol: &[u8],
    slots: usize,
    request_timeout: Duration,
    response_body_idle_timeout: Duration,
) -> Fixture {
    let mut tasks = JoinSet::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tasks.spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (certs, key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
    let (mut server_config, mut client_config) = generate_tls_config(certs.clone(), key);
    server_config.alpn_protocols = vec![protocol.to_vec()];
    client_config.alpn_protocols = vec![protocol.to_vec()];
    let server = ProxyServer::new_with_tls_config(
        certs,
        server_config,
        "127.0.0.1:0",
        target.to_string(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
    )
    .await
    .unwrap();
    let target = server.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tasks.spawn(async move {
        loop {
            server.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let client = ProxyClient::new_with_tls_config(
        client_config,
        "127.0.0.1:0",
        target.to_string(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        None,
    )
    .await
    .unwrap()
    .with_request_options(ProxyClientOptions {
        request_timeout,
        max_in_flight_requests: slots.try_into().unwrap(),
        response_body_idle_timeout,
    });
    let addr = client.local_addr().unwrap();
    tasks.spawn(async move {
        loop {
            client.accept().await.unwrap();
        }
    });
    Fixture {
        url: format!("http://{addr}"),
        addr,
        connections,
        _tasks: tasks,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// Real Hyper senders over an in-memory connection make worker failures and
// connection closure deterministic, without racing TCP shutdown against dispatch.
async fn sender_for_test(http2: bool) -> (crate::http_version::HttpSender, JoinSet<()>) {
    use hyper_util::rt::TokioIo;
    let (client, server) = tokio::io::duplex(4096);
    let mut tasks = JoinSet::new();
    let service = hyper::service::service_fn(|_| async {
        Ok::<_, std::convert::Infallible>(hyper::Response::new(crate::full("ok")))
    });
    let sender = if http2 {
        tasks.spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(crate::TokioExecutor)
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        let (sender, connection) = super::http2::handshake(client).await.unwrap();
        tasks.spawn(async move {
            let _ = connection.await;
        });
        sender.into()
    } else {
        tasks.spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .unwrap();
        tasks.spawn(async move {
            let _ = connection.await;
        });
        sender.into()
    };
    (sender, tasks)
}

#[tokio::test]
async fn worker_panic_preserves_http2_sender_but_reconnects_http1() {
    for http2 in [false, true] {
        let (sender, _tasks) = sender_for_test(http2).await;
        let mut sender = Some(sender);
        let worker_sender = super::take_sender(&mut sender).unwrap();
        let failure: Result<super::ForwardResult, _> = tokio::spawn(async move {
            let _sender = worker_sender;
            panic!("simulated forwarding worker panic");
        })
        .await;
        assert!(matches!(&failure, Err(error) if error.is_panic()));
        assert_eq!(super::worker_finished(&mut sender, failure), !http2);
        if http2 {
            let mut next = super::take_sender(&mut sender).unwrap();
            timeout(Duration::from_secs(1), next.ready())
                .await
                .unwrap()
                .unwrap();
            assert!(!next.is_closed());
        } else {
            assert!(sender.is_none());
        }
    }
}

#[tokio::test]
async fn closed_sender_is_not_dispatched() {
    for http2 in [false, true] {
        let (sender, mut tasks) = sender_for_test(http2).await;
        tasks.shutdown().await;
        let mut sender = Some(sender);
        assert!(sender.as_ref().unwrap().is_closed());
        assert!(super::take_sender(&mut sender).is_none());
    }
}

#[tokio::test]
async fn http2_stalled_request_does_not_block_fast_request() {
    let entered = Arc::new(Notify::new());
    let signal = entered.clone();
    let app = Router::new()
        .route(
            "/slow",
            get(move || {
                let signal = signal.clone();
                async move {
                    signal.notify_one();
                    std::future::pending::<&'static str>().await
                }
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_H2, 2, Duration::from_millis(800)).await;
    let client = http_client();
    let slow = tokio::spawn(client.get(format!("{}/slow", fixture.url)).send());
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let fast = timeout(
        Duration::from_millis(400),
        client.get(format!("{}/fast", fixture.url)).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fast.text().await.unwrap(), "fast");
    assert_eq!(
        slow.await.unwrap().unwrap().status(),
        http::StatusCode::GATEWAY_TIMEOUT
    );
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http1_timeout_reconnects_without_replaying_post() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let app = Router::new()
        .route(
            "/slow",
            post(move || {
                let count = count.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<&'static str>().await
                }
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_HTTP11, 2, Duration::from_millis(300)).await;
    let client = http_client();
    let slow = client
        .post(format!("{}/slow", fixture.url))
        .send()
        .await
        .unwrap();
    assert_eq!(slow.status(), http::StatusCode::GATEWAY_TIMEOUT);
    let fast = client
        .get(format!("{}/fast", fixture.url))
        .send()
        .await
        .unwrap();
    assert_eq!(fast.text().await.unwrap(), "fast");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn streaming_bodies_hold_capacity_and_expired_requests_are_not_forwarded() {
    for (protocol, slots) in [(ALPN_H2, 1), (ALPN_HTTP11, 2)] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<
            Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>,
        >(1);
        // A stream which remains open until the test drops body_tx.
        let body_rx = Arc::new(tokio::sync::Mutex::new(Some(body_rx)));
        let app = Router::new()
            .route(
                "/stream",
                get(move || {
                    let body_rx = body_rx.clone();
                    async move {
                        let rx = body_rx.lock().await.take().unwrap();
                        axum::body::Body::new(TestBody(rx))
                    }
                }),
            )
            .route(
                "/fast",
                get(move || {
                    let count = count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        "fast"
                    }
                }),
            );
        let fixture = proxy(app, protocol, slots, Duration::from_millis(300)).await;
        let client = http_client();
        let stream = client
            .get(format!("{}/stream", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(stream.status(), http::StatusCode::OK);
        let blocked = client
            .get(format!("{}/fast", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(blocked.status(), http::StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(body_tx);
        assert!(stream.bytes().await.unwrap().is_empty());
        let fast = client
            .get(format!("{}/fast", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(fast.text().await.unwrap(), "fast");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

// Avoid a new stream adapter dependency for a controllable streaming response.
struct TestBody(
    tokio::sync::mpsc::Receiver<Result<hyper::body::Frame<bytes::Bytes>, std::convert::Infallible>>,
);

impl hyper::body::Body for TestBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.0.poll_recv(cx)
    }
}

#[tokio::test]
async fn http2_disconnected_caller_releases_slot_without_reconnect() {
    let entered = Arc::new(Notify::new());
    let signal = entered.clone();
    let app = Router::new()
        .route(
            "/slow",
            get(move || {
                let signal = signal.clone();
                async move {
                    signal.notify_one();
                    std::future::pending::<&'static str>().await
                }
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_H2, 1, Duration::from_secs(5)).await;
    let mut source = TcpStream::connect(fixture.addr).await.unwrap();
    source
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    drop(source);
    let response = timeout(
        Duration::from_secs(1),
        http_client().get(format!("{}/fast", fixture.url)).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.text().await.unwrap(), "fast");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stalled_upload_times_out_without_blocking_http2() {
    let entered = Arc::new(Notify::new());
    let signal = entered.clone();
    let app = Router::new()
        .route(
            "/upload",
            post(move |request: axum::extract::Request| {
                let signal = signal.clone();
                async move {
                    signal.notify_one();
                    let _ = axum::body::to_bytes(request.into_body(), 1024).await;
                    "upload finished"
                }
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_H2, 2, Duration::from_millis(800)).await;
    let mut source = TcpStream::connect(fixture.addr).await.unwrap();
    source
        .write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
        .await
        .unwrap();
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    let fast = timeout(
        Duration::from_millis(400),
        http_client().get(format!("{}/fast", fixture.url)).send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fast.text().await.unwrap(), "fast");
    let mut response = [0; 1024];
    let len = timeout(Duration::from_secs(2), source.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..len]).starts_with("HTTP/1.1 504"));
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dropping_streaming_response_releases_slot() {
    for protocol in [ALPN_HTTP11, ALPN_H2] {
        let (_body_tx, body_rx) = tokio::sync::mpsc::channel(1);
        let body_rx = Arc::new(tokio::sync::Mutex::new(Some(body_rx)));
        let app =
            Router::new()
                .route(
                    "/stream",
                    get(move || {
                        let body_rx = body_rx.clone();
                        async move {
                            axum::body::Body::new(TestBody(body_rx.lock().await.take().unwrap()))
                        }
                    }),
                )
                .route("/fast", get(|| async { "fast" }));
        let fixture = proxy(app, protocol, 1, Duration::from_secs(5)).await;
        let client = http_client();
        let response = client
            .get(format!("{}/stream", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        drop(response);
        let fast = timeout(
            Duration::from_secs(1),
            client.get(format!("{}/fast", fixture.url)).send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fast.text().await.unwrap(), "fast");
        let expected_connections = if protocol == ALPN_HTTP11 { 2 } else { 1 };
        assert_eq!(
            fixture.connections.load(Ordering::SeqCst),
            expected_connections
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_clean_close_preserves_response() {
    let app = Router::new().route(
        "/",
        get(|| async { ([(http::header::CONNECTION, "close")], "ok") }),
    );
    let fixture = proxy(app, ALPN_HTTP11, 2, Duration::from_secs(3)).await;
    let client = http_client();
    for i in 0..30 {
        let response = client
            .get(format!("{}/", fixture.url))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(status, http::StatusCode::OK, "request {i}: {body}");
        assert_eq!(body, "ok");
    }
}

#[tokio::test]
async fn early_response_keeps_upload_bounded() {
    let active = Arc::new(AtomicUsize::new(0));
    let counter = active.clone();
    let app = Router::new().route(
        "/",
        post(move |request: axum::extract::Request| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = axum::body::to_bytes(request.into_body(), 1024).await;
                    counter.fetch_sub(1, Ordering::SeqCst);
                });
                http::StatusCode::OK
            }
        }),
    );
    let fixture = proxy(app, ALPN_H2, 1, Duration::from_millis(300)).await;
    let mut sources = Vec::new();
    for i in 0..3 {
        let mut source = TcpStream::connect(fixture.addr).await.unwrap();
        source
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
            .await
            .unwrap();
        let mut response = [0; 1024];
        if i > 0 {
            // The previous response was empty, but its unfinished upload must
            // still occupy the sole slot until its deadline cancels it.
            assert!(
                timeout(Duration::from_millis(50), source.read(&mut response))
                    .await
                    .is_err()
            );
        }
        let n = timeout(Duration::from_secs(2), source.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 "));
        sources.push(source);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "uploads survived their request deadline"
    );
}

#[tokio::test]
async fn early_response_allows_upload_to_finish_before_releasing_slot() {
    let (uploaded_tx, uploaded_rx) = tokio::sync::oneshot::channel();
    let uploaded_tx = Arc::new(tokio::sync::Mutex::new(Some(uploaded_tx)));
    let app = Router::new()
        .route(
            "/upload",
            post(move |request: axum::extract::Request| {
                let uploaded_tx = uploaded_tx.clone();
                async move {
                    tokio::spawn(async move {
                        let body = axum::body::to_bytes(request.into_body(), 1024)
                            .await
                            .unwrap();
                        uploaded_tx.lock().await.take().unwrap().send(body).unwrap();
                    });
                    http::StatusCode::OK
                }
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_H2, 1, Duration::from_secs(5)).await;
    let mut source = TcpStream::connect(fixture.addr).await.unwrap();
    source
        .write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\na")
        .await
        .unwrap();
    let mut response = [0; 1024];
    let len = timeout(Duration::from_secs(2), source.read(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&response[..len]).starts_with("HTTP/1.1 200"));

    let mut fast = tokio::spawn(http_client().get(format!("{}/fast", fixture.url)).send());
    assert!(
        timeout(Duration::from_millis(100), &mut fast)
            .await
            .is_err()
    );
    source.write_all(b"bc").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), uploaded_rx)
            .await
            .unwrap()
            .unwrap(),
        "abc"
    );
    let response = timeout(Duration::from_secs(2), fast)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "fast");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn non_reading_source_times_out_and_releases_capacity() {
    for protocol in [ALPN_HTTP11, ALPN_H2] {
        let started = Arc::new(Notify::new());
        let signal = started.clone();
        let app = Router::new()
            .route(
                "/stream",
                get(move || {
                    let signal = signal.clone();
                    async move {
                        let (tx, rx) = tokio::sync::mpsc::channel(1);
                        tokio::spawn(async move {
                            let chunk = bytes::Bytes::from(vec![b'x'; 64 * 1024]);
                            // An endless body eventually fills the source TCP window.
                            while tx
                                .send(Ok(hyper::body::Frame::data(chunk.clone())))
                                .await
                                .is_ok()
                            {
                                signal.notify_one();
                            }
                        });
                        axum::body::Body::new(TestBody(rx))
                    }
                }),
            )
            .route("/fast", get(|| async { "fast" }));
        let fixture = proxy_with_idle_timeout(
            app,
            protocol,
            1,
            Duration::from_secs(5),
            Duration::from_millis(250),
        )
        .await;
        let mut source = TcpStream::connect(fixture.addr).await.unwrap();
        source
            .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        // Keep the connection open without reading any response bytes. The only
        // slot must become available well before the five-second request deadline.
        let response = timeout(
            Duration::from_secs(3),
            http_client().get(format!("{}/fast", fixture.url)).send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.text().await.unwrap(), "fast");
        assert_eq!(
            fixture.connections.load(Ordering::SeqCst),
            if protocol == ALPN_HTTP11 { 2 } else { 1 }
        );
        drop(source);
    }
}

#[tokio::test]
async fn silent_response_body_times_out_and_releases_capacity() {
    for protocol in [ALPN_HTTP11, ALPN_H2] {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let rx = Arc::new(tokio::sync::Mutex::new(Some(rx)));
        let app = Router::new()
            .route(
                "/silent",
                get(move || {
                    let rx = rx.clone();
                    async move { axum::body::Body::new(TestBody(rx.lock().await.take().unwrap())) }
                }),
            )
            .route("/fast", get(|| async { "fast" }));
        let fixture = proxy_with_idle_timeout(
            app,
            protocol,
            1,
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
        .await;
        let client = http_client();
        let response = client
            .get(format!("{}/silent", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert!(
            timeout(Duration::from_secs(2), response.bytes())
                .await
                .unwrap()
                .is_err()
        );
        let response = client
            .get(format!("{}/fast", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "fast");
    }
}

#[tokio::test]
async fn progressing_response_outlives_idle_and_request_deadlines() {
    for protocol in [ALPN_HTTP11, ALPN_H2] {
        let app = Router::new().route(
            "/",
            get(|| async {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                tokio::spawn(async move {
                    for _ in 0..10 {
                        tx.send(Ok(hyper::body::Frame::data(bytes::Bytes::from_static(
                            b"x",
                        ))))
                        .await
                        .unwrap();
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                });
                axum::body::Body::new(TestBody(rx))
            }),
        );
        let fixture = proxy_with_idle_timeout(
            app,
            protocol,
            1,
            Duration::from_millis(200),
            Duration::from_millis(200),
        )
        .await;
        let client = http_client();
        let response = client
            .get(format!("{}/", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "xxxxxxxxxx");
        // An idle keep-alive connection has no active body and must not time out.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let response = client
            .get(format!("{}/", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.text().await.unwrap(), "xxxxxxxxxx");
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn flow_control_blocked_upload_deadline_releases_capacity() {
    let app = Router::new()
        .route(
            "/upload",
            post(|request: axum::extract::Request| async move {
                // Keep the body alive without consuming it. A sufficiently large
                // upload fills both the target socket and the HTTP/2 stream window.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    drop(request);
                });
                http::StatusCode::OK
            }),
        )
        .route("/fast", get(|| async { "fast" }));
    let fixture = proxy(app, ALPN_H2, 1, Duration::from_millis(400)).await;
    let mut source = TcpStream::connect(fixture.addr).await.unwrap();
    source
        .write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000000\r\n\r\n")
        .await
        .unwrap();
    let (mut reader, mut writer) = source.into_split();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _ = writer.write_all(&vec![b'x'; 16 * 1024 * 1024]).await;
        std::future::pending::<()>().await;
    });
    let mut headers = [0; 1024];
    let n = timeout(Duration::from_secs(2), reader.read(&mut headers))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&headers[..n]).starts_with("HTTP/1.1 200"));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let response = http_client()
        .get(format!("{}/fast", fixture.url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "fast");
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
}

// Obtain a real Incoming body without a TCP socket or TLS handshake. The source
// connection stays driven while the forwarding worker consumes the request.
async fn incoming_request(
    raw: Vec<u8>,
    tasks: &mut JoinSet<()>,
) -> http::Request<hyper::body::Incoming> {
    let (mut source, server) = tokio::io::duplex(4096);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    tasks.spawn(async move {
        let service = hyper::service::service_fn(move |request| {
            tx.lock().unwrap().take().unwrap().send(request).unwrap();
            std::future::pending::<
                Result<
                    http::Response<http_body_util::Full<bytes::Bytes>>,
                    std::convert::Infallible,
                >,
            >()
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(server), service)
            .await;
    });
    tasks.spawn(async move {
        let _ = source.write_all(&raw).await;
        std::future::pending::<()>().await;
    });
    rx.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_uploads_reset_streams_and_preserve_other_http2_responses() {
    use http_body_util::BodyExt;
    use std::future::poll_fn;
    let mut tasks = JoinSet::new();
    let (client, server) = tokio::io::duplex(4096);
    let (reset_tx, mut reset_rx) = tokio::sync::mpsc::channel(8);
    let finish_other = Arc::new(Notify::new());
    let finish = finish_other.clone();
    tasks.spawn(async move {
        // No upload can make progress, regardless of socket buffer sizes.
        let mut connection = h2::server::Builder::new()
            .initial_window_size(0)
            .handshake::<_, bytes::Bytes>(server)
            .await
            .unwrap();
        let mut streams = JoinSet::new();
        while let Some(request) = connection.accept().await {
            let (request, mut respond) = request.unwrap();
            let other = request.uri().path() == "/other";
            let mut response = if request.uri().path() == "/late" {
                None
            } else {
                Some(
                    respond
                        .send_response(http::Response::new(()), !other)
                        .unwrap(),
                )
            };
            let reset_tx = reset_tx.clone();
            let finish = finish.clone();
            streams.spawn(async move {
                if other {
                    finish.notified().await;
                    response
                        .as_mut()
                        .unwrap()
                        .send_data(bytes::Bytes::from_static(b"still streaming"), true)
                        .unwrap();
                } else {
                    let reason = match response.as_mut() {
                        Some(response) => poll_fn(|cx| response.poll_reset(cx)).await.unwrap(),
                        None => poll_fn(|cx| respond.poll_reset(cx)).await.unwrap(),
                    };
                    assert_eq!(reason, h2::Reason::CANCEL);
                    reset_tx.send(()).await.unwrap();
                }
                drop(request);
            });
        }
    });
    let (sender, connection) = super::http2::handshake(client).await.unwrap();
    tasks.spawn(async move {
        let _ = connection.await;
    });
    let mut sender = Some(crate::http_version::HttpSender::Http2(sender));
    let slots = Arc::new(tokio::sync::Semaphore::new(2));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let other_request = incoming_request(
        b"GET /other HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        &mut tasks,
    )
    .await;
    let other = tokio::spawn(super::forward(
        super::take_sender(&mut sender).unwrap(),
        super::PendingRequest {
            request: other_request,
            response_tx: tx,
            deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            permit: slots.clone().acquire_owned().await.unwrap(),
        },
        None,
        crate::attestation::AttestationType::None,
    ));
    let response = timeout(Duration::from_secs(1), rx).await.unwrap().unwrap();
    // Cover both completed and partial source bodies, with and without early
    // response headers. Even a fully read source body must wait for send capacity.
    for (path, length, supplied) in [
        ("/upload", 1, 1),
        ("/upload", 1_000_000, 128 * 1024),
        ("/late", 1, 1),
        ("/late", 1_000_000, 128 * 1024),
    ] {
        let mut raw =
            format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\n\r\n")
                .into_bytes();
        raw.extend(vec![b'x'; supplied]);
        let request = incoming_request(raw, &mut tasks).await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(super::forward(
            super::take_sender(&mut sender).unwrap(),
            super::PendingRequest {
                request,
                response_tx: tx,
                deadline: tokio::time::Instant::now() + Duration::from_millis(150),
                permit: slots.clone().acquire_owned().await.unwrap(),
            },
            None,
            crate::attestation::AttestationType::None,
        ));
        assert_eq!(
            rx.await.unwrap().status(),
            if path == "/late" {
                http::StatusCode::GATEWAY_TIMEOUT
            } else {
                http::StatusCode::OK
            },
        );
        let result = timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(!result.reconnect);
        timeout(Duration::from_secs(1), reset_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let permit = timeout(Duration::from_secs(1), slots.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
    }
    finish_other.notify_one();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "still streaming"
    );
    assert!(!other.await.unwrap().reconnect);
}

#[tokio::test]
async fn http2_upload_and_response_preserve_trailers() {
    use http_body_util::BodyExt;
    let mut tasks = JoinSet::new();
    let (client, server) = tokio::io::duplex(4096);
    tasks.spawn(async move {
        let mut connection = h2::server::handshake(server).await.unwrap();
        let mut streams = JoinSet::new();
        while let Some(request) = connection.accept().await {
            let (request, mut respond) = request.unwrap();
            streams.spawn(async move {
                assert!(!request.headers().contains_key("connection"));
                assert!(!request.headers().contains_key("x-hop"));
                assert!(!request.headers().contains_key("transfer-encoding"));
                assert_eq!(request.headers()["te"], "trailers");
                let mut response = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut body = request.into_body();
                let mut received = Vec::new();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    received.extend_from_slice(&data);
                }
                assert_eq!(received, b"abcdef");
                let trailers = body.trailers().await.unwrap().unwrap();
                assert_eq!(trailers["x-checksum"], "valid");
                response
                    .send_data(bytes::Bytes::from(received), false)
                    .unwrap();
                response.send_trailers(trailers).unwrap();
            });
        }
    });
    let (sender, connection) = super::http2::handshake(client).await.unwrap();
    tasks.spawn(async move {
        let _ = connection.await;
    });
    let request = incoming_request(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTE: trailers\r\nTrailer: x-checksum\r\nConnection: x-hop\r\nx-hop: remove\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\nx-checksum: valid\r\n\r\n".to_vec(),
        &mut tasks,
    ).await;
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(super::forward(
        crate::http_version::HttpSender::Http2(sender),
        super::PendingRequest {
            request,
            response_tx: tx,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
            permit: slots.clone().acquire_owned().await.unwrap(),
        },
        None,
        crate::attestation::AttestationType::None,
    ));
    let response = timeout(Duration::from_secs(2), rx).await.unwrap().unwrap();
    let body = timeout(Duration::from_secs(2), response.into_body().collect())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(body.trailers().unwrap()["x-checksum"], "valid");
    assert_eq!(body.to_bytes(), "abcdef");
    assert!(!worker.await.unwrap().reconnect);
    assert_eq!(slots.available_permits(), 1);
}

/// Serves a single-frame response through the idle wrapper on a reusable connection.
async fn finite_idle_response(body: bytes::Bytes) -> (TcpStream, JoinSet<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (inbound, _) = listener.accept().await.unwrap();
    let (io, activity, idle) = super::response_idle::new(inbound, Duration::from_millis(200));
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let service = hyper::service::service_fn(move |_| {
            let response = activity.track(hyper::Response::new(http_body_util::BodyExt::boxed(
                http_body_util::BodyExt::map_err(crate::full(body.clone()), Into::into),
            )));
            async { Ok::<_, std::convert::Infallible>(response) }
        });
        tokio::select! {
            result = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(io), service) => result.unwrap(),
            _ = idle => (),
        }
    });
    (source, tasks)
}

/// Checks that a blocked final frame remains subject to the idle timeout.
#[tokio::test]
async fn idle_timeout_covers_final_buffered_frame() {
    let (mut source, mut tasks) =
        finite_idle_response(bytes::Bytes::from(vec![b'x'; 16 * 1024 * 1024])).await;
    source
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    // Keep the socket open without reading. Consuming the final body frame must
    // not disable the timeout while its bytes are still buffered by Hyper.
    timeout(Duration::from_secs(2), tasks.join_next())
        .await
        .expect("final buffered frame escaped the idle timeout")
        .unwrap()
        .unwrap();
}

/// Checks that flushed empty and nonempty responses leave keep-alive connections usable.
#[tokio::test]
async fn flushed_responses_leave_source_keep_alive() {
    use http_body_util::BodyExt;
    // Empty responses must also disarm the timer after their headers are flushed.
    for body in [bytes::Bytes::new(), bytes::Bytes::from_static(b"ok")] {
        let (source, mut tasks) = finite_idle_response(body.clone()).await;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(source))
                .await
                .unwrap();
        tasks.spawn(async move {
            connection.await.unwrap();
        });
        for _ in 0..2 {
            let response = sender
                .send_request(http::Request::new(crate::full("")))
                .await
                .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                body
            );
            tokio::time::sleep(Duration::from_millis(350)).await;
            assert!(
                !sender.is_closed(),
                "flushed response timed out on keep-alive connection"
            );
        }
    }
}
