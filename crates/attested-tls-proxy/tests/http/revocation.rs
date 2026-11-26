use std::{
    fs,
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime},
};

use attested_tls::{AttestedTlsClient, TlsCertAndKey, self_signed::generate_self_signed_cert, tls};
use attested_tls_proxy::{AttestationGenerator, ProxyServer, attestation::AttestationVerifier};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::rustls::{crypto::aws_lc_rs, pki_types::PrivatePkcs8KeyDer};

#[tokio::test]
async fn live_http_connections_recheck_anonymous_and_authenticated_peers() {
    let _ = aws_lc_rs::default_provider().install_default();
    for h2 in [false, true] {
        for listed in [false, true] {
            timeout(Duration::from_secs(5), exercise(h2, listed))
                .await
                .unwrap();
        }
    }
}

async fn exercise(h2: bool, listed: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clients");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let identity = listed.then(|| {
        fs::write(&path, hex::encode(key.public_key_raw())).unwrap();
        let cert = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap();
        TlsCertAndKey {
            cert_chain: vec![cert.der().clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        // Omit Date at the origin so the header on the wire must come from the proxy.
        let (stream, _) = listener.accept().await.unwrap();
        hyper::server::conn::http1::Builder::new()
            .auto_date_header(false)
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(|_| async {
                    Ok::<_, std::convert::Infallible>(Response::new(String::from("ok")))
                }),
            )
            .await
            .unwrap();
    });
    let (tls, handler) = connect(h2, identity, &path, target).await;
    let req = || {
        Request::get("http://localhost/")
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    if h2 {
        let (mut tx, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(conn);
        check(async || tx.send_request(req()).await, path, handler).await;
    } else {
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        check(async || tx.send_request(req()).await, path, handler).await;
    }
    backend.abort();
}

async fn check(
    mut request: impl AsyncFnMut() -> Result<Response<Incoming>, hyper::Error>,
    path: std::path::PathBuf,
    handler: JoinHandle<()>,
) {
    let started = SystemTime::now();
    let res = request().await.unwrap();
    let finished = chrono::DateTime::<chrono::Utc>::from(SystemTime::now()).timestamp();
    let started = chrono::DateTime::<chrono::Utc>::from(started).timestamp();
    let value = res.headers()[http::header::DATE].to_str().unwrap();
    let date = chrono::NaiveDateTime::parse_from_str(value, "%a, %d %b %Y %T GMT")
        .unwrap()
        .and_utc()
        .timestamp();
    assert!(
        (started..=finished).contains(&date),
        "Date {value} is outside the request interval ({started}..={finished} Unix seconds)"
    );
    assert_eq!(res.into_body().collect().await.unwrap().to_bytes(), "ok");
    let replacement = path.with_extension("new");
    fs::write(&replacement, "# empty").unwrap();
    fs::rename(replacement, path).unwrap();
    assert!(
        request().await.is_err(),
        "revoked request received HTTP headers"
    );
    handler.await.unwrap(); // The entire connection closed, including on HTTP/2.
}

async fn connect(
    h2: bool,
    identity: Option<TlsCertAndKey>,
    path: &Path,
    target: SocketAddr,
) -> (tokio_rustls::client::TlsStream<TcpStream>, JoinHandle<()>) {
    let server_id = generate_self_signed_cert(target.ip()).unwrap();
    let mut config = tls::client_config(
        identity.as_ref(),
        Some(server_id.cert_chain[0].clone()),
        false,
    )
    .unwrap();
    config.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    let client = AttestedTlsClient::new_with_tls_config(
        config,
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        identity.map(|id| id.cert_chain),
    )
    .unwrap();
    let server = ProxyServer::new(
        server_id,
        "127.0.0.1:0",
        target.to_string(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        tls::ClientAuth::KeyAllowlist {
            path: path.to_owned(),
            open_when_missing: true,
        },
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap().to_string();
    let handler = tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() });
    let (tls, _, _) = client.connect_tcp(&address).await.unwrap();
    (tls, handler)
}

#[tokio::test]
async fn streaming_upload_is_cut_off_when_the_allowlist_appears() {
    let _ = aws_lc_rs::default_provider().install_default();
    timeout(Duration::from_secs(15), async {
        tokio::join!(streaming_upload(false), streaming_upload(true));
    })
    .await
    .unwrap();
}

async fn streaming_upload(h2: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clients");
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut tls, handler) = connect(h2, None, &path, target.local_addr().unwrap()).await;
    let client = tokio::spawn(async move {
        if h2 {
            let (mut tx, connection) = h2::client::handshake(tls).await.unwrap();
            let (response, mut body) = tx
                .send_request(
                    Request::post("http://localhost/")
                        .header(http::header::CONTENT_LENGTH, 16)
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            body.send_data(Bytes::from_static(b"partial!"), false)
                .unwrap();
            let (_, ()) = tokio::join!(connection, async {
                assert!(
                    response.await.is_err(),
                    "revoked upload received a response"
                );
                drop(body);
                drop(tx);
            });
        } else {
            tls.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n8\r\npartial!\r\n").await.unwrap();
            assert!(
                tls.read_u8().await.is_err(),
                "revoked upload received a response"
            );
        }
    });
    let (stream, _) = target.accept().await.unwrap();
    let mut backend = BufReader::new(stream);
    let mut received = Vec::new();
    backend.read_until(b'!', &mut received).await.unwrap();
    assert!(
        received.ends_with(b"partial!"),
        "upload must be in progress"
    );
    fs::write(&path, "# closed").unwrap();
    timeout(Duration::from_secs(6), async {
        handler.await.unwrap();
        client.await.unwrap();
        let result = backend.read_to_end(&mut received).await;
        if let Err(err) = result {
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        }
    })
    .await
    .expect("revocation must close the connection and stop forwarding the upload");
}
