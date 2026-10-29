//! A small gRPC wire fixture: HTTP/2 DATA contains length-prefixed messages and
//! final status is carried in trailers. No protobuf compiler or external server
//! is needed to exercise the tunnel's transport guarantees.

use super::common::*;
use attested_tls_proxy::tcp_tunnel::TunnelOptions;
use bytes::Bytes;
use h2::{
    RecvStream, SendStream,
    client::{ResponseFuture, SendRequest},
};
use std::{future::poll_fn, time::Duration};
use tokio::net::TcpStream;

fn message(payload: &[u8]) -> Bytes {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.into()
}

async fn send(stream: &mut SendStream<Bytes>, mut bytes: Bytes) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = match poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(capacity) => capacity?,
            None => return Err(poll_fn(|cx| stream.poll_reset(cx)).await?.into()),
        };
        if capacity > 0 {
            stream.send_data(bytes.split_to(capacity.min(bytes.len())), false)?;
        }
    }
    Ok(())
}

async fn collect(mut body: RecvStream, status: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    while let Some(data) = body.data().await {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        bytes.extend_from_slice(&data);
    }
    let trailers = body.trailers().await.unwrap().unwrap();
    assert_eq!(trailers["grpc-status"], status);
    assert_eq!(trailers["x-result-bin"], "AAEC");
    bytes
}

async fn open(sender: SendRequest<Bytes>, method: &str) -> (ResponseFuture, SendStream<Bytes>) {
    let mut sender = sender.ready().await.unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("http://application.example/test.Service/{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("x-input-bin", "AAEC")
        .header("x-repeat", "first")
        .header("x-repeat", "second")
        .body(())
        .unwrap();
    sender.send_request(request, false).unwrap()
}

async fn handle(request: http::Request<RecvStream>, mut respond: h2::server::SendResponse<Bytes>) {
    assert_eq!(
        request.uri().authority().unwrap().as_str(),
        "application.example"
    );
    assert_eq!(request.headers()["te"], "trailers");
    assert_eq!(request.headers()["x-input-bin"], "AAEC");
    assert_eq!(request.headers().get_all("x-repeat").iter().count(), 2);
    let method = request.uri().path().rsplit('/').next().unwrap().to_owned();
    let response = http::Response::builder().header("content-type", "application/grpc");
    if method == "TrailersOnly" {
        respond
            .send_response(response.header("grpc-status", "7").body(()).unwrap(), true)
            .unwrap();
        return;
    }
    let mut response = respond
        .send_response(response.body(()).unwrap(), false)
        .unwrap();
    if method == "Cancel" {
        // Exceed the response window while the caller deliberately does not read.
        // RST_STREAM must still get through and leave sibling streams usable.
        let result = send(&mut response, message(&vec![42; 256 * 1024])).await;
        match result {
            Ok(()) => assert_eq!(
                poll_fn(|cx| response.poll_reset(cx)).await.unwrap(),
                h2::Reason::CANCEL
            ),
            Err(error) => assert_eq!(error.reason(), Some(h2::Reason::CANCEL)),
        }
        return;
    }
    let mut request = request.into_body();
    let mut input = Vec::new();
    while let Some(data) = request.data().await {
        let data = data.unwrap();
        request.flow_control().release_capacity(data.len()).unwrap();
        if method == "Bidi" {
            send(&mut response, data).await.unwrap();
        } else {
            input.extend_from_slice(&data);
        }
    }
    if method == "ServerStream" {
        send(&mut response, message(b"first")).await.unwrap();
        send(&mut response, message(b"second")).await.unwrap();
    } else if method != "Bidi" {
        send(&mut response, input.into()).await.unwrap();
    }
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "grpc-status",
        if method == "Error" { "13" } else { "0" }.parse().unwrap(),
    );
    trailers.insert("x-result-bin", "AAEC".parse().unwrap());
    response.send_trailers(trailers).unwrap();
}

#[tokio::test]
async fn grpc_streaming_multiplexing_trailers_and_cancellation() {
    bounded(async {
        let target = listener().await;
        let options = TunnelOptions {
            setup_timeout: Duration::from_secs(1),
            ..TunnelOptions::default()
        };
        let (client, _server) = pair(target.local_addr().unwrap(), options).await;
        let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
        let backend = tokio::spawn(async move {
            let (socket, _) = target.accept().await.unwrap();
            // All RPCs below must travel over this single target connection.
            let mut connection = h2::server::handshake(socket).await.unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            let mut cancelled_tx = Some(cancelled_tx);
            while let Some(result) = connection.accept().await {
                let (request, response) = result.unwrap();
                let cancelled = if request.uri().path().ends_with("/Cancel") {
                    cancelled_tx.take()
                } else {
                    None
                };
                tasks.spawn(async move {
                    handle(request, response).await;
                    if let Some(tx) = cancelled {
                        let _ = tx.send(());
                    }
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let socket = TcpStream::connect(client.addr).await.unwrap();
        // Leave connection-level capacity for siblings when one stream consumes
        // its entire (default 64 KiB) receive window without being read.
        let (sender, connection) = h2::client::Builder::new()
            .initial_connection_window_size(1024 * 1024)
            .handshake(socket)
            .await
            .unwrap();
        let driver = tokio::spawn(connection);

        let (response, mut bidi) = open(sender.clone(), "Bidi").await;
        let mut bidi_response = response.await.unwrap().into_body();
        // Neither an unfinished upload nor an idle response should inherit the
        // setup deadline once the tunnel has been established.
        tokio::time::sleep(Duration::from_millis(1100)).await;

        let (cancelled_response, mut cancelled_upload) = open(sender.clone(), "Cancel").await;
        cancelled_upload.send_data(Bytes::new(), true).unwrap();
        let held_response = cancelled_response.await.unwrap();

        let mut calls = tokio::task::JoinSet::new();
        for method in ["Unary", "ClientStream", "ServerStream", "Error"] {
            let sender = sender.clone();
            calls.spawn(async move {
                let (response, mut upload) = open(sender, method).await;
                let mut expected = message(b"hello").to_vec();
                // Deliberately split a gRPC message across DATA frames.
                upload
                    .send_data(Bytes::copy_from_slice(&expected[..2]), false)
                    .unwrap();
                upload
                    .send_data(Bytes::copy_from_slice(&expected[2..]), false)
                    .unwrap();
                if method == "ClientStream" {
                    upload.send_data(message(b"again"), false).unwrap();
                    expected.extend_from_slice(&message(b"again"));
                }
                upload.send_data(Bytes::new(), true).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.headers()["content-type"], "application/grpc");
                let body = collect(
                    response.into_body(),
                    if method == "Error" { "13" } else { "0" },
                )
                .await;
                if method == "ServerStream" {
                    expected = [message(b"first"), message(b"second")].concat();
                }
                assert_eq!(body, expected);
            });
        }
        for payload in [b"one".as_slice(), b"two", b"three"] {
            let expected = message(payload);
            bidi.send_data(expected.clone(), false).unwrap();
            let data = bidi_response.data().await.unwrap().unwrap();
            bidi_response
                .flow_control()
                .release_capacity(data.len())
                .unwrap();
            assert_eq!(data, expected);
        }
        cancelled_upload.send_reset(h2::Reason::CANCEL);
        cancelled_rx.await.unwrap();
        drop(held_response);
        while let Some(result) = calls.join_next().await {
            result.unwrap();
        }
        bidi.send_data(Bytes::new(), true).unwrap();
        assert!(collect(bidi_response, "0").await.is_empty());

        let (response, mut upload) = open(sender.clone(), "TrailersOnly").await;
        upload.send_data(Bytes::new(), true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
        assert!(response.into_body().is_end_stream());

        // A new call after cancellation must still succeed on this connection.
        let (response, mut upload) = open(sender.clone(), "Unary").await;
        upload
            .send_data(message(b"after cancellation"), true)
            .unwrap();
        assert_eq!(
            collect(response.await.unwrap().into_body(), "0").await,
            message(b"after cancellation")
        );
        drop(sender);
        driver.abort();
        backend.abort();
    })
    .await;
}
