use super::common::*;
use attested_tls::attestation::{AttestationGenerator, AttestationVerifier};
use attested_tls_proxy::tcp_tunnel::{TunnelClient, TunnelOptions, WarmPoolOptions};
use std::{num::NonZeroUsize, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::test]
async fn warm_connection_completes_mutual_tls_and_attestation_before_source_arrival() {
    super::tunnel::exercise_mutual_attestation(1).await;
}

#[tokio::test]
async fn warm_target_greeting_half_close_and_single_use() {
    bounded(async {
        let target = listener().await;
        let (client, _server) = pair_with_pool(
            target.local_addr().unwrap(),
            TunnelOptions {
                max_connections: NonZeroUsize::new(1).unwrap(),
                ..TunnelOptions::default()
            },
            WarmPoolOptions {
                size: 1,
                ..WarmPoolOptions::default()
            },
        )
        .await;
        // No source exists yet; the pool opens the target in advance.
        let (mut backend, _) = target.accept().await.unwrap();
        backend.write_all(b"greeting").await.unwrap();
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        let mut greeting = [0; 8];
        source.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"greeting");
        source.write_all(b"request").await.unwrap();
        source.shutdown().await.unwrap();
        let mut request = Vec::new();
        backend.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        backend.write_all(b"response").await.unwrap();
        backend.shutdown().await.unwrap();
        let mut response = Vec::new();
        source.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        // A new source uses a different target connection, never the used stream.
        let (mut next_backend, _) = target.accept().await.unwrap();
        let mut next_source = TcpStream::connect(client.addr).await.unwrap();
        next_source.write_all(b"next").await.unwrap();
        let mut next = [0; 4];
        next_backend.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"next");
        // No retry/replay after handoff: closing this target closes this source.
        drop(next_backend);
        assert!(matches!(
            next_source.read(&mut [0; 1]).await,
            Ok(0) | Err(_)
        ));
    })
    .await;
}

#[tokio::test]
async fn shutdown_closes_idle_connections_but_drains_assigned_connections() {
    bounded(async {
        let target = listener().await;
        let (mut client, _server) = pair_with_pool(
            target.local_addr().unwrap(),
            TunnelOptions {
                max_connections: NonZeroUsize::new(3).unwrap(),
                ..TunnelOptions::default()
            },
            WarmPoolOptions {
                size: 2,
                ..WarmPoolOptions::default()
            },
        )
        .await;
        let (mut first, _) = target.accept().await.unwrap();
        let (mut second, _) = target.accept().await.unwrap();
        first.write_all(b"1").await.unwrap();
        second.write_all(b"2").await.unwrap();
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        let id = source.read_u8().await.unwrap();
        let (mut active, mut idle) = if id == b'1' {
            (first, second)
        } else {
            assert_eq!(id, b'2');
            (second, first)
        };
        let (mut refill, _) = target.accept().await.unwrap();
        client.signal();
        assert!(matches!(idle.read(&mut [0; 1]).await, Ok(0) | Err(_)));
        assert!(matches!(refill.read(&mut [0; 1]).await, Ok(0) | Err(_)));
        assert!(!client.is_finished());
        source.write_all(b"still live").await.unwrap();
        source.shutdown().await.unwrap();
        let mut received = Vec::new();
        active.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"still live");
        active.shutdown().await.unwrap();
        assert_eq!(source.read(&mut [0; 1]).await.unwrap(), 0);
        client.wait().await;
    })
    .await;
}

#[tokio::test]
async fn configuration_is_lazy_and_dropping_server_future_cancels_warmups() {
    bounded(async {
        provider();
        let upstream = listener().await;
        let client = TunnelClient::new(
            LOCAL,
            upstream.local_addr().unwrap().to_string(),
            None,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
            false,
            TunnelOptions::default(),
        )
        .await
        .unwrap()
        .with_pool(WarmPoolOptions {
            size: 1,
            ..WarmPoolOptions::default()
        })
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), upstream.accept())
                .await
                .is_err()
        );
        let serving = tokio::spawn(client.serve_until(std::future::pending()));
        let (mut warmup, _) = upstream.accept().await.unwrap();
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
        // Drain a possible ClientHello, then require EOF.
        let mut bytes = Vec::new();
        let _ = warmup.read_to_end(&mut bytes).await;
    })
    .await;
}

#[tokio::test]
async fn invalid_pool_configuration_is_rejected() {
    provider();
    for pool in [
        WarmPoolOptions {
            size: 257,
            ..WarmPoolOptions::default()
        },
        WarmPoolOptions {
            max_age: Duration::ZERO,
            ..WarmPoolOptions::default()
        },
    ] {
        let client = TunnelClient::new(
            LOCAL,
            "localhost:443".into(),
            None,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
            false,
            TunnelOptions::default(),
        )
        .await
        .unwrap();
        assert!(client.with_pool(pool).is_err());
    }
}
