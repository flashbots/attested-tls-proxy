mod common;

use attested_tls::{
    AttestedTlsClient, AttestedTlsServer,
    attestation::{AttestationGenerator, AttestationType, AttestationVerifier},
    self_signed::generate_self_signed_cert,
};
use attested_tls_tcp_tunnel::{TunnelClient, TunnelOptions, TunnelServer, tls};
use common::*;
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::rustls::{self, RootCertStore, server::WebPkiClientVerifier};

async fn closed(stream: &mut (impl tokio::io::AsyncRead + Unpin)) {
    match stream.read(&mut [0; 1]).await {
        Ok(0) | Err(_) => {}
        result => panic!("expected EOF or transport error, got {result:?}"),
    }
}

#[tokio::test]
async fn large_binary_transfer_and_source_half_close() {
    bounded(async {
        let target = listener().await;
        let (client, _server) = pair(target.local_addr().unwrap(), TunnelOptions::default()).await;
        let payload: Vec<u8> = (0..1024 * 1024).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, expected);
            input.reverse();
            stream.write_all(&input).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        source.write_all(&payload).await.unwrap();
        source.shutdown().await.unwrap();
        let mut response = Vec::new();
        source.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload.into_iter().rev().collect::<Vec<_>>());
        backend.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn target_half_close_preserves_remaining_upload() {
    bounded(async {
        let target = listener().await;
        let (client, _server) = pair(target.local_addr().unwrap(), TunnelOptions::default()).await;
        let backend = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.unwrap();
            stream.write_all(b"greeting").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).await.unwrap();
            assert_eq!(input, b"after EOF");
        });
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        let mut response = Vec::new();
        source.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"greeting");
        source.write_all(b"after EOF").await.unwrap();
        source.shutdown().await.unwrap();
        backend.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn simultaneous_transfers_use_independent_target_connections() {
    bounded(async {
        let target = listener().await;
        let (client, _server) = pair(target.local_addr().unwrap(), TunnelOptions::default()).await;
        let backend = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let (stream, _) = target.accept().await.unwrap();
                tasks.spawn(async move {
                    let (mut read, mut write) = stream.into_split();
                    let output = vec![42; 512 * 1024];
                    let upload = async {
                        let mut input = Vec::new();
                        read.read_to_end(&mut input).await.unwrap();
                        assert_eq!(input.len(), output.len());
                    };
                    let download = async {
                        write.write_all(&output).await.unwrap();
                        write.shutdown().await.unwrap();
                    };
                    tokio::join!(upload, download);
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let mut tasks = tokio::task::JoinSet::new();
        for n in 0..4 {
            let addr = client.addr;
            tasks.spawn(async move {
                let stream = TcpStream::connect(addr).await.unwrap();
                let (mut read, mut write) = stream.into_split();
                let upload = async {
                    write.write_all(&vec![n; 512 * 1024]).await.unwrap();
                    write.shutdown().await.unwrap();
                };
                let download = async {
                    let mut output = Vec::new();
                    read.read_to_end(&mut output).await.unwrap();
                    assert_eq!(output, vec![42; 512 * 1024]);
                };
                tokio::join!(upload, download);
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        backend.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn client_capacity_includes_setup_and_timeout_does_not_retry() {
    bounded(async {
        provider();
        let stalled_server = listener().await;
        let options = TunnelOptions {
            setup_timeout: Duration::from_millis(150),
            max_connections: NonZeroUsize::new(1).unwrap(),
            ..TunnelOptions::default()
        };
        let client = TunnelClient::new(
            LOCAL,
            stalled_server.local_addr().unwrap().to_string(),
            None,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
            options,
        )
        .await
        .unwrap();
        // Construction has no upstream side effects.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), stalled_server.accept())
                .await
                .is_err()
        );
        let client = Running::client(client);
        let mut first = TcpStream::connect(client.addr).await.unwrap();
        let (_stalled, _) = stalled_server.accept().await.unwrap();
        let mut excess = TcpStream::connect(client.addr).await.unwrap();
        closed(&mut excess).await;
        closed(&mut first).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), stalled_server.accept())
                .await
                .is_err()
        );
        let mut next = TcpStream::connect(client.addr).await.unwrap();
        let (_next, _) = stalled_server.accept().await.unwrap();
        closed(&mut next).await;
    })
    .await;
}

#[tokio::test]
async fn server_capacity_includes_handshakes_and_recovers() {
    bounded(async {
        provider();
        let target = listener().await;
        let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
        let options = TunnelOptions {
            setup_timeout: Duration::from_millis(200),
            max_connections: NonZeroUsize::new(1).unwrap(),
            ..TunnelOptions::default()
        };
        let server = Running::server(
            TunnelServer::new(
                LOCAL,
                target.local_addr().unwrap().to_string(),
                identity,
                AttestationGenerator::with_no_attestation(),
                AttestationVerifier::expect_none(),
                false,
                options,
            )
            .await
            .unwrap(),
        );
        let mut first = TcpStream::connect(server.addr).await.unwrap();
        // Send part of a TLS record, keeping the first handshake pending.
        first.write_all(&[22, 3]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut excess = TcpStream::connect(server.addr).await.unwrap();
        closed(&mut excess).await;
        closed(&mut first).await;
        let mut next = TcpStream::connect(server.addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), next.read(&mut [0; 1]))
                .await
                .is_err()
        );
        closed(&mut next).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), target.accept())
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn established_capacity_recovers_and_graceful_shutdown_drains() {
    bounded(async {
        let target = listener().await;
        let options = TunnelOptions {
            max_connections: NonZeroUsize::new(1).unwrap(),
            shutdown_grace: Duration::from_secs(2),
            ..TunnelOptions::default()
        };
        let (mut client, _server) = pair(target.local_addr().unwrap(), options).await;
        let mut first = TcpStream::connect(client.addr).await.unwrap();
        let (mut backend, _) = target.accept().await.unwrap();
        let mut excess = TcpStream::connect(client.addr).await.unwrap();
        closed(&mut excess).await;
        first.shutdown().await.unwrap();
        closed(&mut backend).await;
        backend.shutdown().await.unwrap();
        closed(&mut first).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut next = TcpStream::connect(client.addr).await.unwrap();
        let (mut backend, _) = target.accept().await.unwrap();
        client.signal();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!client.is_finished());
        assert!(TcpStream::connect(client.addr).await.is_err());
        next.write_all(b"still active").await.unwrap();
        let mut data = [0; 12];
        backend.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"still active");
        next.shutdown().await.unwrap();
        backend.shutdown().await.unwrap();
        client.wait().await;
    })
    .await;
}

#[tokio::test]
async fn forced_shutdown_and_dropped_server_close_active_connections() {
    bounded(async {
        for abort_server in [false, true] {
            let target = listener().await;
            let options = TunnelOptions {
                shutdown_grace: Duration::from_millis(40),
                ..TunnelOptions::default()
            };
            let (mut client, server) = pair(target.local_addr().unwrap(), options).await;
            let mut source = TcpStream::connect(client.addr).await.unwrap();
            let (mut backend, _) = target.accept().await.unwrap();
            if abort_server {
                drop(server);
            } else {
                client.signal();
                client.wait().await;
            }
            closed(&mut source).await;
            closed(&mut backend).await;
        }
    })
    .await;
}

#[tokio::test]
async fn refused_target_closes_source_without_retry() {
    bounded(async {
        let target = listener().await;
        let addr = target.local_addr().unwrap();
        drop(target);
        let (client, _server) = pair(addr, TunnelOptions::default()).await;
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        closed(&mut source).await;
        let rebound = tokio::net::TcpListener::bind(addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), rebound.accept())
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn server_rejects_wrong_protocol_and_attestation_before_target_connect() {
    bounded(async {
        provider();
        for wrong_protocol in [true, false] {
            let target = listener().await;
            let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
            let cert = identity.cert_chain[0].clone();
            let verifier = if wrong_protocol {
                AttestationVerifier::expect_none()
            } else {
                AttestationVerifier::mock()
            };
            let server = Running::server(
                TunnelServer::new(
                    LOCAL,
                    target.local_addr().unwrap().to_string(),
                    identity,
                    AttestationGenerator::with_no_attestation(),
                    verifier,
                    false,
                    TunnelOptions::default(),
                )
                .await
                .unwrap(),
            );
            let mut config = tls::client_config(None, Some(cert), false).unwrap();
            config.alpn_protocols = vec![if wrong_protocol {
                b"h2".to_vec()
            } else {
                b"tcp-tunnel".to_vec()
            }];
            let client = AttestedTlsClient::new_with_tls_config(
                config,
                AttestationGenerator::with_no_attestation(),
                AttestationVerifier::expect_none(),
                None,
            )
            .unwrap();
            let (mut stream, _, _) = client.connect_tcp(&server.addr.to_string()).await.unwrap();
            closed(&mut stream).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), target.accept())
                    .await
                    .is_err()
            );
        }
    })
    .await;
}

#[tokio::test]
async fn client_rejects_wrong_protocol_attestation_and_untrusted_tls() {
    bounded(async {
        provider();
        for mode in 0..3 {
            let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
            let cert = identity.cert_chain[0].clone();
            let mut config = tls::server_config(&identity, false).unwrap();
            config.alpn_protocols = vec![if mode == 0 {
                b"h2".to_vec()
            } else {
                b"tcp-tunnel".to_vec()
            }];
            let server = AttestedTlsServer::new_with_tls_config(
                identity.cert_chain,
                config,
                AttestationGenerator::with_no_attestation(),
                AttestationVerifier::expect_none(),
            )
            .unwrap();
            let incoming = listener().await;
            let addr = incoming.local_addr().unwrap();
            let backend = tokio::spawn(async move {
                let (socket, _) = incoming.accept().await.unwrap();
                if let Ok((mut stream, _, _)) = server.handle_connection(socket).await {
                    // No source payload may reach an incompatible peer.
                    closed(&mut stream).await;
                }
            });
            let verifier = if mode == 1 {
                AttestationVerifier::mock()
            } else {
                AttestationVerifier::expect_none()
            };
            let client = Running::client(
                TunnelClient::new(
                    LOCAL,
                    addr.to_string(),
                    None,
                    AttestationGenerator::with_no_attestation(),
                    verifier,
                    if mode == 2 { None } else { Some(cert) },
                    TunnelOptions::default(),
                )
                .await
                .unwrap(),
            );
            let mut source = TcpStream::connect(client.addr).await.unwrap();
            source.write_all(b"must not reach peer").await.unwrap();
            closed(&mut source).await;
            backend.await.unwrap();
        }
    })
    .await;
}

#[tokio::test]
async fn self_signed_mode_preserves_client_identity_and_mutual_attestation() {
    bounded(async {
        provider();
        let server_identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
        let client_identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(client_identity.cert_chain[0].clone()).unwrap();
        let config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(
                    WebPkiClientVerifier::builder(Arc::new(roots))
                        .build()
                        .unwrap(),
                )
                .with_single_cert(server_identity.cert_chain.clone(), server_identity.key)
                .unwrap();
        let target = listener().await;
        let server = Running::server(
            TunnelServer::new_with_tls_config(
                LOCAL,
                target.local_addr().unwrap().to_string(),
                config,
                AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
                AttestationVerifier::mock(),
                server_identity.cert_chain,
                TunnelOptions::default(),
            )
            .await
            .unwrap(),
        );
        let config = tls::client_config(Some(&client_identity), None, true).unwrap();
        let client = Running::client(
            TunnelClient::new_with_tls_config(
                LOCAL,
                server.addr.to_string(),
                config,
                AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
                AttestationVerifier::mock(),
                Some(client_identity.cert_chain),
                TunnelOptions::default(),
            )
            .await
            .unwrap(),
        );
        let mut source = TcpStream::connect(client.addr).await.unwrap();
        let (mut backend, _) = target.accept().await.unwrap();
        source.write_all(b"authenticated").await.unwrap();
        let mut bytes = [0; 13];
        backend.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"authenticated");
    })
    .await;
}

#[tokio::test]
async fn application_tls_is_opaque_to_the_tunnel() {
    bounded(async {
        provider();
        let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
        let mut server_config = tls::server_config(&identity, false).unwrap();
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        let mut client_config =
            tls::client_config(None, Some(identity.cert_chain[0].clone()), false).unwrap();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let target = listener().await;
        let (client, _server) = pair(target.local_addr().unwrap(), TunnelOptions::default()).await;
        let backend = tokio::spawn(async move {
            let (socket, _) = target.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(socket)
                .await
                .unwrap();
            assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let mut data = [0; 6];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        let socket = TcpStream::connect(client.addr).await.unwrap();
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                socket,
            )
            .await
            .unwrap();
        stream.write_all(b"opaque").await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"opaque");
        stream.shutdown().await.unwrap();
        backend.await.unwrap();
    })
    .await;
}
