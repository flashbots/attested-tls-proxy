//! Exercise the production connection paths; only the evidence is mocked.

use crate::*;
use std::{sync::atomic::Ordering, time::Duration};
use test_helpers::{generate_certificate_chain, generate_tls_config_with_client_auth};
use tokio::io::DuplexStream;

type ServerResult = Result<
    (
        tokio_rustls::server::TlsStream<DuplexStream>,
        Option<MultiMeasurements>,
        AttestationType,
    ),
    AttestedTlsError,
>;
type ClientResult = Result<
    (
        tokio_rustls::client::TlsStream<DuplexStream>,
        Option<MultiMeasurements>,
        AttestationType,
    ),
    AttestedTlsError,
>;

/// Creates mutually trusted TLS credentials and configurations for the test peers.
fn configs() -> (
    Vec<CertificateDer<'static>>,
    Vec<CertificateDer<'static>>,
    ServerConfig,
    ClientConfig,
) {
    let (server_certs, server_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
    let (client_certs, client_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
    let ((server_config, _), (_, client_config)) = generate_tls_config_with_client_auth(
        server_certs.clone(),
        server_key,
        client_certs.clone(),
        client_key,
    );
    (server_certs, client_certs, server_config, client_config)
}

/// Builds endpoints requiring mock peer attestation, with a selectable server evidence type.
fn pair(server_type: AttestationType) -> (AttestedTlsServer, AttestedTlsClient) {
    let (server_certs, client_certs, server_config, client_config) = configs();
    let server = AttestedTlsServer::new_with_tls_config(
        server_certs,
        server_config,
        AttestationGenerator::new(server_type, None).unwrap(),
        AttestationVerifier::mock(),
    )
    .unwrap();
    let client = AttestedTlsClient::new_with_tls_config(
        client_config,
        AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        AttestationVerifier::mock(),
        Some(client_certs),
    )
    .unwrap();
    (server, client)
}

/// Runs both production connection paths over an in-memory transport with a timeout.
async fn connect(
    server: &AttestedTlsServer,
    client: &AttestedTlsClient,
) -> (ServerResult, ClientResult) {
    let (server_io, client_io) = tokio::io::duplex(128 * 1024);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            server.handle_connection(server_io),
            client.connect("127.0.0.1", client_io)
        )
    })
    .await
    .expect("connection must not deadlock")
}

fn counts(counts: &resumption::AttestationCounts) -> (usize, usize) {
    (
        counts.generated.load(Ordering::Relaxed),
        counts.verified.load(Ordering::Relaxed),
    )
}

#[tokio::test]
async fn mutual_attestation_is_reused_on_repeated_resumption() {
    let (server, client) = pair(AttestationType::DcapTdx);
    let mut previous = None;
    for expected in [
        rustls::HandshakeKind::Full,
        rustls::HandshakeKind::Resumed,
        rustls::HandshakeKind::Resumed,
    ] {
        // Clones must share the authenticated session caches.
        let (server_result, client_result) = connect(&server.clone(), &client.clone()).await;
        let (mut server_stream, server_measurements, server_type) = server_result.unwrap();
        let (mut client_stream, client_measurements, client_type) = client_result.unwrap();
        assert_eq!(server_stream.get_ref().1.handshake_kind(), Some(expected));
        assert_eq!(client_stream.get_ref().1.handshake_kind(), Some(expected));
        assert_eq!(server_type, AttestationType::DcapTdx);
        assert_eq!(client_type, AttestationType::DcapTdx);
        assert!(server_measurements.is_some() && client_measurements.is_some());
        let metadata = (
            server_measurements,
            client_measurements,
            server_type,
            client_type,
        );
        if let Some(previous) = &previous {
            assert_eq!(&metadata, previous);
        }
        previous = Some(metadata);
        tokio::time::timeout(Duration::from_secs(5), async {
            client_stream.write_all(b"ping").await.unwrap();
            client_stream.flush().await.unwrap();
            let mut buffer = [0; 4];
            server_stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"ping");
            server_stream.write_all(b"pong").await.unwrap();
            server_stream.flush().await.unwrap();
            client_stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(&buffer, b"pong");
        })
        .await
        .unwrap();
        assert_eq!(counts(&server.counts), (1, 1));
        assert_eq!(counts(&client.counts), (1, 1));
        println!(
            "{expected:?}: server and client each generated 1 quote and verified 1 quote overall"
        );
    }
}

#[tokio::test]
async fn rejected_server_attestation_never_authorizes_client_tickets() {
    let (server, client) = pair(AttestationType::None);
    for attempt in 1..=2 {
        let (server_result, client_result) = connect(&server, &client).await;
        assert!(server_result.is_err());
        assert!(matches!(
            client_result,
            Err(AttestedTlsError::Attestation(_))
        ));
        // The TLS tickets actually arrived before the rejected evidence.
        assert!(client.sessions.pending_count() > 0);
        assert_eq!(counts(&client.counts), (0, attempt));
        assert_eq!(counts(&server.counts).0, attempt);
        let store = ClientStore {
            cache: client.sessions.clone(),
            target: "127.0.0.1".into(),
            record: ConnectionRecord::default(),
        };
        use rustls::client::ClientSessionStore;
        assert!(
            store
                .take_tls13_ticket(&server_name_from_host("127.0.0.1").unwrap())
                .is_none()
        );
    }
}

/// Offers tickets from rejected or abandoned exchanges using an ungated attacker cache.
async fn unverified_client_cannot_resume(abandon: bool) {
    let (server_certs, _, server_config, client_config) = configs();
    let server = AttestedTlsServer::new_with_tls_config(
        server_certs,
        server_config,
        AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        AttestationVerifier::mock(),
    )
    .unwrap();
    // An attacker deliberately uses rustls's ordinary, ungated client cache.
    let connector = TlsConnector::from(Arc::new(client_config));
    for attempt in 1..=2 {
        let (server_io, client_io) = tokio::io::duplex(128 * 1024);
        let (server_result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server.handle_connection(server_io), async {
                let mut stream = connector
                    .connect(server_name_from_host("127.0.0.1").unwrap(), client_io)
                    .await
                    .unwrap();
                // Even on retry, the server must decline the attacker's ticket.
                assert_eq!(
                    stream.get_ref().1.handshake_kind(),
                    Some(rustls::HandshakeKind::Full)
                );
                // Reading the quote also processes the preceding TLS tickets.
                read_length_prefixed_attestation(&mut stream).await.unwrap();
                if !abandon {
                    let message = AttestationExchangeMessage::without_attestation().encode();
                    stream
                        .write_all(&checked_length_prefix(&message).unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&message).await.unwrap();
                    stream.flush().await.unwrap();
                    // Rejection closes TLS without exposing any application data.
                    assert!(stream.read_u8().await.is_err());
                }
            })
        })
        .await
        .unwrap();
        if abandon {
            assert!(matches!(server_result, Err(AttestedTlsError::Io(_))));
        } else {
            assert!(matches!(
                server_result,
                Err(AttestedTlsError::Attestation(_))
            ));
            assert_eq!(counts(&server.counts).1, attempt);
        }
        assert_eq!(counts(&server.counts).0, attempt);
        assert!(server.sessions.pending_count() > 0);
        // Prove retry offered a real ticket, rather than silently doing full TLS.
        assert_eq!(server.sessions.rejected_count(), attempt - 1);
    }
}

#[tokio::test]
async fn rejected_client_ticket_cannot_bypass_attestation() {
    unverified_client_cannot_resume(false).await;
}

#[tokio::test]
async fn abandoned_exchange_ticket_cannot_bypass_attestation() {
    unverified_client_cannot_resume(true).await;
}

#[tokio::test]
async fn losing_either_cache_requires_fresh_attestation() {
    for clear_server in [false, true] {
        let (server, client) = pair(AttestationType::DcapTdx);
        let (s, c) = connect(&server, &client).await;
        s.unwrap();
        c.unwrap();
        if clear_server {
            server.sessions.clear();
        } else {
            client.sessions.clear();
        }
        let (s, c) = connect(&server, &client).await;
        assert_eq!(
            s.unwrap().0.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(
            c.unwrap().0.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(counts(&server.counts), (2, 2));
        assert_eq!(counts(&client.counts), (2, 2));
    }
}

#[tokio::test]
async fn accepted_no_client_attestation_is_reused() {
    let (mut server, mut client) = pair(AttestationType::DcapTdx);
    server.attestation_verifier = AttestationVerifier::expect_none();
    client.attestation_generator = AttestationGenerator::with_no_attestation();
    for expected in [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed] {
        let (s, c) = connect(&server, &client).await;
        let (server_stream, measurements, attestation_type) = s.unwrap();
        let (client_stream, client_measurements, _) = c.unwrap();
        assert_eq!(server_stream.get_ref().1.handshake_kind(), Some(expected));
        assert_eq!(client_stream.get_ref().1.handshake_kind(), Some(expected));
        assert!(measurements.is_none());
        assert_eq!(attestation_type, AttestationType::None);
        assert!(client_measurements.is_some());
        assert_eq!(counts(&server.counts), (1, 1));
        assert_eq!(counts(&client.counts), (0, 1));
    }
}

#[test]
fn experimental_configuration_disables_early_data_and_rejects_stateless_tickets() {
    let (server_certs, client_certs, mut server_config, mut client_config) = configs();
    server_config.max_early_data_size = 1024;
    client_config.enable_early_data = true;
    let server = AttestedTlsServer::new_with_tls_config(
        server_certs.clone(),
        server_config.clone(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
    )
    .unwrap();
    let client = AttestedTlsClient::new_with_tls_config(
        client_config,
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        Some(client_certs),
    )
    .unwrap();
    assert_eq!(server.acceptor.config().max_early_data_size, 0);
    assert!(!client.connector.config().enable_early_data);
    server_config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().unwrap();
    assert!(matches!(
        AttestedTlsServer::new_with_tls_config(
            server_certs,
            server_config,
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
        ),
        Err(AttestedTlsError::StatelessResumptionUnsupported)
    ));
}

/// Poisons a mutex without letting the deliberate test panic escape.
fn poison<T>(mutex: &std::sync::Mutex<T>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = mutex.lock().unwrap();
        panic!("deliberately poison test state");
    }));
    assert!(result.is_err());
    assert!(mutex.is_poisoned());
}

#[tokio::test]
async fn poisoned_caches_and_ticket_metadata_require_fresh_attestation() {
    for server_side in [false, true] {
        for poison_metadata in [false, true] {
            let (server, client) = pair(AttestationType::DcapTdx);
            let (s, c) = connect(&server, &client).await;
            s.unwrap();
            c.unwrap();
            if poison_metadata {
                // All tickets from the first connection share this verified record.
                let authentication = if server_side {
                    server
                        .sessions
                        .tickets
                        .lock()
                        .unwrap()
                        .values()
                        .next()
                        .unwrap()
                        .authentication
                        .clone()
                } else {
                    client
                        .sessions
                        .tickets
                        .lock()
                        .unwrap()
                        .values()
                        .next()
                        .unwrap()[0]
                        .authentication
                        .clone()
                };
                poison(&authentication);
            } else if server_side {
                poison(&server.sessions.tickets);
            } else {
                poison(&client.sessions.tickets);
            }
            let (s, c) = connect(&server, &client).await;
            assert_eq!(
                s.unwrap().0.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            assert_eq!(
                c.unwrap().0.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            assert_eq!(counts(&server.counts), (2, 2));
            assert_eq!(counts(&client.counts), (2, 2));
        }
    }
}

#[test]
fn poisoned_connection_records_return_errors() {
    let record = ConnectionRecord::default();
    poison(&record.selected);
    assert!(matches!(
        record.verified_peer(),
        Err(AttestedTlsError::PoisonedResumptionState)
    ));
    poison(&record.issued);
    assert!(matches!(
        record.authenticate(VerifiedPeer {
            measurements: None,
            attestation_type: AttestationType::None,
        }),
        Err(AttestedTlsError::PoisonedResumptionState)
    ));
}

#[tokio::test]
async fn poisoned_selected_records_decline_tickets_without_poisoning_caches() {
    use rustls::{client::ClientSessionStore, server::StoresServerSessions};
    let (server, client) = pair(AttestationType::DcapTdx);
    let (s, c) = connect(&server, &client).await;
    s.unwrap();
    c.unwrap();
    let record = ConnectionRecord::default();
    poison(&record.selected);
    let client_store = ClientStore {
        cache: client.sessions.clone(),
        target: "127.0.0.1".into(),
        record: record.clone(),
    };
    assert!(
        client_store
            .take_tls13_ticket(&server_name_from_host("127.0.0.1").unwrap())
            .is_none()
    );
    let key = server
        .sessions
        .tickets
        .lock()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    let server_store = ServerStore {
        cache: server.sessions.clone(),
        record,
    };
    assert!(server_store.take(&key).is_none());
    assert!(!server.sessions.tickets.is_poisoned());
    assert!(!client.sessions.tickets.is_poisoned());
}
