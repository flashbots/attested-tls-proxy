use std::time::Duration;

use attested_tls_proxy::{
    AttestationGenerator, ProxyClient, ProxyError, ProxyServer, attestation::AttestationVerifier,
    attested_get::attested_get, self_signed::generate_self_signed_cert,
};
use axum::{Router, http::HeaderMap, routing::get};
use tokio::{net::TcpListener, time::timeout};

#[tokio::test]
async fn normalized_connection_preserves_original_host_header() {
    check_target("127.0.0.1:0", "127.0.0.1").await;
}

#[tokio::test]
async fn scoped_ipv6_connection_preserves_original_host_header() {
    // Scope zero works on loopback without depending on interface indices.
    check_target("[::1]:0", "[::1%0]").await;
}

async fn check_target(listen: &str, host: &str) {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = TcpListener::bind(listen).await.unwrap();
    let server_ip = listener.local_addr().unwrap().ip();
    // A leading zero is removed from the TCP port but must remain in Host.
    let target = format!("{host}:0{}", listener.local_addr().unwrap().port());
    let backend = tokio::spawn(async move {
        let app = Router::new().route(
            "/",
            get(|headers: HeaderMap| async move { headers["host"].to_str().unwrap().to_owned() }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let server = ProxyServer::new(
        generate_self_signed_cert(server_ip).unwrap(),
        listen,
        target.clone(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        false,
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let proxy = tokio::spawn(async move { server.accept().await.unwrap() });
    timeout(Duration::from_secs(5), async {
        let response = attested_get(
            format!("{host}:{}", address.port()),
            "/",
            AttestationVerifier::expect_none(),
            None,
            true,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), target);
    })
    .await
    .unwrap();
    proxy.await.unwrap().abort();
    backend.abort();
}

#[tokio::test]
async fn invalid_http_targets_fail_at_construction() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    for target in ["", "localhost:0", "localhost:65536", "localhost/path"] {
        let result = ProxyClient::new(
            None,
            "127.0.0.1:0",
            target.into(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::expect_none(),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(ProxyError::InvalidTarget(_))),
            "{target}"
        );
    }
    // Server targets require an explicit port, with either TLS constructor.
    for custom_tls in [false, true] {
        let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
        let result = if custom_tls {
            let config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(identity.cert_chain.clone(), identity.key)
                .unwrap();
            ProxyServer::new_with_tls_config(
                identity.cert_chain,
                config,
                "127.0.0.1:0",
                "localhost".into(),
                AttestationGenerator::with_no_attestation(),
                AttestationVerifier::expect_none(),
            )
            .await
        } else {
            ProxyServer::new(
                identity,
                "127.0.0.1:0",
                "localhost".into(),
                AttestationGenerator::with_no_attestation(),
                AttestationVerifier::expect_none(),
                false,
            )
            .await
        };
        assert!(matches!(result, Err(ProxyError::InvalidTarget(_))));
    }
}
