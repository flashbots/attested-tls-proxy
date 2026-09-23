use std::time::Duration;

use attested_tls_proxy::{
    AttestationGenerator, ProxyServer, attestation::AttestationVerifier,
    attested_get::attested_get, self_signed::generate_self_signed_cert,
};
use axum::{Router, routing::get};
use tokio::{net::TcpListener, process::Command, time::timeout};

#[tokio::test]
async fn redirects_never_contact_the_destination_and_cli_rejects_them() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination_url = format!("http://{}/", destination.local_addr().unwrap());
    let location = destination_url.clone();
    let app = Router::new().route(
        "/",
        get(move || {
            let location = location.clone();
            async move {
                (
                    http::StatusCode::FOUND,
                    [(http::header::LOCATION, location)],
                    "redirect body",
                )
            }
        }),
    );
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let backend = tokio::spawn(async move { axum::serve(target, app).await.unwrap() });
    let server = ProxyServer::new(
        generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap(),
        "127.0.0.1:0",
        target_addr.to_string(),
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        false,
    )
    .await
    .unwrap();
    let server_addr = server.local_addr().unwrap().to_string();
    let proxy = tokio::spawn(async move {
        loop {
            server.accept().await.unwrap();
        }
    });

    let response = timeout(
        Duration::from_secs(5),
        attested_get(
            server_addr.clone(),
            "/",
            AttestationVerifier::expect_none(),
            None,
            true,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), http::StatusCode::FOUND);
    assert_eq!(response.headers()[http::header::LOCATION], destination_url);
    assert_eq!(response.text().await.unwrap(), "redirect body");

    // Configure an environment proxy in a subprocess to avoid mutating the test process.
    let output = timeout(
        Duration::from_secs(5),
        Command::new(env!("CARGO_BIN_EXE_attested-tls-proxy"))
            .args([
                "attested-get",
                &server_addr,
                "--allow-self-signed",
                "--allowed-remote-attestation-type",
                "none",
            ])
            .env_remove("MEASUREMENTS_FILE")
            .env("HTTP_PROXY", &destination_url)
            .env("http_proxy", &destination_url)
            .env("ALL_PROXY", &destination_url)
            .env("all_proxy", &destination_url)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("302 Found"), "{stderr}");
    assert!(stderr.contains("redirects are not followed"), "{stderr}");

    // Any connection attempt would remain queued on this listener.
    assert!(
        timeout(Duration::from_millis(100), destination.accept())
            .await
            .is_err()
    );
    proxy.abort();
    backend.abort();
}
