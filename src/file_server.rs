//! Static HTTP file server provided by an attested TLS proxy server
use crate::{
    AttestationGenerator, AttestationVerifier, OuterTlsConfig, OuterTlsMode, ProxyError,
    ProxyServer, TlsCertAndKey,
};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::ToSocketAddrs;
use tower_http::services::ServeDir;

/// Setup a static file server serving the given directory, and a proxy server targetting it
pub async fn attested_file_server(
    path_to_serve: PathBuf,
    outer_cert_and_key: Option<TlsCertAndKey>,
    outer_listen_addr: Option<impl ToSocketAddrs>,
    inner_listen_addr: Option<impl ToSocketAddrs>,
    attestation_generator: AttestationGenerator,
    attestation_verifier: AttestationVerifier,
    client_auth: bool,
) -> Result<(), ProxyError> {
    let target_addr = static_file_server(path_to_serve).await?;

    let server = ProxyServer::new(
        outer_cert_and_key
            .zip(outer_listen_addr)
            .map(|(cert_and_key, listen_addr)| OuterTlsConfig {
                listen_addr,
                tls: OuterTlsMode::CertAndKey(cert_and_key),
            }),
        inner_listen_addr,
        target_addr.to_string(),
        attestation_generator,
        attestation_verifier,
        client_auth,
    )
    .await?;

    loop {
        if let Err(err) = server.accept().await {
            tracing::error!("Failed to handle connection: {err}");
        }
    }
}

/// Statically serve the given filesystem path over HTTP
pub(crate) async fn static_file_server(path: PathBuf) -> Result<SocketAddr, ProxyError> {
    let app = axum::Router::new().fallback_service(ServeDir::new(&path));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tracing::info!("Statically serving {path:?} on {addr}");

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!("HTTP file server: {err}");
        }
    });

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use crate::{OuterTlsConfig, OuterTlsMode, ProxyClient, attestation::AttestationType};

    use super::*;
    use crate::test_helpers::{generate_certificate_chain_for_host, generate_tls_config};
    use tempfile::tempdir;

    /// Given a URL, fetch response body and content type header
    async fn get_body_and_content_type(url: String, client: &reqwest::Client) -> (Vec<u8>, String) {
        let res = client.get(url).send().await.unwrap();

        let content_type = res
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();

        let body = res.bytes().await.unwrap();

        (body.to_vec(), content_type)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_static_file_server() {
        // Create a temporary directory with some files to serve
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("foo.txt");
        tokio::fs::write(file_path, b"bar").await.unwrap();

        let file_path = dir.path().join("index.html");
        tokio::fs::write(file_path, b"<html><body>foo</body></html>")
            .await
            .unwrap();

        let file_path = dir.path().join("data.bin");
        tokio::fs::write(file_path, [0u8; 32]).await.unwrap();

        // Start a static file server
        let target_addr = static_file_server(dir.path().to_path_buf()).await.unwrap();

        // Create TLS configuration
        let (cert_chain, private_key) = generate_certificate_chain_for_host("localhost");
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        // Setup a proxy server targetting the static file server
        let proxy_server = ProxyServer::new(
            Some(OuterTlsConfig {
                listen_addr: "127.0.0.1:0",
                tls: OuterTlsMode::Preconfigured {
                    server_config,
                    certificate_name: "localhost".to_string(),
                },
            }),
            Some("127.0.0.1:0"),
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
            AttestationVerifier::expect_none(),
            false,
        )
        .await
        .unwrap();

        let proxy_addr = proxy_server.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        let proxy_client = ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            format!("localhost:{}", proxy_addr.port()),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        // Accept one client connection per request.
        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
            proxy_client.accept().await.unwrap();
        });

        let client = reqwest::Client::new();

        // This makes the request
        let (body, content_type) =
            get_body_and_content_type(format!("http://{}/foo.txt", proxy_client_addr), &client)
                .await;
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, b"bar");

        let (body, content_type) =
            get_body_and_content_type(format!("http://{}/index.html", proxy_client_addr), &client)
                .await;
        assert_eq!(content_type, "text/html");
        assert_eq!(body, b"<html><body>foo</body></html>");

        let (body, content_type) =
            get_body_and_content_type(format!("http://{}/data.bin", proxy_client_addr), &client)
                .await;
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(body, [0u8; 32]);
    }
}
