use crate::{AttestationGenerator, AttestationVerifier, ProxyError, ProxyServer, TlsCertAndKey};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::ToSocketAddrs;
use tower_http::services::ServeDir;

pub async fn attested_file_server(
    path_to_serve: PathBuf,
    cert_and_key: TlsCertAndKey,
    listen_addr: impl ToSocketAddrs,
    attestation_generator: AttestationGenerator,
    attestation_verifier: AttestationVerifier,
    client_auth: bool,
) -> Result<(), ProxyError> {
    let target_addr = static_file_server(path_to_serve).await?;

    let _server = ProxyServer::new(
        cert_and_key,
        listen_addr,
        target_addr,
        attestation_generator,
        attestation_verifier,
        client_auth,
    )
    .await?;

    Ok(())
}

/// Statically serve the given filesystem path over HTTP
async fn static_file_server(path: PathBuf) -> Result<SocketAddr, ProxyError> {
    let app = axum::Router::new().fallback_service(ServeDir::new(&path));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tracing::info!("Statically serving {path:?} on {addr}");

    tokio::spawn(async move {
        if let Err(err) = axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await
        {
            tracing::error!("HTTP file server: {err}");
        }
    });

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use crate::{attestation::AttestationType, ProxyClient};

    use super::*;
    use crate::test_helpers::{generate_certificate_chain, generate_tls_config};
    use tempfile::tempdir;

    /// Given a url. fetch response body and content type header
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

    #[tokio::test]
    async fn test_static_file_server() {
        let dir = tempdir().unwrap();

        let file_path = dir.path().join("foo.txt");
        tokio::fs::write(file_path, b"bar").await.unwrap();

        let file_path = dir.path().join("index.html");
        tokio::fs::write(file_path, b"<html><body>foo</body></html>")
            .await
            .unwrap();

        let file_path = dir.path().join("data.bin");
        tokio::fs::write(file_path, [0u8; 32]).await.unwrap();

        let target_addr = static_file_server(dir.path().to_path_buf()).await.unwrap();

        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        let proxy_server = ProxyServer::new_with_tls_config(
            cert_chain,
            server_config,
            "127.0.0.1:0",
            target_addr,
            AttestationGenerator::new_not_dummy(AttestationType::DcapTdx).unwrap(),
            AttestationVerifier::expect_none(),
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
            proxy_addr.to_string(),
            AttestationGenerator::with_no_attestation(),
            AttestationVerifier::mock(),
            None,
        )
        .await
        .unwrap();

        let proxy_client_addr = proxy_client.local_addr().unwrap();

        tokio::spawn(async move {
            proxy_client.accept().await.unwrap();
        });

        let client = reqwest::Client::new();

        let (body, content_type) = get_body_and_content_type(
            format!("http://{}/foo.txt", proxy_client_addr.to_string()),
            &client,
        )
        .await;
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, b"bar");

        let (body, content_type) = get_body_and_content_type(
            format!("http://{}/index.html", proxy_client_addr.to_string()),
            &client,
        )
        .await;
        assert_eq!(content_type, "text/html");
        assert_eq!(body, b"<html><body>foo</body></html>");

        let (body, content_type) = get_body_and_content_type(
            format!("http://{}/data.bin", proxy_client_addr.to_string()),
            &client,
        )
        .await;
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(body, [0u8; 32]);
    }
}
