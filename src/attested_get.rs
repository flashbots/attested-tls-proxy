use crate::{AttestationGenerator, AttestationVerifier, ProxyClient, ProxyError};
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Start a proxy-client, send a single HTTP GET request to the given path and return the
/// [reqwest::Response]
pub async fn attested_get(
    target_addr: String,
    url_path: &str,
    attestation_verifier: AttestationVerifier,
    remote_certificate: Option<CertificateDer<'static>>,
) -> Result<reqwest::Response, ProxyError> {
    let proxy_client = ProxyClient::new(
        None,
        "127.0.0.1:0".to_string(),
        target_addr,
        AttestationGenerator::with_no_attestation(),
        attestation_verifier,
        remote_certificate,
    )
    .await?;

    attested_get_with_client(proxy_client, url_path).await
}

/// Given a configured [ProxyClient], make a GET request to the given path and return the
/// [reqwest::Response]
async fn attested_get_with_client(
    proxy_client: ProxyClient,
    url_path: &str,
) -> Result<reqwest::Response, ProxyError> {
    let proxy_client_addr = proxy_client.local_addr().unwrap();

    // Accept a single connection in a separate task
    tokio::spawn(async move {
        if let Err(err) = proxy_client.accept().await {
            tracing::warn!("Atttested get - failed to accept connection: {err}");
        }
    });

    // Remove leading '/' if present
    let url_path = url_path.strip_prefix("/").unwrap_or(url_path);

    // Make a GET request
    let request = reqwest::Request::new(
        reqwest::Method::GET,
        reqwest::Url::parse(&format!("http://{proxy_client_addr}/{url_path}")).unwrap(),
    );
    let client = reqwest::Client::new();
    let response = client.execute(request).await.unwrap();
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        attestation::AttestationType,
        file_server::static_file_server,
        test_helpers::{generate_certificate_chain, generate_tls_config},
        ProxyServer,
    };
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_attested_get() {
        // Create a temporary directory with a file to serve
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("foo.txt");
        tokio::fs::write(file_path, b"bar").await.unwrap();

        // Start a static file server
        let target_addr = static_file_server(dir.path().to_path_buf()).await.unwrap();

        // Create TLS configuration
        let (cert_chain, private_key) = generate_certificate_chain("127.0.0.1".parse().unwrap());
        let (server_config, client_config) = generate_tls_config(cert_chain.clone(), private_key);

        // Setup a proxy server targetting the static file server
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

        // Accept a single connction
        tokio::spawn(async move {
            proxy_server.accept().await.unwrap();
        });

        // Setup a proxy client
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

        // Make a GET request
        let response = attested_get_with_client(proxy_client, "foo.txt")
            .await
            .unwrap();

        // Check the response
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap()
            .to_string();

        let body = response.bytes().await.unwrap();
        assert_eq!(content_type, "text/plain");
        assert_eq!(&body.to_vec(), b"bar");
    }
}
