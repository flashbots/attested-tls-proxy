//! A one-shot attested TLS proxy client which sends a single GET request and returns the response
use crate::{AttestationGenerator, AttestationVerifier, ProxyClient, ProxyError};
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Split an `attested-get` target into a proxy target and an optional request path.
///
/// This lets users write `127.0.0.1:3000/some/path` and still keep the proxy
/// connection target separate from the HTTP request path.
pub fn split_target_and_path(target: &str) -> (String, Option<String>) {
    let Some((target_addr, url_path)) = target.split_once('/') else {
        return (target.to_string(), None);
    };

    let url_path = url_path.trim_start_matches('/').to_string();
    let url_path = if url_path.is_empty() {
        None
    } else {
        Some(url_path)
    };

    (target_addr.to_string(), url_path)
}

/// Start a proxy-client, send a single HTTP GET request to the given path and return the
/// [reqwest::Response]
///
/// Redirects are returned without following them, so requests stay on the attested channel.
pub async fn attested_get(
    target_addr: String,
    url_path: &str,
    attestation_verifier: AttestationVerifier,
    remote_certificate: Option<CertificateDer<'static>>,
    allow_self_signed: bool,
) -> Result<reqwest::Response, ProxyError> {
    let proxy_client = if allow_self_signed {
        let client_config = crate::self_signed::client_tls_config_allow_self_signed()?;
        ProxyClient::new_with_tls_config(
            client_config,
            "127.0.0.1:0".to_string(),
            target_addr,
            AttestationGenerator::with_no_attestation(),
            attestation_verifier,
            None,
        )
        .await?
    } else {
        ProxyClient::new(
            None,
            "127.0.0.1:0".to_string(),
            target_addr,
            AttestationGenerator::with_no_attestation(),
            attestation_verifier,
            remote_certificate,
        )
        .await?
    };

    attested_get_with_client(proxy_client, url_path).await
}

/// Given a configured [ProxyClient], make a GET request to the given path and return the
/// [reqwest::Response]
async fn attested_get_with_client(
    proxy_client: ProxyClient,
    url_path: &str,
) -> Result<reqwest::Response, ProxyError> {
    let proxy_client_addr = proxy_client.local_addr()?;

    // Keep the request on the local proxy and return redirects without following them.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    let url_path = url_path.strip_prefix("/").unwrap_or(url_path);
    let request = client
        .get(format!("http://{proxy_client_addr}/{url_path}"))
        .build()?;

    // Accept a single connection in a separate task
    tokio::spawn(async move {
        if let Err(err) = proxy_client.accept().await {
            tracing::warn!("Atttested get - failed to accept connection: {err}");
        }
    });

    let response = client.execute(request).await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProxyServer,
        attestation::AttestationType,
        file_server::static_file_server,
        test_helpers::{generate_certificate_chain, generate_tls_config},
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
            target_addr.to_string(),
            AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
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

    #[test]
    fn split_target_and_path_handles_embedded_path() {
        let (target, path) = split_target_and_path("127.0.0.1:3000/some/path");
        assert_eq!(target, "127.0.0.1:3000");
        assert_eq!(path.as_deref(), Some("some/path"));
    }

    #[test]
    fn split_target_and_path_leaves_bare_target_alone() {
        let (target, path) = split_target_and_path("127.0.0.1:3000");
        assert_eq!(target, "127.0.0.1:3000");
        assert_eq!(path, None);
    }
}
