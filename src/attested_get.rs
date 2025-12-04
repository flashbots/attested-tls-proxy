use crate::{AttestationGenerator, AttestationVerifier, ProxyClient, ProxyError};
use tokio_rustls::rustls::pki_types::CertificateDer;

pub async fn attested_get(
    target_addr: String,
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

    attested_get_with_client(proxy_client).await
}

async fn attested_get_with_client(
    proxy_client: ProxyClient,
) -> Result<reqwest::Response, ProxyError> {
    let proxy_client_addr = proxy_client.local_addr().unwrap();

    tokio::spawn(async move {
        proxy_client.accept().await.unwrap();
    });

    let request = reqwest::Request::new(
        reqwest::Method::GET,
        reqwest::Url::parse(&proxy_client_addr.to_string()).unwrap(),
    );
    let client = reqwest::Client::new();
    let response = client.execute(request).await.unwrap();
    Ok(response)
}
