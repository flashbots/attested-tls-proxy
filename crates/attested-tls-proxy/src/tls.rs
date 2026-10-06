//! Shared TLS 1.3 configuration for HTTP proxies and TCP tunnels.
use std::sync::Arc;

use crate::self_signed::SkipServerVerification;
use attested_tls::{AttestedTlsError, TlsCertAndKey};
use tokio_rustls::rustls::{
    self, ClientConfig, RootCertStore, ServerConfig, pki_types::CertificateDer,
    server::WebPkiClientVerifier,
};

/// Build a TLS 1.3 client configuration, preserving client authentication even
/// when accepting a self-signed server. The custom CA replaces public roots.
pub fn client_config(
    identity: Option<&TlsCertAndKey>,
    remote_certificate: Option<CertificateDer<'static>>,
    allow_self_signed: bool,
) -> Result<ClientConfig, AttestedTlsError> {
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = if allow_self_signed {
        builder
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new()?)
    } else {
        let roots = match remote_certificate {
            Some(cert) => {
                let mut roots = RootCertStore::empty();
                roots.add(cert)?;
                roots
            }
            None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        };
        builder.with_root_certificates(roots)
    };
    Ok(match identity {
        Some(identity) => {
            builder.with_client_auth_cert(identity.cert_chain.clone(), identity.key.clone_key())?
        }
        None => builder.with_no_client_auth(),
    })
}

/// Build a TLS 1.3 server configuration. Optional client certificate authentication
/// uses public roots. For private client CAs, supply a custom ServerConfig through
/// the HTTP proxy or TCP tunnel's `new_with_tls_config` constructor.
pub fn server_config(
    identity: &TlsCertAndKey,
    client_auth: bool,
) -> Result<ServerConfig, AttestedTlsError> {
    let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
    let builder = if client_auth {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots)).build()?)
    } else {
        builder.with_no_client_auth()
    };
    Ok(builder.with_single_cert(identity.cert_chain.clone(), identity.key.clone_key())?)
}
