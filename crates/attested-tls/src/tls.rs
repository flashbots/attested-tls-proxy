//! TLS 1.3 configuration helpers for attested TLS.
use std::{net::IpAddr, sync::Arc};

use crate::self_signed::{SkipServerVerification, generate_self_signed_cert};
use crate::{AttestedTlsError, TlsCertAndKey};
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
/// uses public roots. For private client CAs, supply a custom ServerConfig to
/// [`crate::AttestedTlsServer::new_with_tls_config`].
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

/// Generate a self-signed certificate for the given IP address and build a TLS 1.3
/// server configuration. Returns the configuration and its certificate chain.
/// Client authentication uses the same public roots as [`server_config`].
pub fn self_signed_server_config(
    ip_address: IpAddr,
    client_auth: bool,
) -> Result<(ServerConfig, Vec<CertificateDer<'static>>), AttestedTlsError> {
    let identity = generate_self_signed_cert(ip_address)?;
    let config = server_config(&identity, client_auth)?;
    Ok((config, identity.cert_chain))
}
