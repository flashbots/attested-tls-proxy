//! TLS 1.3 configuration helpers for attested TLS.
mod client_key_allowlist;

use std::{net::IpAddr, path::PathBuf, sync::Arc};

pub use client_key_allowlist::AllowlistedPeer;
pub(crate) use client_key_allowlist::ClientKeyAllowlist;

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

/// How a TLS server authenticates clients during the handshake.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ClientAuth {
    None,
    WebPki,
    KeyAllowlist {
        path: PathBuf,
        open_when_missing: bool,
    },
}

impl From<bool> for ClientAuth {
    fn from(require_web_pki: bool) -> Self {
        if require_web_pki {
            Self::WebPki
        } else {
            Self::None
        }
    }
}

/// TLS settings with the policy used to reauthorize established connections.
pub struct ServerTlsConfig {
    pub config: ServerConfig,
    pub(crate) allowlist: Option<Arc<ClientKeyAllowlist>>,
}

impl From<ServerConfig> for ServerTlsConfig {
    fn from(config: ServerConfig) -> Self {
        Self {
            config,
            allowlist: None,
        }
    }
}

impl ServerTlsConfig {
    pub fn new(
        identity: &TlsCertAndKey,
        client_auth: impl Into<ClientAuth>,
    ) -> Result<Self, AttestedTlsError> {
        let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
        let auth = client_auth.into();
        let mut allowlist = None;
        let builder = match auth {
            ClientAuth::None => builder.with_no_client_auth(),
            ClientAuth::WebPki => {
                let roots =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                builder.with_client_cert_verifier(
                    WebPkiClientVerifier::builder(Arc::new(roots)).build()?,
                )
            }
            ClientAuth::KeyAllowlist {
                path,
                open_when_missing,
            } => {
                let policy = Arc::new(ClientKeyAllowlist::new(path, open_when_missing));
                allowlist = Some(policy.clone());
                builder.with_client_cert_verifier(policy)
            }
        };
        let mut config =
            builder.with_single_cert(identity.cert_chain.clone(), identity.key.clone_key())?;
        if allowlist.is_some() {
            // Resumed sessions would skip the allowlist check on subsequent connections.
            config.send_tls13_tickets = 0;
        }
        Ok(Self { config, allowlist })
    }
}

/// Build a TLS 1.3 server config with optional Web PKI client authentication.
/// Use [`ServerTlsConfig::new`] for a live key allowlist.
pub fn server_config(
    identity: &TlsCertAndKey,
    client_auth: bool,
) -> Result<ServerConfig, AttestedTlsError> {
    Ok(ServerTlsConfig::new(identity, client_auth)?.config)
}

/// Generate a self-signed certificate for the given IP address and build a TLS 1.3
/// server configuration. Returns the configuration and its certificate chain.
/// Client authentication uses the policy passed to [`server_config`].
pub fn self_signed_server_config(
    ip_address: IpAddr,
    client_auth: bool,
) -> Result<(ServerConfig, Vec<CertificateDer<'static>>), AttestedTlsError> {
    let identity = generate_self_signed_cert(ip_address)?;
    let config = server_config(&identity, client_auth)?;
    Ok((config, identity.cert_chain))
}
