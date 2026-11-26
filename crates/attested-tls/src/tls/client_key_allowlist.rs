//! TLS client authentication by the leaf certificate's Ed25519 public key.
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::HashSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use ed25519_dalek::{Signature, VerifyingKey};
use tokio_rustls::rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, PeerIncompatible,
    SignatureScheme,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use x509_parser::{oid_registry::OID_SIG_ED25519, prelude::*};

const MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct FileVersion {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    modified: SystemTime,
    len: u64,
}

impl FileVersion {
    fn from_file(file: &Metadata) -> Option<Self> {
        if !file.is_file() || file.len() > MAX_BYTES {
            return None;
        }
        Some(Self {
            #[cfg(unix)]
            device: file.dev(),
            #[cfg(unix)]
            inode: file.ino(),
            modified: file.modified().ok()?,
            len: file.len(),
        })
    }
}

#[derive(Debug, Default)]
struct Cache {
    seen_file: bool,
    parsed: Option<CachedFile>,
}

#[derive(Debug)]
struct CachedFile {
    version: FileVersion,
    keys: HashSet<[u8; 32]>,
    // Keep this inode alive across renames so its number cannot be reused on a cache hit.
    _file: File,
}

#[derive(Debug)]
pub(crate) struct ClientKeyAllowlist {
    path: PathBuf,
    open_when_missing: bool,
    cache: Mutex<Cache>,
}

/// The client identity from a completed TLS handshake, bound to its server policy.
#[derive(Clone)]
pub struct AllowlistedPeer {
    policy: Arc<ClientKeyAllowlist>,
    key: Option<[u8; 32]>,
}

impl AllowlistedPeer {
    /// Check the current allowlist without blocking an async worker on filesystem I/O.
    pub async fn is_allowed(&self) -> bool {
        let peer = self.clone();
        tokio::task::spawn_blocking(move || peer.policy.allows(peer.key.as_ref()))
            .await
            .unwrap_or(false)
    }
}

impl ClientKeyAllowlist {
    pub(super) fn new(path: PathBuf, open_when_missing: bool) -> Self {
        Self {
            path,
            open_when_missing,
            cache: Mutex::default(),
        }
    }

    pub(crate) fn peer(
        self: &Arc<Self>,
        cert: Option<&CertificateDer<'_>>,
    ) -> Result<AllowlistedPeer, Error> {
        let key = cert.map(public_key).transpose()?.map(|key| key.to_bytes());
        Ok(AllowlistedPeer {
            policy: self.clone(),
            key,
        })
    }

    fn allows(&self, key: Option<&[u8; 32]>) -> bool {
        let Ok(mut cache) = self.cache.lock() else {
            return false;
        };
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
        let mut file = match options.open(&self.path) {
            Ok(file) => file,
            Err(err) => {
                cache.parsed = None;
                match fs::symlink_metadata(&self.path) {
                    // A present entry can be unreadable or a dangling symlink.
                    Ok(_) => cache.seen_file = true,
                    Err(stat_err)
                        if stat_err.kind() == io::ErrorKind::NotFound
                            && err.kind() == io::ErrorKind::NotFound =>
                    {
                        return self.open_when_missing && !cache.seen_file && key.is_none();
                    }
                    Err(_) => {}
                }
                return false;
            }
        };
        cache.seen_file = true;
        let Some(version) = file
            .metadata()
            .ok()
            .and_then(|m| FileVersion::from_file(&m))
        else {
            return false;
        };
        // Only reuse entries where the filesystem exposes device and inode.
        if cfg!(unix)
            && let Some(cached) = &cache.parsed
            && cached.version == version
        {
            return key.is_some_and(|key| cached.keys.contains(key));
        }

        let keys = match read_keys(&mut file, &version) {
            Ok(Some(keys)) => keys,
            Ok(None) => HashSet::new(), // Cache malformed contents as closed.
            Err(_) => {
                cache.parsed = None;
                return false;
            }
        };
        let allowed = key.is_some_and(|key| keys.contains(key));
        cache.parsed = Some(CachedFile {
            version,
            keys,
            _file: file,
        });
        allowed
    }
}

fn read_keys(file: &mut File, version: &FileVersion) -> io::Result<Option<HashSet<[u8; 32]>>> {
    let mut contents = Vec::with_capacity(version.len as usize);
    file.take(MAX_BYTES + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 != version.len
        || FileVersion::from_file(&file.metadata()?).as_ref() != Some(version)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "allowlist changed while reading",
        ));
    }
    let Ok(text) = std::str::from_utf8(&contents) else {
        return Ok(None);
    };
    let mut keys = HashSet::new();
    for line in text.lines() {
        if line.trim_ascii().is_empty() || line.trim_ascii_start().starts_with('#') {
            continue;
        }
        let mut key = [0; 32];
        if line.bytes().any(|b| b.is_ascii_uppercase())
            || hex::decode_to_slice(line, &mut key).is_err()
        {
            return Ok(None);
        }
        keys.insert(key);
    }
    Ok(Some(keys))
}

fn public_key(cert: &CertificateDer<'_>) -> Result<VerifyingKey, CertificateError> {
    let (remaining, cert) =
        X509Certificate::from_der(cert.as_ref()).map_err(|_| CertificateError::BadEncoding)?;
    let spki = cert.public_key();
    if !remaining.is_empty()
        || spki.algorithm.algorithm != OID_SIG_ED25519
        || spki.algorithm.parameters.is_some()
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(CertificateError::BadEncoding);
    }
    let bytes = spki
        .subject_public_key
        .as_ref()
        .try_into()
        .map_err(|_| CertificateError::BadEncoding)?;
    VerifyingKey::from_bytes(bytes).map_err(|_| CertificateError::BadEncoding)
}

impl ClientCertVerifier for ClientKeyAllowlist {
    fn offer_client_auth(&self) -> bool {
        !self.allows(None)
    }

    fn client_auth_mandatory(&self) -> bool {
        // Once CertificateRequest has been sent, removing the file cannot waive authentication.
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if self.allows(Some(public_key(end_entity)?.as_bytes())) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(CertificateError::ApplicationVerificationFailure.into())
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(CertificateError::BadSignature.into());
        }
        let signature =
            Signature::from_slice(dss.signature()).map_err(|_| CertificateError::BadSignature)?;
        public_key(cert)?
            .verify_strict(message, &signature)
            .map_err(|_| CertificateError::BadSignature)?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
