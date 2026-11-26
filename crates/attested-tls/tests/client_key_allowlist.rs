use std::{fs, sync::Arc};

use attested_tls::{
    TlsCertAndKey,
    self_signed::generate_self_signed_cert,
    tls::{ClientAuth, ServerTlsConfig, client_config},
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519, SignatureAlgorithm};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{self, crypto::aws_lc_rs, pki_types::PrivatePkcs8KeyDer},
};

fn identity(algorithm: &'static SignatureAlgorithm) -> (TlsCertAndKey, String) {
    let key = KeyPair::generate_for(algorithm).unwrap();
    let cert = CertificateParams::default().self_signed(&key).unwrap();
    (
        TlsCertAndKey {
            cert_chain: vec![cert.der().clone()],
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        },
        hex::encode(key.public_key_raw()),
    )
}

// Return the server's handshake result and whether the client supplied a certificate.
async fn handshake(server: &TlsAcceptor, client: &TlsConnector) -> std::io::Result<bool> {
    let (incoming, outgoing) = duplex(64 * 1024);
    let server = async {
        let mut tls = server.accept(incoming).await?;
        tls.write_all(&[1]).await?;
        Ok(tls.get_ref().1.peer_certificates().is_some())
    };
    let client = async {
        let name = "127.0.0.1".try_into().unwrap();
        if let Ok(mut tls) = client.connect(name, outgoing).await {
            // Process session tickets before the next connection with this client config.
            let _ = tls.read_u8().await;
        }
    };
    tokio::join!(server, client).0
}

#[tokio::test]
async fn allowlist_is_enforced_at_every_handshake() {
    let _ = aws_lc_rs::default_provider().install_default();
    let server_id = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
    let (listed, key) = identity(&PKCS_ED25519);
    let (other, other_key) = identity(&PKCS_ED25519);
    let (ecdsa, _) = identity(&PKCS_ECDSA_P256_SHA256);
    let client = |identity| {
        let config = client_config(identity, Some(server_id.cert_chain[0].clone()), false).unwrap();
        TlsConnector::from(Arc::new(config))
    };
    let anonymous = client(None);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_id.cert_chain[0].clone()).unwrap();
    let tls12 = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls12 = TlsConnector::from(Arc::new(tls12));
    let listed = client(Some(&listed));
    let other = client(Some(&other));
    let ecdsa = client(Some(&ecdsa));
    for open_when_missing in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients");
        let auth = ClientAuth::KeyAllowlist {
            path: path.clone(),
            open_when_missing,
        };
        let server = TlsAcceptor::from(Arc::new(
            ServerTlsConfig::new(&server_id, auth).unwrap().config,
        ));
        assert!(handshake(&server, &tls12).await.is_err());
        for client in [&listed, &anonymous] {
            assert_eq!(
                handshake(&server, client).await.ok(),
                open_when_missing.then_some(false)
            );
        }
        fs::write(&path, format!("# clients\n\n{other_key}\n{key}\n")).unwrap();
        assert!(handshake(&server, &other).await.unwrap());
        assert!(handshake(&server, &listed).await.unwrap());
        assert!(handshake(&server, &anonymous).await.is_err());
        assert!(handshake(&server, &ecdsa).await.is_err());

        fs::write(&path, &key).unwrap();
        assert!(handshake(&server, &other).await.is_err());
        // Replacing the inode must invalidate even a matching timestamp and length.
        let replacement = dir.path().join("new");
        fs::write(&replacement, &other_key).unwrap();
        fs::File::open(&replacement)
            .unwrap()
            .set_modified(fs::metadata(&path).unwrap().modified().unwrap())
            .unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(handshake(&server, &listed).await.is_err());
        assert!(handshake(&server, &other).await.unwrap());
        for invalid in ["AB".repeat(32), "a".repeat(63), "gg".repeat(32)] {
            fs::write(&path, format!("{key}\n{invalid}")).unwrap();
            assert!(handshake(&server, &listed).await.is_err());
            assert!(handshake(&server, &anonymous).await.is_err());
        }
        fs::write(&path, "# empty\n").unwrap();
        assert!(handshake(&server, &listed).await.is_err());
        fs::remove_file(&path).unwrap();
        assert!(handshake(&server, &listed).await.is_err());
        assert!(handshake(&server, &anonymous).await.is_err());
        let exact_limit = format!("{key}\n#{}", "x".repeat(65536 - 66));
        fs::write(&path, &exact_limit).unwrap();
        assert!(handshake(&server, &listed).await.unwrap());
        fs::write(&path, format!("{exact_limit}x")).unwrap();
        assert!(handshake(&server, &listed).await.is_err());
        fs::remove_file(&path).unwrap();
        #[cfg(unix)]
        {
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(handshake(&server, &listed).await.is_err());
            fs::remove_file(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        assert!(handshake(&server, &listed).await.is_err());
        assert!(handshake(&server, &anonymous).await.is_err());
    }
}

#[derive(Debug)]
struct MismatchedClientKey(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for MismatchedClientKey {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn certificate_verify_requires_the_listed_private_key() {
    let provider = aws_lc_rs::default_provider();
    let _ = provider.clone().install_default();
    let server_id = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
    let (listed, key) = identity(&PKCS_ED25519);
    let (other, _) = identity(&PKCS_ED25519);
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), key).unwrap();
    let auth = ClientAuth::KeyAllowlist {
        path: file.path().to_owned(),
        open_when_missing: false,
    };
    let server = TlsAcceptor::from(Arc::new(
        ServerTlsConfig::new(&server_id, auth).unwrap().config,
    ));
    let mut config = client_config(None, Some(server_id.cert_chain[0].clone()), false).unwrap();
    let signing_key = provider.key_provider.load_private_key(other.key).unwrap();
    let forged = rustls::sign::CertifiedKey::new(listed.cert_chain, signing_key);
    config.client_auth_cert_resolver = Arc::new(MismatchedClientKey(Arc::new(forged)));
    let err = handshake(&server, &TlsConnector::from(Arc::new(config)))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err.get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadSignature
            ))
        ),
        "{err}"
    );
}

#[tokio::test]
async fn seeing_any_file_latches_even_if_the_client_is_anonymous() {
    let _ = aws_lc_rs::default_provider().install_default();
    let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clients");
    let server = || {
        let auth = ClientAuth::KeyAllowlist {
            path: path.clone(),
            open_when_missing: true,
        };
        TlsAcceptor::from(Arc::new(
            ServerTlsConfig::new(&identity, auth).unwrap().config,
        ))
    };
    let client = TlsConnector::from(Arc::new(
        client_config(None, Some(identity.cert_chain[0].clone()), false).unwrap(),
    ));

    for contents in [b"".as_slice(), b"not a key", &[0xff]] {
        let server = server();
        assert!(!handshake(&server, &client).await.unwrap());
        fs::write(&path, contents).unwrap();
        assert!(handshake(&server, &client).await.is_err());
        fs::remove_file(&path).unwrap();
        assert!(handshake(&server, &client).await.is_err());
    }
    #[cfg(unix)]
    for target in [dir.path().join("absent"), "/dev/null".into()] {
        let server = server();
        std::os::unix::fs::symlink(target, &path).unwrap();
        assert!(handshake(&server, &client).await.is_err());
        fs::remove_file(&path).unwrap();
        assert!(handshake(&server, &client).await.is_err());
    }
}
