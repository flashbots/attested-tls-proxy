use anyhow::anyhow;
use attested_tls::TlsCertAndKey;
use std::{fs::File, net::IpAddr, path::PathBuf};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub(super) fn load_tls_cert_and_key_server(
    cert_chain: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ip: IpAddr,
) -> anyhow::Result<TlsCertAndKey> {
    if let Some(private_key) = private_key {
        load_tls_cert_and_key(
            cert_chain.ok_or(anyhow!("Private key given but no certificate chain"))?,
            private_key,
        )
    } else {
        if cert_chain.is_some() {
            return Err(anyhow!("Certificate chain provided but no private key"));
        }
        tracing::warn!("No TLS ceritifcate provided - generating self-signed");
        Ok(attested_tls_proxy::self_signed::generate_self_signed_cert(
            ip,
        )?)
    }
}

/// Load TLS details from storage
pub(super) fn load_tls_cert_and_key(
    cert_chain: PathBuf,
    private_key: PathBuf,
) -> anyhow::Result<TlsCertAndKey> {
    let key = load_private_key_pem(private_key)?;
    let cert_chain = load_certs_pem(cert_chain)?;
    Ok(TlsCertAndKey { key, cert_chain })
}

/// load certificates from a PEM-encoded file
pub(super) fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
}

/// load TLS private key from a PEM-encoded file
pub(super) fn load_private_key_pem(path: PathBuf) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::BufReader::new(File::open(path)?))?
        .ok_or_else(|| anyhow!("No private key found in PEM"))
}

/// Given a certificate chain, convert it to a PEM encoded string
pub(super) fn certs_to_pem_string(
    certs: &[CertificateDer<'_>],
) -> Result<String, pem_rfc7468::Error> {
    let mut out = String::new();
    for cert in certs {
        let block =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert.as_ref())?;
        out.push_str(&block);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::{SignatureScheme, crypto::aws_lc_rs};

    fn load_pem_fixture(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), pem)?;
        load_private_key_pem(file.path().to_owned())
    }

    // Public test fixtures only; never use these keys in a deployment.
    const RSA_PKCS1_PEM: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsvbL9Jh5+CRiwD4rdixOmHcI/vpwUD0j8PDpDStTTICGpSqN
l7WlSMaFJn5Tc9aXgSftKDiBnPQzPEBBBVxnbJ8MgIY4YilBehoGBY035CPZ+C8P
8wZN7+VoRATUYPYzFdq/cdyCPqB+ZpnJjIRy5WXDlPO8fuGlx5+IvUwEeVIQAXsE
AkXg0Ky3PnB5gyDinCGTM3eM77SzFuWU5LptZjPa9Aap9/QoCrXkC+sbX7pOsWYe
U8JJErIfqBdBT4s/1tVqRmll2Fljr0O65O348zjqkZiQJvRpWvRtSQHK4VurUhHj
7sO6qmdbXD4P9I9Vrug+pAO1J0YDemKpcnO/WQIDAQABAoIBABDOwuru4w2eBTQ+
4oAPuzXwgATKan/urhBz379f4UvfCkY6z99+rM4/7sNlu9q2PbZglJJhdDLUcHdp
JXImcoQuD9OGR4dYjpC0Hvqof6ZKg68eZGYTooA0UG2K8pNErBmSWMaNyiGtmxFx
wg8TZWMMAqlblsln0dUEs6frmsP1+3AQ8BKyJFCV2TOipf/ja9TcNu9n6ukSwJml
mmDxJS3gTLWxfB0dQs1V+zgLDvqQqjLlgXRXQ8tIualvYY6+tHNJuxeVhyevarGy
lQ1p7GqNFedKQpqMwaXrI/rMY8q75/C0ajKBO7TJZMPRnD5airTNiZ1VG9J+OQrh
Kshdyc0CgYEA92yozUCyY0ns8qs97ixZc3SuKMA6wcmxZEiLv64M64MdKoBM3wfm
wDQGQodg1T3H3Rzw1fZRbaJ4KweG7TKQuey5CY1j7uZyNVNMbGF12Z5HjJhvC88/
lIpB44aYgmOerqrQczX8KVak8kttw+DoQYGbEyubJ/LXfGu1NCnFZ7MCgYEAuSq0
LbRMneV9RVMG4z4Y7MrdXBM1C1NcyUdK5nOhUNlWDSlPKIltxznvHoBT6XsYDYb+
mwPc6Hm6ui75RBhPMlsmoqIeriumnT1Cbr9nk2VZ0+nEKUN6QuG3qH+j8flnh0vc
39wIJs8I2DuYr5EaiUlIaTLWDrKphk3uOzLyNsMCgYEAhuhyaef63HR0hCSm0fTQ
mUlnpMSbxQpKdRmxSUSHuup0vrXSNFHEmcxEFYZnYB4dmgyrrJ5v682IpD2objEC
BL50bibv9FUmtLjElNvXPF83OAvtkIziaAWyw3KiOYZEAY0Vt5wZ8BhUO+Cw6vr4
6K7YdW1zXiblI+w+k0CraE0CgYAZEF25PgmM6e5t/tIU2mf3TXJvLy5j7RHHMP5D
eW1hizmpqGjNnOSeLgpe/5HcLcxQsHAwPXKeiTOsVgVpoTy/HTV6mCU9AC2aZRtj
8Eat3e8tzxu9ViPrf7Ajf7uKWm8YEj3Ak4EK98VDt7VwNlz4LlI94yK0dJyb0Fqp
6rh8jwKBgQCRq5Ot6bClmTPzQo1T52BGtHZBhVGqFc/76J0knZHL/Qper6TG5IP9
L4yOiMqxV7mUGWsDBEAi/sisVSLCZvsdWUFvJ4Bp9YBOSWyZlRK59gsOGzS6Qjw7
fCW7RLfTr0dg2eU3oUTI4B8SHULOhGjSjQ4KCGnbbdIUW2NlFdDkVQ==
-----END RSA PRIVATE KEY-----
"#;

    const RSA_PKCS8_PEM: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChw1TJMP2aYJnY
0wG4ElBAXVyFkQvgsx7Sh7yQjbs/WlSE7VOBOJIwKGhVWJk9vJpRWYl6WhiQn/ui
msd06YPkZhvoIotiESyQI7RRpv4YHWj5n8Gomwphj28ttLx3u7AiUWq9uK7mIsFT
Cf6YzUIYQf6FlQu+mYDObtSOtZWmSW69NtZWi2YyXNHPcooPnol8Y0OOd+V6XZrK
Qq8hGfj/7B6HjGbNUH02sKSWC7H7pn+BglNNpX0Znrx+oeEVH4pycYarolixVC0p
N7aK/v+jWiSc3U3Nz6lWALVuzsl2hOC10ie0kVNgheh4bP78YoglKiLHMVO/CRo6
IzjXeuWTAgMBAAECggEAGarj5jS22OshHk2FBU8qmrv1tV/pkZL6fg95tTo4Dvpn
VNxPlr6CO8/9liVD0478sZHSha6MHU61X/zNT1jKS9CD9xacJUhyWMDBmP81bGAm
Sw21beqEAC0BSDBYg2strJRcqpQGdI/pOyLn2hkftreqCko3Hdw/mwHtCmP3xfW6
QrmmSOQVq7hKSVCRSs6Do+SW+BLJLb/7ZoU4V8g8nakGh9oXmVKl5CDn/w9f+NSc
VUatPt2+7GMCnUKmQ9qodcuz/EINkimmZY1L2e9WhF9ETm/l292j9Vo2bU7KNoBB
E+9Cn+wMh23mmacSmY7S9SDBkQgVKmRMAyoFxTPmAQKBgQDXwXZLyhYDrtBMOKED
IgFeXMSQj5JZZ10suXYd3nX7iapiNimm5Febe/b4UinhwTzne6WanSvs92vPR5xN
XbJOcep4+YLFt30ZyAb8tyekkdC13rbKNraFWV1+wBs6yT3lfal5JF7Ko7TezYuG
E+nJdrzndLeV8o0yZy8zxT9FAQKBgQC/76rBFpqxBlHCVLLjPEwKvbvsgtRIrqfg
TeKUPS+QHMezYnrQkOiODyUA0/Xs4NBrDI7XuA6tjG0ZLPJWbjckNcvdka0bFQmN
jXXqnTwBsEcFlUFdXVt3EmuIn0K++EBemLndFhn0Wscwn7AO6cQWTA+qy+xuP0Pj
5gGo30hGkwKBgDk3kQugWB456fuMuQZ/qiVALNC5gnI7OzZ1KKHbMSa353uMKZec
zq7pPSG1iG3aNTCeVdie/dsl8m1R7F2ID5VGGIxkfw24D3Ea3t9+IwE9uj/BBHCz
+ct7W5QVliMM42FM5fi+cHUE3R6JHAs+lK1c09P93AHkBRXsz1PHZ3QBAoGAbWgD
MG9fHBtbDWfUVH0xZ0oBze5BbXDJVq1uw0shSodtOg6frTV8qkVttUwdObpocyzE
W6iaDUkngxtAxA2tNuHHZHQ+dVqHiH2jQmoAI4JE6aTLjpnBol0ImOcXV94Qaxup
jqGjh8sbEddktwt/b6pJn/T/v1QmsciRF563BysCgYB7t1HngCHE6zCGQdxDDp5A
Vb9rJaarKKy5TIX0svK4iGxmoD/qCf9o5LwKwoQLPf4K2F8fhEZZGes+62M5HzmZ
FCKYluqG2/M/gs/AE9K+btrpuIbZZB5Prris+THkBBxHTt49WFxwkVK+CbQxg0VC
32K3vJkhe2O33oHoyzQRfw==
-----END PRIVATE KEY-----
"#;

    const P256_SEC1_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP37GKC//8GKtvmYmf62bpDsD8vlhlxLZ1PNbTICsvo9oAoGCCqGSM49
AwEHoUQDQgAEoCwAV5jHuPli5xYkmgQiGsa+MsZLXXmqrUR5Wu0S5Xgsm5lv/wy3
JSUC8mADyuZZsVyaFkSgSGkyyJfwSvVLNg==
-----END EC PRIVATE KEY-----
"#;

    #[test]
    fn original_key_formats_work_with_tls_provider() {
        let provider = aws_lc_rs::default_provider();
        for (pem, scheme) in [
            (RSA_PKCS1_PEM, SignatureScheme::RSA_PSS_SHA256),
            (RSA_PKCS8_PEM, SignatureScheme::RSA_PSS_SHA256),
            (P256_SEC1_PEM, SignatureScheme::ECDSA_NISTP256_SHA256),
        ] {
            let key = load_pem_fixture(pem.as_bytes()).unwrap();
            match pem {
                RSA_PKCS1_PEM => assert!(matches!(&key, PrivateKeyDer::Pkcs1(_))),
                RSA_PKCS8_PEM => assert!(matches!(&key, PrivateKeyDer::Pkcs8(_))),
                P256_SEC1_PEM => assert!(matches!(&key, PrivateKeyDer::Sec1(_))),
                _ => unreachable!(),
            }
            let signing_key = provider.key_provider.load_private_key(key).unwrap();
            let signer = signing_key.choose_scheme(&[scheme]).unwrap();
            assert!(
                !signer
                    .sign(b"TLS key loading regression test")
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn missing_and_malformed_keys_fail_and_other_pem_blocks_are_skipped() {
        let certificate = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
        for pem in [
            "",
            "not PEM",
            certificate,
            "-----BEGIN PRIVATE KEY-----\ninvalid base64!\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(load_pem_fixture(pem.as_bytes()).is_err());
        }
        let bundle = format!("{certificate}{RSA_PKCS1_PEM}{P256_SEC1_PEM}");
        assert!(matches!(
            load_pem_fixture(bundle.as_bytes()).unwrap(),
            PrivateKeyDer::Pkcs1(_)
        ));
    }
}
