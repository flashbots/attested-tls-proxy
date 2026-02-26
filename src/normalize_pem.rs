use anyhow::{Result, anyhow, bail};
use pkcs8::EncodePrivateKey;
use std::io::Cursor;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// Given a PEM encoded private key convert to PKCS8 which Rustls accepts
pub fn normalize_private_key_pem_to_pkcs8(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let der = normalize_private_key_pem_to_pkcs8_der(pem)?;
    let pkcs8_der = PrivatePkcs8KeyDer::from(der);
    Ok(pkcs8_der.into())
}

fn normalize_private_key_pem_to_pkcs8_der(pem: &[u8]) -> Result<Vec<u8>> {
    let mut rd = Cursor::new(pem);

    // Find first private key in the PEM (ignore certs, etc.)
    let item = loop {
        match rustls_pemfile::read_one(&mut rd).map_err(|e| anyhow!("reading PEM: {e}"))? {
            Some(it) => match it {
                rustls_pemfile::Item::Pkcs8Key(_)
                | rustls_pemfile::Item::Pkcs1Key(_)
                | rustls_pemfile::Item::Sec1Key(_) => break it,
                _ => continue,
            },
            None => bail!("No private key found in PEM"),
        }
    };

    match item {
        // Already PKCS#8: pass through DER bytes
        rustls_pemfile::Item::Pkcs8Key(k) => Ok(k.secret_pkcs8_der().to_vec()),

        // RSA PKCS#1 ("BEGIN RSA PRIVATE KEY") -> PKCS#8
        rustls_pemfile::Item::Pkcs1Key(k) => {
            use pkcs1::DecodeRsaPrivateKey;
            use rsa::RsaPrivateKey;

            let key = RsaPrivateKey::from_pkcs1_der(k.secret_pkcs1_der())
                .map_err(|e| anyhow!("Parsing PKCS#1 RSA key: {e:?}"))?;

            let pkcs8 = key
                .to_pkcs8_der()
                .map_err(|e| anyhow!("Encoding PKCS#8 RSA key: {e:?}"))?;

            Ok(pkcs8.as_bytes().to_vec())
        }

        // SEC1 ("BEGIN EC PRIVATE KEY") for P-256 -> PKCS#8
        rustls_pemfile::Item::Sec1Key(k) => {
            let sk = p256::SecretKey::from_sec1_der(k.secret_sec1_der())
                .map_err(|e| anyhow!("Parsing SEC1 P-256 key: {e:?}"))?;

            let pkcs8 = sk
                .to_pkcs8_der()
                .map_err(|e| anyhow!("Encoding PKCS#8 P-256 key: {e:?}"))?;

            Ok(pkcs8.as_bytes().to_vec())
        }

        _ => Err(anyhow!("unexpected PEM item (filtered earlier)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn convert_private_key_to_pkcs8() {
        let _key = normalize_private_key_pem_to_pkcs8(RSA_PKCS1_PEM.as_bytes()).unwrap();
        let _key = normalize_private_key_pem_to_pkcs8(RSA_PKCS8_PEM.as_bytes()).unwrap();
    }
}
