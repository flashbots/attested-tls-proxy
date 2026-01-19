//! Generation and verification of AK certificates from the vTPM
use crate::attestation::azure::{nv_index, MaaError};
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::EndEntityCert;

/// The NV index where we expect to be able to read the AK certificate from the vTPM
const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

// microsoftRSADevicesRoot2021 is the root CA certificate used to sign Azure TDX vTPM certificates.
// This is different from the AME root CA used by TrustedLaunch VMs.
// The certificate can be downloaded from:
// http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt
const MICROSOFT_RSA_DEVICES_ROOT_2021: &str = "-----BEGIN CERTIFICATE-----
MIIFkjCCA3qgAwIBAgIQGWCAkS2F96VGa+6hm2M3rjANBgkqhkiG9w0BAQwFADBa
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
KQYDVQQDEyJNaWNyb3NvZnQgUlNBIERldmljZXMgUm9vdCBDQSAyMDIxMB4XDTIx
MDgyNjIzMzkxOFoXDTQ2MDgyNjIzNDcxNFowWjELMAkGA1UEBhMCVVMxHjAcBgNV
BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0IFJT
QSBEZXZpY2VzIFJvb3QgQ0EgMjAyMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBALF4kgr3bAptorWmkrM6u47osmLfg67KxZPE4W74Zw5Bu64tjEuzegcB
6lFkoXi2V4eLdIRshk3l14jul6ghCML/6gh4hYiTExky3XMY05wg0d1o+AdhuyvC
anXvQZratosnL+KhR2qFeagthciIrCibIIKX91LvqRl/Eg8uo82fl30gieB40Sun
Pe/SfMJLb7AYbQ95yHK8G1lTFUHkIfPbAY6SfkOBUpNJ6UAtjlAmIaHYpdcdOayf
qXyhW3+Hf0Ou2wiKYJihCqh3TaI2hqmiv4p4CScug9sDcTyafA6OYLyTe3vx7Krn
BOUvkSkTj80GrXSKCWnrw+bE7z0deptPuLS6+n83ImLsBZ3XYhX4iUPmTRSU9vr7
q0cZA8P8zAzLaeN+uK14l92u/7TMhkp5etmLE9DMd9MtnsLZSy18UpW4ZlBXxt9Z
w/RFKStlNbK5ILsI2HdSjgkF0DxZtNnCiEQehMu5DBfCdXo1P90iJhfF1MD+2Kh5
xeuDQEC7Dh3gUSXIkOm/72u1fE52r0uY+aH1TCQGbCrijI9Jf78lFbI7L6Ll3YAa
89MrDs2tAQG0SaJdabh4k5orqaJOgaqrrq61RzcMjlZGI3dOdL+f6romKOccFkm0
k+gwjvZ9xaJ5i9SB6Lq/GrA8YxzjmKHHVPmGGdm/v93R0oNGfyvxAgMBAAGjVDBS
MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSERIYG
AJg/LKqzxYnzrC7J5p0JAzAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwF
AAOCAgEAd3RAo42nyNbVvj+mxZ03VV+ceU6nCdgIS8RZfZBxf+lqupRzKUV9UW59
IRCSeMH3gHfGSVhmwH1AJHkFIhd5meSShF4lPPmvYMmrbfOrwiUunqz2aix/QkRp
geMOe10wm6dEHHAw/eNi3PWhc+jdGJNV0SdnqcwJg/t5db8Y7RCVW+tG3DtEa63U
B4sGNlBbaUffdSdYL5TCRXm2mkcCWruu/gmDTgoabFmI4j9ss0shsIxwqVVEq2zk
EH1ypZrHSmVrTRh9hPHWpkOxnh9yqpGDXcSll09ZZUBUhx7YUX6p+BTVWnuuyR4T
bXS8P6fUS5Q2WF0WR07BrGYlBqomsEwMhth1SmBKn6tXfQyWkgr4pVl5XkkC7Bfv
pmw90csy8ycwog+x4L9kO1Nr6OPwnJ9V39oMifNDxnvYVBX7EhjoiARPp+97feNJ
YwMt4Os/WSeD++IhBB9xVsrI+jZufySQ02C/w1LBFR6zPy+a+v+6WlvMxDBEDWOj
JyDQ6kzkWxIG35klzLnwHybuIsFIIR1QGL1l47eW2dM4hB9oCay6z3FX5xYBIFvA
yp8up+KbjfH/NIWfPBXhYMW64DagB9P2cW5LBRz+AzDA+JF/OdYpb6vxv3lzjLQb
U9zMFwSrzEF5o2Aa/n+xZ90Naj78AYaTM18DalA17037fjucDN8=
-----END CERTIFICATE-----";

// azureVirtualTPMRoot2023 is the root CA for Azure vTPM (used by both Trusted Launch and TDX)
// Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Valid until: 2048-06-01
const AZURE_VIRTUAL_TPM_ROOT_2023: &str = "-----BEGIN CERTIFICATE-----
MIIFsDCCA5igAwIBAgIQUfQx2iySCIpOKeDZKd5KpzANBgkqhkiG9w0BAQwFADBp
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTow
OAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1dGhv
cml0eSAyMDIzMB4XDTIzMDYwMTE4MDg1M1oXDTQ4MDYwMTE4MTU0MVowaTELMAkG
A1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE6MDgGA1UE
AxMxQXp1cmUgVmlydHVhbCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkg
MjAyMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALoMMwvdRJ7+bW00
adKE1VemNqJS+268Ure8QcfZXVOsVO22+PL9WRoPnWo0r5dVoomYGbobh4HC72s9
sGY6BGRe+Ui2LMwuWnirBtOjaJ34r1ZieNMcVNJT/dXW5HN/HLlm/gSKlWzqCEx6
gFFAQTvyYl/5jYI4Oe05zJ7ojgjK/6ZHXpFysXnyUITJ9qgjn546IJh/G5OMC3mD
fFU7A/GAi+LYaOHSzXj69Lk1vCftNq9DcQHtB7otO0VxFkRLaULcfu/AYHM7FC/S
q6cJb9Au8K/IUhw/5lJSXZawLJwHpcEYzETm2blad0VHsACaLNucZL5wBi8GEusQ
9Wo8W1p1rUCMp89pufxa3Ar9sYZvWeJlvKggWcQVUlhvvIZEnT+fteEvwTdoajl5
qSvZbDPGCPjb91rSznoiLq8XqgQBBFjnEiTL+ViaZmyZPYUsBvBY3lKXB1l2hgga
hfBIag4j0wcgqlL82SL7pAdGjq0Fou6SKgHnkkrV5CNxUBBVMNCwUoj5mvEjd5mF
7XPgfM98qNABb2Aqtfl+VuCkU/G1XvFoTqS9AkwbLTGFMS9+jCEU2rw6wnKuGv1T
x9iuSdNvsXt8stx4fkVeJvnFpJeAIwBZVgKRSTa3w3099k0mW8qGiMnwCI5SfdZ2
SJyD4uEmszsnieE6wAWd1tLLg1jvAgMBAAGjVDBSMA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRL/iZalMH2M8ODSCbd8+WwZLKqlTAQ
BgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEALgNAyg8I0ANNO/8I
2BhpTOsbywN2YSmShAmig5h4sCtaJSM1dRXwA+keY6PCXQEt/PRAQAiHNcOF5zbu
OU1Bw/Z5Z7k9okt04eu8CsS2Bpc+POg9js6lBtmigM5LWJCH1goMD0kJYpzkaCzx
1TdD3yjo0xSxgGhabk5Iu1soD3OxhUyIFcxaluhwkiVINt3Jhy7G7VJTlEwkk21A
oOrQxUsJH0f2GXjYShS1r9qLPzLf7ykcOm62jHGmLZVZujBzLIdNk1bljP9VuGW+
cISBwzkNeEMMFufcL2xh6s/oiUnXicFWvG7E6ioPnayYXrHy3Rh68XLnhfpzeCzv
bz/I4yMV38qGo/cAY2OJpXUuuD/ZbI5rT+lRBEkDW1kxHP8cpwkRwGopV8+gX2KS
UucIIN4l8/rrNDEX8T0b5U+BUqiO7Z5YnxCya/H0ZIwmQnTlLRTU2fW+OGG+xyIr
jMi/0l6/yWPUkIAkNtvS/yO7USRVLPbtGVk3Qre6HcqacCXzEjINcJhGEVg83Y8n
M+Y+a9J0lUnHytMSFZE85h88OseRS2QwqjozUo2j1DowmhSSUv9Na5Ae22ycciBk
EZSq8a4rSlwqthaELNpeoTLUk6iVoUkK/iLvaMvrkdj9yJY1O/gvlfN2aiNTST/2
bd+PA4RBToG9rXn6vNkUWdbLibU=
-----END CERTIFICATE-----";

// globalVirtualTPMCA03 is the intermediate CA that issues TDX vTPM AK certificates
// Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Issuer: Azure Virtual TPM Root Certificate Authority 2023
// Valid: 2025-04-24 to 2027-04-24
const GLOBAL_VIRTUAL_TPMCA03_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIFnDCCA4SgAwIBAgITMwAAAAknQOWscnsOpgAAAAAACTANBgkqhkiG9w0BAQwF
ADBpMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
MTowOAYDVQQDEzFBenVyZSBWaXJ0dWFsIFRQTSBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAyMDIzMB4XDTI1MDQyNDE4MDExN1oXDTI3MDQyNDE4MDExN1owJTEj
MCEGA1UEAxMaR2xvYmFsIFZpcnR1YWwgVFBNIENBIC0gMDMwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDYGYtis5ka0cxQkhU11jslgX6wzjR/UXQIFdUn
8juTUMJl91VokwUPX3WfXeog7mtbWyYWD8SI0BSnchRGlV8u3AhcW61/HetHqmIL
tD0c75UATi+gsTQnpwKPA/m38MGGyXFETr3xHXjilUPfIhmxO4ImuNJ0R95bZYhx
bLYmOZpVUcj8oz980An8HlIqSzrskQR6NiuEmikHkHc1/CpoNunrr8kQNPF6gxex
IrvXsKLUAuUqnNtcQWc/8Er5EN9+TdX6AOjUmKriVGbCInP1m/aC+DWH/+aJ/8aD
pKze6fe7OHh2BL9hxqIsmJAStIh4siRdLYTt8hKGmkdzOWnRAgMBAAGjggF/MIIB
ezASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwICBDAXBgNVHSUEEDAO
BgVngQUIAQYFZ4EFCAMwHQYDVR0OBBYEFGcJhvj5gV6TrfnJZOcUCtqZywotMB8G
A1UdIwQYMBaAFEv+JlqUwfYzw4NIJt3z5bBksqqVMHYGA1UdHwRvMG0wa6BpoGeG
ZWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL0F6dXJlJTIwVmly
dHVhbCUyMFRQTSUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIw
MjMuY3JsMIGDBggrBgEFBQcBAQR3MHUwcwYIKwYBBQUHMAKGZ2h0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvQXp1cmUlMjBWaXJ0dWFsJTIwVFBN
JTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAyMy5jcnQwDQYJ
KoZIhvcNAQEMBQADggIBAJPP3Z2z1zhzUS3qSRVgyoUVnaxCGuMHzPQAZuoPBVpz
wKnv4HqyjMgT8pBtQqxkqAsg7KiqbPfO97bMCHcuqkkfHjw8yg6IYt01RjUjVPKq
lrsY2iw7hFWNWr8SGMa10JdNYNyf5dxob5+mKAwEOhLzKNwq9rM/uIvZky77pNly
RLt55XEPfBMYdI9I8uQ5Uqmrw7mVJfERMfTBhSQF9BrcajAsaLcs7qEUyj0yUdJf
cgZkfCoUEUSPr3OwLHaYeV1J6VidhIYsYo53sXXal91d60NspYgei2nJFei/+R3E
SWnGbPBW+EQ4FbvZXxu57zUMX9mM7lC+GoXLvA6/vtKShEi9ZXl2PSnBQ/R2A7b3
AXyg4fmMLFausEk6OiuU8E/bvp+gPLOJ8YrX7SAJVuEn+koJaK5G7os5DMIh7/KM
l9cI9WxPwqoWjp4VBfrF4hDOCmKWrqtFUDQCML8qD8RTxlQKQtgeGAcNDfoAuL9K
VtSG5/iIhuyBEFYEHa3vRWbSaHCUzaHJsTmLcz4cp1VDdepzqZRVuErBzJKFnBXb
zRNW32EFmcAUKZImIsE5dgB7y7eiijf33VWNfWmK05fxzQziWFWRYlET4SVc3jMn
PBiY3N8BfK8EBOYbLvzo0qn2n3SAmPhYX3Ag6vbbIHd4Qc8DQKHRV0PB8D3jPGmD
-----END CERTIFICATE-----";

/// The intermediate chain for azure
static GLOBAL_VIRTUAL_TPMCA03: Lazy<Vec<CertificateDer<'static>>> = Lazy::new(|| {
    let (_type_label, cert_der) =
        pem_rfc7468::decode_vec(GLOBAL_VIRTUAL_TPMCA03_PEM.as_bytes()).expect("Cannot decode PEM");
    vec![CertificateDer::from(cert_der)]
});

/// The root anchors for azure
static AZURE_ROOT_ANCHORS: Lazy<Vec<TrustAnchor<'static>>> = Lazy::new(|| {
    vec![
        // Microsoft RSA Devices Root CA 2021 (older VMs)
        pem_to_trust_anchor(MICROSOFT_RSA_DEVICES_ROOT_2021),
        // Azure Virtual TPM Root CA 2023 (TDX + newer trusted launch)
        pem_to_trust_anchor(AZURE_VIRTUAL_TPM_ROOT_2023),
    ]
});

/// Verify an AK certificate against azure root CA
pub fn verify_ak_cert_with_azure_roots(ak_cert_der: &[u8], now_secs: u64) -> Result<(), MaaError> {
    let ak_cert_der: CertificateDer = ak_cert_der.into();
    let end_entity_cert = EndEntityCert::try_from(&ak_cert_der)?;

    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));

    end_entity_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &AZURE_ROOT_ANCHORS,
        &GLOBAL_VIRTUAL_TPMCA03,
        now,
        AnyEku,
        None,
        None,
    )?;
    tracing::debug!("Successfully verified AK certificate from vTPM");

    Ok(())
}

/// Retrieve an AK certificate from the vTPM
pub fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
    tracing::debug!("Reading AK certificate from vTPM");
    let mut context = nv_index::get_session_context()?;
    nv_index::read_nv_index(&mut context, TPM_AK_CERT_IDX)
}

/// Convert a PEM-encoded cert into a TrustAnchor
fn pem_to_trust_anchor(pem: &str) -> TrustAnchor<'static> {
    let (_type_label, der_vec) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    // Leaking is ok here because plan is to set this up so it is only called once
    let leaked: &'static [u8] = Box::leak(der_vec.into_boxed_slice());
    let cert_der: &'static CertificateDer<'static> =
        Box::leak(Box::new(CertificateDer::from(leaked)));
    webpki::anchor_from_trusted_cert(cert_der).expect("Failed to create trust anchor")
}

/// Allows any EKU - we could change this to only accept 1.3.6.1.4.1.567.10.3.12 which is the EKU
/// given in the AK certificate
struct AnyEku;

impl webpki::ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

#[cfg(test)]
#[tokio::test]
async fn root_should_be_fresh() {
    let response = reqwest::get(
        "http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt",
    )
    .await
    .unwrap();
    let ca_der = response.bytes().await.unwrap();
    assert_eq!(
        pem_rfc7468::decode_vec(MICROSOFT_RSA_DEVICES_ROOT_2021.as_bytes())
            .unwrap()
            .1,
        ca_der
    );
}
