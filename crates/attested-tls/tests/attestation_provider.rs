#![cfg(unix)]

use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    time::Duration,
};

use attested_tls::attestation::{
    AttestationEvidence, AttestationGenerator, AttestationType, mock_platform_metadata,
    provider::ProviderResponse,
};
use parity_scale_codec::Encode;

#[test]
fn provider_receives_each_binding_and_returns_assembled_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provider.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let generator = AttestationGenerator::new(AttestationType::DcapTdx, Some(path)).unwrap();
    let server = std::thread::spawn(move || {
        for input in [[42; 64], [73; 64]] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert_eq!(request, input);

            let response = ProviderResponse::Ok(
                AttestationEvidence {
                    quote: request,
                    platform: mock_platform_metadata(AttestationType::DcapTdx).unwrap(),
                }
                .into(),
            )
            .encode();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    });

    for input in [[42; 64], [73; 64]] {
        let message = generator.generate_attestation(input).unwrap();
        assert_eq!(
            message.attestation_type().unwrap(),
            AttestationType::DcapTdx
        );
        let evidence = message.attestation_evidence.unwrap();
        assert_eq!(evidence.quote, input);
        assert_eq!(
            evidence.platform.encode(),
            mock_platform_metadata(AttestationType::DcapTdx)
                .unwrap()
                .encode()
        );
    }
    server.join().unwrap();
}
