//! Serve HTTP/2 after a TLS handshake and server attestation exchange.
//!
//! Run with `cargo run -p attested-tls --example self_signed_http2`.
//! This example uses mock attestation through the crate's development dependencies.
//! Applications using real attestation must build without `attestation/mock`.

use std::convert::Infallible;

use attested_tls::{
    AttestedTlsServer,
    attestation::{AttestationGenerator, AttestationVerifier},
    tls::self_signed_server_config,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "could not install the TLS crypto provider")?;

    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    let address = listener.local_addr()?;

    // Generate self-signed cert and rustls server config
    let (mut config, cert_chain) = self_signed_server_config(address.ip(), false)?;

    // Supply the application protocol as http2. AttestedTlsServer maps it to
    // `flashbots-ratls/1+h2` and also advertises its bare protocol fallback.
    config.alpn_protocols = vec![b"h2".to_vec()];

    let server = AttestedTlsServer::new_with_tls_config(
        cert_chain,
        config,
        AttestationGenerator::detect()?,
        // This server attests itself and expects no client attestation.
        AttestationVerifier::expect_none(),
    )?;

    println!("Listening on {address}");

    loop {
        let (socket, peer) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(server, socket).await {
                eprintln!("Connection from {peer} failed: {error}");
            }
        });
    }
}

// Handle an incoming TCP connection
async fn serve_connection(server: AttestedTlsServer, socket: TcpStream) -> Result<(), Error> {
    // This completes both TLS and attestation before returning the stream
    let (stream, _client_measurements, _client_attestation_type) =
        server.handle_connection(socket).await?;

    // Enforce http2
    if stream.get_ref().1.alpn_protocol() != Some(b"flashbots-ratls/1+h2".as_slice()) {
        return Err("client did not negotiate HTTP/2".into());
    }

    // Serve http2 connection
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service_fn(handle_request))
        .await?;
    Ok(())
}

// Respond with a hello message
async fn handle_request(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    println!("{} {}", request.method(), request.uri());
    Ok(Response::new(Full::new(Bytes::from_static(
        b"Hello over attested TLS and HTTP/2!\n",
    ))))
}
