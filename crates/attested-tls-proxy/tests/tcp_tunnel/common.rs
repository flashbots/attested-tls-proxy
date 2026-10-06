#![allow(dead_code)]
use attested_tls::attestation::{AttestationGenerator, AttestationVerifier};
use attested_tls_proxy::self_signed::generate_self_signed_cert;
use attested_tls_proxy::tcp_tunnel::{TunnelClient, TunnelError, TunnelOptions, TunnelServer};
use std::{future::Future, net::SocketAddr, time::Duration};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

pub const LOCAL: &str = "127.0.0.1:0";

pub fn provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("test timed out")
}

pub async fn listener() -> TcpListener {
    TcpListener::bind(LOCAL).await.unwrap()
}

pub struct Running {
    pub addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), TunnelError>>>,
}

impl Running {
    pub fn client(client: TunnelClient) -> Self {
        let addr = client.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        Self {
            addr,
            shutdown: Some(tx),
            task: Some(tokio::spawn(client.serve_until(async {
                let _ = rx.await;
            }))),
        }
    }

    pub fn server(server: TunnelServer) -> Self {
        let addr = server.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        Self {
            addr,
            shutdown: Some(tx),
            task: Some(tokio::spawn(server.serve_until(async {
                let _ = rx.await;
            }))),
        }
    }

    pub fn signal(&mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().unwrap().is_finished()
    }

    pub async fn wait(mut self) {
        self.task.take().unwrap().await.unwrap().unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub async fn pair(target: SocketAddr, options: TunnelOptions) -> (Running, Running) {
    provider();
    let identity = generate_self_signed_cert("127.0.0.1".parse().unwrap()).unwrap();
    let cert = identity.cert_chain[0].clone();
    let server = TunnelServer::new(
        LOCAL,
        target.to_string(),
        identity,
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        false,
        options,
    )
    .await
    .unwrap();
    let server = Running::server(server);
    let client = TunnelClient::new(
        LOCAL,
        server.addr.to_string(),
        None,
        AttestationGenerator::with_no_attestation(),
        AttestationVerifier::expect_none(),
        Some(cert),
        false, // No startup check.
        options,
    )
    .await
    .unwrap();
    (Running::client(client), server)
}
