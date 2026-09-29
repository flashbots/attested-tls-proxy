#![cfg(unix)]
mod common;

use common::*;
use std::{net::SocketAddr, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
};

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_attested-tls-tcp-tunnel"));
    command.kill_on_drop(true);
    for variable in [
        "LISTEN_ADDR",
        "MEASUREMENTS_FILE",
        "TLS_PRIVATE_KEY_PATH",
        "TLS_CERTIFICATE_PATH",
        "CLIENT_ATTESTATION_TYPE",
        "SERVER_ATTESTATION_TYPE",
        "OVERRIDE_AZURE_OUTDATED_TCB",
    ] {
        command.env_remove(variable);
    }
    command
}

async fn start(args: &[&str]) -> (Child, SocketAddr) {
    let mut child = command().args(args).stdout(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let Some(address) = value["fields"]["address"].as_str() {
            // Keep stdout open: tracing may log again during shutdown.
            tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
            return (child, address.parse().unwrap());
        }
    }
    panic!("process exited before logging its listening address");
}

async fn terminate(child: &mut Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().unwrap().to_string()])
        .status()
        .await
        .unwrap();
    assert!(status.success());
    assert!(child.wait().await.unwrap().success());
}

#[tokio::test]
async fn cli_round_trip_and_sigterm_shutdown() {
    bounded(async {
        let target = listener().await;
        let target_addr = target.local_addr().unwrap().to_string();
        let (mut server, server_addr) = start(&[
            "server",
            &target_addr,
            "--listen-addr",
            LOCAL,
            "--server-attestation-type",
            "none",
            "--allowed-remote-attestation-type",
            "none",
            "--shutdown-grace-secs",
            "0",
            "--log-json",
        ])
        .await;
        let (mut client, client_addr) = start(&[
            "client",
            &server_addr.to_string(),
            "--client-attestation-type",
            "none",
            "--allowed-remote-attestation-type",
            "none",
            "--allow-self-signed",
            "--shutdown-grace-secs",
            "0",
            "--log-json",
        ])
        .await;
        assert!(client_addr.ip().is_loopback());
        let mut source = TcpStream::connect(client_addr).await.unwrap();
        let (mut backend, _) = target.accept().await.unwrap();
        source.write_all(b"cli smoke test").await.unwrap();
        let mut bytes = [0; 14];
        backend.read_exact(&mut bytes).await.unwrap();
        backend.write_all(&bytes).await.unwrap();
        source.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"cli smoke test");
        terminate(&mut server).await;
        assert!(matches!(source.read(&mut [0; 1]).await, Ok(0) | Err(_)));
        terminate(&mut client).await;
    })
    .await;
}

#[tokio::test]
async fn cli_requires_an_explicit_verification_policy() {
    let output = command()
        .args(["client", "127.0.0.1:443"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Exactly one of"));
}
