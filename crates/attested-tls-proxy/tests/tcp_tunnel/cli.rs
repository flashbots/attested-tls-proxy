#![cfg(unix)]

use super::common::*;
use std::{net::SocketAddr, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
};

fn command() -> Command {
    clean_command(env!("CARGO_BIN_EXE_attested-tls-proxy"))
}

fn clean_command(program: &str) -> Command {
    let mut command = Command::new(program);
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
    let (child, address, _) = start_command(command().args(args)).await;
    (child, address)
}

async fn start_command(
    command: &mut Command,
) -> (Child, SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let mut child = command.stderr(Stdio::piped()).spawn().unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        if let Some(address) = value["fields"]["address"].as_str() {
            // Keep stderr open: tracing may log again during shutdown.
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let mut tx = Some(tx);
                while let Ok(Some(line)) = lines.next_line().await {
                    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if value["fields"]["message"] == "Accept failed; retrying"
                        && let Some(tx) = tx.take()
                    {
                        let _ = tx.send(());
                    }
                }
            });
            return (child, address.parse().unwrap(), rx);
        }
    }
    panic!("process exited before logging its listening address");
}

#[tokio::test]
async fn descriptor_exhaustion_preserves_tunnels_and_recovers() {
    exercise_descriptor_exhaustion(true).await;
}

#[tokio::test]
async fn descriptor_exhaustion_does_not_delay_shutdown() {
    exercise_descriptor_exhaustion(false).await;
}

async fn exercise_descriptor_exhaustion(recover: bool) {
    bounded(async {
        let target = listener().await;
        // Limit only the child, leaving the test runner's descriptor limit intact.
        let (mut server, server_addr, accept_error) = start_command(clean_command("sh").args([
            "-c",
            "ulimit -n 64 && exec \"$@\"",
            "sh",
            env!("CARGO_BIN_EXE_attested-tls-proxy"),
            "tcp-tunnel-server",
            &target.local_addr().unwrap().to_string(),
            "--listen-addr",
            LOCAL,
            "--server-attestation-type",
            "none",
            "--allowed-remote-attestation-type",
            "none",
            "--setup-timeout-secs",
            "2",
            "--shutdown-grace-secs",
            "0",
            "--log-json",
        ]))
        .await;
        let (mut client, client_addr) = start(&[
            "tcp-tunnel-client",
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
        let mut source = TcpStream::connect(client_addr).await.unwrap();
        let (mut backend, _) = target.accept().await.unwrap();

        let mut stalled = Vec::new();
        for _ in 0..80 {
            stalled.push(TcpStream::connect(server_addr).await.unwrap());
        }
        accept_error
            .await
            .expect("server must report descriptor exhaustion");
        assert!(server.try_wait().unwrap().is_none());
        source.write_all(b"still alive").await.unwrap();
        let mut bytes = [0; 11];
        backend.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still alive");
        backend.write_all(&bytes).await.unwrap();
        source.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still alive");

        if !recover {
            // Less than the one-second accept backoff, with descriptors still
            // exhausted: shutdown must interrupt the pending retry delay.
            tokio::time::timeout(
                std::time::Duration::from_millis(750),
                terminate(&mut server),
            )
            .await
            .expect("shutdown was blocked by accept backoff");
            terminate(&mut client).await;
            return;
        }

        drop(stalled);
        // The listener must resume acceptance after descriptors become available.
        let mut recovered = TcpStream::connect(client_addr).await.unwrap();
        let (mut recovered_backend, _) = target.accept().await.unwrap();
        recovered.write_all(b"recovered").await.unwrap();
        let mut bytes = [0; 9];
        recovered_backend.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"recovered");
        terminate(&mut server).await;
        terminate(&mut client).await;
    })
    .await;
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
    cli_round_trip(0).await;
}

#[tokio::test]
async fn cli_warm_pool_round_trip_and_sigterm_shutdown() {
    cli_round_trip(1).await;
}

async fn cli_round_trip(pool_size: usize) {
    bounded(async {
        let target = listener().await;
        let target_addr = target.local_addr().unwrap().to_string();
        let (mut server, server_addr) = start(&[
            "tcp-tunnel-server",
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
            "tcp-tunnel-client",
            &server_addr.to_string(),
            "--client-attestation-type",
            "none",
            "--allowed-remote-attestation-type",
            "none",
            "--allow-self-signed",
            "--pool-size",
            &pool_size.to_string(),
            "--shutdown-grace-secs",
            "0",
            "--log-json",
        ])
        .await;
        assert!(client_addr.ip().is_loopback());
        let warm_backend = if pool_size > 0 {
            Some(target.accept().await.unwrap().0)
        } else {
            None
        };
        let mut source = TcpStream::connect(client_addr).await.unwrap();
        let mut backend = match warm_backend {
            Some(backend) => backend,
            None => target.accept().await.unwrap().0,
        };
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
    for subcommand in ["tcp-tunnel-client", "tcp-tunnel-server"] {
        for policy in [
            vec![],
            vec![
                "--measurements-file",
                "unused.json",
                "--allowed-remote-attestation-type",
                "none",
            ],
        ] {
            let output = command()
                .args([subcommand, "127.0.0.1:443"])
                .args(policy)
                .output()
                .await
                .unwrap();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("Exactly one of"));
        }
    }
}
