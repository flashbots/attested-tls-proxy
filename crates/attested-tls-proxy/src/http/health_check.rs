//! Provides health / version details for an attested proxy server or client
use axum::{Json, Router, routing::get};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Version information
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VersionDetails {
    pub cargo_package_version: String,
}

impl VersionDetails {
    fn new() -> Self {
        Self {
            cargo_package_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

async fn health_handler() -> Json<VersionDetails> {
    Json(VersionDetails::new())
}

/// Start a HTTP health check server which returns the cargo package version number
pub async fn server(listen_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
    let app = Router::new()
        .fallback(get(health_handler))
        .layer(axum::middleware::map_response(super::add_response_date));

    let listener = TcpListener::bind(listen_addr).await?;
    let listen_addr = listener.local_addr()?;
    tracing::info!("Starting health check server at {}", listen_addr);

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!("Health check server closed: {err}");
        }
    });

    Ok(listen_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let addr = server("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let started = std::time::SystemTime::now();
        let response = reqwest::get(format!("http://{addr}")).await.unwrap();
        crate::http::test_helpers::assert_current_date(response.headers(), started);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();
        assert_eq!(body, serde_json::to_string(&VersionDetails::new()).unwrap());
    }

    #[tokio::test]
    async fn malformed_http_request_gets_a_date_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let addr = server("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nMalformed Header: value\r\n\r\n")
            .await
            .unwrap();

        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
        assert!(
            response.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("date"))
            }),
            "{response}"
        );
    }
}
