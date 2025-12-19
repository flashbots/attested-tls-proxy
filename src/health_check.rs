use axum::{routing::get, Json, Router};
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
    let app = Router::new().fallback(get(health_handler));

    let listener = TcpListener::bind(listen_addr).await?;
    let listen_addr = listener.local_addr()?;
    tracing::info!("Starting health check server at {}", listen_addr);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(listen_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let addr = server("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let response = reqwest::get(format!("http://{addr}")).await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();
        assert_eq!(body, serde_json::to_string(&VersionDetails::new()).unwrap())
    }
}
