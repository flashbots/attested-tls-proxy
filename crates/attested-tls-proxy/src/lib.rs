//! HTTP and TCP proxies over attested TLS.
pub mod http;
pub mod measurements;
mod target;
pub mod tcp_tunnel;
pub use target::InvalidTarget;

// Preserve the original HTTP proxy API at the crate root.
pub use http::*;

/// Default number of concurrent connections on an attested HTTP or TCP tunnel listener.
pub const DEFAULT_MAX_CONNECTIONS: std::num::NonZeroUsize =
    std::num::NonZeroUsize::new(256).unwrap();

async fn wait_for_revocation(peer: Option<attested_tls::tls::AllowlistedPeer>) {
    let Some(peer) = peer else {
        return std::future::pending().await;
    };
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        timer.tick().await;
        if !peer.is_allowed().await {
            return;
        }
    }
}
