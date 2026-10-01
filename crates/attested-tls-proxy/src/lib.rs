//! HTTP and TCP proxies over attested TLS.
pub mod http;
pub mod self_signed;
mod target;
pub mod tcp_tunnel;
pub mod tls;
pub use target::InvalidTarget;

// Preserve the original HTTP proxy API at the crate root.
pub use http::*;
