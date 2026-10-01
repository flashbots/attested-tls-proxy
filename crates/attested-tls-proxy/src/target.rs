/// A target is not a host/IP with a valid, nonzero port.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("target must be a hostname, IPv4 address, or bracketed IPv6 address with a valid port")]
pub struct InvalidTarget;

/// Validate and process a caller-supplied target address/hostname
pub(crate) fn normalize_target(
    target: &str,
    default_port: Option<u16>,
) -> Result<String, InvalidTarget> {
    let invalid = || InvalidTarget;
    let (host, port) = if target.starts_with('[') {
        let end = target.find(']').ok_or_else(invalid)?;
        // SocketAddrV6 validates both the IPv6 address and an optional numeric
        // scope ID. Keep the original host text for the actual connection.
        format!("{}:0", &target[..=end])
            .parse::<std::net::SocketAddrV6>()
            .map_err(|_| invalid())?;
        let tail = &target[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or_else(invalid)?)
        };
        (&target[..=end], port)
    } else {
        match target.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (target, None),
        }
    };
    if host.is_empty()
        || host
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '/' | '@' | '?' | '#'))
    {
        return Err(invalid());
    }
    let port = match port {
        Some(port) => port.parse::<u16>().map_err(|_| invalid())?,
        None => default_port.ok_or_else(invalid)?,
    };
    if port == 0 {
        return Err(invalid());
    }
    Ok(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targets_are_unambiguous() {
        for (input, expected) in [
            ("example.com", "example.com:443"),
            ("127.0.0.1:42", "127.0.0.1:42"),
            ("example.com:00443", "example.com:443"),
            ("[::1]", "[::1]:443"),
            ("[::1]:42", "[::1]:42"),
            ("[fe80::1%3]", "[fe80::1%3]:443"),
            ("[fe80::1%3]:8080", "[fe80::1%3]:8080"),
            ("[fe80::1%0]:8080", "[fe80::1%0]:8080"),
        ] {
            assert_eq!(normalize_target(input, Some(443)).unwrap(), expected);
        }
        for input in [
            "",
            "host:0",
            "host:65536",
            "host:",
            "host/path",
            "::1",
            "[oops]:443",
            "[::1]oops",
            "user@host:443",
            "host?query:443",
            "host#fragment:443",
            "host name:443",
            "[fe80::1%]:443",
            "[fe80::1%-1]:443",
            "[fe80::1%4294967296]:443",
            "[fe80::1%3%4]:443",
            "[fe80::1%eth0]:443",
        ] {
            assert!(normalize_target(input, Some(443)).is_err(), "{input}");
        }
        assert!(normalize_target("host", None).is_err());
        assert!(normalize_target("host", Some(0)).is_err());
        assert_eq!(normalize_target("[::1]:80", None).unwrap(), "[::1]:80");
    }
    #[test]
    fn scoped_ipv6_target_preserves_routing_information() {
        use std::net::{SocketAddr, ToSocketAddrs};
        let target = normalize_target("[fe80::1%3]:08080", None).unwrap();
        assert_eq!(target, "[fe80::1%3]:8080");
        let SocketAddr::V6(address) = target.to_socket_addrs().unwrap().next().unwrap() else {
            panic!("expected IPv6 address");
        };
        assert_eq!(address.scope_id(), 3);
        assert_eq!(address.port(), 8080);
        assert_eq!(
            *address.ip(),
            "fe80::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
    }
}
