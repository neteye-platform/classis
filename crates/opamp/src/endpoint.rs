//! The OpAMP endpoint's protocol shell — what any server-side of this protocol must do with a
//! request body, framework-free (ADR-0010).
//!
//! There are two OpAMP server endpoints in this project: the Server's, and the Client's own when it
//! runs as a Gateway — downstream, a Gateway *is* an OpAMP server
//! ([ADR-0015](../../../docs/adr/0015-client-modes-and-a-gateway-that-passes-packages-only-to-the-hosts-they-were-offered-to.md)). Both accept the same path, the same media
//! type and the same bodies, and both were written separately. The Baseline's gzip MUST, and with
//! it the rule that the size limit applies *after* decompression, ended up in exactly one of them.
//!
//! This module takes `&str` and `&[u8]` and returns owned bytes on purpose. It pulls in no HTTP
//! stack, so both axum handlers can call it, and [`BodyError`] names the fault rather than the
//! status code — the Server answers `413`/`415`, and a Gateway is a hop whose status codes are its
//! own business.

use std::io::Read as _;

/// The one path the protocol is served on.
pub const OPAMP_PATH: &str = "/v1/opamp";

/// The media type both transports carry protobuf under.
pub const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";

/// Whether a `Content-Type` header names the protobuf media type.
///
/// `starts_with` rather than equality: a peer may append parameters (`; charset=utf-8`), and the
/// Baseline's requirement is on the type, not on the whole header.
#[must_use]
pub fn is_protobuf(content_type: &str) -> bool {
    content_type.starts_with(PROTOBUF_CONTENT_TYPE)
}

/// Why a request body could not be turned into protobuf bytes.
///
/// Deliberately not a status code: each endpoint maps this to what its own transport prescribes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// A `Content-Encoding` this endpoint does not implement. Carries what was asked for, so the
    /// answer can name it.
    UnsupportedEncoding(String),
    /// `Content-Encoding: gzip` that is not gzip, or is truncated.
    UndecodableGzip,
    /// The body is larger than the limit — *after* decompression, where that applies.
    TooLarge,
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEncoding(encoding) => {
                write!(f, "unsupported Content-Encoding: {encoding}")
            }
            Self::UndecodableGzip => write!(f, "invalid gzip body"),
            Self::TooLarge => write!(
                f,
                "the decompressed request body exceeds the message size limit"
            ),
        }
    }
}

impl std::error::Error for BodyError {}

/// The request body as protobuf bytes: decompressed when the peer gzipped it, and never larger
/// than `limit`.
///
/// Accepting gzip is a Baseline MUST. The limit applying **after** decompression is the other half
/// of that MUST and the reason this is one function: a few kilobytes of gzip can decompress to
/// gigabytes, so an endpoint that checks only the received size has no limit at all against a peer
/// that compresses. Decompression is therefore bounded to `limit + 1` bytes and stops there —
/// enough to know the body is too big, never enough to be the attack.
///
/// An absent or `identity` encoding copies the body through, still bounded by `limit`.
pub fn decode_body(
    body: &[u8],
    content_encoding: &str,
    limit: usize,
) -> Result<Vec<u8>, BodyError> {
    match content_encoding {
        "" | "identity" => {
            if body.len() > limit {
                return Err(BodyError::TooLarge);
            }
            Ok(body.to_vec())
        }
        "gzip" => {
            let mut decoded = Vec::new();
            let mut reader = flate2::read::GzDecoder::new(body).take(limit as u64 + 1);
            match reader.read_to_end(&mut decoded) {
                Ok(_) if decoded.len() > limit => Err(BodyError::TooLarge),
                Ok(_) => Ok(decoded),
                Err(_) => Err(BodyError::UndecodableGzip),
            }
        }
        other => Err(BodyError::UnsupportedEncoding(other.to_string())),
    }
}

/// Checks the specification's transport rule on a URL (Q-1): `wss://` and `https://` anywhere,
/// `ws://` and `http://` only to a loopback literal, any other scheme never.
///
/// # Errors
/// Returns a sentence naming the URL and what to use instead.
pub fn check_url(url: &str) -> Result<(), String> {
    match url.split_once("://").map(|(scheme, _)| scheme) {
        Some("wss" | "https") => Ok(()),
        Some("ws" | "http") if is_loopback_literal(host_of(url)) => Ok(()),
        Some("ws" | "http") => Err(format!(
            "{url}: plaintext is for 127.0.0.1 and ::1 alone — use wss:// or https://"
        )),
        _ => Err(format!(
            "{url} must start with wss:// or https:// (ws:// or http:// only to 127.0.0.1 or ::1)"
        )),
    }
}

/// Whether `url` is plaintext — `ws://` or `http://` — wherever its host is.
#[must_use]
pub fn is_plaintext(url: &str) -> bool {
    matches!(
        url.split_once("://").map(|(scheme, _)| scheme),
        Some("ws" | "http")
    )
}

/// The host of `url`, without credentials or port; a bracketed IPv6 host keeps its brackets off.
#[must_use]
pub fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    }
}

/// Whether `host` — as it appears in a URL or a listen address — is a loopback literal, the one
/// place plaintext is allowed (specification Q-1). Only `127.0.0.1` and `::1` count; a host name
/// never does, not even `localhost`, because a name can be made to resolve anywhere.
#[must_use]
pub fn is_loopback_literal(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    matches!(
        host.parse::<std::net::IpAddr>(),
        Ok(ip) if ip == std::net::Ipv4Addr::LOCALHOST || ip == std::net::Ipv6Addr::LOCALHOST
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzipped(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("compress");
        encoder.finish().expect("finish gzip")
    }

    #[test]
    fn a_media_type_with_parameters_is_still_protobuf() {
        assert!(is_protobuf(PROTOBUF_CONTENT_TYPE));
        assert!(is_protobuf("application/x-protobuf; charset=utf-8"));
        assert!(!is_protobuf("application/json"));
        assert!(!is_protobuf(""));
    }

    #[test]
    fn an_unencoded_body_passes_through() {
        assert_eq!(decode_body(b"report", "", 1024), Ok(b"report".to_vec()));
        assert_eq!(
            decode_body(b"report", "identity", 1024),
            Ok(b"report".to_vec())
        );
    }

    #[test]
    fn a_gzipped_body_is_accepted_because_the_baseline_requires_it() {
        let body = gzipped(b"report");
        assert_eq!(decode_body(&body, "gzip", 1024), Ok(b"report".to_vec()));
    }

    #[test]
    fn an_oversized_plain_body_is_refused() {
        assert_eq!(decode_body(b"0123456789", "", 4), Err(BodyError::TooLarge));
        // Exactly the limit is not over it.
        assert_eq!(decode_body(b"0123", "", 4), Ok(b"0123".to_vec()));
    }

    /// The rule this module exists for: a small gzip that decompresses past the limit is refused,
    /// and decompression stops at the limit rather than running to completion first.
    /// Verifies: ADR-0010
    #[test]
    fn a_gzip_bomb_buys_no_more_memory_than_a_plain_body_would() {
        let body = gzipped(&vec![b'a'; 10 * 1024 * 1024]);
        assert!(
            body.len() < 64 * 1024,
            "the compressed form must be far under the limit for this to test anything"
        );
        assert_eq!(
            decode_body(&body, "gzip", 64 * 1024),
            Err(BodyError::TooLarge)
        );
    }

    /// Verifies: ADR-0010
    #[test]
    fn what_is_not_gzip_under_a_gzip_header_is_refused() {
        assert_eq!(
            decode_body(b"not gzip at all", "gzip", 1024),
            Err(BodyError::UndecodableGzip)
        );
        // A truncated stream: the header is right and the rest is missing.
        let truncated = &gzipped(b"report")[..6];
        assert_eq!(
            decode_body(truncated, "gzip", 1024),
            Err(BodyError::UndecodableGzip)
        );
    }

    /// Verifies: ADR-0010
    #[test]
    fn an_encoding_this_endpoint_does_not_implement_names_itself() {
        assert_eq!(
            decode_body(b"...", "br", 1024),
            Err(BodyError::UnsupportedEncoding("br".to_string()))
        );
        assert_eq!(
            decode_body(b"...", "br", 1024).unwrap_err().to_string(),
            "unsupported Content-Encoding: br"
        );
    }

    /// Verifies: ADR-0010, ADR-0013
    #[test]
    fn only_the_loopback_literals_are_loopback() {
        for host in ["127.0.0.1", "::1", "[::1]"] {
            assert!(is_loopback_literal(host), "{host}");
        }
        for host in [
            "localhost",
            "127.0.0.2",
            "0.0.0.0",
            "::",
            "10.0.0.1",
            "example.org",
            "",
        ] {
            assert!(!is_loopback_literal(host), "{host}");
        }
    }

    /// Verifies: ADR-0010
    #[test]
    fn plaintext_urls_are_accepted_on_the_loopback_literals_alone() {
        for url in [
            "wss://fleet.example/v1/opamp",
            "https://10.0.0.1/x",
            "ws://127.0.0.1:4320/v1/opamp",
            "http://[::1]:4318/v1/metrics",
        ] {
            assert_eq!(check_url(url), Ok(()), "{url}");
        }
        for url in [
            "ws://fleet.example/v1/opamp",
            "http://localhost:4318/v1/metrics",
            "http://192.168.1.5/x",
            "http://127.0.0.1.evil.example/x",
            "http://user@10.0.0.1/x",
            "ftp://127.0.0.1/x",
            "127.0.0.1:4320",
        ] {
            assert!(check_url(url).is_err(), "{url} was accepted");
        }
    }
}
