//! The OpAMP communication layer (ADR-0011, ADR-0010). Without features it is the wire layer: the
//! protobuf types generated from the specification, the WebSocket framing, the endpoint's body
//! rules, `InstanceUid`, and the attribute keys an `AgentDescription` is read by.
//!
//! It holds what the specification defines and nothing else, so it serves any OpAMP server or
//! agent written in Rust. Two features add each side on top, end to end, and neither is on by
//! default:
//!
//! - `client` — `opamp::client`: an Agent's protocol state machine and its connection over either
//!   transport, TLS included;
//! - `server` — `opamp::server`: one server endpoint for both transports around a handler, and the
//!   listener it is served on.
//!
//! Both build their TLS with `opamp::tls` from the material the application hands them. The crate
//! reads no file and no configuration format.
//!
//! This crate's version follows the specification's: `0.20.x` is generated from opamp-spec
//! `v0.20.0`, which [`BASELINE`] states.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

/// The OpAMP protobuf types, generated from the vendored Baseline schema by
/// [`build.rs`](../build.rs). The `.proto` package is `opamp.proto.v1`; the generated types are
/// exposed flat so callers write `opamp::proto::AgentToServer`.
pub mod proto {
    // Generated code: we do not control its formatting or doc-comment style, so lint it loosely.
    #![allow(clippy::all, clippy::pedantic)]
    include!(concat!(env!("OUT_DIR"), "/opamp.proto.v1.rs"));
}

pub mod attributes;
#[cfg(feature = "client")]
#[cfg_attr(docsrs, doc(cfg(feature = "client")))]
pub mod client;
pub mod endpoint;
pub mod frame;
#[cfg(feature = "server")]
#[cfg_attr(docsrs, doc(cfg(feature = "server")))]
pub mod server;
#[cfg(any(feature = "client", feature = "server"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "client", feature = "server"))))]
pub mod tls;
pub mod uid;

/// The opamp-spec release these types are generated from, e.g. `v0.20.0`.
pub const BASELINE: &str = env!("OPAMP_BASELINE");

#[cfg(test)]
mod tests {
    /// The crate's `MAJOR.MINOR` is the Baseline's (ADR-0010), so the dependency a user declares
    /// says which OpAMP it speaks. Moving the Baseline without moving the version fails here.
    /// Verifies: ADR-0010
    #[test]
    fn the_crate_version_is_the_baselines() {
        let minor_of = |v: &str| {
            let mut parts = v.trim_start_matches('v').split('.');
            (
                parts.next().map(str::to_owned),
                parts.next().map(str::to_owned),
            )
        };
        assert_eq!(
            minor_of(env!("CARGO_PKG_VERSION")),
            minor_of(super::BASELINE),
            "the crate version {} must carry the Baseline {}'s MAJOR.MINOR",
            env!("CARGO_PKG_VERSION"),
            super::BASELINE
        );
    }
}
