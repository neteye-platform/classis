//! What the Server and the Client implement identically that is this project's own rather than
//! OpAMP's: the version this build reports and its grammar, the platform vocabulary,
//! when a certificate counts as ending and what a certificate is called, and what a
//! package signature covers, and the shape of a space's name and its enrolment key.
//! The protocol and its transport, TLS included, are in the `opamp` crate.

#![forbid(unsafe_code)]

pub mod ending;
pub mod enrolment_key;
pub mod naming;
pub mod package;
pub mod platform;
pub mod version;
