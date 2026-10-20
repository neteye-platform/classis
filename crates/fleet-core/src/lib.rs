//! What the Server and the Client implement identically that is this project's own rather than
//! OpAMP's (ADR-0010): the version this build reports and its grammar, the platform vocabulary,
//! when a certificate counts as ending and what a certificate is called (ADR-0028), and the
//! bootstrap certificate's PKCS#12 file (ADR-0029), and the host a certificate that names none is
//! taken for (ADR-0039), and the proofs a renewal and an enrolment request carry in their CSR
//! (ADR-0021 clause 27, ADR-0039).
//! The protocol and its transport, TLS included, are in the `opamp` crate (ADR-0010).

#![forbid(unsafe_code)]

pub mod bootstrap_proof;
pub mod csr;
pub mod ending;
pub mod host;
pub mod naming;
pub mod package;
pub mod pkcs12;
pub mod platform;
pub mod renewal;
pub mod version;
