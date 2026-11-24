//! The OAuth 2.0 client-credentials grant (RFC 6749 §4.4) and bearer token usage (RFC 6750), and
//! nothing else of OAuth: no other grants, no scopes, no refresh tokens, no credentials in the
//! request body.
//!
//! - [`bearer`]: reading a presented Bearer credential and the `WWW-Authenticate` challenges that
//!   answer a refusal, and reading a challenge back. Always compiled; needs no feature.
//! - [`secret`]: generating the 256-bit credentials this crate issues, and hashing them. Always
//!   compiled.
//! - `server` (feature `server`): the token endpoint, an axum route over a storage trait the
//!   application implements.
//! - `client` (feature `client`): the one request a host makes to that endpoint.
//!
//! The crate says nothing of the application using it.

pub mod bearer;
pub mod secret;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;
