//! OAuth 2.0 dynamic client registration (RFC 7591), profiled for one purpose: a client registers
//! itself to use the client-credentials grant (RFC 6749 §4.4) with HTTP Basic authentication, under
//! an initial access token (§1.2) sent as a Bearer credential (RFC 6750). Nothing else of RFC 7591
//! is implemented: no redirect URIs, no other grants or authentication methods, no software
//! statements, no registration management (RFC 7592).
//!
//! - `server` (feature `server`): the registration endpoint, an axum route over a storage trait the
//!   application implements. It issues the `client_id` and `client_secret`; the application keeps
//!   only a hash of the secret.
//! - `client` (feature `client`): the one request a client makes to that endpoint.
//!
//! Reading the Bearer credential and the challenges that answer a refusal is the job of
//! [`oauth_token::bearer`], and generating and hashing the secret that of [`oauth_token::secret`];
//! this crate has no copy of either.
//!
//! The crate says nothing of the application using it: the Bearer realm, the way an initial access
//! token is judged and any field added to a response come from the application.

/// The one grant type of this profile, the only value of `grant_types` that is accepted.
pub const GRANT_TYPE: &str = "client_credentials";

/// The one client authentication method of this profile, and the default of RFC 7591 §2.
pub const TOKEN_ENDPOINT_AUTH_METHOD: &str = "client_secret_basic";

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;
