//! Where the authentication of Agents plugs in.
//!
//! The Server speaks plain HTTP behind a reverse proxy, and it does not authenticate Agents: what
//! admits an Agent — a random string it presents, checked by a library in front of the Server —
//! lives outside it. This module is the seam that library plugs into, so that adding it later
//! touches no route: an [`AgentAuthenticator`] is asked about every request of the Agent plane
//! (`/v1/opamp`, over HTTP and over a WebSocket, and the package download) before the request is
//! served, and may name the host the request speaks for.
//!
//! The only implementation today is [`AdmitEveryone`]. Without an authenticator in front of it, any
//! peer that reaches the Agent port is admitted and may claim any identity in its OpAMP messages:
//! the port must be reachable through the authenticating proxy alone.

use axum::http::HeaderMap;

/// What an authenticator learned about a request it admitted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Admitted {
    /// The host the request speaks for, when the authenticator knows one. `None` leaves the
    /// identity to the OpAMP message's `instance_uid`, as for a request that carries no proof.
    pub host: Option<String>,
}

/// A request an authenticator refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// A short name of the check that failed, for the log. Never a value of the request.
    pub check: &'static str,
}

/// Decides whether a request of the Agent plane is admitted.
pub trait AgentAuthenticator: Send + Sync {
    /// Admits the request whose headers these are, or refuses it. A refusal counts as a failure of
    /// the peer's address for the throttle, as any refused admission does.
    ///
    /// # Errors
    /// Returns the [`Refusal`] naming the check that failed.
    fn authenticate(&self, headers: &HeaderMap) -> Result<Admitted, Refusal>;
}

/// Admits every request: the Server authenticates no Agent.
#[derive(Clone, Copy, Debug, Default)]
pub struct AdmitEveryone;

impl AgentAuthenticator for AdmitEveryone {
    fn authenticate(&self, _headers: &HeaderMap) -> Result<Admitted, Refusal> {
        Ok(Admitted::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderValue};

    /// The only implementation admits a request with no credential at all, and one with any.
    #[test]
    fn admit_everyone_admits_with_or_without_a_credential() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            AdmitEveryone.authenticate(&headers),
            Ok(Admitted::default())
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer whatever"),
        );
        assert_eq!(
            AdmitEveryone.authenticate(&headers),
            Ok(Admitted::default())
        );
    }
}
