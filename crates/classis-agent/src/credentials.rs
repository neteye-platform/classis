//! What a host is, to its Server, after `enrol` (ADR-0064 clause 7): the five values of
//! `state.json`. Only the value is here: reading and writing `state.json`, and carrying the token
//! upstream, arrive with the authentication cutover; until then the Client authenticates by its
//! client certificate and nothing builds this type.
//!
//! The client secret and the access token are held in buffers wiped on drop (ADR-0057), and neither
//! is ever formatted: a `Debug` of this type names them and prints nothing of them.

use zeroize::Zeroizing;

/// The identity and the credentials of an enrolled host.
#[derive(Clone)]
pub struct Credentials {
    /// The Server's base URL, against which `/v1/enrol` and `/v1/token` are resolved.
    pub endpoint: String,
    /// The Space the enrolment key named, as the Server returned it.
    pub space: String,
    /// The host's `client_id`: its Device ID.
    pub device_id: String,
    /// What replaces the token without losing the host's identity.
    pub client_secret: Zeroizing<String>,
    /// The host's main credential, which every upstream request carries.
    pub access_token: Zeroizing<String>,
}

impl Credentials {
    /// The value of the `Authorization` header every upstream request carries.
    #[must_use]
    pub fn authorization(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.access_token.as_str()))
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("endpoint", &self.endpoint)
            .field("space", &self.space)
            .field("device_id", &self.device_id)
            .field("client_secret", &"<redacted>")
            .field("access_token", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials() -> Credentials {
        Credentials {
            endpoint: "https://fleet.example".to_string(),
            space: "lab".to_string(),
            device_id: "0193a6f0-0000-7000-8000-000000000000".to_string(),
            client_secret: Zeroizing::new("the-client-secret".to_string()),
            access_token: Zeroizing::new("the-access-token".to_string()),
        }
    }

    /// The two secrets are never formatted.
    /// Verifies: ADR-0057
    #[test]
    fn the_debug_form_names_no_secret() {
        let shown = format!("{:?}", credentials());
        assert!(!shown.contains("the-client-secret"), "{shown}");
        assert!(!shown.contains("the-access-token"), "{shown}");
        assert!(shown.contains("lab"), "{shown}");
    }

    #[test]
    fn the_authorization_is_a_bearer_credential() {
        assert_eq!(
            credentials().authorization().as_str(),
            "Bearer the-access-token"
        );
    }
}
