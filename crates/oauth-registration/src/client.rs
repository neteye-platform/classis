//! The request a client makes to a registration endpoint: RFC 7591 §3.1, a JSON request
//! authenticated with an initial access token as a Bearer credential (§1.2), answered as in §3.2.
//!
//! The `reqwest::Client` is the caller's, and **it must not follow redirects**: a redirect would
//! resend the initial access token wherever it points. A redirect answer is reported as
//! [`Error::Rejected`].

use reqwest::header::{ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{IntoUrl, StatusCode};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use oauth_token::bearer::{parse_challenges, Challenge};

use crate::{GRANT_TYPE, TOKEN_ENDPOINT_AUTH_METHOD};

/// The most of a response body that is read.
const MAX_RESPONSE: usize = 64 * 1024;

/// The credentials the endpoint issued (RFC 7591 §3.2.1).
#[derive(Debug)]
pub struct Registered {
    pub client_id: String,
    pub client_secret: Zeroizing<String>,
    /// Every other member of the response, such as `client_id_issued_at`, the registered metadata
    /// and the extension fields the application behind the endpoint adds. The caller reads the
    /// ones it knows and ignores the rest.
    pub fields: Map<String, Value>,
}

/// What the endpoint answered instead of credentials (RFC 7591 §3.2.2, RFC 6750 §3).
#[derive(Debug)]
pub struct Rejection {
    pub status: StatusCode,
    /// The `error` code of the JSON body, when it has one.
    pub error: Option<String>,
    /// The challenges of every `WWW-Authenticate` header; empty when there is none.
    pub challenges: Vec<Challenge>,
}

#[derive(Debug)]
pub enum Error {
    /// The request could not be made or the response could not be read.
    Transport(reqwest::Error),
    /// A `201` response that is not a registration response (§3.2.1), or a body over the limit.
    Malformed(&'static str),
    /// Any answer other than `201`.
    Rejected(Rejection),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Transport(error) => write!(f, "registration request failed: {error}"),
            Error::Malformed(reason) => write!(f, "malformed registration response: {reason}"),
            Error::Rejected(rejection) => {
                write!(f, "registration refused with {}", rejection.status)?;
                if let Some(code) = &rejection.error {
                    write!(f, " ({code})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport(error) => Some(error),
            Error::Malformed(_) | Error::Rejected(_) => None,
        }
    }
}

/// Registers a client at `endpoint` for the client-credentials grant, with `initial_access_token`
/// as the proof of the right to do so.
pub async fn register(
    http: &reqwest::Client,
    endpoint: impl IntoUrl,
    initial_access_token: &str,
) -> Result<Registered, Error> {
    let request = json!({
        "grant_types": [GRANT_TYPE],
        "token_endpoint_auth_method": TOKEN_ENDPOINT_AUTH_METHOD,
    });
    let body = serde_json::to_vec(&request).expect("a JSON value is always serialisable");
    let response = http
        .post(endpoint)
        .bearer_auth(initial_access_token)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .map_err(Error::Transport)?;

    let status = response.status();
    let challenges = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(parse_challenges)
        .collect();
    let body = read_limited(response).await.map_err(Error::Transport)?;

    if status != StatusCode::CREATED {
        let error = body
            .as_deref()
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .and_then(|body| body.get("error")?.as_str().map(str::to_owned));
        return Err(Error::Rejected(Rejection {
            status,
            error,
            challenges,
        }));
    }
    let body = body.ok_or(Error::Malformed("the response body is too large"))?;
    let Ok(Value::Object(mut fields)) = serde_json::from_slice(&body) else {
        return Err(Error::Malformed("not a JSON object"));
    };
    let client_secret = match fields.remove("client_secret") {
        Some(Value::String(secret)) => Zeroizing::new(secret),
        _ => return Err(Error::Malformed("client_secret is missing or not a string")),
    };
    let client_id = match fields.remove("client_id") {
        Some(Value::String(id)) => id,
        _ => return Err(Error::Malformed("client_id is missing or not a string")),
    };
    if client_id.is_empty() {
        return Err(Error::Malformed("client_id is empty"));
    }
    if client_secret.is_empty() {
        return Err(Error::Malformed("client_secret is empty"));
    }
    Ok(Registered {
        client_id,
        client_secret,
        fields,
    })
}

/// The body, or `None` when it is longer than [`MAX_RESPONSE`]. The buffer is allocated once at its
/// largest so no earlier, smaller copy of a secret is left behind when it grows.
async fn read_limited(
    mut response: reqwest::Response,
) -> Result<Option<Zeroizing<Vec<u8>>>, reqwest::Error> {
    let mut body = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE));
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}
