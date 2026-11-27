//! The request a host makes to a token endpoint: RFC 6749 §4.4.2, client authentication by HTTP
//! Basic with the form-encoded credentials of §2.3.1.
//!
//! The `reqwest::Client` is the caller's, and **it must not follow redirects**: a redirect would
//! resend the client's credentials wherever it points. A redirect answer is reported as
//! [`Error::Rejected`].

use reqwest::header::{ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE};
use reqwest::{IntoUrl, StatusCode};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::bearer::{parse_challenges, Challenge};

/// The most of a response body that is read.
const MAX_RESPONSE: usize = 64 * 1024;

/// A token the endpoint issued.
#[derive(Debug)]
pub struct AccessToken {
    pub access_token: Zeroizing<String>,
    /// Seconds until the token expires; `None` when the endpoint sent no `expires_in`.
    pub expires_in: Option<u64>,
}

/// What the endpoint answered instead of a token (RFC 6749 §5.2).
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
    /// A `200` response that is not a token response (§5.1), or a body over the limit.
    Malformed(&'static str),
    /// Any answer other than `200`.
    Rejected(Rejection),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Transport(error) => write!(f, "token request failed: {error}"),
            Error::Malformed(reason) => write!(f, "malformed token response: {reason}"),
            Error::Rejected(rejection) => {
                write!(f, "token request refused with {}", rejection.status)?;
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

#[derive(Deserialize)]
struct Success {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct Failure {
    error: String,
}

/// Asks `endpoint` for an access token with the client-credentials grant.
pub async fn request_token(
    http: &reqwest::Client,
    endpoint: impl IntoUrl,
    client_id: &str,
    client_secret: &str,
) -> Result<AccessToken, Error> {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "client_credentials")
        .finish();
    let secret = Zeroizing::new(form_encode(client_secret));
    let response = http
        .post(endpoint)
        .basic_auth(form_encode(client_id), Some(secret.as_str()))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
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

    if status != StatusCode::OK {
        let error = body
            .as_deref()
            .and_then(|body| serde_json::from_slice::<Failure>(body).ok())
            .map(|failure| failure.error);
        return Err(Error::Rejected(Rejection {
            status,
            error,
            challenges,
        }));
    }
    let body = body.ok_or(Error::Malformed("the response body is too large"))?;
    let success: Success =
        serde_json::from_slice(&body).map_err(|_| Error::Malformed("not a token response"))?;
    let access_token = Zeroizing::new(success.access_token);
    if !success.token_type.eq_ignore_ascii_case("bearer") {
        return Err(Error::Malformed("token_type is not Bearer"));
    }
    if access_token.is_empty() {
        return Err(Error::Malformed("access_token is empty"));
    }
    Ok(AccessToken {
        access_token,
        expires_in: success.expires_in,
    })
}

fn form_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// The body, or `None` when it is longer than [`MAX_RESPONSE`]. The buffer is allocated once at its
/// largest so no earlier, smaller copy of a token is left behind when it grows.
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
