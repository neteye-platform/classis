//! The token endpoint of RFC 6749 §4.4 (client-credentials grant), as an axum route over a storage
//! trait the application implements.
//!
//! # What a request is and what answers it
//!
//! `POST` only. The body is read to at most [`MAX_BODY`] bytes; a longer one, or one that cannot be
//! read within that bound, is a plain `413 Payload Too Large` with no OAuth body. A request is
//! judged in this order, and the first failure answers it:
//!
//! 1. **Malformed request**, `400 invalid_request` ([`parse_request`]): a `Content-Type` other than
//!    UTF-8 `application/x-www-form-urlencoded`; a body that is not UTF-8; more than one
//!    `Authorization` header or an `Authorization` header without a valid scheme; a repeated
//!    `grant_type`, `scope` or `client_secret`; two client-authentication methods (an
//!    `Authorization` header together with a `client_secret` in the body); a missing `grant_type`.
//!    Empty parameter values count as omitted before any of this is judged, and unknown parameters
//!    are ignored, repeated or not (RFC 6749 §3.2).
//! 2. **Client authentication**, `401 invalid_client` (§5.2): no `Authorization` header (a
//!    `client_secret` in the body alone is no authentication), Basic credentials that cannot be
//!    read, an unknown client or a wrong secret, answered with `WWW-Authenticate: Basic
//!    realm="token"`; an `Authorization` header of another scheme, answered with a challenge of
//!    that scheme.
//! 3. **Grant**, `400 unsupported_grant_type`, then **scope**, `400 invalid_scope`: this profile
//!    defines no scopes, so any non-empty `scope` is refused.
//!
//! Every response carries `Cache-Control: no-store` and `Pragma: no-cache` (§5.1), including the
//! errors.
//!
//! A client authenticates with HTTP Basic only. Its username and password are each
//! `application/x-www-form-urlencoded`-encoded before the Basic encoding (§2.3.1), and decoded in
//! reverse order here. Percent-escapes that are not valid UTF-8 are refused as unreadable
//! credentials; a malformed escape such as `%zz` is kept as written, as form decoding does.
//!
//! The application's [`TokenStore`] is synchronous and is called on a blocking thread of the Tokio
//! runtime, so it may do file I/O or block on a database without stalling the endpoint.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::{post, MethodRouter};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use http::header::{
    HeaderMap, HeaderValue, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE,
};
use http::StatusCode;
use percent_encoding::percent_decode_str;
use serde_json::json;
use zeroize::Zeroizing;

use crate::secret;

/// The most a request body may hold, checked before it is parsed.
pub const MAX_BODY: usize = 8 * 1024;

const REALM: &str = "token";
const GRANT: &str = "client_credentials";

/// How long an access token lives. There is no default: the application states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// The token is good until it is replaced; the response has no `expires_in`.
    Never,
    /// The token expires this many seconds after it is issued.
    Seconds(NonZeroU64),
}

/// A store failure. It is answered with a bare `500`; what went wrong stays with the store.
#[derive(Debug)]
pub struct StoreError;

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the token store failed")
    }
}

impl std::error::Error for StoreError {}

/// What the endpoint needs of the application's records. A client has one active token; issuing a
/// new one replaces the old, and that replacement is the old one's revocation.
pub trait TokenStore: Send + Sync {
    /// `SHA-256(client_secret)` of the client, or `None` when there is no such client.
    fn client_secret_hash(&self, client_id: &str) -> Result<Option<[u8; 32]>, StoreError>;

    /// Makes `SHA-256(access_token)` the client's one active token, overwriting the previous one,
    /// with its expiry as seconds since the UNIX epoch (`None`: it never expires).
    fn replace_token(
        &self,
        client_id: &str,
        token_hash: [u8; 32],
        expires_at: Option<u64>,
    ) -> Result<(), StoreError>;
}

/// The route to mount on a path of the application's choosing. The lifetime is a required
/// argument: without one the endpoint cannot be built.
///
/// ```
/// use std::num::NonZeroU64;
/// use std::sync::Arc;
/// use axum::Router;
/// use oauth_token::server::{endpoint, Lifetime, StoreError, TokenStore};
///
/// struct Store;
/// impl TokenStore for Store {
///     fn client_secret_hash(&self, _: &str) -> Result<Option<[u8; 32]>, StoreError> { Ok(None) }
///     fn replace_token(&self, _: &str, _: [u8; 32], _: Option<u64>) -> Result<(), StoreError> {
///         Ok(())
///     }
/// }
///
/// let _: Router = Router::new().route("/token", endpoint(Arc::new(Store), Lifetime::Never));
/// let _ = endpoint(Arc::new(Store), Lifetime::Seconds(NonZeroU64::new(3600).unwrap()));
/// ```
///
/// Omitting the lifetime does not compile:
///
/// ```compile_fail
/// use std::sync::Arc;
/// use oauth_token::server::{endpoint, StoreError, TokenStore};
///
/// struct Store;
/// impl TokenStore for Store {
///     fn client_secret_hash(&self, _: &str) -> Result<Option<[u8; 32]>, StoreError> { Ok(None) }
///     fn replace_token(&self, _: &str, _: [u8; 32], _: Option<u64>) -> Result<(), StoreError> {
///         Ok(())
///     }
/// }
///
/// let _ = endpoint(Arc::new(Store));
/// ```
pub fn endpoint<S: TokenStore + 'static>(store: Arc<S>, lifetime: Lifetime) -> MethodRouter {
    let store: Arc<dyn TokenStore> = store;
    post(move |request: Request| issue(store.clone(), lifetime, request))
        .layer(axum::middleware::map_response(never_cached))
}

async fn never_cached(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// A parsed token request.
#[derive(Debug)]
pub struct TokenRequest {
    pub client: ClientAuth,
    /// Non-empty.
    pub grant_type: String,
    /// `None` when omitted or empty.
    pub scope: Option<String>,
}

/// What a request offers as client authentication.
#[derive(Debug)]
pub enum ClientAuth {
    /// Nothing usable: no `Authorization` header (a `client_secret` in the body alone included).
    Missing,
    /// HTTP Basic, its username and password already form-decoded.
    Basic {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
    /// A Basic header whose credentials cannot be read.
    UnreadableBasic,
    /// An `Authorization` header of another scheme, kept as sent.
    Unsupported { scheme: String },
}

/// Why a request was refused before client authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The body is longer than [`MAX_BODY`].
    TooLarge,
    /// `400 invalid_request`.
    Invalid,
}

/// Judges a request's headers and body (step 1 of the order above) without any I/O, so a fuzzer can
/// drive it.
pub fn parse_request(headers: &HeaderMap, body: &[u8]) -> Result<TokenRequest, RequestError> {
    if body.len() > MAX_BODY {
        return Err(RequestError::TooLarge);
    }
    require_form_content_type(headers)?;

    let mut values = headers.get_all(AUTHORIZATION).iter();
    let authorization = values.next();
    if values.next().is_some() {
        return Err(RequestError::Invalid);
    }

    let body = std::str::from_utf8(body).map_err(|_| RequestError::Invalid)?;
    let mut grant_type = None;
    let mut scope = None;
    let mut body_secret = false;
    for (name, value) in form_urlencoded::parse(body.as_bytes()) {
        if value.is_empty() {
            continue;
        }
        let repeated = match name.as_ref() {
            "grant_type" => grant_type.replace(value.into_owned()).is_some(),
            "scope" => scope.replace(value.into_owned()).is_some(),
            "client_secret" => std::mem::replace(&mut body_secret, true),
            _ => false,
        };
        if repeated {
            return Err(RequestError::Invalid);
        }
    }
    if authorization.is_some() && body_secret {
        return Err(RequestError::Invalid);
    }
    let grant_type = grant_type.ok_or(RequestError::Invalid)?;

    let client = match authorization {
        None => ClientAuth::Missing,
        Some(value) => client_auth(value)?,
    };
    Ok(TokenRequest {
        client,
        grant_type,
        scope,
    })
}

fn require_form_content_type(headers: &HeaderMap) -> Result<(), RequestError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or(RequestError::Invalid)?;
    if values.next().is_some() {
        return Err(RequestError::Invalid);
    }
    let value = value.to_str().map_err(|_| RequestError::Invalid)?;
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Err(RequestError::Invalid);
    }
    for parameter in parts {
        if let Some((name, value)) = parameter.split_once('=') {
            let value = value.trim().trim_matches('"');
            if name.trim().eq_ignore_ascii_case("charset") && !value.eq_ignore_ascii_case("utf-8") {
                return Err(RequestError::Invalid);
            }
        }
    }
    Ok(())
}

fn client_auth(value: &HeaderValue) -> Result<ClientAuth, RequestError> {
    let value = value.to_str().map_err(|_| RequestError::Invalid)?;
    let (scheme, rest) = value.split_once(' ').unwrap_or((value, ""));
    if scheme.is_empty() || !scheme.bytes().all(is_tchar) {
        return Err(RequestError::Invalid);
    }
    if !scheme.eq_ignore_ascii_case("Basic") {
        return Ok(ClientAuth::Unsupported {
            scheme: scheme.to_owned(),
        });
    }
    Ok(match basic_credentials(rest.trim_start_matches(' ')) {
        Some((client_id, client_secret)) => ClientAuth::Basic {
            client_id,
            client_secret,
        },
        None => ClientAuth::UnreadableBasic,
    })
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// RFC 7617 `user-id ":" password`, then RFC 6749 §2.3.1: each part is form-decoded.
fn basic_credentials(encoded: &str) -> Option<(String, Zeroizing<String>)> {
    let decoded = Zeroizing::new(STANDARD.decode(encoded).ok()?);
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    Some((
        form_decode(client_id)?,
        Zeroizing::new(form_decode(client_secret)?),
    ))
}

fn form_decode(part: &str) -> Option<String> {
    let spaced = Zeroizing::new(part.replace('+', " "));
    percent_decode_str(&spaced)
        .decode_utf8()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

async fn issue(store: Arc<dyn TokenStore>, lifetime: Lifetime, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let request = match parse_request(&parts.headers, &body) {
        Ok(request) => request,
        Err(RequestError::TooLarge) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(RequestError::Invalid) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request")
        }
    };

    let (client_id, client_secret) = match request.client {
        ClientAuth::Basic {
            client_id,
            client_secret,
        } => (client_id, client_secret),
        ClientAuth::Missing | ClientAuth::UnreadableBasic => return invalid_client("Basic"),
        ClientAuth::Unsupported { scheme } => return invalid_client(&scheme),
    };
    let presented = secret::hash(&client_secret);
    let lookup = {
        let (store, client_id) = (store.clone(), client_id.clone());
        tokio::task::spawn_blocking(move || store.client_secret_hash(&client_id)).await
    };
    let stored = match lookup {
        Ok(Ok(stored)) => stored,
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let equal = secret::hashes_equal(&presented, &stored.unwrap_or([0; 32]));
    if stored.is_none() || !equal {
        return invalid_client("Basic");
    }

    if request.grant_type != GRANT {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    if request.scope.is_some() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope");
    }

    let access_token = secret::generate();
    let token_hash = secret::hash(&access_token);
    let expires_at = match lifetime {
        Lifetime::Never => None,
        Lifetime::Seconds(seconds) => Some(unix_now().saturating_add(seconds.get())),
    };
    let replaced = tokio::task::spawn_blocking(move || {
        store.replace_token(&client_id, token_hash, expires_at)
    })
    .await;
    if !matches!(replaced, Ok(Ok(()))) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let mut body = json!({ "access_token": access_token.as_str(), "token_type": "Bearer" });
    if let Lifetime::Seconds(seconds) = lifetime {
        body["expires_in"] = json!(seconds.get());
    }
    Json(body).into_response()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn oauth_error(status: StatusCode, code: &str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

fn invalid_client(scheme: &str) -> Response {
    let challenge = HeaderValue::from_str(&format!("{scheme} realm=\"{REALM}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("Basic realm=\"token\""));
    let mut response = oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
    response
}
