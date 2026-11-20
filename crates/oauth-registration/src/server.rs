//! The registration endpoint of RFC 7591, as an axum route over a storage trait the application
//! implements.
//!
//! # What a request is and what answers it
//!
//! `POST` only. A request is judged in this order, and the first failure answers it. Nothing about
//! the body is learnt by a caller that has not presented a valid initial access token, and the body
//! of such a caller is never read.
//!
//! 1. **Initial access token** (RFC 7591 §3, RFC 6750 §3): read with [`oauth_token::bearer`]. No
//!    credential, or one of another scheme, is `401` with `WWW-Authenticate: Bearer realm="…"` and
//!    no error code; a malformed token is `401 Bearer error="invalid_token"`; two transmission
//!    methods are `400 Bearer error="invalid_request"`. Then the application judges the token
//!    ([`RegistrationStore::authorise`]): a token it refuses is `401 Bearer error="invalid_token"`.
//! 2. **Body size**: the body is read to at most [`MAX_BODY`] bytes; a longer one, or one that
//!    cannot be read within that bound, is a plain `413 Payload Too Large` with no body.
//! 3. **Client metadata** (§§2, 3.2.2, [`parse_request`]): the `Content-Type` must be
//!    `application/json` and the body a JSON object. Only `grant_types` and
//!    `token_endpoint_auth_method` are understood. Every other member is ignored, and is not
//!    echoed (§2). `grant_types` must be `["client_credentials"]`: omitted, it defaults to
//!    `["authorization_code"]` (§2), which this profile does not support. An omitted
//!    `token_endpoint_auth_method` defaults to `client_secret_basic` (§2), the only method
//!    supported. Anything else is `400`, `application/json`, `{"error":
//!    "invalid_client_metadata"}`.
//! 4. **Registration** ([`RegistrationStore::register`]): the application stores the new client
//!    under the grant of step 1. If the grant is no longer valid, the answer is that of a token it
//!    refuses at step 1.
//!
//! A store failure at either step is a bare `500`.
//!
//! On success the answer is `201 Created` with `application/json` and the fields of §3.2.1:
//! `client_id`, `client_secret`, `client_id_issued_at`, `client_secret_expires_at` (`0`: the secret
//! does not expire) and all the registered metadata, together with the fields the application adds
//! as a response extension. An extension field named like one the crate sets is dropped: the
//! application cannot overwrite a credential.
//!
//! Every response of the endpoint, errors included, carries `Cache-Control: no-store` and
//! `Pragma: no-cache`.
//!
//! The application's [`RegistrationStore`] is synchronous and is called on a blocking thread of the
//! Tokio runtime, so it may do file I/O or block on a database without stalling the endpoint.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::{post, MethodRouter};
use axum::Json;
use http::header::{
    HeaderMap, HeaderValue, InvalidHeaderValue, CACHE_CONTROL, CONTENT_TYPE, PRAGMA,
    WWW_AUTHENTICATE,
};
use http::StatusCode;
use oauth_token::bearer::{presented, Refusal};
use oauth_token::secret;
use serde_json::{json, Map, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{GRANT_TYPE, TOKEN_ENDPOINT_AUTH_METHOD};

/// The most a request body may hold, checked before it is parsed.
pub const MAX_BODY: usize = 8 * 1024;

/// A store failure. It is answered with a bare `500`; what went wrong stays with the store.
#[derive(Debug)]
pub struct StoreError;

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the registration store failed")
    }
}

impl std::error::Error for StoreError {}

/// The metadata a client is registered with (RFC 7591 §2). The profile has one value of each, so
/// there is one value of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub grant_types: &'static [&'static str],
    pub token_endpoint_auth_method: &'static str,
}

impl Metadata {
    /// What every client of this profile is registered with.
    pub const REGISTERED: Metadata = Metadata {
        grant_types: &[GRANT_TYPE],
        token_endpoint_auth_method: TOKEN_ENDPOINT_AUTH_METHOD,
    };
}

/// A client to store. The secret itself is not here: only its hash is the store's to keep.
#[derive(Debug)]
pub struct NewClient {
    /// A UUID version 7 (RFC 9562), in its hyphenated lower-case form.
    pub client_id: String,
    /// `SHA-256(client_secret)`.
    pub client_secret_hash: [u8; 32],
    /// Seconds since the UNIX epoch (RFC 7591 §3.2.1 `client_id_issued_at`).
    pub client_id_issued_at: u64,
    pub metadata: Metadata,
}

/// What the endpoint needs of the application. Registration is two steps, so that a caller without
/// a valid initial access token learns nothing about the validation of metadata.
pub trait RegistrationStore: Send + Sync {
    /// What an authorised initial access token stands for, as the application sees it (the
    /// account whose key it is, say). The crate only hands it from the first step to the second.
    type Grant: Send + 'static;

    /// Judges an initial access token: its grant, or `None` when the application refuses it.
    fn authorise(&self, initial_access_token: &str) -> Result<Option<Self::Grant>, StoreError>;

    /// Stores a new client under `grant`. It returns the fields the application adds to the
    /// response (§3.2.1 permits extensions), or `None` when the grant is not valid any more, for
    /// instance because the key it stood for was replaced between the two steps.
    fn register(
        &self,
        grant: &Self::Grant,
        client: NewClient,
    ) -> Result<Option<Map<String, Value>>, StoreError>;
}

/// The route to mount on a path of the application's choosing. `realm` is the Bearer realm of the
/// challenge that answers a request with no usable credential; a realm that cannot be written into
/// a header is refused here rather than on a request.
///
/// ```
/// use std::sync::Arc;
/// use axum::Router;
/// use oauth_registration::server::{
///     endpoint, NewClient, RegistrationStore, StoreError,
/// };
///
/// struct Store;
/// impl RegistrationStore for Store {
///     type Grant = ();
///     fn authorise(&self, _: &str) -> Result<Option<()>, StoreError> { Ok(None) }
///     fn register(
///         &self,
///         _: &(),
///         _: NewClient,
///     ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, StoreError> {
///         Ok(None)
///     }
/// }
///
/// let _: Router = Router::new().route("/register", endpoint(Arc::new(Store), "example").unwrap());
/// assert!(endpoint(Arc::new(Store), "bad\nrealm").is_err());
/// ```
pub fn endpoint<S: RegistrationStore + 'static>(
    store: Arc<S>,
    realm: &str,
) -> Result<MethodRouter, InvalidHeaderValue> {
    let challenges = Arc::new(Challenges {
        unauthenticated: Refusal::Unauthenticated.challenge(realm)?,
        invalid_token: Refusal::InvalidToken.challenge(realm)?,
        invalid_request: Refusal::InvalidRequest.challenge(realm)?,
    });
    Ok(
        post(move |request: Request| register(store.clone(), challenges.clone(), request))
            .layer(axum::middleware::map_response(never_cached)),
    )
}

async fn never_cached(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// The `WWW-Authenticate` value of each refusal, made once from the application's realm.
struct Challenges {
    unauthenticated: HeaderValue,
    invalid_token: HeaderValue,
    invalid_request: HeaderValue,
}

impl Challenges {
    fn refuse(&self, refusal: Refusal) -> Response {
        let challenge = match refusal {
            Refusal::Unauthenticated => &self.unauthenticated,
            Refusal::InvalidToken => &self.invalid_token,
            Refusal::InvalidRequest => &self.invalid_request,
        };
        let mut response = refusal.status().into_response();
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, challenge.clone());
        response
    }
}

/// Why a request was refused after the initial access token was accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The body is longer than [`MAX_BODY`]: `413`.
    TooLarge,
    /// `400 invalid_client_metadata`: the request is not a JSON object under `application/json`,
    /// or a metadata value it states is not supported.
    InvalidMetadata,
}

/// Judges a request's `Content-Type` and body (steps 2 and 3 of the order above) without any I/O,
/// so a fuzzer can drive it. The accepted request registers [`Metadata::REGISTERED`].
pub fn parse_request(headers: &HeaderMap, body: &[u8]) -> Result<Metadata, RequestError> {
    if body.len() > MAX_BODY {
        return Err(RequestError::TooLarge);
    }
    require_json_content_type(headers)?;
    let Ok(Value::Object(request)) = serde_json::from_slice(body) else {
        return Err(RequestError::InvalidMetadata);
    };

    let grant_types = match request.get("grant_types") {
        Some(Value::Array(members)) => {
            !members.is_empty() && members.iter().all(|member| member == GRANT_TYPE)
        }
        _ => false,
    };
    let auth_method = match request.get("token_endpoint_auth_method") {
        None => true,
        Some(method) => method == TOKEN_ENDPOINT_AUTH_METHOD,
    };
    if grant_types && auth_method {
        Ok(Metadata::REGISTERED)
    } else {
        Err(RequestError::InvalidMetadata)
    }
}

/// RFC 7591 §3.1: `application/json`, whatever its parameters; the media type is case-insensitive.
fn require_json_content_type(headers: &HeaderMap) -> Result<(), RequestError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(RequestError::InvalidMetadata);
    };
    let media_type = value
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    match media_type {
        Some(media_type) if media_type.eq_ignore_ascii_case("application/json") => Ok(()),
        _ => Err(RequestError::InvalidMetadata),
    }
}

async fn register<S: RegistrationStore + 'static>(
    store: Arc<S>,
    challenges: Arc<Challenges>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();

    let token = match presented(&parts.headers, &parts.uri).token() {
        Ok(token) => Zeroizing::new(token.to_owned()),
        Err(refusal) => return challenges.refuse(refusal),
    };
    let authorised = {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.authorise(&token)).await
    };
    let grant = match authorised {
        Ok(Ok(Some(grant))) => grant,
        Ok(Ok(None)) => return challenges.refuse(Refusal::InvalidToken),
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let metadata = match parse_request(&parts.headers, &body) {
        Ok(metadata) => metadata,
        Err(RequestError::TooLarge) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(RequestError::InvalidMetadata) => return invalid_client_metadata(),
    };

    let client_id = Uuid::now_v7().to_string();
    let client_secret = secret::generate();
    let client = NewClient {
        client_id: client_id.clone(),
        client_secret_hash: secret::hash(&client_secret),
        client_id_issued_at: unix_now(),
        metadata,
    };
    let issued_at = client.client_id_issued_at;
    let registered = tokio::task::spawn_blocking(move || store.register(&grant, client)).await;
    let extension = match registered {
        Ok(Ok(Some(extension))) => extension,
        Ok(Ok(None)) => return challenges.refuse(Refusal::InvalidToken),
        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let mut fields = Map::new();
    fields.insert("client_id".into(), json!(client_id));
    fields.insert("client_secret".into(), json!(client_secret.as_str()));
    fields.insert("client_id_issued_at".into(), json!(issued_at));
    fields.insert("client_secret_expires_at".into(), json!(0));
    fields.insert("grant_types".into(), json!(metadata.grant_types));
    fields.insert(
        "token_endpoint_auth_method".into(),
        json!(metadata.token_endpoint_auth_method),
    );
    for (name, value) in extension {
        fields.entry(name).or_insert(value);
    }
    (StatusCode::CREATED, Json(Value::Object(fields))).into_response()
}

fn invalid_client_metadata() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_client_metadata" })),
    )
        .into_response()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
