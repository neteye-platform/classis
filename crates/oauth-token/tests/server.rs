//! The token endpoint, driven with hand-built HTTP requests against an in-memory store. Every
//! expected status, header and field is read off the RFC section cited, not off the implementation.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::Router;
use oauth_token::server::{
    endpoint, parse_request, ClientAuth, Lifetime, RequestError, StoreError, TokenStore, MAX_BODY,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const FORM: &str = "application/x-www-form-urlencoded";
const GRANT: &str = "grant_type=client_credentials";
/// RFC 6749 §4.4.2's example credentials, `s6BhdRkqt3:gX1fBat3bV`.
const RFC_BASIC: &str = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW";
const WRONG_SECRET_BASIC: &str = "Basic Y2xpZW50LTE6d3Jvbmc=";

fn sha256(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// A client's active token hash and its expiry.
type Active = ([u8; 32], Option<u64>);

#[derive(Default)]
struct MemStore {
    secrets: Mutex<HashMap<String, [u8; 32]>>,
    tokens: Mutex<HashMap<String, Active>>,
    replacements: Mutex<usize>,
    fail_lookup: AtomicBool,
    fail_replace: AtomicBool,
}

impl MemStore {
    fn active(&self, id: &str) -> Option<Active> {
        self.tokens.lock().unwrap().get(id).copied()
    }

    fn no_token_issued(&self) -> bool {
        self.tokens.lock().unwrap().is_empty()
    }
}

impl TokenStore for MemStore {
    fn client_secret_hash(&self, client_id: &str) -> Result<Option<[u8; 32]>, StoreError> {
        if self.fail_lookup.load(Ordering::SeqCst) {
            return Err(StoreError);
        }
        Ok(self.secrets.lock().unwrap().get(client_id).copied())
    }

    fn replace_token(
        &self,
        client_id: &str,
        token_hash: [u8; 32],
        expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        if self.fail_replace.load(Ordering::SeqCst) {
            return Err(StoreError);
        }
        *self.replacements.lock().unwrap() += 1;
        self.tokens
            .lock()
            .unwrap()
            .insert(client_id.to_owned(), (token_hash, expires_at));
        Ok(())
    }
}

/// The RFC's example client, one whose id is `client-1`, and clients whose credentials need
/// form-encoding.
fn store() -> Arc<MemStore> {
    let store = MemStore::default();
    for (id, secret) in [
        ("s6BhdRkqt3", "gX1fBat3bV"),
        ("client-1", "s3cret"),
        ("a b:c", "p+q%é"),
        ("id+plus", "sec ret"),
        ("ünï", "100%"),
        ("a:b:c", "::"),
    ] {
        store
            .secrets
            .lock()
            .unwrap()
            .insert(id.to_owned(), sha256(secret));
    }
    Arc::new(store)
}

fn app(store: &Arc<MemStore>, lifetime: Lifetime) -> Router {
    Router::new().route("/token", endpoint(store.clone(), lifetime))
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("a JSON body")
    }

    fn error(&self) -> String {
        self.json()["error"]
            .as_str()
            .expect("an error code")
            .to_owned()
    }

    fn access_token(&self) -> String {
        self.json()["access_token"]
            .as_str()
            .expect("an access token")
            .to_owned()
    }

    fn challenge(&self) -> &str {
        self.headers
            .get(WWW_AUTHENTICATE)
            .expect("a challenge")
            .to_str()
            .unwrap()
    }
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body,
    }
}

fn request(
    authorization: &[&str],
    content_type: Option<&str>,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::builder().method(Method::POST).uri("/token");
    for value in authorization {
        builder = builder.header(AUTHORIZATION, *value);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder.body(body.into()).unwrap()
}

/// A request with the form content type, the given Authorization (if any) and body.
async fn post(app: &Router, authorization: Option<&str>, body: &str) -> Answer {
    let authorization: Vec<&str> = authorization.into_iter().collect();
    send(app, request(&authorization, Some(FORM), body.to_owned())).await
}

fn assert_never_cached(answer: &Answer) {
    assert_eq!(answer.headers.get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(answer.headers.get(PRAGMA).unwrap(), "no-cache");
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Verifies: ADR-0064
/// RFC 6749 §4.4.2: the example request, `POST` with `Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW`
/// and the form body `grant_type=client_credentials`, is a valid access token request.
#[tokio::test]
async fn the_rfc_example_request_is_granted() {
    let store = store();
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), GRANT).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(answer.json()["access_token"].is_string());
}

/// Verifies: ADR-0064
/// RFC 6749 §5.1 and §4.4.3: `200`, `application/json`, `access_token` and `token_type` ("Bearer",
/// RFC 6750 §4), no `refresh_token`, `Cache-Control: no-store`, `Pragma: no-cache`.
#[tokio::test]
async fn a_success_response_is_a_json_token_response_without_a_refresh_token() {
    let store = store();
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), GRANT).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.headers.get(CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_never_cached(&answer);
    let body = answer.json();
    let mut names: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["access_token", "token_type"]);
    assert_eq!(body["token_type"], "Bearer");
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4 (256 random bits as 43 base64url characters, which fits RFC 6750 §2.1's
/// `b64token`): only that alphabet appears in an issued token.
#[tokio::test]
async fn the_token_is_43_base64url_characters() {
    let store = store();
    let token = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), GRANT)
        .await
        .access_token();
    assert_eq!(token.len(), 43);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}

/// Verifies: ADR-0064
/// RFC 6749 §5.1 (`expires_in` is the lifetime in seconds) and ADR-0064 clause 4: a finite token
/// has `expires_in` and an expiry in the store.
#[tokio::test]
async fn a_finite_lifetime_has_expires_in_and_a_store_expiry() {
    let store = store();
    let lifetime = Lifetime::Seconds(NonZeroU64::new(3600).unwrap());
    let before = unix_now();
    let answer = post(&app(&store, lifetime), Some(RFC_BASIC), GRANT).await;
    let after = unix_now();
    assert_eq!(answer.json()["expires_in"], 3600);
    let expires_at = store.active("s6BhdRkqt3").unwrap().1.expect("an expiry");
    assert!((before + 3600..=after + 3600).contains(&expires_at));
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4: a non-expiring token omits `expires_in`, and the store gets no expiry.
#[tokio::test]
async fn never_omits_expires_in_and_stores_no_expiry() {
    let store = store();
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), GRANT).await;
    assert!(answer.json().get("expires_in").is_none());
    assert_eq!(store.active("s6BhdRkqt3").unwrap().1, None);
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4: the store receives `SHA-256(access_token)`, and nothing else of the token.
#[tokio::test]
async fn the_store_gets_the_hash_of_the_token() {
    let store = store();
    let token = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), GRANT)
        .await
        .access_token();
    assert_eq!(store.active("s6BhdRkqt3").unwrap().0, sha256(&token));
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4: issuing a token overwrites the client's hash; that overwrite is the
/// revocation of the one before.
#[tokio::test]
async fn a_second_token_replaces_the_first() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    let first = post(&app, Some(RFC_BASIC), GRANT).await.access_token();
    let second = post(&app, Some(RFC_BASIC), GRANT).await.access_token();
    assert_ne!(first, second);
    assert_eq!(store.active("s6BhdRkqt3").unwrap().0, sha256(&second));
    assert_eq!(*store.replacements.lock().unwrap(), 2);
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3.1: the client identifier and secret are form-encoded (`+` is a space, `%XX`
/// a byte, UTF-8) and then Basic-encoded; the server decodes them in reverse order. The headers
/// are the Basic encodings of the form-encoded pairs, written out by hand.
#[tokio::test]
async fn basic_credentials_that_need_form_encoding_round_trip() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for (basic, id) in [
        // `a+b%3Ac:p%2Bq%25%C3%A9` for `a b:c` and `p+q%é`
        ("YStiJTNBYzpwJTJCcSUyNSVDMyVBOQ==", "a b:c"),
        // `id%2Bplus:sec+ret`
        ("aWQlMkJwbHVzOnNlYytyZXQ=", "id+plus"),
        // `%C3%BCn%C3%AF:100%25`
        ("JUMzJUJDbiVDMyVBRjoxMDAlMjU=", "ünï"),
        // `a%3Ab%3Ac:%3A%3A`
        ("YSUzQWIlM0FjOiUzQSUzQQ==", "a:b:c"),
    ] {
        let answer = post(&app, Some(&format!("Basic {basic}")), GRANT).await;
        assert_eq!(answer.status, StatusCode::OK, "{id}");
        assert!(store.active(id).is_some(), "{id}");
    }
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3.1: the decoding is the form decoding, so a `+` the client did not encode is read
/// as a space and the credentials do not match: here `id+plus:sec+ret`, read as `id plus`.
#[tokio::test]
async fn an_unencoded_plus_is_read_as_a_space() {
    let store = store();
    let answer = post(
        &app(&store, Lifetime::Never),
        Some("Basic aWQrcGx1czpzZWMrcmV0"),
        GRANT,
    )
    .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
}

/// Verifies: ADR-0064
/// RFC 9110 §11.1: the authentication scheme name is case-insensitive.
#[tokio::test]
async fn the_basic_scheme_is_case_insensitive() {
    let store = store();
    let authorization = "bAsIc czZCaGRSa3F0MzpnWDFmQmF0M2JW";
    let answer = post(&app(&store, Lifetime::Never), Some(authorization), GRANT).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// Verifies: ADR-0064
/// RFC 6749 §3.2: a parameter sent without a value is treated as omitted, so an empty `scope` is
/// no scope and an empty `grant_type` beside a real one is the real one.
#[tokio::test]
async fn empty_parameters_count_as_omitted() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for body in [
        "grant_type=client_credentials&scope=",
        "grant_type=&grant_type=client_credentials",
        "grant_type=client_credentials&client_secret=&extra=",
    ] {
        assert_eq!(
            post(&app, Some(RFC_BASIC), body).await.status,
            StatusCode::OK,
            "{body}"
        );
    }
    let answer = post(&app, Some(RFC_BASIC), "grant_type=").await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error(), "invalid_request");
}

/// Verifies: ADR-0064
/// RFC 6749 §3.2: the server MUST ignore request parameters it does not recognise.
#[tokio::test]
async fn unknown_parameters_are_ignored() {
    let store = store();
    let body = "grant_type=client_credentials&foo=1&resource=x";
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), body).await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3.1 and §3.2 (ADR-0064 clause 4: "multiple authentication methods are refused"):
/// `client_id` is a request parameter the RFC defines, so a body `client_id` that is not the Basic
/// username names a second identity and is an invalid request, judged before the secret is
/// checked; one that names the same client is no second identity and is accepted.
#[tokio::test]
async fn a_body_client_id_other_than_the_basic_username_is_an_invalid_request() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    let other = post(
        &app,
        Some(RFC_BASIC),
        "grant_type=client_credentials&client_id=other",
    )
    .await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    assert_eq!(other.error(), "invalid_request");
    assert!(store.no_token_issued());
    let same = post(
        &app,
        Some(RFC_BASIC),
        "grant_type=client_credentials&client_id=s6BhdRkqt3",
    )
    .await;
    assert_eq!(same.status, StatusCode::OK);
    // Form-decoded like the username: `+` is a space.
    let spaced = post(
        &app,
        Some("Basic YStiJTNBYzpwJTJCcSUyNSVDMyVBOQ=="),
        "grant_type=client_credentials&client_id=a+b%3Ac",
    )
    .await;
    assert_eq!(spaced.status, StatusCode::OK);
}

/// Verifies: ADR-0064
/// RFC 6749 §3.2: request parameters MUST NOT be included more than once; §5.2: `invalid_request`
/// covers a request that repeats a parameter. The repeat is judged before client authentication.
#[tokio::test]
async fn a_repeated_parameter_is_an_invalid_request() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for body in [
        "grant_type=client_credentials&grant_type=client_credentials",
        "grant_type=client_credentials&scope=a&scope=b",
        "grant_type=client_credentials&client_secret=a&client_secret=b",
        "grant_type=client_credentials&client_id=s6BhdRkqt3&client_id=s6BhdRkqt3",
        "grant_type=client_credentials&foo=1&foo=2",
    ] {
        let answer = post(&app, Some(RFC_BASIC), body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(answer.error(), "invalid_request", "{body}");
    }
    let unauthenticated = post(&app, None, "grant_type=a&grant_type=b").await;
    assert_eq!(unauthenticated.status, StatusCode::BAD_REQUEST);
    assert!(store.no_token_issued());
    // A repeat of which one is empty is no repeat: empty counts as omitted.
    let answer = post(
        &app,
        Some(RFC_BASIC),
        "grant_type=client_credentials&foo=1&foo=",
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3: the client MUST NOT use more than one authentication method per request, and
/// ADR-0064 clause 4: credentials in the body are not supported. With Basic, a `client_secret` in
/// the body is a second method: `400 invalid_request`.
#[tokio::test]
async fn a_body_secret_beside_basic_is_an_invalid_request() {
    let store = store();
    let body = "grant_type=client_credentials&client_secret=gX1fBat3bV";
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), body).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error(), "invalid_request");
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3.1 and ADR-0064 clause 4: a `client_secret` in the body is not client
/// authentication, so alone it is missing authentication: `401 invalid_client` with the Basic
/// challenge.
#[tokio::test]
async fn a_body_secret_alone_is_missing_authentication() {
    let store = store();
    let body = "grant_type=client_credentials&client_id=s6BhdRkqt3&client_secret=gX1fBat3bV";
    let answer = post(&app(&store, Lifetime::Never), None, body).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.error(), "invalid_client");
    assert_eq!(answer.challenge(), "Basic realm=\"token\"");
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 6749 §2.3: more than one authentication method, here two `Authorization` headers, is
/// `400 invalid_request`.
#[tokio::test]
async fn two_authorization_headers_are_an_invalid_request() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    let answer = send(
        &app,
        request(&[RFC_BASIC, WRONG_SECRET_BASIC], Some(FORM), GRANT),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error(), "invalid_request");
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 6749 §5.2: invalid client authentication is `401 invalid_client`, and when the client used
/// the `Authorization` header the server answers with `WWW-Authenticate`; ADR-0064 clause 4 fixes
/// the challenge as `Basic realm="token"` for an unknown client, a wrong secret and missing or
/// unreadable authentication alike.
#[tokio::test]
async fn failed_client_authentication_is_a_basic_challenge() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for (name, authorization) in [
        ("missing", None),
        ("wrong secret", Some(WRONG_SECRET_BASIC)),
        ("unknown client", Some("Basic Z2hvc3Q6czNjcmV0")),
        ("not base64", Some("Basic !!!")),
        ("no colon", Some("Basic bm9jb2xvbg==")),
        ("bad percent-escape", Some("Basic eDolRkY=")),
        ("no credentials", Some("Basic")),
    ] {
        let answer = post(&app, authorization, GRANT).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(answer.error(), "invalid_client", "{name}");
        assert_eq!(answer.challenge(), "Basic realm=\"token\"", "{name}");
        assert_eq!(
            answer.headers.get(CONTENT_TYPE).unwrap(),
            "application/json",
            "{name}"
        );
        assert_never_cached(&answer);
    }
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 6749 §5.2: the `WWW-Authenticate` challenge of a `401` must match the authentication scheme
/// the client used; ADR-0064 clause 4 adds that this does not mean the scheme is supported. The
/// scheme is echoed as sent, with the realm.
#[tokio::test]
async fn another_scheme_is_challenged_in_that_scheme() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for (authorization, challenge) in [
        ("Bearer abc.def", "Bearer realm=\"token\""),
        ("digest username=\"x\"", "digest realm=\"token\""),
        ("Negotiate", "Negotiate realm=\"token\""),
    ] {
        let answer = post(&app, Some(authorization), GRANT).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization}");
        assert_eq!(answer.error(), "invalid_client", "{authorization}");
        assert_eq!(answer.challenge(), challenge, "{authorization}");
    }
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 9110 §11.6.2: an `Authorization` value starts with an `auth-scheme` token; one that does not
/// is a malformed request, not a client to challenge.
#[tokio::test]
async fn an_authorization_header_without_a_scheme_is_an_invalid_request() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for authorization in ["", "(x) y", "\"Basic\" x"] {
        let answer = post(&app, Some(authorization), GRANT).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{authorization:?}");
        assert_eq!(answer.error(), "invalid_request", "{authorization:?}");
    }
}

/// Verifies: ADR-0064
/// RFC 6749 §4.4.2 and §5.2: a request without the required `grant_type` is `invalid_request`; a
/// grant type the server does not support is `unsupported_grant_type`.
#[tokio::test]
async fn the_grant_type_is_required_and_must_be_client_credentials() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for body in ["", "scope=", "other=1"] {
        let answer = post(&app, Some(RFC_BASIC), body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body:?}");
        assert_eq!(answer.error(), "invalid_request", "{body:?}");
    }
    for body in [
        "grant_type=password&username=a&password=b",
        "grant_type=authorization_code&code=x",
        "grant_type=refresh_token&refresh_token=x",
        "grant_type=Client_Credentials",
    ] {
        let answer = post(&app, Some(RFC_BASIC), body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(answer.error(), "unsupported_grant_type", "{body}");
    }
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// RFC 6749 §5.2 (`invalid_scope`) and ADR-0064 clause 4: this profile defines no scopes, so a
/// non-empty `scope` is refused.
#[tokio::test]
async fn a_scope_is_refused() {
    let store = store();
    let body = "grant_type=client_credentials&scope=read";
    let answer = post(&app(&store, Lifetime::Never), Some(RFC_BASIC), body).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error(), "invalid_scope");
    assert!(store.no_token_issued());
}

/// Verifies: ADR-0064
/// The documented evaluation order: a malformed request is judged before client authentication,
/// which is judged before the grant, which is judged before the scope. RFC 6749 leaves the order
/// open; the profile picks it.
#[tokio::test]
async fn the_evaluation_order_is_request_then_client_then_grant_then_scope() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    let bad_client = Some(WRONG_SECRET_BASIC);

    let answer = post(&app, bad_client, "scope=read").await;
    assert_eq!(answer.error(), "invalid_request", "malformed beats client");

    let answer = post(&app, bad_client, "grant_type=password&scope=read").await;
    assert_eq!(answer.error(), "invalid_client", "client beats grant");

    let answer = post(&app, Some(RFC_BASIC), "grant_type=password&scope=read").await;
    assert_eq!(
        answer.error(),
        "unsupported_grant_type",
        "grant beats scope"
    );

    let answer = post(
        &app,
        Some(RFC_BASIC),
        "grant_type=client_credentials&scope=read",
    )
    .await;
    assert_eq!(answer.error(), "invalid_scope");
}

/// Verifies: ADR-0064
/// RFC 6749 §4.4.2 and §3.2: the body is `application/x-www-form-urlencoded` in UTF-8; a `charset`
/// parameter naming UTF-8 is allowed (RFC 2045 §5.1: media type and parameter names are
/// case-insensitive), another content type or charset is not.
#[tokio::test]
async fn the_content_type_must_be_utf8_form_urlencoded() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for content_type in [
        FORM,
        "application/x-www-form-urlencoded; charset=utf-8",
        "application/x-www-form-urlencoded;charset=\"UTF-8\"",
        "Application/X-WWW-Form-Urlencoded; foo=bar",
    ] {
        let answer = send(&app, request(&[RFC_BASIC], Some(content_type), GRANT)).await;
        assert_eq!(answer.status, StatusCode::OK, "{content_type}");
    }
    for content_type in [
        Some("application/json"),
        Some("text/plain"),
        Some("application/x-www-form-urlencoded; charset=iso-8859-1"),
        Some("application/x-www-form-urlencodedx"),
        None,
    ] {
        let answer = send(&app, request(&[RFC_BASIC], content_type, GRANT)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{content_type:?}");
        assert_eq!(answer.error(), "invalid_request", "{content_type:?}");
    }
}

/// Verifies: ADR-0064
/// RFC 6749 §4.4.2: the body is UTF-8; bytes that are not are a malformed request.
#[tokio::test]
async fn a_body_that_is_not_utf8_is_an_invalid_request() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    let body = b"grant_type=client_credentials&x=\xff\xfe".to_vec();
    let answer = send(&app, request(&[RFC_BASIC], Some(FORM), body)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.error(), "invalid_request");
}

/// Verifies: ADR-0064
/// ADR-0064 clause 8: the body is bounded before it is parsed. A body at the limit is read; one
/// byte over is a plain `413`, with no OAuth body, whatever else is wrong with the request.
#[tokio::test]
async fn the_body_is_bounded_at_8_kib() {
    assert_eq!(MAX_BODY, 8192);
    let store = store();
    let app = app(&store, Lifetime::Never);
    let padded = |len: usize| {
        let mut body = format!("{GRANT}&pad=");
        body.push_str(&"a".repeat(len - body.len()));
        body
    };

    let at_limit = post(&app, Some(RFC_BASIC), &padded(8192)).await;
    assert_eq!(at_limit.status, StatusCode::OK);

    let over = post(&app, Some(RFC_BASIC), &padded(8193)).await;
    assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(over.body.is_empty());
    assert!(over.headers.get(CONTENT_TYPE).is_none());
    assert_never_cached(&over);

    let wrong_everything = send(&app, request(&[], Some("text/plain"), "x".repeat(20_000))).await;
    assert_eq!(wrong_everything.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(wrong_everything.body.is_empty());
}

/// Verifies: ADR-0064
/// RFC 6749 §3.2: the token endpoint is requested with `POST`; any other method is refused, and
/// ADR-0064 clause 4's cache headers are on that response too.
#[tokio::test]
async fn only_post_is_served() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let request = Request::builder()
            .method(method.clone())
            .uri("/token")
            .body(Body::empty())
            .unwrap();
        let answer = send(&app, request).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_never_cached(&answer);
    }
}

/// Verifies: ADR-0064
/// RFC 6749 §5.1 and §5.2: every response of the endpoint is `application/json` and carries
/// `Cache-Control: no-store` and `Pragma: no-cache`, error responses included; an error response
/// has an `error` member.
#[tokio::test]
async fn every_response_is_never_cached_and_errors_are_json() {
    let store = store();
    let app = app(&store, Lifetime::Never);
    for (authorization, body) in [
        (Some(RFC_BASIC), GRANT),
        (Some(RFC_BASIC), ""),
        (Some(RFC_BASIC), "grant_type=password"),
        (Some(RFC_BASIC), "grant_type=client_credentials&scope=x"),
        (None, GRANT),
    ] {
        let answer = post(&app, authorization, body).await;
        assert_never_cached(&answer);
        assert_eq!(
            answer.headers.get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        if answer.status != StatusCode::OK {
            assert_eq!(answer.json().as_object().unwrap().len(), 1, "only `error`");
            assert!(answer.json()["error"].is_string());
        }
    }
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4: a store that fails is a bare `500`, with no detail on the wire, and no token
/// is left active when none was delivered.
#[tokio::test]
async fn a_store_error_is_a_bare_500() {
    let store = store();
    let app = app(&store, Lifetime::Never);

    store.fail_replace.store(true, Ordering::SeqCst);
    let answer = post(&app, Some(RFC_BASIC), GRANT).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(answer.body.is_empty());
    assert_never_cached(&answer);
    assert!(store.no_token_issued());

    store.fail_lookup.store(true, Ordering::SeqCst);
    let answer = post(&app, Some(RFC_BASIC), GRANT).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(answer.body.is_empty());
}

/// Verifies: ADR-0064
/// ADR-0064 clause 4: the request parser, driven without a runtime, reads Basic credentials after
/// form-decoding and never prints the secret.
#[test]
fn the_parser_decodes_credentials_and_hides_the_secret() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(FORM));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Basic YStiJTNBYzpwJTJCcSUyNSVDMyVBOQ=="),
    );
    let parsed = parse_request(&headers, GRANT.as_bytes()).unwrap();
    assert_eq!(parsed.grant_type, "client_credentials");
    assert_eq!(parsed.scope, None);
    let ClientAuth::Basic {
        client_id,
        client_secret,
    } = &parsed.client
    else {
        panic!("{parsed:?}");
    };
    assert_eq!(client_id, "a b:c");
    assert_eq!(client_secret.as_str(), "p+q%é");
    assert!(!format!("{parsed:?}").contains("p+q"));
}

/// Verifies: ADR-0064
/// ADR-0064 clause 8: the parser refuses an oversized body itself, before looking at it.
#[test]
fn the_parser_bounds_its_input() {
    let headers = HeaderMap::new();
    let body = vec![b'a'; MAX_BODY + 1];
    assert_eq!(
        parse_request(&headers, &body).unwrap_err(),
        RequestError::TooLarge
    );
}
