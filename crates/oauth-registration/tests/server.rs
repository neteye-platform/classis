//! The registration endpoint, driven with hand-built HTTP requests against an in-memory store.
//! Every expected status, header and field is read off the RFC section cited, not off the
//! implementation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use oauth_registration::server::{
    endpoint, parse_request, Metadata, NewClient, RegistrationStore, RequestError, StoreError,
    MAX_BODY,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

const JSON: &str = "application/json";
const TOKEN: &str = "iat-s3cret_token.1";
const REALM: &str = "example";
/// The body of the RFC 7591 §3.1 example request, adapted to the client-credentials grant: its
/// metadata this profile does not understand stays, to be ignored (§2).
const RFC_3_1_ADAPTED: &str = r#"{
  "redirect_uris": ["https://client.example.org/callback", "https://client.example.org/callback2"],
  "client_name": "My Example Client",
  "client_name#ja-Jpan-JP": "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["client_credentials"],
  "logo_uri": "https://client.example.org/logo.png",
  "jwks_uri": "https://client.example.org/my_public_keys.jwks",
  "example_extension_parameter": "example_value"
}"#;
const MINIMAL: &str = r#"{"grant_types":["client_credentials"]}"#;

fn sha256(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// What an authorised token stands for in this store: the token itself, so that the second step
/// can tell whether it is still the current one.
struct Grant {
    token: String,
}

struct MemStore {
    current_token: Mutex<String>,
    rotate_on_authorise: AtomicBool,
    fail_authorise: AtomicBool,
    fail_register: AtomicBool,
    extension: Mutex<Map<String, Value>>,
    authorised: Mutex<Vec<String>>,
    clients: Mutex<Vec<NewClient>>,
}

impl MemStore {
    fn new() -> Arc<MemStore> {
        let mut extension = Map::new();
        extension.insert("owner".into(), json!("alice"));
        Arc::new(MemStore {
            current_token: Mutex::new(TOKEN.to_owned()),
            rotate_on_authorise: AtomicBool::new(false),
            fail_authorise: AtomicBool::new(false),
            fail_register: AtomicBool::new(false),
            extension: Mutex::new(extension),
            authorised: Mutex::new(Vec::new()),
            clients: Mutex::new(Vec::new()),
        })
    }

    fn clients(&self) -> MutexGuard<'_, Vec<NewClient>> {
        self.clients.lock().unwrap()
    }

    fn authorised(&self) -> Vec<String> {
        self.authorised.lock().unwrap().clone()
    }
}

impl RegistrationStore for MemStore {
    type Grant = Grant;

    fn authorise(&self, initial_access_token: &str) -> Result<Option<Grant>, StoreError> {
        self.authorised
            .lock()
            .unwrap()
            .push(initial_access_token.to_owned());
        if self.fail_authorise.load(Ordering::SeqCst) {
            return Err(StoreError);
        }
        let mut current = self.current_token.lock().unwrap();
        if *current != initial_access_token {
            return Ok(None);
        }
        let grant = Grant {
            token: current.clone(),
        };
        if self.rotate_on_authorise.load(Ordering::SeqCst) {
            *current = "a-newer-token".to_owned();
        }
        Ok(Some(grant))
    }

    fn register(
        &self,
        grant: &Grant,
        client: NewClient,
    ) -> Result<Option<Map<String, Value>>, StoreError> {
        if self.fail_register.load(Ordering::SeqCst) {
            return Err(StoreError);
        }
        if *self.current_token.lock().unwrap() != grant.token {
            return Ok(None);
        }
        self.clients().push(client);
        Ok(Some(self.extension.lock().unwrap().clone()))
    }
}

fn app(store: &Arc<MemStore>) -> Router {
    app_with_realm(store, REALM)
}

fn app_with_realm(store: &Arc<MemStore>, realm: &str) -> Router {
    Router::new().route("/register", endpoint(store.clone(), realm).unwrap())
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Map<String, Value> {
        match serde_json::from_slice(&self.body).expect("a JSON body") {
            Value::Object(object) => object,
            other => panic!("a JSON object expected, got {other}"),
        }
    }

    fn str_field(&self, name: &str) -> String {
        self.json()[name]
            .as_str()
            .unwrap_or_else(|| panic!("{name} is a string"))
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

/// Every response of the endpoint carries both cache headers (RFC 7591 §3.2.1; §3.2.2 for
/// errors), so each send checks it.
async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    let answer = Answer {
        status: parts.status,
        headers: parts.headers,
        body,
    };
    assert_cached_never(&answer);
    answer
}

fn assert_cached_never(answer: &Answer) {
    assert_eq!(
        answer.headers[CACHE_CONTROL], "no-store",
        "{}",
        answer.status
    );
    assert_eq!(answer.headers[PRAGMA], "no-cache", "{}", answer.status);
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

fn request(
    method: Method,
    authorization: &[&str],
    content_type: Option<&str>,
    body: impl Into<Vec<u8>>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri("/register");
    for value in authorization {
        builder = builder.header(AUTHORIZATION, *value);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    }
    builder.body(Body::from(body.into())).unwrap()
}

async fn register(app: &Router, body: &str) -> Answer {
    send(
        app,
        request(Method::POST, &[&bearer()], Some(JSON), body.as_bytes()),
    )
    .await
}

fn assert_invalid_client_metadata(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.headers[CONTENT_TYPE], JSON);
    assert_eq!(
        Value::Object(answer.json()),
        json!({ "error": "invalid_client_metadata" })
    );
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A JSON registration request of exactly `len` bytes, padded with an ignored member.
fn padded_request(len: usize) -> String {
    let head = r#"{"grant_types":["client_credentials"],"pad":""#;
    let tail = r#""}"#;
    format!("{head}{}{tail}", "a".repeat(len - head.len() - tail.len()))
}

/// Verifies: ADR-0064
/// RFC 7591 §3.1 and §3.2.1: the example request, adapted to the client-credentials grant, is
/// answered `201 Created`, `application/json`, with `client_id`, `client_secret`,
/// `client_id_issued_at`, `client_secret_expires_at` (`0`: no expiry) and every registered
/// metadata field, plus the application's extension field and nothing else.
#[tokio::test]
async fn the_rfc_example_request_is_answered_as_section_3_2_1_says() {
    let store = MemStore::new();
    let before = unix_now();
    let answer = register(&app(&store), RFC_3_1_ADAPTED).await;
    let after = unix_now();

    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(answer.headers[CONTENT_TYPE], JSON);
    let body = answer.json();
    let mut names: Vec<&str> = body.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "client_id",
            "client_id_issued_at",
            "client_secret",
            "client_secret_expires_at",
            "grant_types",
            "owner",
            "token_endpoint_auth_method",
        ]
    );
    assert!(body["client_id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(body["client_secret"]
        .as_str()
        .is_some_and(|secret| !secret.is_empty()));
    let issued_at = body["client_id_issued_at"].as_u64().unwrap();
    assert!((before..=after).contains(&issued_at));
    assert_eq!(body["client_secret_expires_at"], json!(0));
    assert_eq!(body["grant_types"], json!(["client_credentials"]));
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(body["owner"], "alice");
}

/// Verifies: ADR-0064
/// RFC 7591 §2: members the server does not understand are ignored, not rejected and not part of
/// the registered metadata, so they are not echoed (§3.2.1 echoes the registered metadata).
#[tokio::test]
async fn unknown_metadata_is_ignored_and_not_echoed() {
    let store = MemStore::new();
    let answer = register(
        &app(&store),
        r#"{
          "grant_types": ["client_credentials"],
          "redirect_uris": ["https://client.example.org/callback"],
          "response_types": ["token"],
          "client_name": "My Example Client",
          "scope": "a b",
          "made_up_member": {"nested": [1, 2, 3]}
        }"#,
    )
    .await;

    assert_eq!(answer.status, StatusCode::CREATED);
    let body = answer.json();
    for name in [
        "redirect_uris",
        "response_types",
        "client_name",
        "scope",
        "made_up_member",
    ] {
        assert!(!body.contains_key(name), "{name} was echoed");
    }
    assert_eq!(store.clients().len(), 1);
}

/// Verifies: ADR-0064
/// RFC 7591 §2: `grant_types` omitted defaults to `["authorization_code"]`, which this profile does
/// not support: `400 invalid_client_metadata` (§3.2.2), and nothing is stored.
#[tokio::test]
async fn omitted_grant_types_are_refused() {
    let store = MemStore::new();
    let app = app(&store);
    for body in [
        "{}",
        r#"{"token_endpoint_auth_method":"client_secret_basic"}"#,
        r#"{"client_name":"x"}"#,
    ] {
        let answer = register(&app, body).await;
        assert_invalid_client_metadata(&answer);
    }
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §2 (`grant_types` is an array of strings), §3.2.2: any grant type other than
/// `client_credentials`, alone or beside it, an empty array, and a value that is not an array of
/// strings are `invalid_client_metadata`; the names are case-sensitive.
#[tokio::test]
async fn other_grant_types_are_refused() {
    let store = MemStore::new();
    let app = app(&store);
    for grant_types in [
        r#"["authorization_code"]"#,
        r#"["client_credentials","authorization_code"]"#,
        r#"["refresh_token","client_credentials"]"#,
        r#"["urn:ietf:params:oauth:grant-type:jwt-bearer"]"#,
        "[]",
        r#""client_credentials""#,
        "null",
        "true",
        "1",
        r#"{"client_credentials":true}"#,
        "[1]",
        "[null]",
        r#"[["client_credentials"]]"#,
        r#"["Client_Credentials"]"#,
        r#"[" client_credentials"]"#,
    ] {
        let answer = register(&app, &format!(r#"{{"grant_types":{grant_types}}}"#)).await;
        assert_invalid_client_metadata(&answer);
    }
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §2: a repeated `client_credentials` is the same grant type stated twice; the registered
/// metadata, answered under §3.2.1, states it once.
#[tokio::test]
async fn a_repeated_client_credentials_grant_is_harmless() {
    let store = MemStore::new();
    let answer = register(
        &app(&store),
        r#"{"grant_types":["client_credentials","client_credentials"]}"#,
    )
    .await;
    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(answer.json()["grant_types"], json!(["client_credentials"]));
}

/// Verifies: ADR-0064
/// RFC 7591 §2: an omitted `token_endpoint_auth_method` defaults to `client_secret_basic`, and §3.2.1
/// returns all the registered metadata, so the default is echoed.
#[tokio::test]
async fn an_omitted_auth_method_defaults_and_is_echoed() {
    let store = MemStore::new();
    let answer = register(&app(&store), MINIMAL).await;
    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(
        answer.json()["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(
        store.clients()[0].metadata,
        Metadata {
            grant_types: &["client_credentials"],
            token_endpoint_auth_method: "client_secret_basic"
        }
    );
}

/// Verifies: ADR-0064
/// RFC 7591 §2 and §3.2.2: an authentication method other than `client_secret_basic`, or a value
/// that is not a string, is `invalid_client_metadata`.
#[tokio::test]
async fn other_auth_methods_are_refused() {
    let store = MemStore::new();
    let app = app(&store);
    for method in [
        r#""client_secret_post""#,
        r#""client_secret_jwt""#,
        r#""private_key_jwt""#,
        r#""none""#,
        r#""""#,
        r#""Client_Secret_Basic""#,
        "null",
        "5",
        "true",
        r#"["client_secret_basic"]"#,
        r#"{"a":1}"#,
    ] {
        let answer = register(
            &app,
            &format!(
                r#"{{"grant_types":["client_credentials"],"token_endpoint_auth_method":{method}}}"#
            ),
        )
        .await;
        assert_invalid_client_metadata(&answer);
    }
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §3.2.1: the issued credentials are the server's to make. An extension field named like
/// one the crate sets is dropped; the others pass through.
#[tokio::test]
async fn an_extension_cannot_overwrite_a_field_the_crate_sets() {
    let store = MemStore::new();
    {
        let mut extension = store.extension.lock().unwrap();
        for name in [
            "client_id",
            "client_secret",
            "client_id_issued_at",
            "client_secret_expires_at",
            "grant_types",
            "token_endpoint_auth_method",
        ] {
            extension.insert(name.to_owned(), json!("overwritten"));
        }
    }
    let answer = register(&app(&store), MINIMAL).await;
    assert_eq!(answer.status, StatusCode::CREATED);
    let body = answer.json();
    assert_eq!(body["owner"], "alice");
    assert_eq!(body["client_id"], store.clients()[0].client_id.as_str());
    assert_ne!(body["client_secret"], "overwritten");
    assert_eq!(body["client_secret"].as_str().unwrap().len(), 43);
    assert!(body["client_id_issued_at"].is_u64());
    assert_eq!(body["client_secret_expires_at"], json!(0));
    assert_eq!(body["grant_types"], json!(["client_credentials"]));
    assert_eq!(body["token_endpoint_auth_method"], "client_secret_basic");
}

/// Verifies: ADR-0064
/// RFC 9562 §5.7 (UUID version 7: version nibble `7`, variant `10`) and ADR-0064 clause 2: the
/// `client_id` is a UUID version 7. The store gets that id and the issue time of the response,
/// and only the SHA-256 of the secret the response carries.
#[tokio::test]
async fn the_store_gets_a_uuid_v7_and_only_the_hash_of_the_secret() {
    let store = MemStore::new();
    let answer = register(&app(&store), MINIMAL).await;
    assert_eq!(answer.status, StatusCode::CREATED);

    let clients = store.clients();
    let [client] = clients.as_slice() else {
        panic!("one client expected")
    };
    let id = answer.str_field("client_id");
    assert_eq!(client.client_id, id);
    let digits: Vec<char> = id.chars().collect();
    assert_eq!(digits.len(), 36);
    assert_eq!(digits[14], '7', "version nibble of {id}");
    assert!(
        matches!(digits[19], '8' | '9' | 'a' | 'b'),
        "variant of {id}"
    );
    assert_eq!(id, id.to_ascii_lowercase());
    let parsed = uuid::Uuid::parse_str(&id).unwrap();
    assert_eq!(parsed.get_version_num(), 7);
    assert_eq!(
        client.client_secret_hash,
        sha256(&answer.str_field("client_secret"))
    );
    assert_eq!(
        client.client_id_issued_at,
        answer.json()["client_id_issued_at"].as_u64().unwrap()
    );
    assert_eq!(client.metadata, Metadata::REGISTERED);
}

/// Verifies: ADR-0064
/// RFC 4648 §5 and ADR-0064 clause 2: the secret is 256 random bits as 43 base64url characters
/// without padding; two registrations never share an id or a secret.
#[tokio::test]
async fn the_secret_is_43_base64url_characters() {
    let store = MemStore::new();
    let app = app(&store);
    let first = register(&app, MINIMAL).await;
    let second = register(&app, MINIMAL).await;

    let secret = first.str_field("client_secret");
    assert_eq!(secret.len(), 43);
    assert!(secret
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    assert_eq!(URL_SAFE_NO_PAD.decode(&secret).unwrap().len(), 32);
    assert_ne!(secret, second.str_field("client_secret"));
    assert_ne!(first.str_field("client_id"), second.str_field("client_id"));
}

/// Verifies: ADR-0064
/// RFC 6750 §3 and ADR-0064 clause 6: no credential, or a scheme that is not Bearer, is `401` with a
/// challenge that has the application's realm and no error code. The request is not read further
/// and nothing is stored.
#[tokio::test]
async fn no_usable_credential_is_challenged_with_the_realm() {
    let store = MemStore::new();
    let app = app(&store);
    for authorization in [
        &[][..],
        &["Basic dXNlcjpwYXNz"][..],
        &["Digest username=\"a\""][..],
        &[""][..],
    ] {
        let answer = send(
            &app,
            request(Method::POST, authorization, Some(JSON), MINIMAL),
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        assert_eq!(answer.challenge(), "Bearer realm=\"example\"");
        assert!(answer.body.is_empty());
    }
    assert!(store.authorised().is_empty());
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 6750 §5.3: a token in the URL is not a credential; with no header the request is
/// unauthenticated, and with a header as well it is two transmission methods (§2, §3.1).
#[tokio::test]
async fn a_token_in_the_url_is_no_credential() {
    let store = MemStore::new();
    let app = app(&store);

    let mut alone = request(Method::POST, &[], Some(JSON), MINIMAL);
    *alone.uri_mut() = format!("/register?access_token={TOKEN}").parse().unwrap();
    let answer = send(&app, alone).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.challenge(), "Bearer realm=\"example\"");

    let mut both = request(Method::POST, &[&bearer()], Some(JSON), MINIMAL);
    *both.uri_mut() = format!("/register?access_token={TOKEN}").parse().unwrap();
    let answer = send(&app, both).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.challenge(), "Bearer error=\"invalid_request\"");
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 6750 §2.1 (`b64token`), §3.1 (`invalid_token`) and ADR-0064 clause 6: a Bearer header whose
/// token is missing or outside the `b64token` syntax is `401 Bearer error="invalid_token"`, and
/// the application is never asked about it.
#[tokio::test]
async fn a_malformed_token_is_an_invalid_token() {
    let store = MemStore::new();
    let app = app(&store);
    for authorization in [
        "Bearer",
        "Bearer ",
        "Bearer a b",
        "Bearer a,b",
        "Bearer \"x\"",
    ] {
        let answer = send(
            &app,
            request(Method::POST, &[authorization], Some(JSON), MINIMAL),
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization}");
        assert_eq!(answer.challenge(), "Bearer error=\"invalid_token\"");
    }
    assert!(store.authorised().is_empty());
}

/// Verifies: ADR-0064
/// RFC 6750 §2 and §3.1 and ADR-0064 clause 6: two `Authorization` headers are more than one way
/// of presenting a token: `400 Bearer error="invalid_request"`.
#[tokio::test]
async fn two_authorization_headers_are_an_invalid_request() {
    let store = MemStore::new();
    let answer = send(
        &app(&store),
        request(Method::POST, &[&bearer(), &bearer()], Some(JSON), MINIMAL),
    )
    .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.challenge(), "Bearer error=\"invalid_request\"");
    assert!(store.authorised().is_empty());
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 6750 §3.1 and ADR-0064 clause 6: an unknown or replaced key is an invalid token, `401
/// Bearer error="invalid_token"`; the scheme is case-insensitive and the token is not (RFC 9110
/// §11.1).
#[tokio::test]
async fn a_refused_token_is_an_invalid_token() {
    let store = MemStore::new();
    let app = app(&store);
    for authorization in [
        "Bearer other-token".to_owned(),
        format!("Bearer {}", TOKEN.to_ascii_uppercase()),
    ] {
        let answer = send(
            &app,
            request(Method::POST, &[&authorization], Some(JSON), MINIMAL),
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{authorization}");
        assert_eq!(answer.challenge(), "Bearer error=\"invalid_token\"");
        assert!(answer.body.is_empty());
    }
    assert!(store.clients().is_empty());

    let answer = send(
        &app,
        request(
            Method::POST,
            &[&format!("bEaReR {TOKEN}")],
            Some(JSON),
            MINIMAL,
        ),
    )
    .await;
    assert_eq!(answer.status, StatusCode::CREATED);
}

/// Verifies: ADR-0064
/// RFC 7591 §1.2 and ADR-0064 clause 2: the application is handed the token exactly as sent.
#[tokio::test]
async fn the_application_receives_the_token_as_sent() {
    let store = MemStore::new();
    let answer = register(&app(&store), MINIMAL).await;
    assert_eq!(answer.status, StatusCode::CREATED);
    assert_eq!(store.authorised(), [TOKEN]);
}

/// Verifies: ADR-0064
/// RFC 6750 §3.1 and ADR-0064 clause 6: a token that stopped being valid between the two steps (the
/// key was replaced) is an invalid token, and the client is not stored.
#[tokio::test]
async fn a_token_replaced_between_the_two_steps_is_an_invalid_token() {
    let store = MemStore::new();
    store.rotate_on_authorise.store(true, Ordering::SeqCst);
    let answer = register(&app(&store), MINIMAL).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.challenge(), "Bearer error=\"invalid_token\"");
    assert!(answer.body.is_empty());
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 6750 §3 and RFC 9110 §5.6.4: the realm is the application's, and a quote or a backslash in
/// it is written as a quoted pair; a realm that cannot be a header value is refused when the
/// endpoint is built.
#[tokio::test]
async fn the_realm_is_the_applications() {
    let store = MemStore::new();
    let app = app_with_realm(&store, "my \"realm\"\\");
    let answer = send(&app, request(Method::POST, &[], Some(JSON), MINIMAL)).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.challenge(), "Bearer realm=\"my \\\"realm\\\"\\\\\"");

    assert!(endpoint(store.clone(), "bad\nrealm").is_err());
}

/// Verifies: ADR-0064
/// RFC 7591 §3.2.2 and ADR-0064 clause 2: a caller without a valid token learns nothing of the
/// validation of metadata: a request whose body is wrong, or too large, is answered as one with no
/// credential, or with a refused one.
#[tokio::test]
async fn metadata_errors_are_not_reached_without_a_valid_token() {
    let store = MemStore::new();
    let app = app(&store);
    let oversized = padded_request(MAX_BODY + 1);
    for body in ["not json", "[]", "{}", oversized.as_str()] {
        let answer = send(&app, request(Method::POST, &[], Some("text/plain"), body)).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.challenge(), "Bearer realm=\"example\"");

        let answer = send(
            &app,
            request(Method::POST, &["Bearer wrong"], Some("text/plain"), body),
        )
        .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
        assert_eq!(answer.challenge(), "Bearer error=\"invalid_token\"");
    }
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §3.1 (a JSON request) and §3.2.2: a body that is not JSON, or not a JSON object, is
/// `400 invalid_client_metadata` with a JSON body.
#[tokio::test]
async fn a_body_that_is_not_a_json_object_is_invalid_client_metadata() {
    let store = MemStore::new();
    let app = app(&store);
    for body in [
        "",
        "not json",
        "[]",
        "[{\"grant_types\":[\"client_credentials\"]}]",
        "\"client_credentials\"",
        "null",
        "42",
        "true",
        "{",
        "{\"grant_types\":[\"client_credentials\"]",
        "{\"grant_types\":[\"client_credentials\"]} trailing",
        "\u{feff}{\"grant_types\":[\"client_credentials\"]}",
    ] {
        let answer = register(&app, body).await;
        assert_invalid_client_metadata(&answer);
    }
    let answer = send(
        &app,
        request(
            Method::POST,
            &[&bearer()],
            Some(JSON),
            b"{\"grant_types\":[\"client_credentials\"],\"x\":\"\xff\"}".as_slice(),
        ),
    )
    .await;
    assert_invalid_client_metadata(&answer);
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §3.1 (`Content-Type: application/json`) and §3.2.2: any other media type, none, or
/// two `Content-Type` headers is `invalid_client_metadata`, even with a valid body; parameters
/// and the case of the media type do not matter (RFC 9110 §8.3.1).
#[tokio::test]
async fn the_content_type_must_be_application_json() {
    let store = MemStore::new();
    let app = app(&store);
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
        Some("application/jsonx"),
        Some("application/json-seq"),
        Some("application/"),
        Some(""),
        Some("json"),
    ] {
        let answer = send(
            &app,
            request(Method::POST, &[&bearer()], content_type, MINIMAL),
        )
        .await;
        assert_invalid_client_metadata(&answer);
    }
    let mut two = request(Method::POST, &[&bearer()], Some(JSON), MINIMAL);
    two.headers_mut()
        .append(CONTENT_TYPE, HeaderValue::from_static(JSON));
    let answer = send(&app, two).await;
    assert_invalid_client_metadata(&answer);
    assert!(store.clients().is_empty());

    for content_type in [
        "application/json; charset=utf-8",
        "APPLICATION/JSON",
        "application/json ;charset=UTF-8",
    ] {
        let answer = send(
            &app,
            request(Method::POST, &[&bearer()], Some(content_type), MINIMAL),
        )
        .await;
        assert_eq!(answer.status, StatusCode::CREATED, "{content_type}");
    }
}

/// Verifies: ADR-0064
/// ADR-0064 clause 8: a body of 8 KiB is read and judged, one byte more is a plain `413` with no
/// body, whatever its content.
#[tokio::test]
async fn the_body_is_bounded_at_8_kib() {
    assert_eq!(MAX_BODY, 8192);
    let store = MemStore::new();
    let app = app(&store);

    let answer = register(&app, &padded_request(8192)).await;
    assert_eq!(answer.status, StatusCode::CREATED);

    let answer = register(&app, &padded_request(8193)).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(answer.body.is_empty());
    assert!(!answer.headers.contains_key(CONTENT_TYPE));

    let answer = register(&app, &"x".repeat(1024 * 1024)).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(answer.body.is_empty());
    assert_eq!(store.clients().len(), 1);
}

/// Verifies: ADR-0064
/// RFC 7591 §3.2.1 and §3.2.2: every response of the endpoint carries `Cache-Control: no-store` and
/// `Pragma: no-cache`, whatever its status. (`send` checks it for every other test too.)
#[tokio::test]
async fn every_response_carries_both_cache_headers() {
    let store = MemStore::new();
    let app = app(&store);
    let mut statuses = Vec::new();

    for request in [
        request(Method::POST, &[&bearer()], Some(JSON), MINIMAL),
        request(Method::POST, &[&bearer()], Some(JSON), "{}"),
        request(Method::POST, &[], Some(JSON), MINIMAL),
        request(Method::POST, &["Bearer x"], Some(JSON), MINIMAL),
        request(Method::POST, &[&bearer(), &bearer()], Some(JSON), MINIMAL),
        request(
            Method::POST,
            &[&bearer()],
            Some(JSON),
            padded_request(MAX_BODY + 1),
        ),
        request(Method::GET, &[&bearer()], None, ""),
    ] {
        statuses.push(send(&app, request).await.status.as_u16());
    }
    store.fail_register.store(true, Ordering::SeqCst);
    statuses.push(register(&app, MINIMAL).await.status.as_u16());

    assert_eq!(statuses, [201, 400, 401, 401, 400, 413, 405, 500]);
}

/// Verifies: ADR-0064
/// ADR-0064 clause 2: a store failure at either step is a bare `500`, with no body, and stores
/// nothing.
#[tokio::test]
async fn a_store_error_is_a_bare_500() {
    let store = MemStore::new();
    let app = app(&store);

    store.fail_authorise.store(true, Ordering::SeqCst);
    let answer = register(&app, MINIMAL).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(answer.body.is_empty());
    assert!(!answer.headers.contains_key(WWW_AUTHENTICATE));
    assert!(!answer.headers.contains_key(CONTENT_TYPE));

    store.fail_authorise.store(false, Ordering::SeqCst);
    store.fail_register.store(true, Ordering::SeqCst);
    let answer = register(&app, MINIMAL).await;
    assert_eq!(answer.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(answer.body.is_empty());
    assert!(!answer.headers.contains_key(WWW_AUTHENTICATE));
    assert!(!answer.headers.contains_key(CONTENT_TYPE));
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §3 (registration is a `POST`): any other method is `405` and the store is not asked.
#[tokio::test]
async fn only_post_registers() {
    let store = MemStore::new();
    let app = app(&store);
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        let answer = send(
            &app,
            request(method.clone(), &[&bearer()], Some(JSON), MINIMAL),
        )
        .await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
    assert!(store.authorised().is_empty());
    assert!(store.clients().is_empty());
}

/// Verifies: ADR-0064
/// RFC 7591 §2, §3.2.2 and ADR-0064 clause 8: the parser, which a fuzzer drives, accepts exactly
/// what the endpoint registers and is bounded at 8 KiB.
#[test]
fn the_parser_judges_headers_and_body() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON));
    assert_eq!(
        parse_request(&headers, MINIMAL.as_bytes()),
        Ok(Metadata::REGISTERED)
    );
    assert_eq!(
        parse_request(&headers, RFC_3_1_ADAPTED.as_bytes()),
        Ok(Metadata::REGISTERED)
    );
    assert_eq!(
        parse_request(&headers, b"{}"),
        Err(RequestError::InvalidMetadata)
    );
    assert_eq!(
        parse_request(&headers, padded_request(MAX_BODY).as_bytes()),
        Ok(Metadata::REGISTERED)
    );
    assert_eq!(
        parse_request(&headers, padded_request(MAX_BODY + 1).as_bytes()),
        Err(RequestError::TooLarge)
    );
    assert_eq!(
        parse_request(&HeaderMap::new(), MINIMAL.as_bytes()),
        Err(RequestError::InvalidMetadata)
    );
}
