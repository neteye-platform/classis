//! The registration client, driven against a stub HTTP server that records what it receives and
//! answers with the example responses of RFC 7591 §3.2.1 and §3.2.2. The server half of this crate
//! is not involved: the client is judged on what it sends and how it reads what the RFC says may
//! come back.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::Router;
use oauth_registration::client::{register, Error, Registered, Rejection};
use reqwest::redirect::Policy;
use serde_json::{json, Value};

/// What the stub received.
struct Received {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Reply {
    status: StatusCode,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
}

struct Stub {
    received: Mutex<Vec<Received>>,
    reply: Reply,
}

async fn answer(State(stub): State<Arc<Stub>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap()
        .to_vec();
    stub.received.lock().unwrap().push(Received {
        method: parts.method,
        path: parts.uri.path().to_owned(),
        headers: parts.headers,
        body,
    });
    let mut response = Response::builder().status(stub.reply.status);
    for (name, value) in &stub.reply.headers {
        response = response.header(*name, *value);
    }
    response.body(Body::from(stub.reply.body.clone())).unwrap()
}

async fn serve(
    status: StatusCode,
    headers: &[(&'static str, &'static str)],
    body: &str,
) -> (SocketAddr, Arc<Stub>) {
    serve_bytes(status, headers, body.as_bytes().to_vec()).await
}

async fn serve_bytes(
    status: StatusCode,
    headers: &[(&'static str, &'static str)],
    body: Vec<u8>,
) -> (SocketAddr, Arc<Stub>) {
    let stub = Arc::new(Stub {
        received: Mutex::new(Vec::new()),
        reply: Reply {
            status,
            headers: headers.to_vec(),
            body,
        },
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(answer).with_state(stub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, stub)
}

/// The workspace builds reqwest without a TLS provider of its own; install the one every binary
/// installs, once, even though these exchanges are plaintext. Redirects are off, as the client
/// module requires of its caller.
fn http() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
}

const JSON: (&str, &str) = ("content-type", "application/json");
const NO_STORE: (&str, &str) = ("cache-control", "no-store");
const NO_CACHE: (&str, &str) = ("pragma", "no-cache");

/// The initial access token of the RFC 7591 §3.1 example request.
const RFC_INITIAL_ACCESS_TOKEN: &str = "ey23f2.adfj230.af32-developer321";
const RFC_SECRET: &str = "cf136dc3c1fc93f31185e5885805d";

/// The body of RFC 7591 §3.2.1's example response, as it is printed there.
const RFC_3_2_1: &str = r#"{
  "client_id": "s6BhdRkqt3",
  "client_secret": "cf136dc3c1fc93f31185e5885805d",
  "client_id_issued_at": 2893256800,
  "client_secret_expires_at": 2893276800,
  "redirect_uris": [
    "https://client.example.org/callback",
    "https://client.example.org/callback2"],
  "grant_types": ["authorization_code", "refresh_token"],
  "client_name": "My Example Client",
  "client_name#ja-Jpan-JP":
     "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
  "token_endpoint_auth_method": "client_secret_basic",
  "logo_uri": "https://client.example.org/logo.png",
  "jwks_uri": "https://client.example.org/my_public_keys.jwks",
  "example_extension_parameter": "example_value"
}"#;

/// The body of RFC 7591 §3.2.2's second example error response. The RFC folds the description over
/// three lines to fit its page, which JSON does not allow inside a string, so it is one line here.
const RFC_3_2_2: &str = r#"{
  "error": "invalid_client_metadata",
  "error_description": "The grant type 'authorization_code' must be registered along with the response type 'code' but found only 'implicit' instead."
}"#;

async fn ask(addr: SocketAddr) -> Result<Registered, Error> {
    register(
        &http(),
        format!("http://{addr}/register"),
        RFC_INITIAL_ACCESS_TOKEN,
    )
    .await
}

fn rejected(result: Result<Registered, Error>) -> Rejection {
    match result {
        Err(Error::Rejected(rejection)) => rejection,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn malformed(result: Result<Registered, Error>) {
    assert!(
        matches!(result, Err(Error::Malformed(_))),
        "expected a malformed response, got {result:?}"
    );
}

/// RFC 7591 §3.1 and §1.2: the request is a `POST` with `Content-Type: application/json`,
/// `Accept: application/json`, `Authorization: Bearer <initial access token>` (the example's
/// `ey23f2.adfj230.af32-developer321`) and a JSON body stating the grant type
/// `client_credentials` and the method `client_secret_basic`, and nothing else.
#[tokio::test]
async fn the_request_is_the_one_of_rfc_7591() {
    let (addr, stub) = serve(StatusCode::CREATED, &[JSON], RFC_3_2_1).await;
    ask(addr).await.unwrap();

    let received = stub.received.lock().unwrap();
    let [request] = received.as_slice() else {
        panic!("one request expected")
    };
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, "/register");
    assert_eq!(request.headers["content-type"], "application/json");
    assert_eq!(request.headers["accept"], "application/json");
    assert_eq!(
        request.headers["authorization"],
        "Bearer ey23f2.adfj230.af32-developer321"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).unwrap(),
        json!({
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic"
        })
    );
}

/// RFC 7591 §3.2.1: the example response gives `client_id` `s6BhdRkqt3` and `client_secret`
/// `cf136dc3c1fc93f31185e5885805d`; every other member is kept for the caller, and what the caller
/// does not ask for (the example's registered metadata and extension) is ignored without error.
#[tokio::test]
async fn the_rfc_example_response_is_read() {
    let (addr, _) = serve(StatusCode::CREATED, &[JSON, NO_STORE, NO_CACHE], RFC_3_2_1).await;
    let registered = ask(addr).await.unwrap();

    assert_eq!(registered.client_id, "s6BhdRkqt3");
    assert_eq!(registered.client_secret.as_str(), RFC_SECRET);
    assert!(!registered.fields.contains_key("client_id"));
    assert!(!registered.fields.contains_key("client_secret"));
    assert_eq!(
        registered.fields["client_id_issued_at"],
        json!(2_893_256_800u64)
    );
    assert_eq!(
        registered.fields["client_secret_expires_at"],
        json!(2_893_276_800u64)
    );
    assert_eq!(
        registered.fields["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(
        registered.fields["example_extension_parameter"],
        "example_value"
    );
    assert_eq!(
        registered.fields["client_name#ja-Jpan-JP"],
        "\u{30AF}\u{30E9}\u{30A4}\u{30A2}\u{30F3}\u{30C8}\u{540D}"
    );
}

/// RFC 7591 §3.2.1 (a response may carry extension fields): a field the application behind the
/// endpoint adds, of any JSON type, is available to the caller in `fields`.
#[tokio::test]
async fn an_extension_field_is_available_to_the_caller() {
    let (addr, _) = serve(
        StatusCode::CREATED,
        &[JSON],
        r#"{"client_id":"a","client_secret":"b","owner":"alice","nested":{"n":[1,2]}}"#,
    )
    .await;
    let registered = ask(addr).await.unwrap();
    assert_eq!(registered.fields["owner"], "alice");
    assert_eq!(registered.fields["nested"], json!({"n": [1, 2]}));
    assert_eq!(registered.fields.len(), 2);
}

/// RFC 7591 §3.2.1: `client_id` and `client_secret` are REQUIRED in a `201` response. A response
/// without either, with one that is not a string or is empty, or that is not a JSON object, is
/// malformed.
#[tokio::test]
async fn a_response_without_its_credentials_is_malformed() {
    for body in [
        r#"{"client_secret":"b"}"#,
        r#"{"client_id":"a"}"#,
        r#"{"client_id":1,"client_secret":"b"}"#,
        r#"{"client_id":"a","client_secret":null}"#,
        r#"{"client_id":"","client_secret":"b"}"#,
        r#"{"client_id":"a","client_secret":""}"#,
        "{}",
        "[]",
        r#""client_id""#,
        "not json",
        "",
    ] {
        let (addr, _) = serve(StatusCode::CREATED, &[JSON], body).await;
        malformed(ask(addr).await);
    }
}

/// RFC 7591 §3.2.2 and RFC 6750 §3.1: an error response is reported with its status, the `error`
/// code of its JSON body (the RFC's own `invalid_client_metadata` example) and no challenge.
#[tokio::test]
async fn an_rfc_error_response_is_reported_with_its_error_code() {
    let (addr, _) = serve(
        StatusCode::BAD_REQUEST,
        &[JSON, NO_STORE, NO_CACHE],
        RFC_3_2_2,
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.error.as_deref(), Some("invalid_client_metadata"));
    assert!(rejection.challenges.is_empty());
}

/// RFC 6750 §3.1: `401` with `WWW-Authenticate: Bearer error="invalid_token"` is reported with that
/// challenge parsed, and no error code when the body has none; a challenge without an error is
/// read as such.
#[tokio::test]
async fn a_bearer_challenge_is_parsed() {
    let (addr, _) = serve(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", "Bearer error=\"invalid_token\"")],
        "",
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejection.error, None);
    let [challenge] = rejection.challenges.as_slice() else {
        panic!("one challenge expected, got {:?}", rejection.challenges)
    };
    assert!(challenge.is_bearer());
    assert_eq!(challenge.error(), Some("invalid_token"));

    let (addr, _) = serve(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", "Bearer realm=\"example\"")],
        "",
    )
    .await;
    let rejection = rejected(ask(addr).await);
    let [challenge] = rejection.challenges.as_slice() else {
        panic!("one challenge expected")
    };
    assert_eq!(challenge.error(), None);
    assert_eq!(challenge.param("realm"), Some("example"));

    let (addr, _) = serve(
        StatusCode::BAD_REQUEST,
        &[("www-authenticate", "Bearer error=\"invalid_request\"")],
        "",
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.challenges[0].error(), Some("invalid_request"));
}

/// RFC 7591 §3.2.1: only `201 Created` is success. Any other status, a `200` with credentials
/// included, is a rejection, and an unreadable body gives it no error code.
#[tokio::test]
async fn any_status_but_201_is_a_rejection() {
    for status in [
        StatusCode::OK,
        StatusCode::NO_CONTENT,
        StatusCode::PAYLOAD_TOO_LARGE,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (addr, _) = serve(status, &[JSON], RFC_3_2_1).await;
        let rejection = rejected(ask(addr).await);
        assert_eq!(rejection.status, status);
        assert_eq!(rejection.error, None);
    }
    let (addr, _) = serve(StatusCode::INTERNAL_SERVER_ERROR, &[], "<html>").await;
    assert_eq!(rejected(ask(addr).await).error, None);
}

/// RFC 6750 §5.3: the caller's client decides about redirects, and it does
/// not follow them; a `307` is a rejection and the initial access token goes nowhere else.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (elsewhere, other) = serve(StatusCode::CREATED, &[JSON], RFC_3_2_1).await;
    let location: &'static str = Box::leak(format!("http://{elsewhere}/stolen").into_boxed_str());
    let (addr, first) = serve(
        StatusCode::TEMPORARY_REDIRECT,
        &[("location", location)],
        "",
    )
    .await;

    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(first.received.lock().unwrap().len(), 1);
    assert!(other.received.lock().unwrap().is_empty());
}

/// A request that cannot be made is a transport error, apart from a malformed response and from a
/// rejection.
#[tokio::test]
async fn an_unreachable_endpoint_is_a_transport_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert!(matches!(ask(addr).await, Err(Error::Transport(_))));
}

/// The response body that is read is bounded; a `201` whose body is longer is
/// malformed rather than read into memory.
#[tokio::test]
async fn a_response_body_over_the_limit_is_malformed() {
    let padding = "a".repeat(70 * 1024);
    let body = format!(r#"{{"client_id":"a","client_secret":"b","pad":"{padding}"}}"#);
    let (addr, _) = serve(StatusCode::CREATED, &[JSON], &body).await;
    malformed(ask(addr).await);

    let (addr, _) = serve_bytes(StatusCode::BAD_REQUEST, &[JSON], vec![b'x'; 70 * 1024]).await;
    assert_eq!(rejected(ask(addr).await).error, None);
}

/// Neither the secret, nor the initial access token, appears in the
/// `Debug` output of a result or an error.
#[tokio::test]
async fn no_secret_is_printed() {
    let (addr, _) = serve(StatusCode::CREATED, &[JSON], RFC_3_2_1).await;
    let registered = ask(addr).await.unwrap();
    let printed = format!("{registered:?}");
    assert!(!printed.contains(RFC_SECRET), "{printed}");
    assert!(printed.contains("s6BhdRkqt3"));

    let (addr, _) = serve(StatusCode::UNAUTHORIZED, &[], RFC_3_2_1).await;
    let error = ask(addr).await.unwrap_err();
    for printed in [format!("{error:?}"), error.to_string()] {
        assert!(!printed.contains(RFC_SECRET), "{printed}");
        assert!(!printed.contains(RFC_INITIAL_ACCESS_TOKEN), "{printed}");
    }

    let closed = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let error = ask(closed).await.unwrap_err();
    assert!(!format!("{error:?}").contains(RFC_INITIAL_ACCESS_TOKEN));
}
