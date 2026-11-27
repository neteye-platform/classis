//! The token client, driven against a stub HTTP server that records what it receives and answers
//! with the example responses of RFC 6749 §5.1 and §5.2. The server half of this crate is not
//! involved: the client is judged on what it sends and how it reads what the RFC says may come back.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::Router;
use oauth_token::client::{request_token, Error, Rejection};
use reqwest::redirect::Policy;

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

const JSON: (&str, &str) = ("content-type", "application/json;charset=UTF-8");
const NO_STORE: (&str, &str) = ("cache-control", "no-store");
const NO_CACHE: (&str, &str) = ("pragma", "no-cache");

/// Adapted from RFC 6749 §5.1's example response: the token type is `Bearer`, which is what this
/// profile issues, and the token values are deliberately dummy, not a literal copy of the RFC.
const RFC_5_1_BEARER: &str = r#"{
  "access_token":"test-token",
  "token_type":"Bearer",
  "expires_in":3600,
  "refresh_token":"test-refresh-token",
  "example_parameter":"example_value"
}"#;

async fn ask(addr: SocketAddr) -> Result<oauth_token::client::AccessToken, Error> {
    request_token(
        &http(),
        format!("http://{addr}/v1/token"),
        "s6BhdRkqt3",
        "gX1fBat3bV",
    )
    .await
}

fn rejected(result: Result<oauth_token::client::AccessToken, Error>) -> Rejection {
    match result {
        Err(Error::Rejected(rejection)) => rejection,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// RFC 6749 §4.4.2: the request is a `POST` with `Authorization: Basic …` (the example's
/// `czZCaGRSa3F0MzpnWDFmQmF0M2JW` for `s6BhdRkqt3:gX1fBat3bV`), `Content-Type:
/// application/x-www-form-urlencoded` and the body `grant_type=client_credentials`.
#[tokio::test]
async fn the_request_is_the_one_of_the_rfc_example() {
    let (addr, stub) = serve(StatusCode::OK, &[JSON], RFC_5_1_BEARER).await;
    ask(addr).await.unwrap();

    let received = stub.received.lock().unwrap();
    let [request] = received.as_slice() else {
        panic!("one request expected")
    };
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, "/v1/token");
    assert_eq!(
        request.headers["authorization"],
        "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW"
    );
    assert_eq!(
        request.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(request.body, b"grant_type=client_credentials");
}

/// RFC 6749 §2.3.1: the identifier and secret are form-encoded before the Basic encoding. The
/// expected header is the base64 of `a+b%3Ac:p%2Bq%25%C3%A9`, written out by hand, for the
/// identifier `a b:c` and the secret `p+q%é`.
#[tokio::test]
async fn the_credentials_are_form_encoded_before_the_basic_encoding() {
    let (addr, stub) = serve(StatusCode::OK, &[JSON], RFC_5_1_BEARER).await;
    request_token(&http(), format!("http://{addr}/t"), "a b:c", "p+q%é")
        .await
        .unwrap();
    let received = stub.received.lock().unwrap();
    assert_eq!(
        received[0].headers["authorization"],
        "Basic YStiJTNBYzpwJTJCcSUyNSVDMyVBOQ=="
    );
}

/// RFC 6749 §5.1: the example response, with its `refresh_token` and `example_parameter`: the
/// client MUST ignore value names in the response that it does not recognise.
#[tokio::test]
async fn unknown_response_fields_are_ignored() {
    let (addr, _) = serve(StatusCode::OK, &[JSON, NO_STORE, NO_CACHE], RFC_5_1_BEARER).await;
    let token = ask(addr).await.unwrap();
    assert_eq!(token.access_token.as_str(), "test-token");
    assert_eq!(token.expires_in, Some(3600));
}

/// RFC 6749 §5.1: `expires_in` is RECOMMENDED, so a response without it is a token without a
/// stated lifetime (A non-expiring token omits it).
#[tokio::test]
async fn a_response_without_expires_in_has_none() {
    let body = r#"{"access_token":"abc","token_type":"Bearer"}"#;
    let (addr, _) = serve(StatusCode::OK, &[JSON], body).await;
    let token = ask(addr).await.unwrap();
    assert_eq!(token.expires_in, None);
}

/// RFC 6749 §5.1: `token_type` is case-insensitive ("The token type is case insensitive"), so
/// `bearer` is accepted as `Bearer` is.
#[tokio::test]
async fn the_token_type_is_case_insensitive() {
    for token_type in ["bearer", "Bearer", "BEARER"] {
        let body = format!(r#"{{"access_token":"abc","token_type":"{token_type}"}}"#);
        let (addr, _) = serve(StatusCode::OK, &[JSON], &body).await;
        assert_eq!(
            ask(addr).await.unwrap().access_token.as_str(),
            "abc",
            "{token_type}"
        );
    }
}

/// RFC 6749 §5.1's example token type `example`, and any other type, is not a Bearer token (RFC
/// 6750 §4): the client refuses what it cannot use as one.
#[tokio::test]
async fn a_token_type_other_than_bearer_is_refused() {
    for token_type in ["example", "mac", "Bearer2", ""] {
        let body = format!(r#"{{"access_token":"abc","token_type":"{token_type}"}}"#);
        let (addr, _) = serve(StatusCode::OK, &[JSON], &body).await;
        assert!(
            matches!(ask(addr).await, Err(Error::Malformed(_))),
            "{token_type:?}"
        );
    }
}

/// RFC 6749 §5.1: a successful response has an `access_token` and a `token_type`; anything that is
/// not that JSON object is a malformed response, not a token.
#[tokio::test]
async fn a_malformed_success_response_is_an_error() {
    for body in [
        "",
        "not json",
        "[]",
        "{}",
        r#"{"token_type":"Bearer"}"#,
        r#"{"access_token":"abc"}"#,
        r#"{"access_token":"","token_type":"Bearer"}"#,
        r#"{"access_token":5,"token_type":"Bearer"}"#,
        r#"{"access_token":"abc","token_type":"Bearer","expires_in":"3600"}"#,
        r#"{"access_token":"abc","token_type":"Bearer","expires_in":-1}"#,
    ] {
        let (addr, _) = serve(StatusCode::OK, &[JSON], body).await;
        assert!(
            matches!(ask(addr).await, Err(Error::Malformed(_))),
            "{body:?}"
        );
    }
}

/// A response is read up to a bound; one over it is no token response.
#[tokio::test]
async fn an_oversized_response_is_refused() {
    let mut body = br#"{"access_token":"abc","token_type":"Bearer","pad":""#.to_vec();
    body.extend(std::iter::repeat_n(b'a', 70 * 1024));
    body.extend_from_slice(br#""}"#);
    let (addr, _) = serve_bytes(StatusCode::OK, &[JSON], body).await;
    assert!(matches!(ask(addr).await, Err(Error::Malformed(_))));
}

/// RFC 6749 §5.2: the example error response, `400` with `{"error":"invalid_request"}`, is
/// reported with its status and code and without a challenge.
#[tokio::test]
async fn the_rfc_error_response_is_mapped() {
    let (addr, _) = serve(
        StatusCode::BAD_REQUEST,
        &[JSON, NO_STORE, NO_CACHE],
        "{\n  \"error\":\"invalid_request\"\n}",
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::BAD_REQUEST);
    assert_eq!(rejection.error.as_deref(), Some("invalid_request"));
    assert!(rejection.challenges.is_empty());
}

/// RFC 6749 §5.2: `401 invalid_client` with `WWW-Authenticate: Basic realm="token"` is
/// reported with the parsed challenge.
#[tokio::test]
async fn an_invalid_client_response_carries_its_basic_challenge() {
    let (addr, _) = serve(
        StatusCode::UNAUTHORIZED,
        &[JSON, ("www-authenticate", "Basic realm=\"token\"")],
        r#"{"error":"invalid_client"}"#,
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.status, StatusCode::UNAUTHORIZED);
    assert_eq!(rejection.error.as_deref(), Some("invalid_client"));
    let [challenge] = rejection.challenges.as_slice() else {
        panic!("{rejection:?}")
    };
    assert!(!challenge.is_bearer());
    assert_eq!(challenge.scheme, "Basic");
    assert_eq!(challenge.param("realm"), Some("token"));
}

/// RFC 6750 §3: a Bearer challenge's `error` is reachable from the rejection, which is how a caller
/// tells `invalid_token` from a bare challenge.
#[tokio::test]
async fn a_bearer_challenge_is_parsed() {
    let (addr, _) = serve(
        StatusCode::UNAUTHORIZED,
        &[("www-authenticate", "Bearer error=\"invalid_token\"")],
        "",
    )
    .await;
    let rejection = rejected(ask(addr).await);
    assert_eq!(rejection.error, None);
    assert!(rejection.challenges[0].is_bearer());
    assert_eq!(rejection.challenges[0].error(), Some("invalid_token"));
}

/// RFC 6749 §5.2 allows `error` codes the client does not know, and a server may answer with no
/// JSON at all: the status is still reported, the code is absent.
#[tokio::test]
async fn an_error_without_a_json_code_is_still_reported() {
    for (status, body) in [
        (StatusCode::INTERNAL_SERVER_ERROR, "boom"),
        (StatusCode::BAD_GATEWAY, ""),
        (StatusCode::BAD_REQUEST, r#"{"message":"x"}"#),
        (StatusCode::BAD_REQUEST, r#"{"error":5}"#),
    ] {
        let (addr, _) = serve(status, &[], body).await;
        let rejection = rejected(ask(addr).await);
        assert_eq!(rejection.status, status);
        assert_eq!(rejection.error, None, "{body:?}");
    }
    let (addr, _) = serve(
        StatusCode::BAD_REQUEST,
        &[JSON],
        r#"{"error":"something_new"}"#,
    )
    .await;
    assert_eq!(
        rejected(ask(addr).await).error.as_deref(),
        Some("something_new")
    );
}

/// RFC 6749 §5.1: only `200` is a token response; another success status, and a redirect that the
/// caller's client does not follow, are rejections, and the redirect is not chased.
#[tokio::test]
async fn only_200_is_a_token_response_and_redirects_are_not_followed() {
    let (addr, _) = serve(StatusCode::CREATED, &[JSON], RFC_5_1_BEARER).await;
    assert_eq!(rejected(ask(addr).await).status, StatusCode::CREATED);

    let (addr, stub) = serve(StatusCode::FOUND, &[("location", "/elsewhere")], "").await;
    assert_eq!(rejected(ask(addr).await).status, StatusCode::FOUND);
    assert_eq!(stub.received.lock().unwrap().len(), 1);
}

/// A request that cannot be made is a transport error, distinct from a rejection or a malformed
/// response.
#[tokio::test]
async fn a_refused_connection_is_a_transport_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert!(matches!(ask(addr).await, Err(Error::Transport(_))));
}

/// The token is held in `Zeroizing`, whose `Debug` shows no content.
#[tokio::test]
async fn the_token_is_not_printed() {
    let (addr, _) = serve(StatusCode::OK, &[JSON], RFC_5_1_BEARER).await;
    let token = ask(addr).await.unwrap();
    assert!(!format!("{token:?}").contains("test-token"));
}
