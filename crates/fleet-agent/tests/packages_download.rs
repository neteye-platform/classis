//! The artifact download (ADR-0026, ADR-0033): a Server cannot make the Client fill its staging
//! filesystem before the content hash — which comes only after the whole stream lands — can reject
//! the body. The cap is enforced both from an over-large `Content-Length` up front and, for a
//! chunked response that advertises none, while the bytes stream in. And the download goes to this
//! Client's own Server origin and nowhere else (ADR-0033 clause 13).

use std::net::SocketAddr;

use axum::body::Body;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;
use fleet_agent::config::ClientConfig;
use fleet_agent::packages::{download_and_verify, Progress};
use fleet_agent::supervisor::agent::PackageDownload;
use futures_util::stream;

/// A server with the responses the download tests need.
///
/// The listener is bound first so the routes can name the address they redirect to: the
/// cross-origin case needs a second origin on the same process, and `127.0.0.1` versus `[::1]` is
/// one — one port, a different host in the URL, which is exactly what the origin rule compares.
/// Both are loopback literals, the one place a download may be plaintext (ADR-0026). The Client's
/// Server origin is `127.0.0.1`.
async fn spawn() -> SocketAddr {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
    opamp::tls::install_ring_provider();
    // Both loopbacks on one port, as two listeners: a `[::]` socket takes IPv4 too on Linux but
    // not on Windows, where IPV6_V6ONLY is the default.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let listener_v6 = tokio::net::TcpListener::bind(("::1", port))
        .await
        .expect("bind the IPv6 loopback on the same port");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let elsewhere = format!("http://[::1]:{port}/refuses-credentials");
    let app = Router::new()
        // A known-length body: `Content-Length` says up front it is too big.
        .route("/known", get(|| async { vec![0u8; 4096] }))
        // A chunked body: no `Content-Length`, so only the running check can bound it. Eight 1 KiB
        // chunks, streamed, well past a 1 KiB ceiling.
        .route(
            "/chunked",
            get(|| async {
                let chunks = (0..8).map(|_| Ok::<_, std::io::Error>(vec![0u8; 1024]));
                Body::from_stream(stream::iter(chunks))
            }),
        )
        // A redirect within the origin, to where the bytes actually live.
        .route("/redirect", get(|| async { Redirect::to("/artifact") }))
        .route("/artifact", get(|| async { vec![0u8; 4096] }))
        // A route that will not serve the artifact without the header the offer names.
        .route(
            "/guarded",
            get(|headers: axum::http::HeaderMap| async move {
                match headers.get(axum::http::header::AUTHORIZATION) {
                    Some(value) if value == "Bearer artifact-token" => {
                        (axum::http::StatusCode::OK, vec![0u8; 4096])
                    }
                    _ => (axum::http::StatusCode::UNAUTHORIZED, Vec::new()),
                }
            }),
        )
        // A redirect that stays on this origin, to the source that needs the credential.
        .route("/to-guarded", get(|| async { Redirect::to("/guarded") }))
        // A redirect that bounces the download to a *different* origin — the harvesting shape.
        .route("/leaks", get(|| async move { Redirect::to(&elsewhere) }))
        // The other origin, which refuses anything carrying someone else's credential: a request
        // that reached it with the header would show up as a `401`.
        .route(
            "/refuses-credentials",
            get(|headers: axum::http::HeaderMap| async move {
                if headers.contains_key("x-api-key") {
                    (axum::http::StatusCode::UNAUTHORIZED, Vec::new())
                } else {
                    (axum::http::StatusCode::OK, vec![0u8; 4096])
                }
            }),
        );
    let app_v6 = app.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    tokio::spawn(async move {
        axum::serve(listener_v6, app_v6).await.expect("serve");
    });
    addr
}

/// A Client whose Server origin is `addr`, holding a verification key. The key never verifies
/// anything here: every test stops at the size ceiling, the hash, or a refusal before it.
fn small_cap_config(max_artifact_size_bytes: u64, addr: SocketAddr) -> ClientConfig {
    ClientConfig {
        endpoint: format!("ws://{addr}/v1/opamp"),
        max_artifact_size_bytes,
        packages: Some(fleet_agent::config::PackagesConfig {
            verification_key: Some(hex::encode([7u8; 32])),
            ..Default::default()
        }),
        package_key: Some(vec![7u8; 32]),
        ..ClientConfig::default()
    }
}

fn download(url: String) -> PackageDownload {
    PackageDownload {
        name: "otelcol".to_string(),
        version: "1.0.0".to_string(),
        hash: b"pkg".to_vec(),
        download_url: url,
        // Never reached: the size ceiling refuses the body before any hash is computed.
        content_hash: vec![0u8; 32],
        // Present, so the offer passes the policy that refuses an unsigned one before any byte.
        signature: vec![1u8; 64],
        headers: Vec::new(),
    }
}

/// The same download, carrying the headers the offer named.
fn download_with(url: String, headers: &[(&str, &str)]) -> PackageDownload {
    PackageDownload {
        headers: headers
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        ..download(url)
    }
}

/// A body whose `Content-Length` already exceeds the ceiling is refused before a byte is written,
/// and nothing is left staged.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_body_too_large_by_its_content_length_is_refused() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");
    let config = small_cap_config(1024, addr);

    let err = download_and_verify(
        &download(format!("http://{addr}/known")),
        &config,
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("an over-large artifact must be refused");
    assert!(err.contains("max_artifact_size_bytes"), "got {err}");
    assert!(
        !staging.path().join("otelcol.staged").exists(),
        "the staged file is cleaned up on refusal"
    );
}

/// A chunked body that advertises no length is stopped the moment the stream crosses the ceiling —
/// the case an attacker would use to dodge the up-front check.
/// Verifies: ADR-0026
#[tokio::test]
async fn a_chunked_body_is_stopped_once_it_crosses_the_ceiling() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");
    let config = small_cap_config(1024, addr);

    let err = download_and_verify(
        &download(format!("http://{addr}/chunked")),
        &config,
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("a streaming body past the ceiling must be refused");
    assert!(err.contains("max_artifact_size_bytes"), "got {err}");
    assert!(!staging.path().join("otelcol.staged").exists());
}

/// The ceiling does not get in the way of an ordinary artifact that fits under it.
#[tokio::test]
async fn a_body_within_the_ceiling_streams_through_to_verification() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");
    // A 4 KiB known body under an 8 KiB ceiling reaches the hash check — which then fails on the
    // deliberately wrong content_hash, proving the size gate let it past.
    let config = small_cap_config(8192, addr);

    let err = download_and_verify(
        &download(format!("http://{addr}/known")),
        &config,
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("the wrong content hash still fails, but past the size gate");
    assert!(
        !err.contains("max_artifact_size_bytes"),
        "a body under the ceiling must not be refused for size: {err}"
    );
}

/// A redirect that stays on the Server's origin is followed (ADR-0033 clause 13). Reaching the
/// artifact (and then failing only on the deliberately wrong content hash) proves the redirect was
/// followed, not refused.
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn a_download_follows_a_redirect_within_the_servers_origin() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download(format!("http://{addr}/redirect")),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("the wrong content hash still fails — but only after following the redirect");
    assert!(
        err.contains("content hash"),
        "the redirect was followed to the artifact and streamed: {err}"
    );
}

/// The Baseline: *"The Agent SHOULD include the HTTP headers provided in the headers field for the
/// GET request."* They go to the Server's own origin, the only place a download goes (ADR-0033).
/// Reaching the content-hash check (which then fails on the deliberately wrong hash) is what proves
/// the header travelled; without it the same call fails with `401 Unauthorized`.
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn a_download_carries_the_headers_the_offer_named() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download_with(
            format!("http://{addr}/guarded"),
            &[("Authorization", "Bearer artifact-token")],
        ),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("the wrong content hash still fails — but only after the source served the bytes");
    assert!(
        err.contains("content hash"),
        "the credential reached the source and the artifact streamed: {err}"
    );
}

/// And without them the same route refuses — the guard is real, not a route that always answers.
#[tokio::test]
async fn a_download_without_the_headers_is_refused_by_a_guarded_source() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download(format!("http://{addr}/guarded")),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("a guarded source refuses an unauthenticated download");
    assert!(err.contains("401"), "got {err}");
}

/// A redirect to another origin is refused before that origin is asked, so neither the offered
/// header nor anything else reaches it: the download fails naming the origin it pointed at
/// (ADR-0033 clause 13). The other origin here refuses anything carrying the header, so a leak
/// would surface as `401` rather than as this refusal.
/// Verifies: ADR-0026, ADR-0033
#[tokio::test]
async fn a_redirect_to_another_origin_is_refused_and_carries_no_header_there() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download_with(
            format!("http://{addr}/leaks"),
            &[("x-api-key", "operator-secret")],
        ),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("the hop off the origin is refused");
    assert!(
        err.contains("[::1]") && err.contains("own Server origin"),
        "the refusal names the origin it pointed at: {err}"
    );
    // The refusal is the one made before any request, not an answer the other origin gave: a `401`
    // from it would read differently. (A plain "no 401 in the text" test is no test here — the
    // random port of the origin may itself contain those digits.)
    assert!(
        err.starts_with("refusing a download from"),
        "nothing reached the other origin: {err}"
    );
}

/// Following the chain by hand must not break an ordinary redirect: a same-origin one still carries
/// the header, because that is the origin it was given for.
#[tokio::test]
async fn an_offered_header_survives_a_redirect_within_the_same_origin() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download_with(
            format!("http://{addr}/to-guarded"),
            &[("Authorization", "Bearer artifact-token")],
        ),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("the wrong content hash still fails — but only after the guarded source served");
    assert!(
        err.contains("content hash"),
        "a same-origin redirect keeps the credential: {err}"
    );
}

/// A header the offer names that is not a valid HTTP header fails the download loudly rather than
/// being skipped, and the message names the key without its value.
/// Verifies: ADR-0026
#[tokio::test]
async fn an_unusable_offered_header_fails_the_download_by_name() {
    let addr = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");

    let err = download_and_verify(
        &download_with(
            format!("http://{addr}/known"),
            &[("no good", "super-secret-value")],
        ),
        &small_cap_config(8192, addr),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("an unusable header is refused rather than dropped");
    assert!(err.contains("no good"), "the key is named: {err}");
    assert!(
        !err.contains("super-secret-value"),
        "the value must never appear: {err}"
    );
}

/// The staging directory is kept owner-only, so the verified artifact cannot be swapped for another
/// between the hash check and the installer re-opening it (TOCTOU). It starts deliberately wide here
/// and must be narrowed; the hardening happens before a byte is written, so even a failing download
/// leaves it owner-only.
/// Verifies: ADR-0026
#[cfg(unix)]
#[tokio::test]
async fn the_staging_directory_is_kept_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let addr = spawn().await;
    let scratch = tempfile::tempdir().expect("tempdir");
    let staging = scratch.path().join("packages");
    std::fs::create_dir_all(&staging).expect("mkdir");
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).expect("widen");

    // Fails on the deliberately wrong content hash — the directory is hardened regardless.
    let _ = download_and_verify(
        &download(format!("http://{addr}/known")),
        &small_cap_config(8192, addr),
        &staging,
        &Progress::default(),
    )
    .await;

    let mode = std::fs::metadata(&staging)
        .expect("metadata")
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o700,
        "the staging directory must be owner-only"
    );
}

/// An origin that counts the requests it receives, so a test can show that none was sent.
async fn counted_source() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    opamp::tls::install_ring_provider();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new().route(
        "/artifact",
        get(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { vec![0u8; 16] }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    (addr, hits)
}

/// An absolute `download_url` on another origin than the Client's own Server is refused before a
/// request is sent, naming that origin: the check is on the absence of the request, not on the
/// outcome of the download (ADR-0033 clause 13).
/// Verifies: ADR-0033
#[tokio::test]
async fn an_absolute_url_on_another_origin_is_refused_without_a_request() {
    let (elsewhere, hits) = counted_source().await;
    // The Server origin: the test origins of `spawn`, not this one.
    let server = spawn().await;
    let staging = tempfile::tempdir().expect("tempdir");
    let err = download_and_verify(
        &download(format!("http://{elsewhere}/artifact")),
        &small_cap_config(8192, server),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("another origin is refused");
    assert!(
        err.contains(&format!("http://{elsewhere}")) && err.contains("own Server origin"),
        "got {err}"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a request reached the other origin"
    );
}

/// There is no unsigned posture: an offer carrying no signature, and any offer to a Client holding
/// no verification key, is refused before a request reaches the source, naming what is missing.
/// Verifies: ADR-0026, ADR-0018
#[tokio::test]
async fn an_unsigned_offer_or_an_unkeyed_client_fetches_nothing() {
    let (source, hits) = counted_source().await;
    let staging = tempfile::tempdir().expect("tempdir");
    let url = format!("http://{source}/artifact");

    let unsigned = PackageDownload {
        signature: Vec::new(),
        ..download(url.clone())
    };
    let err = download_and_verify(
        &unsigned,
        &small_cap_config(8192, source),
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("an unsigned offer is refused");
    assert!(err.contains("no signature"), "got {err}");

    let mut unkeyed = small_cap_config(8192, source);
    unkeyed.package_key = None;
    if let Some(packages) = unkeyed.packages.as_mut() {
        packages.verification_key = None;
    }
    let err = download_and_verify(
        &download(url),
        &unkeyed,
        staging.path(),
        &Progress::default(),
    )
    .await
    .expect_err("a Client without a key takes no package");
    assert!(err.contains("verification_key"), "got {err}");

    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a request reached the source"
    );
}

/// One HTTPS origin on its own port that asks for a client certificate without requiring one, and
/// records whether the download presented one. `/artifact` serves bytes; `/redirect` sends the
/// download on to `next`.
async fn tls_origin(
    pki: &(rcgen::Issuer<'static, rcgen::KeyPair>, String),
    next: Option<String>,
) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use axum::Extension;
    use opamp::server::listen::{ClientAuth, Listener, PeerCertificate, ServerTls};
    let key = rcgen::KeyPair::generate().expect("key");
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("params")
        .signed_by(&key, &pki.0)
        .expect("signed");
    let config = ServerTls {
        identity: opamp::tls::Identity {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
        },
        client_auth: ClientAuth::Optional {
            ca_pem: pki.1.clone().into_bytes(),
        },
    }
    .rustls_config()
    .expect("tls");
    let presented = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = presented.clone();
    let record = move |Extension(peer): Extension<PeerCertificate>| {
        let seen = seen.clone();
        async move {
            if peer.present() {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    };
    let mut app = Router::new().route(
        "/artifact",
        get({
            let record = record.clone();
            move |peer| async move {
                record(peer).await;
                vec![0u8; 64]
            }
        }),
    );
    if let Some(next) = next {
        app = app.route(
            "/redirect",
            get(move |peer| async move {
                record(peer).await;
                Redirect::to(&next)
            }),
        );
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(
        Listener::new(listener, opamp::server::listen::Handle::new())
            .with_tls(config)
            .serve(app),
    );
    (addr, presented)
}

/// This Client's certificate goes to its own Server's origin and to no other: the download from it
/// presents the certificate, and a redirect to another host is refused before that host is reached
/// (ADR-0033 clause 13).
/// Verifies: ADR-0021, ADR-0026, ADR-0033
#[tokio::test]
async fn the_client_certificate_goes_to_the_servers_origin_alone() {
    opamp::tls::install_ring_provider();
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["download test CA".to_string()]).expect("params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let ca_pem = ca.pem();
    let pki = (
        rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).expect("issuer"),
        ca_pem.clone(),
    );

    let (mirror, mirror_saw) = tls_origin(&pki, None).await;
    let (server, server_saw) = tls_origin(&pki, Some(format!("https://{mirror}/artifact"))).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let client_key = rcgen::KeyPair::generate().expect("client key");
    let client_cert = rcgen::CertificateParams::new(vec!["edge-01".to_string()])
        .expect("params")
        .signed_by(&client_key, &pki.0)
        .expect("signed");
    for (name, pem) in [
        ("ca.pem", ca_pem),
        ("client.pem", client_cert.pem()),
        ("client-key.pem", client_key.serialize_pem()),
    ] {
        std::fs::write(dir.path().join(name), pem).expect("write");
    }
    let config = ClientConfig {
        endpoint: format!("wss://{server}/v1/opamp"),
        tls: Some(fleet_agent::config::TlsConfig {
            ca_file: Some(dir.path().join("ca.pem")),
            cert_file: Some(dir.path().join("client.pem")),
            key_file: Some(dir.path().join("client-key.pem")),
        }),
        packages: Some(fleet_agent::config::PackagesConfig {
            verification_key: Some(hex::encode([7u8; 32])),
            ..Default::default()
        }),
        package_key: Some(vec![7u8; 32]),
        state_dir: dir.path().join("state"),
        ..ClientConfig::default()
    };

    let err = download_and_verify(
        &download(format!("https://{server}/artifact")),
        &config,
        &dir.path().join("staging"),
        &Progress::default(),
    )
    .await
    .expect_err("the hash of the test bytes does not match");
    assert!(err.contains("hash"), "the bytes arrived: {err}");
    assert!(
        server_saw.load(std::sync::atomic::Ordering::SeqCst),
        "the Server's origin is shown the certificate"
    );

    let err = download_and_verify(
        &download(format!("https://{server}/redirect")),
        &config,
        &dir.path().join("staging"),
        &Progress::default(),
    )
    .await
    .expect_err("the redirect off the origin is refused");
    assert!(err.contains(&mirror.to_string()), "{err}");
    assert!(
        !mirror_saw.load(std::sync::atomic::Ordering::SeqCst),
        "the mirror was shown the Client's certificate"
    );
}
