//! Server-offered packages (ADR-0026): resolving a download URL, downloading the artifact from this
//! Client's own Server origin over TLS 1.3 (ADR-0033), and **verifying it before it is applied** —
//! the content hash and the Ed25519 signature, both always. What protects an installed binary is
//! verification; what the origin rule protects is what a download exposes — the offered headers and
//! this Client's certificate — and that a host never reaches past its Server for software.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use opamp::proto::PackageDownloadDetails;
use sha2::{Digest, Sha256};
use tracing::{info, Instrument as _};

use crate::config::ClientConfig;
use crate::supervisor::agent::PackageDownload;

/// Resolves an offered `download_url` to an absolute URL. An absolute `http(s)://` URL is used as
/// given — and then held to [`ServerOrigin::permit`]; a path (the Server's zero-config default) is
/// resolved against the Client's own OpAMP endpoint host, `ws(s)://` mapped to `http(s)://`.
pub fn resolve_url(download_url: &str, endpoint: &str) -> Result<String, String> {
    if download_url.starts_with("http://") || download_url.starts_with("https://") {
        return Ok(download_url.to_string());
    }
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| format!("cannot resolve {download_url} against endpoint {endpoint}"))?;
    let http_scheme = match scheme {
        "ws" | "http" => "http",
        "wss" | "https" => "https",
        other => return Err(format!("unexpected endpoint scheme {other}")),
    };
    let host_port = rest.split(['/', '?']).next().unwrap_or("");
    let path = if download_url.starts_with('/') {
        download_url.to_string()
    } else {
        format!("/{download_url}")
    };
    Ok(format!("{http_scheme}://{host_port}{path}"))
}

/// Refuses an offered package name that is not a safe file-name token, before it is ever joined
/// into the staging path. The Server validates a package name to letters, digits, `.`, `_`, `+`,
/// and `-` (`validate_identity_token`) before it stores one, so a name outside that set is not a
/// package the Server would legitimately offer — it is a malicious or non-conforming peer steering
/// the staged file out of this Agent's own directory: a `/`, a `\`, or a lone `..` in the name
/// would make `staging_dir.join(format!("{name}.staged"))` land somewhere else, with bytes the
/// offering peer controls and *before* verification. Refused rather than sanitized: rewriting a bad
/// name could collide two distinct packages onto one staged file, and a name this shape is a signal
/// something is wrong, not a typo to paper over.
fn ensure_safe_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(format!(
            "the package name must be 1–64 characters, not {name:?}"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(format!(
            "the package name {name:?} may hold only letters, digits, '.', '_', '+', and '-'"
        ));
    }
    Ok(())
}

/// Downloads the artifact to a file and verifies it (ADR-0026). Returns the path of the verified
/// artifact, ready for the Supervisor to swap over the Managed Process's binary.
///
/// The artifact is a program — tens or hundreds of megabytes — so it is streamed to `staging_dir`
/// and hashed as it arrives, never assembled in memory or read back: the signature covers the
/// Agent type, the version and that hash, not the bytes themselves. `staging_dir` is the
/// receiving Agent's own (ADR-0017), so the install that follows is a rename inside one
/// filesystem.
/// Verifies: ADR-0026
pub async fn download_and_verify(
    package: &PackageDownload,
    config: &ClientConfig,
    staging_dir: &Path,
    progress: &Progress,
) -> Result<PathBuf, String> {
    download_and_verify_patiently(package, config, staging_dir, progress, Patience::default()).await
}

/// How long a download waits when its own Server origin answers `429` or `503` with
/// `Retry-After` (ADR-0026 clause 49): each wait the `Retry-After`, capped, and the waits of one
/// download together bounded.
#[derive(Debug, Clone, Copy)]
pub struct Patience {
    /// The longest single wait, whatever `Retry-After` asks.
    pub per_wait: std::time::Duration,
    /// The most all waits of one download add up to.
    pub total: std::time::Duration,
}

impl Default for Patience {
    fn default() -> Self {
        Patience {
            per_wait: std::time::Duration::from_secs(60),
            total: std::time::Duration::from_secs(30 * 60),
        }
    }
}

/// [`download_and_verify`] with the waits on `Retry-After` stated — what a test drives short.
///
/// # Errors
/// As [`download_and_verify`].
pub async fn download_and_verify_patiently(
    package: &PackageDownload,
    config: &ClientConfig,
    staging_dir: &Path,
    progress: &Progress,
    patience: Patience,
) -> Result<PathBuf, String> {
    // First, before any URL is resolved or a byte is written: the staged path is built from this
    // name, and a name that could escape the staging directory is refused outright.
    ensure_safe_package_name(&package.name)?;
    // Refused before a byte is fetched: no key, or no signature to check with it (ADR-0026).
    let key = signature_policy(&package.signature, config.package_key())?;
    let url = resolve_url(&package.download_url, &config.endpoint)?;
    let origin = ServerOrigin::new(config)?;
    // Every request goes to this Client's own Server origin (ADR-0033), which is where its
    // certificate belongs: the download route sits behind the Agent plane's handshake.
    let identified = download_client(crate::tls::client_tls(config)?)?;
    // A count, never a key and never a value — and the source without whatever authorises reaching
    // it. This line goes to the log file, and through the bridge to the destination the Server named
    // (ADR-0016), which is the same reason the span below carries the redacted form: a pre-signed
    // URL puts its signature in the query, and a log line is a poor place to keep one.
    let source = source_of(&url);
    info!(package = %package.name, url = %source, headers = package.headers.len(), "downloading package");
    let download = tracing::info_span!("download", source = %source);
    let mut response = send_patiently(&origin, &identified, &url, &package.headers, patience)
        .instrument(download.clone())
        .await?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }

    std::fs::create_dir_all(staging_dir)
        .map_err(|e| format!("cannot create {}: {e}", staging_dir.display()))?;
    // Keep the staging directory owner-only. The artifact is verified here and then re-opened by the
    // installer (`install::write_program`, the Supervisor's swap); if another local user could write
    // into this directory they could swap the file in that window and defeat the hash and signature
    // check it already passed (TOCTOU). Owner-only closes it — the predictable `<name>.staged`
    // filename is then harmless, since no other user can reach the directory to race it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staging_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot restrict {}: {e}", staging_dir.display()))?;
    }
    let path = staging_dir.join(format!("{}.staged", package.name));

    // Stream to disk, hashing on the way past: peak memory is one chunk, whatever the artifact
    // weighs. A failure anywhere leaves no half-written file behind for the next attempt to trip
    // over. The size ceiling stops a Server from filling the staging filesystem with an endless
    // body before the content hash — which comes only after the whole stream lands — can reject it.
    let staged = match write_stream(
        &path,
        &mut response,
        progress,
        config.max_artifact_size_bytes,
    )
    .instrument(download.clone())
    .await
    {
        Ok(hash) => hash,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    };
    // The bytes are in; what remains is deciding whether they are the right ones. Its own phase of
    // the trace (ADR-0016), because the hash and the signature are what a package's security rests
    // on and "it failed to install" must be able to say which of the two.
    drop(download);
    let verify = tracing::info_span!("verify", bytes = staged.len).entered();
    if let Err(e) = verify_staged(&path, &staged, package, key) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    drop(verify);
    info!(package = %package.name, version = %package.version, bytes = staged.len, "package verified");
    Ok(path)
}

/// How many redirects an artifact download will follow.
const MAX_REDIRECTS: usize = 5;

/// A download client over `tls`: TLS 1.3, no redirect of its own — every hop is checked here
/// (`send_download`) — and per-operation timeouts rather than one for the whole transfer, since a
/// large artifact over a modest link legitimately takes minutes.
pub(crate) fn download_client(tls: opamp::client::ClientTls) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(30))
        .read_timeout(std::time::Duration::from_secs(60));
    tls.apply(builder)?
        .build()
        .map_err(|e| format!("cannot build the download client: {e}"))
}

/// Where a download may go (ADR-0033 clause 13): this Client's own Server origin — the scheme, host
/// and port of its OpAMP endpoint, `wss` mapped to `https` (and `ws` to `http`, which the endpoint
/// may only be on the loopback) — and nowhere else. Every URL is held to the transport rule first.
pub struct ServerOrigin {
    server: reqwest::Url,
}

impl ServerOrigin {
    /// # Errors
    /// Returns an error when the endpoint cannot be parsed.
    pub fn new(config: &ClientConfig) -> Result<Self, String> {
        let server = resolve_url("/", &config.endpoint)?;
        let server =
            reqwest::Url::parse(&server).map_err(|e| format!("cannot parse {server}: {e}"))?;
        Ok(ServerOrigin { server })
    }

    fn is_server(&self, url: &reqwest::Url) -> bool {
        same_origin(&self.server, url)
    }

    /// Whether a download may go to `url`, and why not when it may not: the message names the
    /// origin it pointed at, and is what the Client reports `InstallFailed` with.
    fn permit(&self, url: &reqwest::Url) -> Result<(), String> {
        opamp::endpoint::check_url(url.as_str())
            .map_err(|e| format!("refusing {}: {e}", source_of(url.as_str())))?;
        if self.is_server(url) {
            return Ok(());
        }
        Err(format!(
            "refusing a download from {}: a package is fetched only from this Client's own \
             Server origin, {} (ADR-0033)",
            origin_label(url),
            origin_label(&self.server)
        ))
    }
}

/// The scheme, host and port of a URL, for a message.
fn origin_label(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}

/// Sends the download request, walking every redirect by hand.
///
/// Each hop is checked against [`ServerOrigin`] before it is requested, so nothing — not the offer,
/// not a redirect — takes the download to another host or onto plaintext, and nothing is fetched
/// from a refused one. Every hop is therefore the Server's own origin, the one the offered headers
/// and this Client's certificate (the `client`) are for.
pub(crate) async fn send_download(
    origin: &ServerOrigin,
    client: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
) -> Result<reqwest::Response, String> {
    let mut current =
        reqwest::Url::parse(url).map_err(|e| format!("cannot parse {}: {e}", source_of(url)))?;
    for _ in 0..=MAX_REDIRECTS {
        origin.permit(&current)?;
        let request = with_headers(client.get(current.clone()), headers)?;
        let response = request
            .send()
            .await
            .map_err(|e| format!("cannot download {}: {e}", source_of(current.as_str())))?;
        let Some(location) = redirect_target(&response) else {
            return Ok(response);
        };
        current = current.join(&location).map_err(|e| {
            format!(
                "{} redirected to an unusable location: {e}",
                source_of(current.as_str())
            )
        })?;
    }
    Err(format!(
        "{} redirected more than {MAX_REDIRECTS} times",
        source_of(url)
    ))
}

/// [`send_download`], waiting out a `429` or `503` with `Retry-After` in seconds from the Server's
/// own origin — a Gateway behind one, whose cache is still fetching, or the Server's rate limit —
/// within `patience` (ADR-0026 clause 49). Anything else is returned as it came, for the caller to
/// fail on.
pub(crate) async fn send_patiently(
    origin: &ServerOrigin,
    client: &reqwest::Client,
    url: &str,
    headers: &[(String, String)],
    patience: Patience,
) -> Result<reqwest::Response, String> {
    let waits = Waits::new(patience);
    loop {
        let response = send_download(origin, client, url, headers).await?;
        match waits.asked(url, &response)? {
            Some(wait) => tokio::time::sleep(wait).await,
            None => return Ok(response),
        }
    }
}

/// The waits of one download on `Retry-After` (ADR-0026 clause 49): each one at least a second and
/// at most [`Patience::per_wait`], and none begun that would end past the deadline set when the
/// download began — so the requests count against the bound as well as the waits.
pub(crate) struct Waits {
    deadline: tokio::time::Instant,
    per_wait: std::time::Duration,
    total: std::time::Duration,
}

impl Waits {
    pub(crate) fn new(patience: Patience) -> Self {
        Waits {
            deadline: tokio::time::Instant::now() + patience.total,
            per_wait: patience.per_wait,
            total: patience.total,
        }
    }

    /// How long `response` — from the Server's own origin, the only one [`send_download`] reaches
    /// — asks the download to wait before it asks again: `None` when it is not a `429` or `503`
    /// with `Retry-After` in seconds, which the caller takes as it is.
    ///
    /// # Errors
    /// Returns the failure once a wait would end past the deadline.
    pub(crate) fn asked(
        &self,
        url: &str,
        response: &reqwest::Response,
    ) -> Result<Option<std::time::Duration>, String> {
        let status = response.status();
        let busy = status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::SERVICE_UNAVAILABLE;
        if !busy {
            return Ok(None);
        }
        let Some(after) = retry_after(response) else {
            return Ok(None);
        };
        let wait = after
            .max(std::time::Duration::from_secs(1))
            .min(self.per_wait);
        if tokio::time::Instant::now() + wait > self.deadline {
            return Err(format!(
                "{} answered {status} for longer than this Client waits ({} s)",
                source_of(url),
                self.total.as_secs()
            ));
        }
        info!(url = %source_of(url), %status, wait_secs = wait.as_secs_f64(), "the download is asked to wait");
        Ok(Some(wait))
    }
}

/// A `Retry-After` in seconds; an HTTP date is not used, and neither is anything unreadable.
fn retry_after(response: &reqwest::Response) -> Option<std::time::Duration> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(std::time::Duration::from_secs)
}

/// Attaches the offered headers to a request.
///
/// A header that is not a valid header fails the download loudly rather than being skipped: a
/// silently dropped credential comes back as an opaque `401` that nothing explains. The message
/// names the **key only** — it travels to the Server as `PackageStatuses.error_message` and into
/// the log file, and the value is the secret.
fn with_headers(
    mut request: reqwest::RequestBuilder,
    headers: &[(String, String)],
) -> Result<reqwest::RequestBuilder, String> {
    for (key, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(key.as_bytes()).map_err(|_| {
            format!("the offered download header {key:?} is not a valid header name")
        })?;
        let mut value = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
            format!(
                "the offered download header {key:?} carries a value that is not a valid header"
            )
        })?;
        // As the OpAMP transport marks its own credential (`opamp::client::connection`).
        value.set_sensitive(true);
        request = request.header(name, value);
    }
    Ok(request)
}

/// Where an artifact is being fetched from, without whatever authorises the fetch.
///
/// The span this labels leaves the host for a destination the *Server* named (ADR-0016 clause 23), and
/// a download URL is one of the few strings here that can carry a credential in plain sight: a
/// pre-signed URL puts its signature in the query. The scheme, host and path answer the question a
/// trace is read for — *which artifact was fetched* — and the query answers none of it.
///
/// A URL that will not parse is reported as nothing rather than as itself: the one case where the
/// query cannot be found is the case where it must not be assumed absent.
pub(crate) fn source_of(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "an unparseable url".to_string();
    };
    parsed.set_query(None);
    parsed.set_fragment(None);
    // A username or password in the URL itself is the other place a credential hides.
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.to_string()
}

/// Whether two URLs share an origin: same scheme, host, and port.
fn same_origin(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// The `Location` of a redirect response, or `None` when the response is the artifact itself.
fn redirect_target(response: &reqwest::Response) -> Option<String> {
    if !response.status().is_redirection() {
        return None;
    }
    response
        .headers()
        .get(reqwest::header::LOCATION)?
        .to_str()
        .ok()
        .map(str::to_string)
}

/// What streaming the download to disk produced: its size and its content hash.
struct Staged {
    len: u64,
    content_hash: Vec<u8>,
}

/// How far an artifact download has got, shared with whoever reports it.
///
/// The download is a plain `await` inside the transport loop; this is how that loop learns the
/// progress of the future it is polling without the download having to know anything about
/// reporting. Cheap enough to update per chunk.
#[derive(Debug, Default)]
pub struct Progress {
    /// Bytes written so far.
    downloaded: AtomicU64,
    /// The artifact's total size, from `Content-Length`; `0` when the Server did not say.
    total: AtomicU64,
}

impl Progress {
    /// The Baseline's `PackageDownloadDetails` as of now: how far along, and how fast since
    /// `started`. Percent stays `0` while the total is unknown — a made-up percentage would be
    /// worse than none.
    pub fn details(&self, started: std::time::Instant) -> PackageDownloadDetails {
        let downloaded = self.downloaded.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let seconds = started.elapsed().as_secs_f64();
        PackageDownloadDetails {
            download_percent: if total > 0 {
                (downloaded as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            download_bytes_per_second: if seconds > 0.0 {
                downloaded as f64 / seconds
            } else {
                0.0
            },
        }
    }
}

/// The message for a download that has reached `max_bytes`, or `None` while it is within the
/// ceiling. `max_bytes == 0` is never passed — the loader refuses it (a bound, not a switch).
fn over_cap(len: u64, max_bytes: u64) -> Option<String> {
    (len > max_bytes).then(|| {
        format!("the artifact exceeds the {max_bytes}-byte limit (max_artifact_size_bytes)")
    })
}

async fn write_stream(
    path: &Path,
    response: &mut reqwest::Response,
    progress: &Progress,
    max_bytes: u64,
) -> Result<Staged, String> {
    use tokio::io::AsyncWriteExt;

    // What the Server advertises, so a percentage is possible at all.
    let advertised = response.content_length().unwrap_or(0);
    progress.total.store(advertised, Ordering::Relaxed);
    // Refuse a body that says up front it is too large, before a single byte is written. A lying or
    // absent Content-Length is caught by the running check below instead.
    if let Some(e) = over_cap(advertised, max_bytes) {
        return Err(e);
    }
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("cannot read the download: {e}"))?
    {
        len += chunk.len() as u64;
        // Stop the moment the body crosses the ceiling — a chunked response carries no
        // Content-Length, so this running check is what bounds it at all.
        if let Some(e) = over_cap(len, max_bytes) {
            return Err(e);
        }
        hasher.update(&chunk);
        progress.downloaded.store(len, Ordering::Relaxed);
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    file.flush()
        .await
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(Staged {
        len,
        content_hash: hasher.finalize().to_vec(),
    })
}

/// Verifies the streamed artifact: the content hash from the stream, then the signature over what
/// the offer says the artifact is — its Agent type (the package's name), its version and that
/// hash (ADR-0026). A signed artifact offered as another type's program, or under another version,
/// does not verify.
fn verify_staged(
    _path: &Path,
    staged: &Staged,
    package: &PackageDownload,
    key: &[u8],
) -> Result<(), String> {
    if staged.content_hash != package.content_hash {
        return Err("the downloaded artifact does not match its content hash".to_string());
    }
    let statement =
        fleet_core::package::statement(&package.name, &package.version, &package.content_hash);
    check_signature(&statement, &package.signature, key)
}

/// The signature policy (ADR-0026): there is no unsigned posture. An offer is refused before
/// anything is downloaded when this Client holds no verification key, or when the offer carries no
/// signature to check with it. `Ok` is the key the signature is then checked against.
fn signature_policy<'a>(signature: &[u8], key: Option<&'a [u8]>) -> Result<&'a [u8], String> {
    let Some(key) = key else {
        return Err(
            "refusing the package: [packages] verification_key is not set, and nothing is \
             installed without a signature"
                .to_string(),
        );
    };
    if signature.is_empty() {
        return Err("refusing the package: the offer carries no signature".to_string());
    }
    Ok(key)
}

fn check_signature(bytes: &[u8], signature: &[u8], key: &[u8]) -> Result<(), String> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(bytes, signature)
        .map_err(|_| {
            "the artifact's signature is invalid — it must cover the Agent type, the version and \
             the SHA-256 (opamp-fleetctl package sign --agent-type … --version …)"
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// A loopback server answering each request with the next of `answers` — a status and an
    /// optional `Retry-After` — and `200 the-bytes` once they run out; returns its address and the
    /// count of requests.
    async fn answering(
        answers: Vec<(u16, Option<&'static str>)>,
    ) -> (std::net::SocketAddr, std::sync::Arc<AtomicU64>) {
        let count = std::sync::Arc::new(AtomicU64::new(0));
        let seen = count.clone();
        let answers = std::sync::Arc::new(answers);
        let app = axum::Router::new().route(
            "/file",
            axum::routing::get(move || {
                let (seen, answers) = (seen.clone(), answers.clone());
                async move {
                    use axum::response::IntoResponse as _;
                    let n = seen.fetch_add(1, Ordering::SeqCst) as usize;
                    match answers.get(n) {
                        Some((status, after)) => {
                            let mut response = axum::http::StatusCode::from_u16(*status)
                                .expect("status")
                                .into_response();
                            if let Some(after) = after {
                                response.headers_mut().insert(
                                    axum::http::header::RETRY_AFTER,
                                    axum::http::HeaderValue::from_static(after),
                                );
                            }
                            response
                        }
                        None => "the-bytes".into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        (addr, count)
    }

    fn origin_for(endpoint: &str) -> (ServerOrigin, reqwest::Client) {
        opamp::tls::install_ring_provider();
        let config: ClientConfig =
            toml::from_str(&format!("endpoint = \"{endpoint}\"\n")).expect("config");
        let client = download_client(crate::tls::trust(&config).expect("trust")).expect("client");
        (ServerOrigin::new(&config).expect("origin"), client)
    }

    const SHORT: Patience = Patience {
        per_wait: std::time::Duration::from_millis(10),
        total: std::time::Duration::from_secs(5),
    };

    /// A `503` and a `429` with `Retry-After` from the Client's own Server origin are waited out,
    /// and the download goes on.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_download_waits_out_retry_after_from_its_server_origin() {
        let (server, count) = answering(vec![(503, Some("30")), (429, Some("30"))]).await;
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let response = send_patiently(
            &origin,
            &client,
            &format!("http://{server}/file"),
            &[],
            SHORT,
        )
        .await
        .expect("waited out");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    /// The waits of one download are bounded: a Server origin that keeps answering `503` makes the
    /// download fail once the next wait would pass the bound.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_download_gives_up_once_its_waits_reach_the_bound() {
        let (server, count) = answering(vec![(503, Some("30")); 100]).await;
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let patience = Patience {
            per_wait: std::time::Duration::from_millis(10),
            total: std::time::Duration::from_millis(35),
        };
        let err = send_patiently(
            &origin,
            &client,
            &format!("http://{server}/file"),
            &[],
            patience,
        )
        .await
        .expect_err("gave up");
        assert!(err.contains("longer than this Client waits"), "{err}");
        let requests = count.load(Ordering::SeqCst);
        assert!(
            (2..=4).contains(&requests),
            "at most three waits of 10 ms fit in 35 ms: {requests}"
        );
    }

    /// A `Retry-After: 0` does not make the download ask in a tight loop for ever: the asking ends
    /// at the deadline, after a bounded number of requests.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn a_retry_after_of_zero_does_not_loop_without_bound() {
        let (server, count) = answering(vec![(503, Some("0")); 1000]).await;
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let patience = Patience {
            per_wait: std::time::Duration::from_millis(10),
            total: std::time::Duration::from_millis(100),
        };
        let err = send_patiently(
            &origin,
            &client,
            &format!("http://{server}/file"),
            &[],
            patience,
        )
        .await
        .expect_err("gave up");
        assert!(err.contains("longer than this Client waits"), "{err}");
        let requests = count.load(Ordering::SeqCst);
        assert!((1..=11).contains(&requests), "{requests} requests");
    }

    /// The time the requests take counts against the bound, not only the waits: a slow origin
    /// exhausts it although the waits alone would not.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn request_time_counts_against_the_bound() {
        let count = std::sync::Arc::new(AtomicU64::new(0));
        let seen = count.clone();
        let app = axum::Router::new().route(
            "/file",
            axum::routing::get(move || {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        [(axum::http::header::RETRY_AFTER, "0")],
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let patience = Patience {
            per_wait: std::time::Duration::from_millis(1),
            total: std::time::Duration::from_millis(150),
        };
        let err = send_patiently(
            &origin,
            &client,
            &format!("http://{server}/file"),
            &[],
            patience,
        )
        .await
        .expect_err("gave up");
        assert!(err.contains("longer than this Client waits"), "{err}");
        let requests = count.load(Ordering::SeqCst);
        assert!(
            (2..=3).contains(&requests),
            "{requests} requests in 150 ms of 60 ms each"
        );
    }

    /// A `503` whose `Retry-After` is an HTTP date, missing or unreadable is not waited out.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn an_unusable_retry_after_is_not_waited_out() {
        for after in [Some("Wed, 21 Oct 2015 07:28:00 GMT"), None, Some("soon")] {
            let (server, count) = answering(vec![(503, after)]).await;
            let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
            let response = send_patiently(
                &origin,
                &client,
                &format!("http://{server}/file"),
                &[],
                SHORT,
            )
            .await
            .expect("a response");
            assert_eq!(
                response.status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "{after:?}"
            );
            assert_eq!(count.load(Ordering::SeqCst), 1, "{after:?}");
        }
    }

    /// A redirect off the Server's origin is refused before the host it points at is asked: the
    /// download fails naming that origin, and nothing is fetched from it (ADR-0033 clause 13).
    /// Verifies: ADR-0033
    #[tokio::test]
    async fn a_redirect_off_the_origin_is_refused_without_a_fetch() {
        let (mirror, count) = answering(Vec::new()).await;
        let target = format!("http://{mirror}/file");
        let app = axum::Router::new().route(
            "/file",
            axum::routing::get(move || {
                let target = target.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let err = send_patiently(
            &origin,
            &client,
            &format!("http://{server}/file"),
            &[],
            SHORT,
        )
        .await
        .expect_err("refused");
        assert!(err.contains(&format!("http://{mirror}")), "{err}");
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "the other host is never asked"
        );
    }

    /// An absolute `download_url` on another origin is refused without a byte fetched, and the
    /// refusal names that origin (ADR-0033 clause 13) — whatever the offer's headers would have
    /// carried never leaves the host.
    /// Verifies: ADR-0033
    #[tokio::test]
    async fn an_absolute_url_on_another_origin_is_refused_without_a_fetch() {
        let (other, count) = answering(Vec::new()).await;
        let (server, _) = answering(Vec::new()).await;
        let (origin, client) = origin_for(&format!("ws://{server}/v1/opamp"));
        let err = send_patiently(
            &origin,
            &client,
            &format!("http://{other}/file"),
            &[("Authorization".to_string(), "Bearer t".to_string())],
            SHORT,
        )
        .await
        .expect_err("refused");
        assert!(
            err.contains(&format!("http://{other}")) && err.contains("own Server origin"),
            "{err}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 0, "nothing was fetched");
    }

    /// What labels the download span must not carry what authorises the download: the span goes to
    /// a destination the Server named (ADR-0016 clause 23), and a pre-signed URL is a credential.
    /// Verifies: ADR-0026, ADR-0016
    #[test]
    fn the_download_source_drops_whatever_authorises_it() {
        assert_eq!(
            source_of("https://mirror.example/artifacts/agent.tar.gz?X-Amz-Signature=deadbeef"),
            "https://mirror.example/artifacts/agent.tar.gz"
        );
        assert_eq!(
            source_of("https://user:secret@mirror.example/agent.tar.gz#frag"),
            "https://mirror.example/agent.tar.gz"
        );
        assert_eq!(source_of("not a url"), "an unparseable url");
    }

    #[test]
    fn resolve_url_absolutizes_a_path_against_the_endpoint() {
        assert_eq!(
            resolve_url("/api/v1/packages/otelcol/file", "ws://host:4320/v1/opamp").unwrap(),
            "http://host:4320/api/v1/packages/otelcol/file"
        );
        assert_eq!(
            resolve_url("/api/v1/packages/x/file", "wss://host:4320/v1/opamp").unwrap(),
            "https://host:4320/api/v1/packages/x/file"
        );
        // An absolute URL is used as given.
        assert_eq!(
            resolve_url("https://cdn.example/x.bin", "ws://host/v1/opamp").unwrap(),
            "https://cdn.example/x.bin"
        );
    }

    /// A staged artifact, written where a real download would leave it.
    fn stage(dir: &tempfile::TempDir, bytes: &[u8]) -> (PathBuf, Staged) {
        let path = dir.path().join("otelcol.staged");
        std::fs::write(&path, bytes).expect("write");
        (
            path,
            Staged {
                len: bytes.len() as u64,
                content_hash: Sha256::digest(bytes).to_vec(),
            },
        )
    }

    fn offer(content_hash: Vec<u8>, signature: Vec<u8>) -> PackageDownload {
        PackageDownload {
            name: "otelcol".to_string(),
            version: "1.0.0".to_string(),
            hash: b"pkg".to_vec(),
            download_url: "/x".to_string(),
            content_hash,
            signature,
            headers: Vec::new(),
        }
    }

    /// A header value is a credential, and this struct travels inside a `Debug`-deriving type that
    /// a log line could one day print. The key is diagnosable, the value never appears.
    /// Verifies: ADR-0026
    #[test]
    fn a_download_never_debug_prints_its_header_values() {
        let mut package = offer(vec![0u8; 32], Vec::new());
        package.headers = vec![(
            "Authorization".to_string(),
            "Bearer super-secret-value".to_string(),
        )];

        let printed = format!("{package:?}");
        assert!(
            printed.contains("Authorization"),
            "the key stays diagnosable: {printed}"
        );
        assert!(
            !printed.contains("super-secret-value"),
            "the value must never be printed: {printed}"
        );
    }

    /// Only a redirect that stays on the same scheme, host and port may carry the offered headers.
    #[test]
    fn same_origin_compares_scheme_host_and_port() {
        let parse = |url: &str| reqwest::Url::parse(url).expect("url");
        let source = parse("https://mirror.example/artifact.tar.gz");

        assert!(same_origin(&source, &parse("https://mirror.example/else")));
        // The default port is the same port.
        assert!(same_origin(&source, &parse("https://mirror.example:443/x")));
        // A different host, port, or scheme is somewhere else.
        assert!(!same_origin(&source, &parse("https://cdn.example/x")));
        assert!(!same_origin(
            &source,
            &parse("https://mirror.example:8443/x")
        ));
        assert!(!same_origin(&source, &parse("http://mirror.example/x")));
    }

    /// A package name is a file-name token, not a path: the safe set mirrors what the Server
    /// validates before it stores one, and anything that could steer the staged file elsewhere —
    /// a separator, a lone `..`, an empty or over-long name — is refused.
    /// Verifies: ADR-0026
    #[test]
    fn a_traversing_package_name_is_refused() {
        assert!(ensure_safe_package_name("otelcol").is_ok());
        assert!(ensure_safe_package_name("otelcol-contrib_1.2.3+build").is_ok());

        for bad in [
            "",
            "../../../../etc/cron.d/x",
            "a/b",
            "a\\b",
            "with space",
            "nul\0byte",
        ] {
            assert!(
                ensure_safe_package_name(bad).is_err(),
                "expected {bad:?} to be refused"
            );
        }
        assert!(
            ensure_safe_package_name(&"x".repeat(65)).is_err(),
            "too long"
        );
        // A lone `..` is within the mirrored charset (only '.' bytes) and cannot traverse: the
        // staged name always gets a `.staged` suffix, so it joins as `...staged`, an ordinary file
        // inside the staging directory — not the parent. A separator is what escapes, and that is
        // refused above.
        assert!(ensure_safe_package_name("..").is_ok());
    }

    /// End to end at the sink: a traversing name is refused by `download_and_verify` before any URL
    /// is resolved or a byte is written, so nothing lands outside the staging directory — and the
    /// error is the one the caller reports as a failed package status.
    /// Verifies: ADR-0026
    #[tokio::test]
    async fn download_refuses_to_stage_a_traversing_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).expect("staging dir");
        let escape_target = dir.path().join("x.staged"); // where `../x` would land

        let config: ClientConfig = toml::from_str("").expect("config");
        let mut package = offer(Sha256::digest(b"x").to_vec(), Vec::new());
        package.name = "../x".to_string();

        let err = download_and_verify(&package, &config, &staging, &Progress::default())
            .await
            .expect_err("a traversing name is refused");
        assert!(err.contains("package name"), "got {err}");
        assert!(
            !escape_target.exists(),
            "nothing was written outside the staging directory"
        );
        assert!(
            std::fs::read_dir(&staging)
                .expect("read staging")
                .next()
                .is_none(),
            "nothing was staged"
        );
    }

    /// Verifies: ADR-0026
    #[test]
    fn the_cap_triggers_only_past_the_limit() {
        assert!(over_cap(1000, 1024).is_none(), "within the ceiling is fine");
        assert!(
            over_cap(1024, 1024).is_none(),
            "exactly at the ceiling is fine"
        );
        let err = over_cap(1025, 1024).expect("past the ceiling is refused");
        assert!(err.contains("max_artifact_size_bytes"), "got {err}");
    }

    fn keypair() -> (ring::signature::Ed25519KeyPair, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair");
        let public = keypair.public_key().as_ref().to_vec();
        (keypair, public)
    }

    /// Verifies: ADR-0026
    #[test]
    fn content_hash_mismatch_is_refused() {
        let (keypair, public) = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, staged) = stage(&dir, b"artifact");
        let signature = keypair
            .sign(&fleet_core::package::statement(
                "otelcol",
                "1.0.0",
                &staged.content_hash,
            ))
            .as_ref()
            .to_vec();

        let wrong = offer(Sha256::digest(b"other").to_vec(), signature.clone());
        assert!(verify_staged(&path, &staged, &wrong, &public).is_err());

        let right = offer(staged.content_hash.clone(), signature);
        assert!(verify_staged(&path, &staged, &right, &public).is_ok());
    }

    /// There is no unsigned posture: no key, or no signature, is refused before anything is
    /// downloaded, and a signature that does not verify refuses the artifact. The Client's own
    /// update takes the same path.
    /// Verifies: ADR-0026, ADR-0018
    #[test]
    fn signature_policy_is_enforced() {
        let (keypair, public) = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = b"the-binary";
        let (path, staged) = stage(&dir, bytes);
        let hash = staged.content_hash.clone();
        let signature = keypair
            .sign(&fleet_core::package::statement("otelcol", "1.0.0", &hash))
            .as_ref()
            .to_vec();

        // Before the download: a key and a signature, or nothing at all.
        assert!(signature_policy(&signature, None).is_err(), "no key");
        assert!(
            signature_policy(&[], Some(&public)).is_err(),
            "no signature"
        );
        assert!(signature_policy(&[], None).is_err(), "neither");
        assert_eq!(
            signature_policy(&signature, Some(&public)),
            Ok(public.as_slice())
        );

        // After it: the signature must verify against the key.
        let check = |signature: Vec<u8>| {
            verify_staged(&path, &staged, &offer(hash.clone(), signature), &public)
        };
        assert!(check(signature.clone()).is_ok());
        let mut bad = signature;
        bad[0] ^= 0xff;
        assert!(check(bad).is_err());
    }

    /// The signature covers which Agent type the artifact is for and at which version: the same
    /// signed bytes offered as another type's program, or under another version, are refused.
    /// Verifies: ADR-0026
    #[test]
    fn a_signature_does_not_carry_over_to_another_type_or_version() {
        let (keypair, public) = keypair();
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, staged) = stage(&dir, b"the-binary");
        let hash = staged.content_hash.clone();
        let signature = keypair
            .sign(&fleet_core::package::statement("otelcol", "1.0.0", &hash))
            .as_ref()
            .to_vec();
        let mut other_type = offer(hash.clone(), signature.clone());
        other_type.name = "telegraf".to_string();
        assert!(verify_staged(&path, &staged, &other_type, &public).is_err());
        let mut other_version = offer(hash.clone(), signature.clone());
        other_version.version = "0.9.0".to_string();
        assert!(verify_staged(&path, &staged, &other_version, &public).is_err());
        let bare = keypair.sign(b"the-binary").as_ref().to_vec();
        assert!(
            verify_staged(&path, &staged, &offer(hash, bare), &public).is_err(),
            "a signature over the bytes alone no longer verifies"
        );
    }

    /// A download goes to the Server's own origin and nowhere else — not another port, not
    /// plaintext, not another host (ADR-0033 clause 13).
    /// Verifies: ADR-0033
    #[test]
    fn a_download_goes_only_to_the_servers_own_origin() {
        let config = ClientConfig {
            endpoint: "wss://fleet.example:4320/v1/opamp".to_string(),
            ..ClientConfig::default()
        };
        let origin = ServerOrigin::new(&config).expect("origin");
        let url = |u: &str| reqwest::Url::parse(u).expect("url");
        assert_eq!(
            origin.permit(&url(
                "https://fleet.example:4320/api/v1/packages/x/1/file?os=linux"
            )),
            Ok(())
        );
        for refused in [
            "https://fleet.example:4321/api/v1/packages/x/1/file",
            "http://fleet.example:4320/api/v1/packages/x/1/file",
            "https://mirror.example/releases/agent.tar.gz",
            "https://evil.example:4320/api/v1/packages/x/1/file",
        ] {
            assert!(origin.permit(&url(refused)).is_err(), "{refused}");
        }
    }
}
