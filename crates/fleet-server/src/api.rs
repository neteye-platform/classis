//! The REST API v1 — the Server's integration contract (ADR-0010, ADR-0023) — and the bundled
//! rudimentary UI. Both belong to the Operator plane and are served on its own listener
//! (ADR-0013); the one exception, the Agent-facing artifact download, is [`download_router`].
//!
//! The OpenAPI document is generated code-first with `utoipa`: the same annotations that register
//! a route describe it, so contract and behaviour cannot drift. Any external portal generates a
//! client from `/api/v1/openapi.json`; the UI is a client of the same routes and nothing more.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use opamp::uid::InstanceUid;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::router::{OpenApiRouter, UtoipaMethodRouterExt};
use utoipa_axum::routes;

use crate::config::RestAuthConfig;
use crate::configs::{self, Configuration, Revision};
use crate::credentials::Credentials;
use crate::deployments::{Deployment, DeploymentError, DeploymentStore};
use crate::fleet::{self, AppState, DeleteError, ForgetError, RestartError, RolloutError};
use crate::labels::LabelError;
use crate::packages::{PackageId, PackageSummary, Platform, SignatureState};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "OpAMP Fleet REST API",
        description = "Read fleet state; create, change, and delete Configurations, Packages \
                       and the Deployments that aim and release them. The stable contract any UI \
                       or portal builds on (ADR-0023, ADR-0034)."
    ),
    tags(
        (name = "fleet", description = "The fleet as the Server sees it"),
        (name = "configurations", description = "Configurations: content an Agent type runs, \
                                                 released only through a Deployment (ADR-0034)"),
        (name = "packages", description = "Software packages the Server delivers (ADR-0026)"),
        (name = "deployments", description = "What reaches a channel of hosts — Packages and \
                                              Configurations under one Selector, and the only \
                                              thing rolled out (ADR-0026, ADR-0034)"),
        (name = "enrolment", description = "How a host gets its first certificate: a window an \
                                            operator opens, and requests an operator decides \
                                            (ADR-0021)"),
        (name = "revocation", description = "What the client CA signed, and the certificates the \
                                             Server no longer admits (ADR-0021)")
    )
)]
struct ApiDoc;

/// The Operator plane's credential check (ADR-0021), precomputed from `[rest.auth]`. Basic only,
/// and it guards the whole plane — the API, its document, the docs page, and the UI — because a
/// browser answers a Basic challenge by itself, which is what spares the rudimentary UI a login
/// page and a session.
pub struct OperatorAuth(
    Arc<Credentials>,
    Option<Arc<crate::throttle::Throttle>>,
    Option<Arc<dyn crate::audit::Audit>>,
);

impl OperatorAuth {
    /// # Errors
    /// Returns an error naming an entry of `[rest.auth]` that is not a hash this Server keeps.
    pub fn from_config(auth: &RestAuthConfig) -> Result<Self, String> {
        Ok(OperatorAuth(Arc::new(auth.credentials()?), None, None))
    }

    /// Records refused sign-ins in `audit` (ADR-0022 clause 1).
    #[must_use]
    pub fn with_audit(mut self, audit: Option<Arc<dyn crate::audit::Audit>>) -> Self {
        self.2 = audit;
        self
    }

    /// Counts this plane's failures in a table of its own (ADR-0021 clause 24).
    #[must_use]
    pub fn with_throttle(mut self, throttle: Arc<crate::throttle::Throttle>) -> Self {
        self.1 = Some(throttle);
        self
    }
}

/// Records every mutating act on the Operator plane, before it runs and once it has run; an act
/// that cannot be recorded is not run (ADR-0022 clauses 1, 6).
async fn record_act(
    State(audit): State<Arc<dyn crate::audit::Audit>>,
    request: Request,
    next: Next,
) -> Response {
    use crate::audit::Entry;
    let method = request.method().clone();
    if matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return next.run(request).await;
    }
    let peer = crate::transport::peer_ip(&request);
    let operator = basic_user(request.headers());
    let path = request.uri().path().to_string();
    let entry = |event: &str, outcome: &str| {
        Entry::new(event, outcome)
            .peer(peer)
            .with("plane", "operator")
            .with("operator", operator.clone())
            .with("method", method.to_string())
            .with("path", path.clone())
    };
    if audit.record(entry("operator.act", "requested")).is_err() {
        return crate::transport::busy();
    }
    let response = next.run(request).await;
    audit.refusal(entry("operator.act", "completed").with("status", response.status().as_u16()));
    response
}

/// The user name of a Basic `Authorization` header, never the password.
fn basic_user(headers: &axum::http::HeaderMap) -> Option<String> {
    use base64::Engine as _;
    let encoded = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    text.split_once(':').map(|(user, _)| user.to_string())
}

/// Refuses every request that carries no configured credential, before any handler sees it, and
/// a peer address that has failed too often before its credential is compared.
async fn authenticate(
    State(auth): State<Arc<OperatorAuth>>,
    request: Request,
    next: Next,
) -> Response {
    let peer = crate::transport::peer_ip(&request);
    let operator = basic_user(request.headers());
    let refusal = |event: &str, outcome: &str| {
        if let Some(audit) = &auth.2 {
            audit.refusal(
                crate::audit::Entry::new(event, outcome)
                    .peer(peer)
                    .with("plane", "operator")
                    .with("operator", operator.clone()),
            );
        }
    };
    if let (Some(throttle), Some(peer)) = (&auth.1, peer) {
        if let Some(wait) = throttle.retry_after(peer) {
            refusal("operator.throttled", "throttled");
            return crate::transport::throttled(wait);
        }
    }
    // The attempt counts before the password is hashed, so attempts sent at once cannot all pass
    // the back-off check first (ADR-0021 clause 2).
    let _attempt = match (&auth.1, peer) {
        (Some(throttle), Some(peer)) => match throttle.begin(peer) {
            Some(attempt) => Some(attempt),
            None => {
                refusal("operator.throttled", "throttled");
                return crate::transport::throttled(throttle.retry_after(peer).unwrap_or(1));
            }
        },
        _ => None,
    };
    let verdict = auth.0.check(peer, request.headers()).await;
    if verdict == crate::credentials::Verdict::Busy {
        return crate::transport::busy();
    }
    if verdict == crate::credentials::Verdict::Refused {
        if let (Some(throttle), Some(peer)) = (&auth.1, peer) {
            throttle.failed(peer);
        }
        refusal("operator.refused", "refused");
        // The challenge is what turns this into a browser prompt rather than a dead end.
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, auth.0.challenge().to_string())],
            "the REST API and the UI require authentication",
        )
            .into_response();
    }
    next.run(request).await
}

pub fn router(state: Arc<AppState>, auth: Option<OperatorAuth>) -> Router {
    let (api, document) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(agents))
        .routes(routes!(restart_agent))
        .routes(routes!(forget_agent))
        .routes(routes!(set_agent_labels))
        .routes(routes!(rollout_to_agent))
        .routes(routes!(list_configurations))
        .routes(routes!(
            get_configuration,
            put_configuration,
            delete_configuration
        ))
        .routes(routes!(list_packages))
        .routes(routes!(
            get_package_set,
            put_package_set,
            delete_package_set
        ))
        // The one route that legitimately carries a program: the framework's 2 MiB default would
        // refuse every real agent binary, so the upload streams past it and the handler bounds it
        // by `max_package_size_bytes` instead (ADR-0010). No other route is unbounded.
        .routes(routes!(put_package_entry, delete_package_entry).layer(DefaultBodyLimit::disable()))
        .routes(routes!(put_entry_signature, delete_entry_signature))
        .routes(routes!(list_deployments))
        .routes(routes!(get_deployment, put_deployment, delete_deployment))
        .routes(routes!(put_deployment_selector))
        .routes(routes!(put_deployment_package, delete_deployment_package))
        .routes(routes!(
            put_deployment_configuration,
            delete_deployment_configuration
        ))
        .routes(routes!(rollout_deployment))
        .routes(routes!(
            get_enrolment_window,
            open_enrolment_window,
            close_enrolment_window
        ))
        .routes(routes!(list_enrolments))
        .routes(routes!(approve_enrolment))
        .routes(routes!(reject_enrolment))
        .routes(routes!(
            list_bootstrap_certificates,
            issue_bootstrap_certificate
        ))
        .routes(routes!(download_bootstrap_p12))
        .routes(routes!(delete_bootstrap_certificate))
        .routes(routes!(list_certificates))
        .routes(routes!(list_revocations, revoke))
        .routes(routes!(lift_revocation))
        .routes(routes!(list_hosts))
        .routes(routes!(set_gateway))
        .split_for_parts();
    // The document is immutable once assembled — serialize it once, serve it forever.
    let document =
        serde_json::to_string_pretty(&document).expect("the OpenAPI document serializes");
    let router = api
        .route(
            "/api/v1/openapi.json",
            get(move || {
                let body = (
                    [(header::CONTENT_TYPE, "application/json")],
                    document.clone(),
                );
                std::future::ready(body.into_response())
            }),
        )
        // The interactive API docs (ADR-0013): a Redoc page rendering /api/v1/openapi.json, with
        // Redoc vendored and served from this same origin so the docs work offline.
        .route("/api/v1/docs", get(docs))
        .route("/api/v1/docs/redoc.js", get(redoc_js))
        .route("/", get(index))
        .route("/ui.css", get(ui_css))
        .route("/ui-carbon.css", get(ui_carbon_css))
        .route("/ui-quiet.css", get(ui_quiet_css))
        .route("/shiki.js", get(shiki_js))
        .with_state(state.clone());
    // Inside the guard, so an act is recorded only once it is authenticated, and named by the
    // operator who made it (ADR-0022 clause 1).
    let router = match state.audit().cloned() {
        Some(audit) => router.layer(middleware::from_fn_with_state(audit, record_act)),
        None => router,
    };
    let router = match auth {
        // Outside every route, so the guard covers every route on this listener — including the
        // UI and the API docs, which are as much of the plane as `/api/v1` is (ADR-0021).
        Some(auth) => router.layer(middleware::from_fn_with_state(Arc::new(auth), authenticate)),
        None => router,
    };
    // Outermost, so a refusal of the guard carries the headers too.
    router.layer(middleware::from_fn(security_headers))
}

/// The policy every page of the plane is held to. Scripts come from this origin, or are the
/// bundled UI's inline ones named by their hash; styles come from this origin, as the UI's
/// stylesheet does, or are inline, as the UI's `style` attributes and the API docs' rendered
/// styles are. Nothing may frame the plane.
static CONTENT_SECURITY_POLICY: std::sync::LazyLock<header::HeaderValue> =
    std::sync::LazyLock::new(|| {
        use base64::Engine as _;
        use sha2::Digest as _;
        let page = include_str!("../static/index.html");
        // Each `<script …>` without a `src`, whatever its other attributes.
        let hashes: String = page
            .split("<script")
            .skip(1)
            .filter_map(|chunk| chunk.split_once('>'))
            .filter(|(attributes, _)| !attributes.contains("src="))
            .filter_map(|(_, rest)| rest.split_once("</script>"))
            .map(|(script, _)| {
                let digest = sha2::Sha256::digest(script.as_bytes());
                format!(
                    " 'sha256-{}'",
                    base64::engine::general_purpose::STANDARD.encode(digest)
                )
            })
            .collect();
        header::HeaderValue::from_str(&format!(
            "default-src 'self'; script-src 'self'{hashes}; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; \
             form-action 'self'; frame-ancestors 'none'"
        ))
        .expect("the policy is a header value")
    });

/// The response headers of the Operator plane: its policy, no framing, no content sniffing, no
/// referrer, no cached `/api/v1` answer, and HSTS. The plane serves TLS on every address
/// (ADR-0013), so a browser that once reached it by name never tries `http://` for it again,
/// where an active attacker could answer and ask for the Basic credentials; browsers ignore the
/// header for an IP address. It names no subdomains: what else runs on the plane's domain is not
/// the plane's to bind.
async fn security_headers(request: Request, next: Next) -> Response {
    let api = request.uri().path().starts_with("/api/v1/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        CONTENT_SECURITY_POLICY.clone(),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        header::HeaderValue::from_static("max-age=31536000"),
    );
    if api {
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    response
}

/// The one route of `/api/v1` that is not the operator's: the artifact bytes an Agent downloads.
/// It is served on the **Agent plane** (ADR-0013), because that is the audience — the
/// `download_url` in a package offer is a path the Client resolves against its own OpAMP endpoint
/// (ADR-0026), so this listener is where the offer already points. It keeps its `/api/v1` path,
/// which every offered Package's `download_url` names.
///
/// Consequently it is not in the OpenAPI document: that document describes the Operator plane.
pub fn download_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/api/v1/packages/{agent_type}/{version}/file",
            get(download_package),
        )
        .with_state(state)
}

/// The bundled UI: one embedded page, no frontend toolchain (ADR-0010).
async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// The bundled UI's default stylesheet, kept apart from the page so its look can be replaced
/// without touching the markup or the scripts.
async fn ui_css() -> Response {
    stylesheet(include_str!("../static/ui.css"))
}

/// The bundled UI's second look, after IBM's Carbon Design System as Würth Phoenix's NetEye wears it.
async fn ui_carbon_css() -> Response {
    stylesheet(include_str!("../static/ui-carbon.css"))
}

/// The bundled UI's third look, the quiet one, where colour says only state and selection.
async fn ui_quiet_css() -> Response {
    stylesheet(include_str!("../static/ui-quiet.css"))
}

/// The vendored Shiki bundle the UI colours an Agent's effective configuration with (ADR-0038),
/// served from this origin like the stylesheets, so `script-src 'self'` admits it.
async fn shiki_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/shiki.js"),
    )
        .into_response()
}

fn stylesheet(css: &'static str) -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], css).into_response()
}

/// The API docs page: renders the OpenAPI document with the vendored Redoc bundle (ADR-0013).
async fn docs() -> Html<&'static str> {
    Html(include_str!("../static/docs.html"))
}

/// The vendored Redoc standalone bundle, served same-origin so the docs page needs no CDN.
async fn redoc_js() -> Response {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../static/redoc.standalone.js"),
    )
        .into_response()
}

/// A machine-readable error, so generated clients get a body they can show.
#[derive(Serialize, ToSchema)]
struct ErrorBody {
    error: String,
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

/// The Instance UID an Agent route names, or the `400` that says it is not one.
fn parse_instance_uid(text: &str) -> Result<InstanceUid, Refusal> {
    InstanceUid::parse(text).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("{text:?} is not an Instance UID"),
        )
    })
}

/// One Agent as the fleet view now shows it — what a write to that Agent answers with. `204` when
/// it was forgotten between the write and the read: the write stands, and the Agent is simply no
/// longer in the view to return.
fn agent_response(state: &AppState, uid: &InstanceUid) -> Response {
    match state
        .snapshot()
        .into_iter()
        .find(|a| a.instance_uid == uid.to_string())
    {
        Some(view) => Json(AgentResponse::from(view)).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// A CSRF guard for the body-less `POST` routes (`restart`, the rollout acts). Those are CORS
/// "simple requests": a cross-origin page can fire them without the preflight the Server would
/// have to answer, so nothing else stops a victim operator's browser from being made to send one.
///
/// Fetch Metadata closes it. A browser sends `Sec-Fetch-Site` on every request and forbids page
/// scripts from setting it, so a value other than `same-origin` (the bundled UI) or `none` (a
/// user-initiated load) marks a cross-site caller, which is refused. A non-browser client — `curl`,
/// a portal — sends no such header and is unaffected, which is why this needs no token and no change
/// to any API client. It is not authentication (that is a separate decision, ADR-0021); it only
/// keeps a browser from being turned into a confused deputy.
///
/// A browser without Fetch Metadata still sends `Origin` on a `POST`, so without `Sec-Fetch-Site`
/// an `Origin` other than the plane's own (`null` included) is refused the same way.
struct SameOrigin;

/// Whether `origin` names the authority this request was sent to — the `Host` header, or the
/// request target's authority over HTTP/2. The scheme is not compared: the plane serves one.
fn is_own_origin(parts: &axum::http::request::Parts, origin: &str) -> bool {
    let own = parts.uri.authority().map(|a| a.as_str()).or_else(|| {
        parts
            .headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
    });
    match (own, origin.split_once("://")) {
        (Some(own), Some((_, authority))) => own.eq_ignore_ascii_case(authority),
        _ => false,
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for SameOrigin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        match parts
            .headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
        {
            Some(site) if site != "same-origin" && site != "none" => Err(error(
                StatusCode::FORBIDDEN,
                format!("cross-site request refused (Sec-Fetch-Site: {site})"),
            )),
            Some(_) => Ok(SameOrigin),
            None => match parts.headers.get(header::ORIGIN) {
                Some(origin) => match origin.to_str() {
                    Ok(origin) if is_own_origin(parts, origin) => Ok(SameOrigin),
                    _ => Err(error(
                        StatusCode::FORBIDDEN,
                        format!("cross-origin request refused (Origin: {origin:?})"),
                    )),
                },
                None => Ok(SameOrigin),
            },
        }
    }
}

/// One Agent as the REST API and the UI see it.
#[derive(Serialize, ToSchema)]
#[schema(as = AgentView)]
struct AgentResponse {
    instance_uid: String,
    /// The Agent *type* — the Baseline's "reverse FQDN that uniquely identifies the Agent type"
    /// (ADR-0016). For a managed Collector this is the `dist.name` it was built with, so every
    /// Collector of one distribution reports the same value. It answers "what is this", never
    /// "which one is this": that is [`service_instance_name`](Self::service_instance_name).
    service_name: String,
    /// The operator's name for this Agent — the `[[supervisor]]` block's `name` (ADR-0016). Empty
    /// for a foreign OpAMP client that reports no `service.instance.name`, which is why the UI
    /// falls back through the type to the UID rather than showing a blank row.
    service_instance_name: String,
    /// The release the Agent reports — `MAJOR.MINOR.PATCH`, with the pre-release when it is not a
    /// release build (ADR-0012). This is what belongs in a column headed "Version"; the commit the
    /// build came from is [`service_build`](Self::service_build). A reported value that is not a
    /// version at all is passed through unchanged, since a Foreign Agent numbers itself however it
    /// likes.
    service_version: String,
    /// Exactly what the Agent reported, commit metadata and all — the answer to "which build is on
    /// that host", which is a question a fleet exists to answer (ADR-0012).
    service_build: String,
    /// The reported `os.description` (e.g. "Ubuntu 24.04.2 LTS"), falling back to `os.type`.
    os: String,
    /// Every reported identifying attribute — what a Selector can match on (ADR-0023).
    identifying_attributes: BTreeMap<String, String>,
    /// Every reported non-identifying attribute — Selectors match these too.
    non_identifying_attributes: BTreeMap<String, String>,
    /// The Configurations a press of the Deployment claiming this Agent would release to it — the
    /// ones it holds that fit this Agent's type (ADR-0034), in name order. Never what it runs;
    /// that is [`assigned_configurations`](Self::assigned_configurations).
    matched_configurations: Vec<String>,
    /// The Configurations rolled out to this Agent (ADR-0034 clause 5), in name order — what its
    /// offer is composed from.
    assigned_configurations: Vec<String>,
    /// The Deployment that claims this Agent **now** — whose Selector matches it — or empty when
    /// none does.
    ///
    /// This is not [`assigned_deployment`](Self::assigned_deployment), and the difference is what
    /// tells four states apart that would otherwise look alike (ADR-0026 point 25). Empty here with
    /// no conflict means the host is in **no channel**: label it, or give it a `channel` attribute. Set
    /// here with nothing assigned and nothing pending means the channel holds nothing this Agent can
    /// take — no Package for its type, or none for its platform. The operator's next move differs
    /// in each case, which is why the Server says which one it is rather than showing an empty
    /// row three ways.
    deployment: String,
    /// The Deployment this Agent's release went **through** (ADR-0034 clause 5), or empty when
    /// nothing has been rolled out to it. Pinned as of that act, so it may name a channel that no
    /// longer claims this Agent.
    assigned_deployment: String,
    /// The Package rolled out to this Agent (ADR-0025), as `<agent type>@<version>`, or empty.
    ///
    /// It is pinned as of the act that released it: re-aiming its Deployment afterwards, or
    /// putting a newer Package in that channel, changes what is *proposed* and never what this Agent
    /// was already given.
    assigned_package: String,
    /// The Configurations waiting for a rollout act toward this Agent (ADR-0025 point 4,
    /// ADR-0034): one its Deployment holds and it is not assigned (`change: "new"`), one whose
    /// saved revision differs from the assigned one (`change: "update"`), one assigned that the
    /// next press drops from a release that keeps something else, applying the smaller map
    /// (`change: "remove"`), or one assigned while the Deployment releases nothing to this Agent
    /// any more, so the next press leaves it with no assignment and it keeps running what it runs
    /// (`change: "kept"`). The Server never acts on this by itself.
    pending_configurations: Vec<PendingConfigurationResponse>,
    /// The Package waiting for a rollout act toward this Agent (ADR-0025 point 4) — at most one:
    /// the candidate of the Deployment that claims it, when that is not what it is assigned, or
    /// the assigned one the next press drops (`change: "remove"`, or `"kept"` as for a
    /// Configuration).
    pending_packages: Vec<PendingPackageResponse>,
    /// The Deployment the next press releases through, when the assignment names another one or
    /// none (ADR-0034 clause 6); empty otherwise. Set alone, it says the press moves only the
    /// assignment over to the claiming Deployment, with the same content.
    pending_deployment: String,
    /// Hex hash of the composed configuration this Agent should run; empty when it is assigned
    /// nothing.
    desired_hash: String,
    /// The Capability Set this Agent declared, as capability names from the Baseline's
    /// `AgentCapabilities` (see docs/CONFORMANCE.md).
    capabilities: Vec<String>,
    /// The Agent's available components (top-level names, sorted); empty until reported.
    available_components: Vec<String>,
    /// The Agent's package installations (ADR-0026), in name order; empty until reported.
    packages: Vec<PackageStatusResponse>,
    /// Why this Agent is proposed nothing — more than one Deployment claims it, and an Agent
    /// belongs to at most one (ADR-0026 point 26). The message names every Deployment in the way.
    /// Absent when at most one claims it.
    #[serde(skip_serializing_if = "Option::is_none")]
    package_conflict: Option<String>,
    /// What the Agent said about the *offer* rather than about a package it holds — an offer it
    /// refuses outright has no package status to carry the reason, and the Client's own Agent
    /// refusing a package it was not configured to take (ADR-0018) is exactly that case. Empty
    /// when the Agent has nothing to complain about.
    package_error: String,
    transport: String,
    connected: bool,
    healthy: bool,
    health_status: String,
    /// Why the Agent is unhealthy — `ComponentHealth.last_error`, which the Baseline says SHOULD
    /// be set when `healthy` is false. Empty when the Agent is healthy or gave no reason.
    health_error: String,
    effective_config: String,
    remote_config_status: String,
    remote_config_error: String,
    in_sync: bool,
    sequence_num: u64,
    last_seen_ms: u64,
    /// Nothing has been heard from this Agent for longer than its staleness budget (ADR-0024).
    ///
    /// Beside [`connected`](Self::connected), never instead of it: that one says a connection
    /// carrying this Agent is open — behind a Gateway, the *Gateway's* — and this one says whether
    /// the Agent itself is still talking. `connected: true, stale: true` is precisely the gatewayed
    /// case, and precisely what an operator needs to be told.
    ///
    /// Only an Agent declaring `ReportsHeartbeat` can be stale: that capability is the promise that
    /// makes silence mean something. Derived on read, never stored.
    stale: bool,
    /// The operator's labels on this Agent (ADR-0024) — matched by Selectors exactly like a
    /// reported attribute, but set here rather than in `supervisor.toml` on the host, so moving a host
    /// between rollout channels is an API call instead of an edit and a restart.
    labels: BTreeMap<String, String>,
    /// Labels this Agent's own reports shadow: set, matching nothing, and therefore doing nothing.
    ///
    /// Reported attributes always win (ADR-0024) — they decide which artifact fits this machine.
    /// A collision is refused when the label is set, so this fills only when an Agent *starts*
    /// reporting a key that was labelled earlier. Shown rather than dropped in silence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    shadowed_labels: Vec<String>,
    /// The labels of this Agent's Client Agent, which hold for it below its own (ADR-0035
    /// clause 4); empty for the Client Agent itself, for an Agent whose Client the Server cannot
    /// tell, and for an ambiguous one.
    inherited_labels: BTreeMap<String, String>,
    /// The Instance UID of this Agent's Client Agent — its own, for the Client Agent — or empty
    /// when the Server cannot tell.
    client_agent: String,
    /// The group this Agent's Client is recognised in holds more than one Client Agent, so it
    /// inherits nothing (ADR-0035 clause 4).
    ambiguous: bool,
    /// The Host this Agent last arrived over (ADR-0035 clause 2), or empty. Behind a Gateway, the
    /// Gateway's.
    host: String,
    /// The `fleet.host.*` values Selectors match on this Agent, from the certificate of the Host it
    /// arrived over directly (ADR-0035 clause 3); empty behind a Gateway.
    host_attributes: BTreeMap<String, String>,
    /// Reported attributes in the Server's `fleet.` space, left out of what Selectors match
    /// (ADR-0035 clause 5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ignored_attributes: Vec<String>,
}

impl From<fleet::AgentView> for AgentResponse {
    fn from(view: fleet::AgentView) -> Self {
        AgentResponse {
            instance_uid: view.instance_uid,
            service_name: view.service_name,
            service_instance_name: view.service_instance_name,
            service_version: view.service_version,
            service_build: view.service_build,
            os: view.os,
            identifying_attributes: view.identifying_attributes,
            non_identifying_attributes: view.non_identifying_attributes,
            matched_configurations: view.matched_configurations,
            assigned_configurations: view.assigned_configurations,
            deployment: view.deployment,
            assigned_deployment: view.assigned_deployment,
            assigned_package: view.assigned_package,
            pending_configurations: view
                .pending_configurations
                .into_iter()
                .map(Into::into)
                .collect(),
            pending_packages: view.pending_packages.into_iter().map(Into::into).collect(),
            pending_deployment: view.pending_deployment,
            desired_hash: view.desired_hash,
            capabilities: view.capabilities,
            available_components: view.available_components,
            packages: view.packages.into_iter().map(Into::into).collect(),
            package_conflict: view.package_conflict,
            package_error: view.package_error,
            transport: view.transport,
            connected: view.connected,
            healthy: view.healthy,
            health_status: view.health_status,
            health_error: view.health_error,
            effective_config: view.effective_config,
            remote_config_status: view.remote_config_status,
            remote_config_error: view.remote_config_error,
            in_sync: view.in_sync,
            sequence_num: view.sequence_num,
            last_seen_ms: view.last_seen_ms,
            stale: view.stale,
            labels: view.labels,
            shadowed_labels: view.shadowed_labels,
            inherited_labels: view.inherited_labels,
            client_agent: view.client_agent,
            ambiguous: view.ambiguous,
            host: view.host,
            host_attributes: view.host_attributes,
            ignored_attributes: view.ignored_attributes,
        }
    }
}

/// One Configuration waiting for a rollout act toward one Agent (ADR-0025).
#[derive(Serialize, ToSchema)]
#[schema(as = PendingConfigurationView)]
struct PendingConfigurationResponse {
    name: String,
    /// `new` — held by the claiming Deployment and not yet assigned; `update` — the saved
    /// revision differs from the assigned one; `remove` — assigned, and dropped by the next press,
    /// which applies the smaller map; `kept` — assigned, and the next press leaves the Agent with
    /// no assignment, so it keeps running it.
    change: String,
}

impl From<fleet::PendingConfigurationView> for PendingConfigurationResponse {
    fn from(view: fleet::PendingConfigurationView) -> Self {
        PendingConfigurationResponse {
            name: view.name,
            change: view.change,
        }
    }
}

/// The Package waiting for a rollout act toward one Agent (ADR-0025).
#[derive(Serialize, ToSchema)]
#[schema(as = PendingPackageView)]
struct PendingPackageResponse {
    /// The Deployment that would release it — the channel this Agent belongs to.
    deployment: String,
    /// The Agent type this Package is built for — its identity, and its wire name.
    agent_type: String,
    version: String,
    /// What an operator reads: the Agent type and the version together.
    display_name: String,
    /// `new` — nothing is assigned for this Agent type; `update` — another version is; `remove` —
    /// the assigned one, which the next press drops; `kept` — the assigned one, while the next
    /// press leaves the Agent with no assignment.
    change: String,
}

impl From<fleet::PendingPackageView> for PendingPackageResponse {
    fn from(view: fleet::PendingPackageView) -> Self {
        PendingPackageResponse {
            deployment: view.deployment,
            agent_type: view.agent_type,
            version: view.version,
            display_name: view.display_name,
            change: view.change,
        }
    }
}

/// One package's installation state as the REST API and UI see it (ADR-0026).
#[derive(Serialize, ToSchema)]
#[schema(as = PackageStatusView)]
struct PackageStatusResponse {
    name: String,
    /// The version the Agent has installed; empty if it has none.
    version: String,
    /// `Downloading`, `Installing`, `Installed`, `InstallPending`, or `InstallFailed`.
    status: String,
    /// The failure reason when `status` is `InstallFailed`.
    error: String,
    /// How far the artifact download has got, as a percentage. Present only while `Downloading`,
    /// and only when the download source stated a size.
    #[serde(skip_serializing_if = "Option::is_none")]
    download_percent: Option<f64>,
    /// The download's current rate in bytes per second. Present only while `Downloading`.
    #[serde(skip_serializing_if = "Option::is_none")]
    download_bytes_per_second: Option<f64>,
}

impl From<fleet::PackageStatusView> for PackageStatusResponse {
    fn from(view: fleet::PackageStatusView) -> Self {
        PackageStatusResponse {
            name: view.name,
            version: view.version,
            status: view.status,
            error: view.error,
            download_percent: view.download_percent,
            download_bytes_per_second: view.download_bytes_per_second,
        }
    }
}

/// The fleet: every Agent the Server knows, its reported attributes, and the Configurations
/// currently matching it.
#[utoipa::path(
    get,
    path = "/api/v1/agents",
    tag = "fleet",
    responses((status = 200, description = "Every known Agent", body = [AgentResponse]))
)]
async fn agents(State(state): State<Arc<AppState>>) -> Json<Vec<AgentResponse>> {
    Json(state.snapshot().into_iter().map(Into::into).collect())
}

/// Queues a restart of the Agent's Managed Process, delivered as the protocol's restart command
/// on the Agent's next exchange — immediately over WebSocket, on the next poll over plain HTTP.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{instance_uid}/restart",
    tag = "fleet",
    params(("instance_uid" = String, Path, description = "The Agent's Instance UID")),
    responses(
        (status = 202, description = "Restart queued"),
        (status = 400, description = "Malformed Instance UID", body = ErrorBody),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such Agent", body = ErrorBody),
        (status = 409, description = "The Agent does not declare AcceptsRestartCommand", body = ErrorBody)
    )
)]
async fn restart_agent(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(instance_uid): Path<String>,
) -> Response {
    let uid = match parse_instance_uid(&instance_uid) {
        Ok(uid) => uid,
        Err((status, why)) => return error(status, why),
    };
    match state.request_restart(&uid) {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(RestartError::UnknownAgent) => error(StatusCode::NOT_FOUND, format!("no agent {uid}")),
        Err(RestartError::NoCapability) => error(
            StatusCode::CONFLICT,
            format!("agent {uid} does not declare AcceptsRestartCommand"),
        ),
    }
}

/// The labels to put on an Agent (ADR-0024). The whole set, replacing what was there.
#[derive(Deserialize, ToSchema)]
struct LabelsBody {
    /// Equality pairs a Selector can match, exactly like a reported attribute — `rollout: canary`
    /// being the one this exists for. An empty map clears the Agent's labels.
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
}

/// Sets an Agent's labels, which decide what Selectors match it.
#[utoipa::path(
    put,
    path = "/api/v1/agents/{instance_uid}/labels",
    tag = "fleet",
    params(("instance_uid" = String, Path, description = "The Agent's Instance UID")),
    request_body = LabelsBody,
    description = "Replace this Agent's labels (ADR-0024, ADR-0035). A label is an operator's \
                   key/value pair that joins what a Deployment's Selector matches, so a rollout \
                   channel is a Server-side decision instead of an edit to supervisor.toml on the \
                   host. An empty map clears them. The labels of a Client's own Agent hold for the \
                   Client's other Agents, below their own. Labels are part of the Agent's record: \
                   they follow a re-key, forgetting the Agent removes them, and they never travel \
                   to the Agent. A key the Agent already reports is refused, because reported \
                   attributes decide which artifact fits the machine and a label must never be \
                   able to overrule them; a key starting `fleet.` is refused, because the Server \
                   fills those from the Host's certificate.",
    responses(
        (status = 200, description = "The Agent, with its new labels", body = AgentResponse),
        (status = 400, description = "Malformed Instance UID, an unusable label, or a key starting `fleet.`", body = ErrorBody),
        (status = 404, description = "No such Agent", body = ErrorBody),
        (status = 409, description = "A label restates an attribute the Agent reports", body = ErrorBody),
        (status = 500, description = "The Agent's record could not be written", body = ErrorBody)
    )
)]
async fn set_agent_labels(
    State(state): State<Arc<AppState>>,
    Path(instance_uid): Path<String>,
    Json(body): Json<LabelsBody>,
) -> Response {
    let uid = match parse_instance_uid(&instance_uid) {
        Ok(uid) => uid,
        Err((status, why)) => return error(status, why),
    };
    match state.set_labels(&uid, body.labels) {
        Ok(()) => agent_response(&state, &uid),
        Err(LabelError::UnknownAgent) => error(StatusCode::NOT_FOUND, format!("no agent {uid}")),
        Err(LabelError::RestatesReported(key)) => error(
            StatusCode::CONFLICT,
            format!(
                "agent {uid} reports {key:?} itself, and a label may not restate it — a reported \
                 attribute decides which artifact fits this machine, so it wins. Change it where it \
                 comes from, in that host's supervisor.toml, or label it under another key"
            ),
        ),
        Err(LabelError::Invalid(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(LabelError::Storage(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// What a per-Agent rollout act names (ADR-0034 clause 6): nothing, or the Deployment that claims
/// the Agent. An empty body releases that Deployment just the same.
#[derive(Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields)]
struct AgentRolloutSpec {
    /// The Deployment the operator means — the one that claims this Agent; its release replaces
    /// the Agent's assignment, pinned as of this press.
    ///
    /// Naming another is refused, and so is any act while no Deployment or a second one claims the
    /// Agent: honouring a name over a conflict would sidestep the conflict for good instead of
    /// fixing it, and make this path the way into a state the fleet-wide act forbids.
    #[serde(default)]
    deployment: Option<String>,
}

/// Rolls the Deployment that claims **this Agent** out to it (ADR-0034 clause 6): its Package for
/// the Agent's type, if that is a candidate, and every Configuration it holds that fits the
/// Agent's type, at its saved revision — replacing the Agent's assignment. The operator's press is
/// the only thing that distributes: saving, Selector edits and label moves all merely change what
/// is *proposed* here.
#[utoipa::path(
    post,
    path = "/api/v1/agents/{instance_uid}/rollout",
    tag = "fleet",
    params(("instance_uid" = String, Path, description = "The Agent's Instance UID")),
    request_body(content = AgentRolloutSpec, description = "Empty, or the claiming Deployment's name"),
    responses(
        (status = 200, description = "Rolled out; the Agent with its new assignment", body = AgentResponse),
        (status = 400, description = "Malformed Instance UID or body", body = ErrorBody),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such Agent", body = ErrorBody),
        (status = 409, description = "The Agent is in no Deployment, in a conflict, or in another one than named; or the Deployment holds nothing, or a Package with an unsigned entry", body = ErrorBody)
    )
)]
async fn rollout_to_agent(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(instance_uid): Path<String>,
    body: Option<Json<AgentRolloutSpec>>,
) -> Response {
    let uid = match parse_instance_uid(&instance_uid) {
        Ok(uid) => uid,
        Err((status, why)) => return error(status, why),
    };
    let spec = body.map(|Json(spec)| spec).unwrap_or_default();
    match state.rollout_to_agent(&uid, spec.deployment.as_deref()) {
        Ok(()) => agent_response(&state, &uid),
        Err(e) => rollout_error(e),
    }
}

/// Forgets what the Server knows about an Agent, dropping its row from the fleet view.
///
/// Reaches no host: nothing is stopped, nothing is uninstalled, and no certificate is revoked —
/// a certificate is the host's, not the Agent's. Its `instance_uid` is released from the Host it
/// was bound to (ADR-0047 clause 2). A Client that is still running reappears on its next report.
#[utoipa::path(
    delete,
    path = "/api/v1/agents/{instance_uid}",
    tag = "fleet",
    params(("instance_uid" = String, Path, description = "The Agent's Instance UID")),
    description = "Forget this Agent: the Server drops what it knows and the row leaves the fleet \
                   view (ADR-0024). Nothing happens on the host — no process is stopped, nothing \
                   is uninstalled, and no certificate is revoked, because a certificate here \
                   proves fleet membership and its host rather than one Agent's identity. The \
                   Instance UID is released from the Host it was bound to (ADR-0047), so its \
                   next report binds it to the host whose certificate carries that report. A \
                   Client still configured for this Server therefore comes back on its next \
                   report. Refused while the \
                   Agent is still reporting, since forgetting it would have its configuration \
                   offered again and a managed process restarted with it.",
    responses(
        (status = 204, description = "The Agent is forgotten"),
        (status = 400, description = "Malformed Instance UID", body = ErrorBody),
        (status = 404, description = "No such Agent", body = ErrorBody),
        (status = 409, description = "The Agent is still reporting", body = ErrorBody)
    )
)]
async fn forget_agent(
    State(state): State<Arc<AppState>>,
    Path(instance_uid): Path<String>,
) -> Response {
    let uid = match parse_instance_uid(&instance_uid) {
        Ok(uid) => uid,
        Err((status, why)) => return error(status, why),
    };
    match state.forget_agent(&uid) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(ForgetError::UnknownAgent) => error(StatusCode::NOT_FOUND, format!("no agent {uid}")),
        Err(ForgetError::StillReporting) => error(
            StatusCode::CONFLICT,
            format!("agent {uid} is still reporting; stop it or wait for it to go stale"),
        ),
    }
}

/// The writable part of a [`Configuration`] — the `PUT` request body; the name comes from the
/// URL. Writes the saved revision (ADR-0025): saving only saves. A Configuration is content only
/// (ADR-0034): what aims it is the Selector of a Deployment that holds it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct ConfigurationSpec {
    body: String,
    /// See [`Revision::role`]. Absent means top-level configuration.
    #[serde(default)]
    role: String,
    /// The Agent type this Configuration is written for, compared raw against the `service.name`
    /// an Agent reports (ADR-0034 clauses 1 and 3). Required: absent or empty is refused `400`.
    /// Read as empty when absent, so the refusal names it.
    #[serde(default)]
    #[schema(required = true)]
    service_name: String,
    /// Read only to refuse it by name: a Configuration has no Selector (ADR-0034 clauses 1 and 9).
    #[serde(default)]
    #[schema(ignore)]
    selector: Option<serde_json::Value>,
}

/// One Configuration as the API shows it (ADR-0025, ADR-0034): the **saved** revision — what
/// editing operates on and what a rollout act releases — and the Deployments holding it. Which
/// Agents run which pinned revision is a fact about the Agents, answered per Agent by
/// `GET /api/v1/agents`.
#[derive(Serialize, ToSchema)]
struct ConfigurationView {
    name: String,
    body: String,
    /// The Baseline's `AgentConfigObject.role` (ADR-0023); absent means top-level configuration.
    #[serde(skip_serializing_if = "String::is_empty")]
    role: String,
    /// The Agent type this Configuration is written for (ADR-0034 clauses 1 and 3).
    service_name: String,
    /// The Deployments that hold this Configuration, in name order — where "whom does it reach"
    /// is answered. Empty means it is saved and no rollout act can release it.
    deployments: Vec<String>,
}

impl ConfigurationView {
    fn of(config: Configuration, deployments: Vec<String>) -> Self {
        ConfigurationView {
            name: config.name,
            body: config.saved.body,
            role: config.saved.role,
            service_name: config.saved.service_name,
            deployments,
        }
    }
}

/// One Configuration as the API answers with it, with the Deployments that hold it read now.
fn configuration_view(state: &AppState, config: Configuration) -> ConfigurationView {
    let deployments = state
        .deployments_holding_configurations()
        .remove(&config.name)
        .unwrap_or_default();
    ConfigurationView::of(config, deployments)
}

/// What a Deployment's rollout act did (ADR-0034 clause 6).
#[derive(Serialize, ToSchema)]
struct RolloutOutcome {
    /// How many Agents the act assigned — every Agent the Deployment claims and the press moved.
    /// An Agent that appears later waits for its own act.
    assigned_agents: usize,
}

/// All Configurations, in name order, each with the Deployments that hold it.
#[utoipa::path(
    get,
    path = "/api/v1/configurations",
    tag = "configurations",
    responses((status = 200, description = "Every stored Configuration", body = [ConfigurationView]))
)]
async fn list_configurations(State(state): State<Arc<AppState>>) -> Json<Vec<ConfigurationView>> {
    let mut holding = state.deployments_holding_configurations();
    Json(
        state
            .configurations()
            .list()
            .into_iter()
            .map(|config| {
                let deployments = holding.remove(&config.name).unwrap_or_default();
                ConfigurationView::of(config, deployments)
            })
            .collect(),
    )
}

/// One Configuration by name.
#[utoipa::path(
    get,
    path = "/api/v1/configurations/{name}",
    tag = "configurations",
    params(("name" = String, Path, description = "The Configuration's name")),
    responses(
        (status = 200, description = "The Configuration", body = ConfigurationView),
        (status = 404, description = "No Configuration of that name", body = ErrorBody)
    )
)]
async fn get_configuration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    match state.configurations().get(&name) {
        Some(config) => Json(configuration_view(&state, config)).into_response(),
        None => error(StatusCode::NOT_FOUND, format!("no configuration {name:?}")),
    }
}

/// Creates a Configuration or replaces its saved revision. **Saving only saves** (ADR-0025):
/// nothing reaches any Agent — every Agent keeps the revision its assignment pins — until a
/// rollout act of a Deployment holding it releases the saved revision as one snapshot.
///
/// A Configuration has no Selector (ADR-0034): a body naming one is refused, and the Deployment
/// that holds the Configuration is where it is aimed.
#[utoipa::path(
    put,
    path = "/api/v1/configurations/{name}",
    tag = "configurations",
    params(("name" = String, Path, description = "The Configuration's name (ADR-0019 grammar)")),
    request_body = ConfigurationSpec,
    responses(
        (status = 200, description = "The stored Configuration — distributed to nobody until a Deployment holding it is rolled out", body = ConfigurationView),
        (status = 400, description = "Invalid name, an empty body, no service_name, or a selector", body = ErrorBody),
        (status = 500, description = "The Configuration could not be persisted", body = ErrorBody)
    )
)]
async fn put_configuration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(spec): Json<ConfigurationSpec>,
) -> Response {
    if spec.selector.is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "a Configuration has no selector — put it into a Deployment and aim the Deployment \
             (PUT /api/v1/deployments/{name}/configurations/{configuration})",
        );
    }
    if let Err(e) = configs::validate_name(&name) {
        return error(
            StatusCode::BAD_REQUEST,
            format!("invalid name {name:?}: {e}"),
        );
    }
    let mut body = spec.body.replace("\r\n", "\n");
    if body.trim().is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "the configuration body is empty; refusing to store it",
        );
    }
    if !body.ends_with('\n') {
        body.push('\n');
    }
    let revision = Revision {
        body,
        // Carried verbatim (ADR-0023): the values are Agent-type-specific, so the Server never
        // validates one against a vocabulary of its own. Empty is top-level configuration.
        role: spec.role,
        // Compared raw against the reported `service.name` (ADR-0034 clause 3). Required, and not
        // validated against the fleet, because a Configuration may precede its first Agent.
        service_name: spec.service_name,
    };
    if let Err(e) = configs::check_type(&revision) {
        return error(StatusCode::BAD_REQUEST, e);
    }
    match state.save_configuration(&name, revision) {
        Ok(config) => {
            info!(configuration = %config.name, role = %config.saved.role, service_name = %config.saved.service_name, bytes = config.saved.body.len(), "configuration saved from the API");
            Json(configuration_view(&state, config)).into_response()
        }
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Maps a rollout refusal onto the REST contract (ADR-0034 clause 6).
fn rollout_error(e: RolloutError) -> Response {
    match e {
        RolloutError::UnknownAgent => error(StatusCode::NOT_FOUND, "no such agent"),
        RolloutError::UnknownResource(e) => error(StatusCode::NOT_FOUND, e),
        RolloutError::NotApplicable(e) => error(StatusCode::CONFLICT, e),
        RolloutError::Storage(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Deletes a Configuration — refused with `409` while an Agent's assignment pins it, saying how
/// many (ADR-0034 clause 8). Rolling those Agents out through a Deployment without it, or
/// forgetting them, comes first. A deleted Configuration leaves every Deployment that held it.
#[utoipa::path(
    delete,
    path = "/api/v1/configurations/{name}",
    tag = "configurations",
    params(("name" = String, Path, description = "The Configuration's name")),
    responses(
        (status = 204, description = "Deleted, and taken out of every Deployment that held it"),
        (status = 404, description = "No Configuration of that name", body = ErrorBody),
        (status = 409, description = "An Agent's assignment pins it", body = ErrorBody),
        (status = 500, description = "The Configuration could not be deleted", body = ErrorBody)
    )
)]
async fn delete_configuration(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    match state.delete_configuration(&name) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no configuration {name:?}")),
        Err(DeleteError::Pinned(e)) => error(StatusCode::CONFLICT, e),
        Err(DeleteError::Storage(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// One stored **Package** as the API shows it (ADR-0026) — never its artifact bytes.
///
/// A Package is identified by *(Agent type, version)*, stated at creation and never edited: a new
/// version is a new Package. It holds one entry per platform and aims at nobody — the Deployments
/// that hold it do (ADR-0026). **Saving never distributes anything** (ADR-0025): a Package reaches
/// an Agent only through a rollout act, and which Agents run it is answered per Agent by
/// `GET /api/v1/agents`.
#[derive(Serialize, ToSchema)]
struct PackageSetView {
    /// The Agent type this Package is built for, matched raw against the `service.name` an Agent
    /// reports before anything else is considered (ADR-0026). Half its identity — and the name it
    /// carries on the wire, which is why it never holds the version.
    agent_type: String,
    /// The version every entry of this Package shares. The other half of its identity.
    version: String,
    /// What an operator reads: the Agent type and the version together. Derived, never stored.
    display_name: String,
    /// One entry per platform. An Agent is offered the one built for the machine it reported, and
    /// never another (ADR-0026).
    entries: Vec<PackageEntryView>,
    /// The Deployments that hold this Package, in name order.
    ///
    /// This is where "whom does it reach" is answered: a Package aims at nobody by itself
    /// (ADR-0026), so an empty list means it is stored and no rollout act can release it.
    deployments: Vec<String>,
}

/// One platform's entry of a Package: an uploaded artifact and its signature (ADR-0033).
#[derive(Serialize, ToSchema)]
struct PackageEntryView {
    /// The operating system, as `os.type` reports it: `linux`, `darwin`, `windows`.
    os: String,
    /// The architecture, as `host.arch` reports it: `amd64`, `arm64`.
    arch: String,
    /// The artifact's size in bytes.
    size: u64,
    /// The artifact's SHA-256, hex — **the exact value the Agent verifies what it downloaded
    /// against** (ADR-0026). Reading it is how an operator answers "did this host take my bytes"
    /// without trusting a status field: it is the same string the Agent reports back in its
    /// `PackageStatuses`, and the same one `opamp-fleetctl package sha256` prints locally.
    content_hash: String,
    /// The per-package hash this entry is offered under, hex. An Agent echoes it once it is in
    /// sync, and the Server stops re-offering while the two agree — so a rollout that seems not to
    /// travel is answered here rather than by reading logs.
    package_hash: String,
    /// The operator's Ed25519 signature over this entry, hex, as `opamp-fleetctl package sign`
    /// prints it (ADR-0033); absent while the entry is unsigned. An unsigned entry is offered to
    /// nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// What the Server found when it checked that signature against `[packages] verification_key`
    /// (ADR-0033). Feedback only: an `invalid` one is stored and offered, and the Agent's own check
    /// decides.
    signature_state: SignatureStateView,
}

/// What the Server found when it checked an entry's signature (ADR-0033).
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum SignatureStateView {
    /// The entry carries no signature; it is offered to nobody.
    Missing,
    /// The signature verifies against the Server's `[packages] verification_key`.
    Valid,
    /// The signature does not verify against that key. Stored, shown as a warning, and never
    /// refused: the Agent's check decides.
    Invalid,
    /// The entry carries a signature and the Server holds no key to check it with.
    Unchecked,
}

impl From<SignatureState> for SignatureStateView {
    fn from(state: SignatureState) -> Self {
        match state {
            SignatureState::Missing => SignatureStateView::Missing,
            SignatureState::Valid => SignatureStateView::Valid,
            SignatureState::Invalid => SignatureStateView::Invalid,
            SignatureState::Unchecked => SignatureStateView::Unchecked,
        }
    }
}

impl PackageSetView {
    fn of(summary: PackageSummary, deployments: Vec<String>) -> Self {
        PackageSetView {
            display_name: summary.id.display_name(),
            agent_type: summary.id.agent_type,
            version: summary.id.version,
            deployments,
            entries: summary
                .entries
                .into_iter()
                .map(|entry| PackageEntryView {
                    os: entry.os,
                    arch: entry.arch,
                    size: entry.size,
                    content_hash: entry.content_hash,
                    package_hash: entry.package_hash,
                    signature: entry.signature,
                    signature_state: entry.signature_state.into(),
                })
                .collect(),
        }
    }
}

/// The Platform the download route names (ADR-0026): the artifact endpoint serves bytes, and a
/// request naming bytes names the Platform they are for.
#[derive(Deserialize)]
struct PlatformQuery {
    /// The operating system, as `os.type`: `linux`, `darwin`, `windows`. Other spellings — `macos`
    /// off a release file name — are accepted and answered canonically.
    os: String,
    /// The architecture, as `host.arch`: `amd64`, `arm64`. Other spellings — `x86_64`, `aarch64` —
    /// are accepted and answered canonically.
    arch: String,
}

impl PlatformQuery {
    fn platform(&self) -> Result<Platform, String> {
        Platform::new(&self.os, &self.arch)
    }
}

/// The `(Package, Platform)` a route names in its path, or the `400` that says which half of it
/// does not parse. `platform_prefix` leads the platform half's message.
fn artifact_of(
    agent_type: &str,
    version: &str,
    os: &str,
    arch: &str,
    platform_prefix: &str,
) -> Result<(PackageId, Platform), Refusal> {
    let id = PackageId::new(agent_type, version).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let platform = Platform::new(os, arch)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("{platform_prefix}{e}")))?;
    Ok((id, platform))
}

/// A stored Package as the API answers with it, read back from the store rather than assembled
/// from whatever the handler happened to be given — so every response describes the Package as it
/// now is.
fn set_response(state: &AppState, id: &PackageId) -> Response {
    match state.packages().and_then(|store| store.summary(id)) {
        Some(summary) => {
            let deployments = state
                .deployments_holding()
                .remove(&id.to_string())
                .unwrap_or_default();
            Json(PackageSetView::of(summary, deployments)).into_response()
        }
        None => error(StatusCode::NOT_FOUND, format!("no package set {id}")),
    }
}

/// Maps a store refusal onto the status the REST contract names: immutability and emptiness are
/// conflicts with the Package's current state (`409`), absence is `404`, bad input `400`.
fn package_error(e: String) -> Response {
    if e.contains("not configured") || e.starts_with("no package set") || e.starts_with("no entry")
    {
        error(StatusCode::NOT_FOUND, e)
    } else if e.contains("immutable") || e.contains("holds no entries") || e.contains("is pinned") {
        error(StatusCode::CONFLICT, e)
    } else if e.starts_with("invalid") || e.starts_with("the ") || e.contains("empty") {
        error(StatusCode::BAD_REQUEST, e)
    } else {
        error(StatusCode::INTERNAL_SERVER_ERROR, e)
    }
}

/// All stored Packages, in identity order — Agent type, then version — and never the artifact
/// bytes.
#[utoipa::path(
    get,
    path = "/api/v1/packages",
    tag = "packages",
    responses(
        (status = 200, description = "Every stored package Set", body = [PackageSetView]),
        (status = 404, description = "Package delivery is not configured", body = ErrorBody)
    )
)]
async fn list_packages(State(state): State<Arc<AppState>>) -> Response {
    match state.packages() {
        Some(store) => {
            let summaries = store.list();
            // One pass over the fleet for the whole list, rather than one per Package.
            let holding = state.deployments_holding();
            Json(
                summaries
                    .into_iter()
                    .map(|summary| {
                        let deployments = holding
                            .get(&summary.id.to_string())
                            .cloned()
                            .unwrap_or_default();
                        PackageSetView::of(summary, deployments)
                    })
                    .collect::<Vec<_>>(),
            )
            .into_response()
        }
        None => error(
            StatusCode::NOT_FOUND,
            "package delivery is not configured on this Server",
        ),
    }
}

/// One stored Package.
#[utoipa::path(
    get,
    path = "/api/v1/packages/{agent_type}/{version}",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type the Set is built for (ADR-0026)"),
        ("version" = String, Path, description = "The Set's version")
    ),
    responses(
        (status = 200, description = "The stored Set", body = PackageSetView),
        (status = 400, description = "Invalid identity", body = ErrorBody),
        (status = 404, description = "No such Set, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn get_package_set(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version)): Path<(String, String)>,
) -> Response {
    match PackageId::load(&agent_type, &version) {
        Ok(id) => set_response(&state, &id),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

/// Creates a Package (ADR-0026). **Saving never distributes** (ADR-0025): the Package reaches an
/// Agent only through a rollout act of a Deployment that holds it. The identity in the path is the
/// whole identity and there is nothing else to write, so creating one that exists answers it
/// unchanged: a new version is a new Package, never a mutation of an old one.
#[utoipa::path(
    put,
    path = "/api/v1/packages/{agent_type}/{version}",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type the Set is built for, compared raw against the `service.name` Agents report"),
        ("version" = String, Path, description = "The Set's version — every entry shares it. A SemVer 2.0.0 version, such as `1.19.0` for upstream's `1.19` (ADR-0043)")
    ),
    responses(
        (status = 200, description = "The stored Set", body = PackageSetView),
        (status = 400, description = "Invalid identity, or a version that is not SemVer", body = ErrorBody),
        (status = 404, description = "Package delivery is not configured", body = ErrorBody),
        (status = 500, description = "The Set could not be persisted", body = ErrorBody)
    )
)]
async fn put_package_set(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version)): Path<(String, String)>,
) -> Response {
    let id = match PackageId::new(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match state.create_package_set(&id) {
        Ok(()) => set_response(&state, &id),
        Err(e) => package_error(e),
    }
}

/// Deletes a Package — entries, artifacts and metadata — refused with `409` while an Agent's
/// assignment pins it, saying how many (ADR-0034 clause 8). A deleted Package leaves every
/// Deployment that held it; nothing is ever uninstalled (ADR-0026).
#[utoipa::path(
    delete,
    path = "/api/v1/packages/{agent_type}/{version}",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type"),
        ("version" = String, Path, description = "The version")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "Invalid identity", body = ErrorBody),
        (status = 404, description = "No such Set, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "An Agent's assignment pins the Package", body = ErrorBody),
        (status = 500, description = "The Set could not be deleted", body = ErrorBody)
    )
)]
async fn delete_package_set(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version)): Path<(String, String)>,
) -> Response {
    // A Package stored under a non-SemVer version is deleted like any other (ADR-0043 clause 3).
    let id = match PackageId::load(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match state.delete_package_set(&id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no package set {id}")),
        Err(e) => package_error(e),
    }
}

/// Stores one platform's artifact as an entry of a Package (ADR-0026, ADR-0033). The artifact is
/// the raw request body; the Package and the platform are the path. New bytes remove the entry's
/// signature, which covered the old hash. Nothing is distributed: the Package reaches nobody until
/// a rollout act releases it (ADR-0025). Refused while the Package is assigned to an Agent — an
/// assigned Package's bytes are immutable.
#[utoipa::path(
    put,
    path = "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type"),
        ("version" = String, Path, description = "The version"),
        ("os" = String, Path, description = "The operating system this artifact is built for, as `os.type`: `linux`, `darwin`, `windows`"),
        ("arch" = String, Path, description = "The architecture, as `host.arch`: `amd64`, `arm64`")
    ),
    request_body(content = Vec<u8>, description = "The artifact bytes", content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "The Set, with the stored entry, unsigned", body = PackageSetView),
        (status = 400, description = "Invalid identity, platform, or an empty artifact", body = ErrorBody),
        (status = 404, description = "No such Set, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Set is assigned to an Agent and its entries are immutable", body = ErrorBody),
        (status = 413, description = "The artifact exceeds max_package_size_bytes", body = ErrorBody),
        (status = 500, description = "The entry could not be persisted", body = ErrorBody),
        (status = 507, description = "Storing it would exceed max_total_package_bytes", body = ErrorBody)
    )
)]
async fn put_package_entry(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version, os, arch)): Path<(String, String, String, String)>,
    body: Body,
) -> Response {
    let id = match PackageId::new(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let platform = match Platform::new(&os, &arch) {
        Ok(platform) => platform,
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("invalid platform: {e}")),
    };
    if let Err(e) = state.check_package_upload(&id) {
        return package_error(e);
    }
    let mut reservation = match state.admit_upload() {
        Ok(reservation) => reservation,
        Err(full) => return error(StatusCode::INSUFFICIENT_STORAGE, full.to_string()),
    };
    // The artifact is streamed into the blob store as it arrives and bounded on the way: taking it
    // as `Bytes` would mean holding a whole program in memory — twice — before writing it out.
    // The store reads on a thread of its own; this side hands it each chunk, and the end only once
    // every limit has passed, so a refused or cancelled upload stores nothing.
    let (chunks, receiver) = tokio::sync::mpsc::channel(8);
    let store = tokio::task::spawn_blocking({
        let state = state.clone();
        let (id, platform) = (id.clone(), platform.clone());
        move || state.put_package_entry(&id, &platform, &mut ChunkReader::new(receiver))
    });
    let streamed = stream_upload(body, &chunks, state.max_package_size(), &mut reservation).await;
    let streamed = streamed.and_then(|written| {
        reservation
            .admit_artifact()
            .map(|()| written)
            .map_err(UploadError::StoreFull)
    });
    let written = match streamed {
        Ok(written) => {
            // The end of the artifact: the store may commit it now. A store that has already
            // given up answers below.
            let _ = chunks.send(Chunk::End).await;
            written
        }
        Err(e) => {
            // Without the end, the store's stream fails and nothing is stored.
            drop(chunks);
            let _ = store.await;
            return match e {
                UploadError::TooLarge(limit) => error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("the artifact exceeds the {limit}-byte package size limit"),
                ),
                UploadError::StoreFull(full) => {
                    error(StatusCode::INSUFFICIENT_STORAGE, full.to_string())
                }
                UploadError::Io(e) => error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("the upload could not be stored: {e}"),
                ),
            };
        }
    };
    drop(chunks);
    let committed = store
        .await
        .unwrap_or_else(|e| Err(format!("the upload could not be stored: {e}")));
    // Stored now, or gone: either way the store counts it from here, and the upload no longer.
    drop(reservation);
    match committed {
        Ok(()) => {
            info!(set = %id, bytes = written, "package entry stored from the API");
            set_response(&state, &id)
        }
        Err(e) => package_error(e),
    }
}

/// Deletes one entry of a Package. Refused while the Package is assigned to an Agent — its bytes
/// are immutable (ADR-0025). The last entry taken away leaves an empty Package: a Package being
/// reassembled is a normal state, and deleting the Package is its own act.
#[utoipa::path(
    delete,
    path = "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type"),
        ("version" = String, Path, description = "The version"),
        ("os" = String, Path, description = "The entry's operating system"),
        ("arch" = String, Path, description = "The entry's architecture")
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "Invalid identity or platform", body = ErrorBody),
        (status = 404, description = "No such Set or entry, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Set is assigned to an Agent and its entries are immutable", body = ErrorBody),
        (status = 500, description = "The entry could not be deleted", body = ErrorBody)
    )
)]
async fn delete_package_entry(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version, os, arch)): Path<(String, String, String, String)>,
) -> Response {
    let (id, platform) = match artifact_of(&agent_type, &version, &os, &arch, "invalid platform: ")
    {
        Ok(pair) => pair,
        Err((status, why)) => return error(status, why),
    };
    match state.delete_package_entry(&id, &platform) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            format!("no entry {}-{} in set {id}", platform.os, platform.arch),
        ),
        Err(e) => package_error(e),
    }
}

/// Writes the operator's Ed25519 signature onto one entry of a Package (ADR-0033), as
/// `opamp-fleetctl package sign` prints it. One signature serves every Deployment that holds the
/// Package; an entry without one is offered to nobody.
///
/// With `[packages] verification_key` set the Server checks it and answers the entry's
/// `signature_state`. An `invalid` signature is stored all the same: the Server only reports, and
/// the Agent's own verification decides. Refused while the Package is assigned to an Agent, like
/// any other write to its entries (ADR-0025).
#[utoipa::path(
    put,
    path = "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type"),
        ("version" = String, Path, description = "The version"),
        ("os" = String, Path, description = "The entry's operating system"),
        ("arch" = String, Path, description = "The entry's architecture")
    ),
    request_body = SignatureSpec,
    responses(
        (status = 200, description = "The Set, with the signed entry and its signature_state", body = PackageSetView),
        (status = 400, description = "Invalid identity or platform, or a signature that is empty, not hex, or not 64 bytes", body = ErrorBody),
        (status = 404, description = "No such Set or entry, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Set is assigned to an Agent and its entries are immutable", body = ErrorBody),
        (status = 500, description = "The signature could not be persisted", body = ErrorBody)
    )
)]
async fn put_entry_signature(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version, os, arch)): Path<(String, String, String, String)>,
    Json(spec): Json<SignatureSpec>,
) -> Response {
    let (id, platform) = match artifact_of(&agent_type, &version, &os, &arch, "invalid platform: ")
    {
        Ok(pair) => pair,
        Err((status, why)) => return error(status, why),
    };
    let signature = match hex::decode(spec.signature.trim()) {
        Ok(bytes) => bytes,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                format!(
                    "the signature must be hex, as `opamp-fleetctl package sign` prints it: {e}"
                ),
            );
        }
    };
    match state.put_package_entry_signature(&id, &platform, signature) {
        Ok(_) => set_response(&state, &id),
        Err(e) => package_error(e),
    }
}

/// Takes one entry's signature away (ADR-0033): the entry is offered to nobody until it is signed
/// again. Refused while the Package is assigned to an Agent (ADR-0025).
#[utoipa::path(
    delete,
    path = "/api/v1/packages/{agent_type}/{version}/entries/{os}/{arch}/signature",
    tag = "packages",
    params(
        ("agent_type" = String, Path, description = "The Agent type"),
        ("version" = String, Path, description = "The version"),
        ("os" = String, Path, description = "The entry's operating system"),
        ("arch" = String, Path, description = "The entry's architecture")
    ),
    responses(
        (status = 200, description = "The Set, with the entry unsigned", body = PackageSetView),
        (status = 400, description = "Invalid identity or platform", body = ErrorBody),
        (status = 404, description = "No such Set, entry or signature, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Set is assigned to an Agent and its entries are immutable", body = ErrorBody),
        (status = 500, description = "The change could not be persisted", body = ErrorBody)
    )
)]
async fn delete_entry_signature(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version, os, arch)): Path<(String, String, String, String)>,
) -> Response {
    let (id, platform) = match artifact_of(&agent_type, &version, &os, &arch, "invalid platform: ")
    {
        Ok(pair) => pair,
        Err((status, why)) => return error(status, why),
    };
    match state.remove_package_entry_signature(&id, &platform) {
        Ok(true) => set_response(&state, &id),
        Ok(false) => error(
            StatusCode::NOT_FOUND,
            format!(
                "entry {}-{} of set {id} carries no signature",
                platform.os, platform.arch
            ),
        ),
        Err(e) => package_error(e),
    }
}

/// Serves an entry's artifact bytes — the `download_url` the Agent is offered points here.
///
/// `200` with the bytes, `400` for a missing or invalid platform or identity, `404` for a Package
/// without an uploaded artifact for that platform.
async fn download_package(
    State(state): State<Arc<AppState>>,
    Path((agent_type, version)): Path<(String, String)>,
    Query(query): Query<PlatformQuery>,
    request: Request,
) -> Response {
    // A read: a pinned Package an older Server stored under a non-SemVer version is still offered
    // (ADR-0043 clause 3), so its bytes are still served.
    let id = match PackageId::load(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let platform = match query.platform() {
        Ok(platform) => platform,
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("invalid platform: {e}")),
    };
    // One answer for every artifact this requester may not fetch, whether or not the store holds
    // it, so the store cannot be listed by probing (ADR-0026 clause 38).
    let not_found = || {
        error(
            StatusCode::NOT_FOUND,
            format!(
                "no set {id} with an artifact for {}-{}",
                platform.os, platform.arch
            ),
        )
    };
    // A member certificate fetches only what is offered to an Agent its host speaks for (ADR-0026
    // clause 3). The download guard admitted the certificate and hands over what it proves; a
    // request without one exists only where no certificate is required, and is tested here no
    // more than at admission.
    if let Some(proofs) = request.extensions().get::<crate::transport::Proofs>() {
        let host = proofs.host.as_deref();
        if !host.is_some_and(|host| state.offers_artifact(host, &id, &platform)) {
            state.audit_refusal(
                crate::audit::Entry::new("download.refused", "refused")
                    .peer(crate::transport::peer_ip(&request))
                    .with("plane", "agent")
                    .with("check", "not offered")
                    .with("host", host.map(str::to_string))
                    .with(
                        "serial",
                        proofs.certificate.as_ref().map(|(id, _)| id.serial.clone()),
                    )
                    .with("agent_type", id.agent_type.clone())
                    .with("version", id.version.clone())
                    .with("platform", platform.tag()),
            );
            return not_found();
        }
    }
    let Some((sha256, size)) = state
        .packages()
        .and_then(|store| store.artifact(&id, &platform))
    else {
        return not_found();
    };
    // Streamed from the blob store, never buffered: a fleet updating at once means many concurrent
    // downloads of the same artifact, and each one holding a copy of a program in memory is how a
    // rollout takes the Server down with it.
    let opened = state
        .packages()
        .map(|store| store.open_artifact(&sha256))
        .unwrap_or_else(|| Err("package delivery is not configured".to_string()));
    let bytes = match opened {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(package = %id, error = %e, "cannot open the stored artifact");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("the artifact of {id} cannot be read"),
            );
        }
    };
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        // So the Agent can size the download, and a truncated transfer is detectable as one.
        .header(header::CONTENT_LENGTH, size)
        .body(Body::from_stream(read_chunks(bytes)))
        .unwrap_or_else(|e| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot serve the artifact of {id}: {e}"),
            )
        })
}

/// Why a streamed upload did not become an artifact.
enum UploadError {
    /// The body grew past the configured package limit; the number is that limit.
    TooLarge(usize),
    /// The body, with the uploads in progress beside it, would take the store past its ceiling.
    StoreFull(crate::fleet::StoreFull),
    Io(std::io::Error),
}

/// What the request side hands the store's reader: the next chunk of the artifact, or its end.
enum Chunk {
    Data(axum::body::Bytes),
    End,
}

/// The upload as the blob store reads it (ADR-0037 clause 4): the request's chunks, handed over a
/// channel to the thread the store reads on. A channel that closes before [`Chunk::End`] is a
/// failed stream — a refused, cut-off or cancelled upload — so the store keeps nothing of it.
struct ChunkReader {
    receiver: tokio::sync::mpsc::Receiver<Chunk>,
    current: axum::body::Bytes,
    ended: bool,
}

impl ChunkReader {
    fn new(receiver: tokio::sync::mpsc::Receiver<Chunk>) -> Self {
        ChunkReader {
            receiver,
            current: axum::body::Bytes::new(),
            ended: false,
        }
    }
}

impl std::io::Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            if self.ended {
                return Ok(0);
            }
            match self.receiver.blocking_recv() {
                Some(Chunk::Data(bytes)) => self.current = bytes,
                Some(Chunk::End) => self.ended = true,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the upload ended before its last byte",
                    ))
                }
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current.split_to(n));
        Ok(n)
    }
}

/// Streams a request body to the store's reader, refusing it the moment it grows past `limit` or
/// takes the store past its ceiling. Returns how many bytes were handed over.
async fn stream_upload(
    body: Body,
    chunks: &tokio::sync::mpsc::Sender<Chunk>,
    limit: usize,
    reservation: &mut crate::fleet::UploadReservation<'_>,
) -> Result<u64, UploadError> {
    use futures_util::StreamExt;

    let mut stream = body.into_data_stream();
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| UploadError::Io(std::io::Error::other(e)))?;
        written += chunk.len() as u64;
        if written > limit as u64 {
            return Err(UploadError::TooLarge(limit));
        }
        reservation
            .grow(chunk.len() as u64)
            .map_err(UploadError::StoreFull)?;
        if chunks.send(Chunk::Data(chunk)).await.is_err() {
            // The store stopped reading: it failed, and says why when it is awaited.
            break;
        }
    }
    Ok(written)
}

/// A stream of an artifact's chunks, read on a thread of its own, so a response body never
/// materialises whole and a slow disk never holds up the runtime.
fn read_chunks(
    mut bytes: Box<dyn std::io::Read + Send>,
) -> impl futures_util::Stream<Item = std::io::Result<Vec<u8>>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::task::spawn_blocking(move || loop {
        let mut buffer = vec![0u8; 64 * 1024];
        let next = match bytes.read(&mut buffer) {
            Ok(0) => return,
            Ok(read) => {
                buffer.truncate(read);
                Ok(buffer)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => Err(e),
        };
        let failed = next.is_err();
        if sender.blocking_send(next).is_err() || failed {
            return;
        }
    });
    futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    })
}

// -------------------------------------------------------------------------------------------
// Deployments (ADR-0026, ADR-0034): the aim and the act — what a Package and a Configuration do
// not have.
// -------------------------------------------------------------------------------------------

/// One Deployment as the REST API shows it.
#[derive(Serialize, ToSchema)]
struct DeploymentView {
    /// The operator's name for this channel, and the path segment that addresses it.
    name: String,
    /// Equality pairs that must all match an attribute the Agent reported, labels included
    /// (ADR-0023). **Never empty**: there is no fleet-wide default, because an Agent belongs to at
    /// most one Deployment and an empty Selector would match every Agent in every other channel.
    selector: std::collections::BTreeMap<String, String>,
    /// At most one Package per Agent type — an Agent has one binary to replace.
    packages: Vec<DeploymentPackageView>,
    /// The Configurations it holds, by name, in name order (ADR-0034). Each reaches the Agents of
    /// this channel whose type it fits.
    configurations: Vec<String>,
    /// Agents this channel claims, and no other does.
    ///
    /// **Zero is the value worth looking at**: a channel aims at nobody when its Selector names an
    /// attribute no Agent reports, or a value none of them carries — and neither is a rejected
    /// write, so nothing else would say so.
    claiming_agents: usize,
    /// Of those, the Agents a rollout act would actually move — what it would release to them
    /// differs from what their assignment pins (ADR-0034 clause 6). Zero here with a non-zero
    /// `claiming_agents` means everyone in the channel already holds it: nothing to do, and nothing
    /// wrong.
    targeted_agents: usize,
    /// Agents this channel matches that **another Deployment matches too**. They are offered nothing
    /// new until an operator narrows a Selector, and they are not in `claiming_agents`.
    conflicting_agents: usize,
}

/// One Package a Deployment holds. Its entries and their signatures are the Package's own
/// (`GET /api/v1/packages`, ADR-0033).
#[derive(Serialize, ToSchema)]
struct DeploymentPackageView {
    /// The Agent type this Package is built for — also the key under which this Deployment holds
    /// it, and the name it carries on the wire.
    agent_type: String,
    version: String,
    /// What an operator reads: the Agent type and the version together.
    display_name: String,
}

impl DeploymentView {
    fn of(deployment: Deployment, reach: crate::fleet::DeploymentReach) -> Self {
        let mut packages: Vec<DeploymentPackageView> = deployment
            .packages
            .values()
            .map(|id| DeploymentPackageView {
                agent_type: id.agent_type.clone(),
                version: id.version.clone(),
                display_name: id.display_name(),
            })
            .collect();
        packages.sort_by(|a, b| a.agent_type.cmp(&b.agent_type));
        DeploymentView {
            name: deployment.name,
            selector: deployment.selector,
            packages,
            configurations: deployment.configurations.into_iter().collect(),
            claiming_agents: reach.claiming,
            targeted_agents: reach.targeted,
            conflicting_agents: reach.conflicting,
        }
    }
}

/// The writable part of a Deployment — the body of `PUT /api/v1/deployments/{name}`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct DeploymentSpec {
    /// The channel this Deployment aims at. Required and never empty.
    selector: std::collections::BTreeMap<String, String>,
}

/// One artifact's Ed25519 signature, as the operator supplies it (ADR-0033).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct SignatureSpec {
    /// The signature over the entry's statement — the Agent type, the version and the artifact's
    /// SHA-256 — hex-encoded, as `opamp-fleetctl package sign` prints it.
    signature: String,
}

/// Maps a store refusal onto the status code that says the same thing.
fn deployment_error(refusal: DeploymentError) -> Response {
    use DeploymentError as E;
    let text = refusal.to_string();
    match refusal {
        E::Invalid(_) => error(StatusCode::BAD_REQUEST, text),
        E::NotFound | E::Missing(_) => error(StatusCode::NOT_FOUND, text),
        E::TypeTaken { .. } | E::Conflict(_) => error(StatusCode::CONFLICT, text),
        E::Storage(_) => error(StatusCode::INTERNAL_SERVER_ERROR, text),
    }
}

/// The Deployment store, or the `404` that says package delivery is not armed on this Server.
fn deployments(state: &AppState) -> Result<&DeploymentStore, Refusal> {
    state.deployment_store().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "package delivery is not configured on this Server".to_string(),
        )
    })
}

/// A status and what to say with it — carried instead of a whole `Response` so a helper's error
/// path stays small (the response is built once, at the handler that returns it).
type Refusal = (StatusCode, String);

/// Every Deployment, in name order.
#[utoipa::path(
    get,
    path = "/api/v1/deployments",
    tag = "deployments",
    responses(
        (status = 200, description = "Every Deployment, in name order", body = [DeploymentView]),
        (status = 404, description = "Package delivery is not configured", body = ErrorBody)
    )
)]
async fn list_deployments(State(state): State<Arc<AppState>>) -> Response {
    match deployments(&state) {
        Ok(store) => {
            let reach = state.deployment_reach();
            Json(
                store
                    .list()
                    .into_iter()
                    .map(|deployment| {
                        let counts = reach.get(&deployment.name).copied().unwrap_or_default();
                        DeploymentView::of(deployment, counts)
                    })
                    .collect::<Vec<_>>(),
            )
            .into_response()
        }
        Err((status, why)) => error(status, why),
    }
}

/// One Deployment.
#[utoipa::path(
    get,
    path = "/api/v1/deployments/{name}",
    tag = "deployments",
    params(("name" = String, Path, description = "the Deployment's name")),
    responses(
        (status = 200, description = "The Deployment", body = DeploymentView),
        (status = 404, description = "No such Deployment, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn get_deployment(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    let store = match deployments(&state) {
        Ok(store) => store,
        Err((status, why)) => return error(status, why),
    };
    match store.get(&name) {
        Some(deployment) => deployment_response(&state, deployment),
        None => error(StatusCode::NOT_FOUND, format!("no deployment {name:?}")),
    }
}

/// Creates a Deployment, or replaces the channel it aims at.
///
/// **This distributes nothing** (ADR-0025). Saving is saving; the rollout act is its own press,
/// and until it happens no Agent is offered anything new.
///
/// The Selector must name at least one pair. There is deliberately no fleet-wide default: an Agent
/// belongs to at most one Deployment, so an empty Selector would collide with every other channel the
/// moment a second one exists — and it is what a forgotten field looks like. Channels are a partition
/// over an attribute every Agent carries (`channel = "stable"`), set at provisioning or as a Server
/// label (ADR-0024), because a Selector is equality and cannot express "not".
#[utoipa::path(
    put,
    path = "/api/v1/deployments/{name}",
    tag = "deployments",
    params(("name" = String, Path, description = "the Deployment's name")),
    request_body = DeploymentSpec,
    responses(
        (status = 200, description = "The stored Deployment — distributed to nobody until rolled out", body = DeploymentView),
        (status = 400, description = "Invalid name, or a Selector that names no pair", body = ErrorBody),
        (status = 404, description = "Package delivery is not configured", body = ErrorBody)
    )
)]
async fn put_deployment(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(spec): Json<DeploymentSpec>,
) -> Response {
    let store = match deployments(&state) {
        Ok(store) => store,
        Err((status, why)) => return error(status, why),
    };
    match store.put(&name, spec.selector) {
        Ok(deployment) => deployment_response(&state, deployment),
        Err(e) => deployment_error(e),
    }
}

/// Deletes a Deployment — refused with `409` while an Agent's assignment names it, saying how many
/// (ADR-0034 clause 8). Rolling those Agents out through another Deployment, or forgetting them,
/// comes first. Nothing is uninstalled either way (ADR-0025).
#[utoipa::path(
    delete,
    path = "/api/v1/deployments/{name}",
    tag = "deployments",
    params(("name" = String, Path, description = "the Deployment's name")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "No such Deployment, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "An Agent's assignment still names this Deployment")
    )
)]
async fn delete_deployment(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    if let Err((status, why)) = deployments(&state) {
        return error(status, why);
    }
    match state.delete_deployment(&name) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no deployment {name:?}")),
        Err(e) => deployment_error(e),
    }
}

/// Re-aims a Deployment. Editable in every state (ADR-0034 clause 7) — moving a channel is how a
/// rollout proceeds. It changes whom the *next* act would reach, never a running offer.
#[utoipa::path(
    put,
    path = "/api/v1/deployments/{name}/selector",
    tag = "deployments",
    params(("name" = String, Path, description = "the Deployment's name")),
    request_body = DeploymentSpec,
    responses(
        (status = 200, description = "The re-aimed Deployment", body = DeploymentView),
        (status = 400, description = "A Selector that names no pair", body = ErrorBody),
        (status = 404, description = "No such Deployment, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn put_deployment_selector(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(spec): Json<DeploymentSpec>,
) -> Response {
    // The same write as `PUT /api/v1/deployments/{name}`, except that this route only re-aims:
    // it never creates.
    if let Ok(store) = deployments(&state) {
        if store.get(&name).is_none() {
            return error(StatusCode::NOT_FOUND, format!("no deployment {name:?}"));
        }
    }
    put_deployment(State(state), Path(name), Json(spec)).await
}

/// Puts a Package into a Deployment.
///
/// At most one per Agent type: a second is refused `409` naming what is already held, because two
/// would collide on the wire map key *and* fit the same Agent. Writing the same one again is the
/// same request arriving twice and succeeds; `?replace=true` is how an operator says they mean to
/// swap the version this channel runs.
#[utoipa::path(
    put,
    path = "/api/v1/deployments/{name}/packages/{agent_type}/{version}",
    tag = "deployments",
    params(
        ("name" = String, Path, description = "the Deployment's name"),
        ("agent_type" = String, Path, description = "the Package's Agent type"),
        ("version" = String, Path, description = "the Package's version"),
        ("replace" = Option<bool>, Query, description = "swap the Package held for this Agent type")
    ),
    responses(
        (status = 200, description = "The Deployment, with the Package", body = DeploymentView),
        (status = 400, description = "Invalid Agent type or version", body = ErrorBody),
        (status = 404, description = "No such Deployment or Package, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Deployment already holds a Package for this Agent type", body = ErrorBody)
    )
)]
async fn put_deployment_package(
    State(state): State<Arc<AppState>>,
    Path((name, agent_type, version)): Path<(String, String, String)>,
    Query(replace): Query<ReplaceQuery>,
) -> Response {
    let id = match PackageId::new(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    // A channel cannot offer what the store does not hold, so a reference to a Package that is not
    // there is a mistake, not a reservation for one uploaded later.
    match state.packages() {
        Some(packages) if packages.summary(&id).is_some() => {}
        _ => {
            return error(
                StatusCode::NOT_FOUND,
                format!("no package {id} — upload it before a deployment can offer it"),
            )
        }
    }
    match state.put_deployment_package(&name, &id, replace.replace.unwrap_or(false)) {
        Ok(deployment) => deployment_response(&state, deployment),
        Err(e) => deployment_error(e),
    }
}

/// Takes a Package out of a Deployment. Editable in every state (ADR-0034 clause 7): an Agent
/// already released keeps the Package its assignment pins until the next press, which drops it.
#[utoipa::path(
    delete,
    path = "/api/v1/deployments/{name}/packages/{agent_type}/{version}",
    tag = "deployments",
    params(
        ("name" = String, Path, description = "the Deployment's name"),
        ("agent_type" = String, Path, description = "the Package's Agent type"),
        ("version" = String, Path, description = "the Package's version")
    ),
    responses(
        (status = 200, description = "The Deployment, without the Package", body = DeploymentView),
        (status = 400, description = "Invalid Agent type or version", body = ErrorBody),
        (status = 404, description = "No such Deployment or Package in it, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn delete_deployment_package(
    State(state): State<Arc<AppState>>,
    Path((name, agent_type, version)): Path<(String, String, String)>,
) -> Response {
    // Taking a Package out writes nothing to it, so an older non-SemVer one may leave too.
    let id = match PackageId::load(&agent_type, &version) {
        Ok(id) => id,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    match state.remove_deployment_package(&name, &id) {
        Ok(deployment) => deployment_response(&state, deployment),
        Err(e) => deployment_error(e),
    }
}

/// Puts a Configuration into a Deployment (ADR-0034 clause 4). A Configuration may sit in several
/// Deployments; holding it already is the same request arriving twice. **This distributes
/// nothing**: the Agents of the channel see it waiting until the next press.
#[utoipa::path(
    put,
    path = "/api/v1/deployments/{name}/configurations/{configuration}",
    tag = "deployments",
    params(
        ("name" = String, Path, description = "the Deployment's name"),
        ("configuration" = String, Path, description = "the Configuration's name")
    ),
    responses(
        (status = 200, description = "The Deployment, with the Configuration", body = DeploymentView),
        (status = 404, description = "No such Deployment or Configuration, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn put_deployment_configuration(
    State(state): State<Arc<AppState>>,
    Path((name, configuration)): Path<(String, String)>,
) -> Response {
    match state.put_deployment_configuration(&name, &configuration) {
        Ok(deployment) => deployment_response(&state, deployment),
        Err(e) => deployment_error(e),
    }
}

/// Takes a Configuration out of a Deployment. Editable in every state (ADR-0034 clause 7): an
/// Agent already released keeps the revision its assignment pins until the next press, which drops
/// it from the Agent's map.
#[utoipa::path(
    delete,
    path = "/api/v1/deployments/{name}/configurations/{configuration}",
    tag = "deployments",
    params(
        ("name" = String, Path, description = "the Deployment's name"),
        ("configuration" = String, Path, description = "the Configuration's name")
    ),
    responses(
        (status = 200, description = "The Deployment, without the Configuration", body = DeploymentView),
        (status = 404, description = "No such Deployment, or it does not hold the Configuration, or package delivery is not configured", body = ErrorBody)
    )
)]
async fn delete_deployment_configuration(
    State(state): State<Arc<AppState>>,
    Path((name, configuration)): Path<(String, String)>,
) -> Response {
    match state.remove_deployment_configuration(&name, &configuration) {
        Ok(deployment) => deployment_response(&state, deployment),
        Err(e) => deployment_error(e),
    }
}

/// `?replace=true` on putting a Package into a Deployment.
#[derive(Deserialize, IntoParams)]
struct ReplaceQuery {
    replace: Option<bool>,
}

/// Rolls a Deployment out to **every Agent it claims and would move** (ADR-0034 clause 6).
///
/// **This is the moment the fleet changes.** Each such Agent's assignment is replaced with this
/// channel's release, pinned as of this press: the Package it holds for the Agent's type, if that
/// is a candidate, and every Configuration it holds that fits the Agent's type, at its saved
/// revision. The hash gates send only what changed. An Agent that enrols — or is labelled into the
/// channel — later is *not* included: it surfaces in the fleet view as waiting, for its own act.
///
/// An Agent some **other** Deployment also claims is skipped rather than counted. Its conflict is
/// reported on the Agent, and a press that quietly resolved it here would be the ranking this
/// model removed wearing a different hat. Nothing is ever uninstalled by an assignment change; an
/// Agent keeps running what it installed.
#[utoipa::path(
    post,
    path = "/api/v1/deployments/{name}/rollout",
    tag = "deployments",
    params(("name" = String, Path, description = "the Deployment's name")),
    responses(
        (status = 200, description = "Rolled out; how many Agents were assigned", body = RolloutOutcome),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such Deployment, or package delivery is not configured", body = ErrorBody),
        (status = 409, description = "The Deployment holds no Package and no Configuration, or a Package with an unsigned entry", body = ErrorBody)
    )
)]
async fn rollout_deployment(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(name): Path<String>,
) -> Response {
    match state.rollout_deployment(&name) {
        Ok(assigned_agents) => {
            info!(deployment = %name, agents = assigned_agents, "deployment rolled out from the API");
            Json(RolloutOutcome { assigned_agents }).into_response()
        }
        Err(e) => rollout_error(e),
    }
}

/// One Deployment as the API answers with it, with the reach counts read from the fleet — so every
/// response says whom this channel reaches as of now, and not as of whenever it was written.
fn deployment_response(state: &AppState, deployment: Deployment) -> Response {
    let reach = state
        .deployment_reach()
        .get(&deployment.name)
        .copied()
        .unwrap_or_default();
    Json(DeploymentView::of(deployment, reach)).into_response()
}

/// The enrolment window as the API answers with it (ADR-0021 clause 20).
#[derive(Serialize, ToSchema)]
struct EnrolmentWindow {
    /// Whether a host with a bootstrap certificate may enrol now.
    open: bool,
    /// When the window closes, in milliseconds since the Unix epoch; absent while it is closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    until_ms: Option<u64>,
}

/// How long to open the enrolment window for.
#[derive(Deserialize, ToSchema)]
struct OpenWindow {
    /// From 1 to 86400 seconds.
    open_for_secs: u64,
}

/// One enrolment request waiting for an operator (ADR-0021 clause 22).
#[derive(Serialize, ToSchema)]
struct PendingEnrolment {
    /// What `approve` and `reject` name: the SHA-256 fingerprint of the requested public key.
    id: String,
    arrived_ms: u64,
    /// The address the request came from, on a direct connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    /// The host of the Gateway the request came through, in place of a peer address (ADR-0039
    /// clause 4).
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    /// The SHA-256 fingerprint of the requested public key, hex — the Client logs the same value,
    /// so an operator can match a request to a host.
    key_fingerprint: String,
    /// The six subject values of the bootstrap certificate the request proves: what an
    /// approval carries into the host certificate (ADR-0036 clause 5). The request's own subject
    /// is not listed, because it is neither trusted nor carried. Absent when that certificate's
    /// subject cannot be carried — `subject_refusal` then says why.
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_subject: Option<HostSubject>,
    /// Why the bootstrap certificate's subject breaks the rules of ADR-0036 clause 1, naming the
    /// attribute: an approval is refused `409` with this reason, and nothing is signed. Absent
    /// when the values can be carried.
    #[serde(skip_serializing_if = "Option::is_none")]
    subject_refusal: Option<String>,
    /// The SHA-256 fingerprint of that bootstrap certificate, hex.
    bootstrap_fingerprint: String,
    /// Its serial, lowercase hex: the `serial` of `GET /api/v1/bootstrap-certificates` when this
    /// Server issued it.
    bootstrap_serial: String,
}

/// What an operator asks a bootstrap certificate for (ADR-0028 clauses 21 to 23, ADR-0029).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct IssueBootstrapRequest {
    /// Required, with `organization` and `organizational_unit`.
    #[serde(default)]
    #[schema(required = true)]
    subject: Option<BootstrapSubject>,
    /// 1 to 90; 10 when absent. Cut to the bootstrap CA's end.
    #[serde(default)]
    validity_days: Option<u32>,
    /// 8 to 128 characters without a control character (ADR-0048). Required: the Server keeps a PKCS#12
    /// file of the certificate and its key under this password, to be downloaded until the
    /// certificate ends or is revoked; the key is never answered in PEM. The password is kept
    /// nowhere. Read as absent when it is missing, so the refusal names it.
    #[serde(default)]
    #[schema(format = Password, required = true)]
    password: Option<String>,
}

/// The subject of a bootstrap certificate: these attributes only, `organization` and
/// `organizational_unit` required and the others optional; the Server sets the common name. Every
/// host certificate issued from it carries them, and they describe and select the Host through
/// `fleet.host.*`; they authorize nothing (ADR-0036 clause 1).
#[derive(Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct BootstrapSubject {
    /// C — exactly two upper-case letters, an ISO 3166-1 alpha-2 code.
    country: Option<String>,
    /// ST — 1 to 64 characters without a control character, as are the others.
    state: Option<String>,
    /// L.
    locality: Option<String>,
    /// O — the customer, typically. Required; absent is refused `400` naming it.
    #[schema(required = true)]
    organization: Option<String>,
    /// OU — the site, typically. Required; absent is refused `400` naming it.
    #[schema(required = true)]
    organizational_unit: Option<String>,
    /// organizationIdentifier (2.5.4.97) — a customer or contract number, a UUID for instance.
    organization_identifier: Option<String>,
}

/// An issued bootstrap certificate, never with its private key: the key is in the PKCS#12 file of
/// `GET /api/v1/bootstrap-certificates/{serial}/p12` (ADR-0036 clause 8).
#[derive(Serialize, ToSchema)]
struct IssuedBootstrap {
    /// What a revocation names, with the authority `bootstrap`.
    serial: String,
    subject: String,
    not_before_ms: u64,
    not_after_ms: u64,
    certificate_pem: String,
}

/// A bootstrap certificate on record (ADR-0028 clause 24).
#[derive(Serialize, ToSchema)]
struct BootstrapView {
    serial: String,
    subject: String,
    /// The SHA-256 fingerprint of its public key, hex.
    key_fingerprint: String,
    issued_ms: u64,
    not_after_ms: u64,
    revoked: bool,
    /// Whether its PKCS#12 file can be downloaded (ADR-0029 clause 4).
    p12: bool,
}

/// The valid bootstrap certificates this Server issued, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/bootstrap-certificates",
    tag = "enrolment",
    responses(
        (status = 200, description = "The valid bootstrap certificates, oldest first", body = Vec<BootstrapView>),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody)
    )
)]
async fn list_bootstrap_certificates(State(state): State<Arc<AppState>>) -> Response {
    let Some(bootstrap) = state.bootstrap() else {
        return enrolment_off();
    };
    let revoked = |id: &crate::revocation::CertId| {
        state
            .revocations()
            .is_some_and(|revocations| revocations.is_certificate_revoked(id))
    };
    let list: Vec<BootstrapView> = bootstrap
        .list()
        .into_iter()
        .map(|entry| BootstrapView {
            revoked: revoked(&entry.id),
            p12: entry.p12 && !revoked(&entry.id),
            serial: entry.serial,
            subject: entry.subject,
            key_fingerprint: entry.key_fingerprint,
            issued_ms: entry.issued_ms,
            not_after_ms: entry.not_after_ms,
        })
        .collect();
    Json(list).into_response()
}

/// Issues a bootstrap certificate with the subject an operator names, which holds at least an
/// organization and an organizational unit, under the password the request names. The key is in no
/// answer: the Server keeps it, encrypted under that password in a PKCS#12 file, for download
/// (ADR-0029, ADR-0036 clause 8). A host with it may only ask to enrol, inside an open window, and
/// an operator approves (ADR-0028).
#[utoipa::path(
    post,
    path = "/api/v1/bootstrap-certificates",
    tag = "enrolment",
    request_body = IssueBootstrapRequest,
    responses(
        (status = 201, description = "Issued; the certificate, its key kept in the PKCS#12 file only", body = IssuedBootstrap),
        (status = 400, description = "No organization, organizational_unit or password, a subject attribute this route does not know, a country that is not two upper-case letters, another value out of bounds, validity_days outside 1 to 90, or a password outside 8 to 128 characters", body = ErrorBody),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody),
        (status = 409, description = "No bootstrap_ca_key_file is configured, the bootstrap CA has ended, or the record is full", body = ErrorBody),
        (status = 503, description = "The audit record cannot be written; nothing was handed out", body = ErrorBody)
    )
)]
async fn issue_bootstrap_certificate(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Json(body): Json<serde_json::Value>,
) -> Response {
    use crate::bootstrap::IssueError;
    let Some(bootstrap) = state.bootstrap() else {
        return enrolment_off();
    };
    let request = match serde_json::from_value::<IssueBootstrapRequest>(body) {
        Ok(request) => {
            let subject = request.subject.unwrap_or_default();
            crate::bootstrap::IssueRequest {
                subject: crate::bootstrap::Subject {
                    country: subject.country,
                    state: subject.state,
                    locality: subject.locality,
                    organization: subject.organization,
                    organizational_unit: subject.organizational_unit,
                    organization_identifier: subject.organization_identifier,
                },
                validity_days: request.validity_days,
                password: request.password.map(crate::bootstrap::Password),
            }
        }
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    // Off the async workers: sealing a PKCS#12 file takes the better part of a second, as
    // password hashing does (ADR-0029).
    let issuer = bootstrap.clone();
    let issued = match tokio::task::spawn_blocking(move || issuer.issue(&request)).await {
        Ok(issued) => issued,
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    match issued {
        Ok(pair) => {
            // The key leaves only once the issuance is on the record (ADR-0022): a refused record
            // leaves a listed, revocable entry and no key in anyone's hands.
            if let Some(audit) = state.audit() {
                let recorded = audit.record(
                    crate::audit::Entry::new("enrolment.bootstrap_issued", "issued")
                        .with("serial", pair.serial.clone())
                        .with("subject", pair.subject.clone())
                        .with("not_after_ms", pair.not_after_ms)
                        .with("p12", "true"),
                );
                if recorded.is_err() {
                    // Nor later: an issuance that is not on the record keeps no file to download.
                    let _ = bootstrap.forget_p12(&pair.serial);
                    return error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "the audit record cannot be written now; nothing was handed out",
                    );
                }
            }
            info!(serial = %pair.serial, subject = %pair.subject, "bootstrap certificate issued");
            (
                StatusCode::CREATED,
                [(header::CACHE_CONTROL, "no-store")],
                Json(IssuedBootstrap {
                    serial: pair.serial,
                    subject: pair.subject,
                    not_before_ms: pair.not_before_ms,
                    not_after_ms: pair.not_after_ms,
                    certificate_pem: pair.certificate_pem,
                }),
            )
                .into_response()
        }
        Err(IssueError::NoKey) => error(
            StatusCode::CONFLICT,
            "this Server does not hold the bootstrap CA's key — set [enrolment] \
             bootstrap_ca_key_file",
        ),
        Err(IssueError::Invalid(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(IssueError::Full) => error(
            StatusCode::CONFLICT,
            format!(
                "{} valid bootstrap certificates are on record already",
                crate::bootstrap::MAX_VALID
            ),
        ),
        Err(IssueError::CaEnded) => error(
            StatusCode::CONFLICT,
            "the bootstrap CA has ended — replace it with `opamp-fleetctl pki bootstrap-ca`",
        ),
        Err(IssueError::Failed(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The PKCS#12 file of a bootstrap certificate, as often as it is asked,
/// until the certificate ends or is revoked (ADR-0029 clause 4). Each download is on the record.
#[utoipa::path(
    get,
    path = "/api/v1/bootstrap-certificates/{serial}/p12",
    tag = "enrolment",
    params(("serial" = String, Path, description = "the serial, as the list names it")),
    responses(
        (status = 200, description = "The PKCS#12 file, `bootstrap.p12`", content_type = "application/x-pkcs12", body = Vec<u8>),
        (status = 404, description = "No such certificate, no file kept for it, revoked or ended — or enrolment is not configured", body = ErrorBody),
        (status = 503, description = "The audit record cannot be written; nothing was handed out", body = ErrorBody)
    )
)]
async fn download_bootstrap_p12(
    State(state): State<Arc<AppState>>,
    Path(serial): Path<String>,
) -> Response {
    let Some(bootstrap) = state.bootstrap() else {
        return enrolment_off();
    };
    let none = || {
        error(
            StatusCode::NOT_FOUND,
            format!("no PKCS#12 file for the bootstrap certificate {serial:?}"),
        )
    };
    let (entry, file) = match bootstrap.p12(&serial) {
        Ok(Some(found)) => found,
        Ok(None) => return none(),
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    // A revocation removes the file before it is answered; one that could not is still no
    // licence to hand it out.
    if state
        .revocations()
        .is_some_and(|revocations| revocations.is_certificate_revoked(&entry.id))
    {
        let _ = bootstrap.forget_p12(&entry.serial);
        return none();
    }
    if let Some(audit) = state.audit() {
        let recorded = audit.record(
            crate::audit::Entry::new("enrolment.bootstrap_p12_downloaded", "downloaded")
                .with("serial", entry.serial.clone()),
        );
        if recorded.is_err() {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the audit record cannot be written now; nothing was handed out",
            );
        }
    }
    info!(serial = %entry.serial, "bootstrap PKCS#12 file downloaded");
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pkcs12".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", fleet_core::pkcs12::FILE_NAME),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        file,
    )
        .into_response()
}

/// Deletes a revoked bootstrap certificate's entry, and any PKCS#12 file of it, from the record.
/// Its revocation stays on the list, so it stays refused for as long as it is valid (ADR-0029 clause 15).
#[utoipa::path(
    delete,
    path = "/api/v1/bootstrap-certificates/{serial}",
    tag = "enrolment",
    params(("serial" = String, Path, description = "the serial, as the list names it")),
    responses(
        (status = 204, description = "Deleted from the record; the revocation stays"),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such certificate on record, or enrolment is not configured", body = ErrorBody),
        (status = 409, description = "The certificate is not revoked — revoke it first", body = ErrorBody),
        (status = 503, description = "The audit record cannot be written; nothing was deleted", body = ErrorBody)
    )
)]
async fn delete_bootstrap_certificate(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(serial): Path<String>,
) -> Response {
    let Some(bootstrap) = state.bootstrap() else {
        return enrolment_off();
    };
    use crate::bootstrap::DeleteError;
    let revoked = |entry: &crate::bootstrap::Entry| {
        state
            .revocations()
            .is_some_and(|revocations| revocations.is_certificate_revoked(&entry.id))
    };
    let recorded = |entry: &crate::bootstrap::Entry| {
        state.audit().is_none_or(|audit| {
            audit
                .record(
                    crate::audit::Entry::new("enrolment.bootstrap_deleted", "deleted")
                        .with("serial", entry.serial.clone())
                        .with("subject", entry.subject.clone()),
                )
                .is_ok()
        })
    };
    match bootstrap.delete(&serial, revoked, recorded) {
        Ok(entry) => {
            info!(serial = %entry.serial, "revoked bootstrap certificate deleted from the record");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(DeleteError::NotFound) => error(
            StatusCode::NOT_FOUND,
            format!("no bootstrap certificate {serial:?} on record"),
        ),
        Err(DeleteError::NotRevoked) => error(
            StatusCode::CONFLICT,
            format!("the bootstrap certificate {serial:?} is not revoked — revoke it first"),
        ),
        Err(DeleteError::Unrecorded) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the audit record cannot be written now; nothing was deleted",
        ),
        Err(DeleteError::Failed(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

fn enrolment_off() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "enrolment is not configured — set [enrolment] bootstrap_ca_file",
    )
}

fn window_view(until_ms: Option<u64>) -> Response {
    Json(EnrolmentWindow {
        open: until_ms.is_some(),
        until_ms,
    })
    .into_response()
}

/// Whether hosts may enrol now, and until when.
#[utoipa::path(
    get,
    path = "/api/v1/enrolment/window",
    tag = "enrolment",
    responses(
        (status = 200, description = "Whether the window is open, and until when", body = EnrolmentWindow),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody)
    )
)]
async fn get_enrolment_window(State(state): State<Arc<AppState>>) -> Response {
    match state.enrolment() {
        Some(enrolment) => window_view(enrolment.window()),
        None => enrolment_off(),
    }
}

/// Opens the enrolment window for a bounded time, or moves its end. It is closed by default, and
/// persisted before this answers, so a Server restart keeps it open until its end (ADR-0037).
#[utoipa::path(
    post,
    path = "/api/v1/enrolment/window",
    tag = "enrolment",
    request_body = OpenWindow,
    responses(
        (status = 200, description = "The window, open until its new end", body = EnrolmentWindow),
        (status = 400, description = "open_for_secs is out of range", body = ErrorBody),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody),
        (status = 500, description = "The window could not be persisted; it is as it was", body = ErrorBody)
    )
)]
async fn open_enrolment_window(
    State(state): State<Arc<AppState>>,
    Json(spec): Json<OpenWindow>,
) -> Response {
    let Some(enrolment) = state.enrolment() else {
        return enrolment_off();
    };
    match enrolment.open(spec.open_for_secs) {
        Ok(until) => {
            info!(secs = spec.open_for_secs, "enrolment window opened");
            note(
                &state,
                crate::audit::Entry::new("enrolment.window", "opened").with("until_ms", until),
            );
            window_view(Some(until))
        }
        Err(crate::enrolment::WindowError::Invalid(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(crate::enrolment::WindowError::Store(e)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the enrolment window could not be persisted: {e}"),
        ),
    }
}

/// Closes the enrolment window now: every enrolling connection ends, and every pending request
/// expires.
#[utoipa::path(
    delete,
    path = "/api/v1/enrolment/window",
    tag = "enrolment",
    responses(
        (status = 204, description = "Closed"),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody),
        (status = 500, description = "Closed, but not persisted: a restart may find the window open until its end", body = ErrorBody)
    )
)]
async fn close_enrolment_window(State(state): State<Arc<AppState>>) -> Response {
    let Some(enrolment) = state.enrolment() else {
        return enrolment_off();
    };
    let expired = enrolment.pending().len();
    let saved = enrolment.close();
    info!("enrolment window closed");
    note(
        &state,
        crate::audit::Entry::new("enrolment.window", "closed").with("expired_requests", expired),
    );
    match saved {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "the enrolment window is closed, but that could not be persisted — a restart may \
                 find it open until its end: {e}"
            ),
        ),
    }
}

/// The enrolment requests waiting for an operator, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/enrolments",
    tag = "enrolment",
    responses(
        (status = 200, description = "The waiting enrolment requests, oldest first", body = Vec<PendingEnrolment>),
        (status = 404, description = "Enrolment is not configured", body = ErrorBody)
    )
)]
async fn list_enrolments(State(state): State<Arc<AppState>>) -> Response {
    let Some(enrolment) = state.enrolment() else {
        return enrolment_off();
    };
    let pending: Vec<PendingEnrolment> = enrolment
        .pending()
        .into_iter()
        .map(|p| PendingEnrolment {
            id: p.id,
            arrived_ms: p.arrived_ms,
            peer: p.requester.peer.map(|ip| ip.to_string()),
            gateway: p.requester.gateway.clone(),
            key_fingerprint: p.key_fingerprint,
            bootstrap_subject: p.requester.carried.clone().ok().map(Into::into),
            subject_refusal: p.requester.carried.err(),
            bootstrap_fingerprint: p.requester.bootstrap_fingerprint,
            bootstrap_serial: p.requester.bootstrap.serial,
        })
        .collect();
    Json(pending).into_response()
}

/// The host of the Gateway a pending request came through, which every audit entry of it names
/// (ADR-0039 clause 12).
fn through_gateway(state: &AppState, id: &str) -> Option<String> {
    state
        .enrolment()?
        .pending()
        .into_iter()
        .find(|pending| pending.id == id)?
        .requester
        .gateway
}

/// Approves one enrolment request: the client CA signs it, and the host is handed its certificate.
#[utoipa::path(
    post,
    path = "/api/v1/enrolments/{id}/approve",
    tag = "enrolment",
    params(("id" = String, Path, description = "the request's id")),
    responses(
        (status = 204, description = "Approved and signed"),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such pending request, or enrolment is not configured", body = ErrorBody),
        (status = 409, description = "The CA could not sign the request, its bootstrap certificate is revoked, or that certificate's subject breaks the rules of ADR-0036 clause 1 — the message names the attribute, and nothing is signed", body = ErrorBody),
        (status = 500, description = "The approval could not be persisted; the request still waits", body = ErrorBody)
    )
)]
async fn approve_enrolment(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(id): Path<String>,
) -> Response {
    let gateway = through_gateway(&state, &id);
    match state.approve_enrolment(&id) {
        Ok(()) => {
            info!(request = %id, "enrolment request approved");
            note(
                &state,
                crate::audit::Entry::new("enrolment.approved", "approved")
                    .with("id", id.clone())
                    .with("gateway", gateway),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::enrolment::DecisionError::NotFound) => error(
            StatusCode::NOT_FOUND,
            format!("no pending enrolment request {id:?}"),
        ),
        Err(crate::enrolment::DecisionError::Revoked) => error(
            StatusCode::CONFLICT,
            format!(
                "enrolment request {id:?} came with a bootstrap certificate that is revoked; it is \
                 withdrawn, and nothing was signed"
            ),
        ),
        Err(
            crate::enrolment::DecisionError::Subject(e) | crate::enrolment::DecisionError::Sign(e),
        ) => error(StatusCode::CONFLICT, e),
        Err(crate::enrolment::DecisionError::Store(e)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the approval could not be persisted, and the request still waits: {e}"),
        ),
    }
}

/// Rejects one enrolment request; its connection is closed.
#[utoipa::path(
    post,
    path = "/api/v1/enrolments/{id}/reject",
    tag = "enrolment",
    params(("id" = String, Path, description = "the request's id")),
    responses(
        (status = 204, description = "Rejected"),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such pending request, or enrolment is not configured", body = ErrorBody),
        (status = 500, description = "The rejection could not be persisted; the request still waits", body = ErrorBody)
    )
)]
async fn reject_enrolment(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(id): Path<String>,
) -> Response {
    let Some(enrolment) = state.enrolment() else {
        return enrolment_off();
    };
    let gateway = through_gateway(&state, &id);
    match enrolment.reject(&id) {
        Ok(()) => {
            info!(request = %id, "enrolment request rejected");
            note(
                &state,
                crate::audit::Entry::new("enrolment.rejected", "rejected")
                    .with("id", id.clone())
                    .with("gateway", gateway),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::enrolment::DecisionError::Store(e)) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("the rejection could not be persisted, and the request still waits: {e}"),
        ),
        Err(_) => error(
            StatusCode::NOT_FOUND,
            format!("no pending enrolment request {id:?}"),
        ),
    }
}

/// One certificate the client CA signed (ADR-0021 clause 33).
#[derive(Serialize, ToSchema)]
struct CertificateView {
    /// `client` — the CA that signed it, as a revocation names it.
    authority: String,
    /// The issuer's name, for reading.
    issuer: String,
    /// The serial, lowercase hex.
    serial: String,
    subject: String,
    /// The SHA-256 fingerprint of the certified public key, hex.
    key_fingerprint: String,
    not_after_ms: u64,
    /// The `instance_uid` of the message that carried the CSR, hex.
    instance_uid: String,
    issued_ms: u64,
    /// On a renewal, the certificate it renewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor: Option<CertificateRef>,
    /// The host it was issued to (ADR-0021 clause 7); absent on one an operator provisioned.
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
}

/// A Host: what a client certificate's host id names (ADR-0021 clause 7, ADR-0035).
#[derive(Serialize, ToSchema)]
struct HostView {
    host: String,
    /// What it is shown by: the `host.name` its Client Agent reports, else the host id. Shown
    /// only; it decides nothing (ADR-0035 clause 7).
    name: String,
    /// A Gateway speaks for any Agent; any other host only for those it reported first.
    gateway: bool,
    /// The `instance_uid`s it speaks for, hex.
    instance_uids: Vec<String>,
    /// How many valid certificates it holds — at most three.
    certificates: usize,
    /// The subject values of the client certificate it was issued (ADR-0035 clause 1), which the
    /// Agents arriving over it directly carry as `fleet.host.*`.
    subject: HostSubject,
    /// When its enrolment was approved, in milliseconds since the Unix epoch; absent for a Host a
    /// provisioned certificate made at its first report.
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_ms: Option<u64>,
    /// The Agents whose record names it as the Host they last arrived over (ADR-0035 clause 2) —
    /// for a Gateway, the Agents behind it.
    agents: Vec<HostAgent>,
}

/// The subject values a Host carries (ADR-0035 clause 1), or a bootstrap certificate carries into
/// the host certificate an approval issues (ADR-0036 clause 3); an empty one is absent from the
/// certificate.
#[derive(Serialize, ToSchema)]
struct HostSubject {
    /// `C`, as `fleet.host.country`.
    country: String,
    /// `ST`, as `fleet.host.state`.
    state: String,
    /// `L`, as `fleet.host.locality`.
    locality: String,
    /// `O`, as `fleet.host.organization`.
    organization: String,
    /// `OU`, as `fleet.host.site`.
    organizational_unit: String,
    /// `organizationIdentifier`, as `fleet.host.organization_id`.
    organization_identifier: String,
}

impl From<crate::revocation::SubjectValues> for HostSubject {
    fn from(values: crate::revocation::SubjectValues) -> Self {
        HostSubject {
            country: values.country,
            state: values.state,
            locality: values.locality,
            organization: values.organization,
            organizational_unit: values.organizational_unit,
            organization_identifier: values.organization_identifier,
        }
    }
}

/// One Agent under the Host it arrived over (ADR-0035 clause 7).
#[derive(Serialize, ToSchema)]
struct HostAgent {
    instance_uid: String,
    service_name: String,
    service_instance_name: String,
    /// The `host.name` it reports, or empty.
    host_name: String,
    /// Whether it is a Client Agent: it reports `supervisor.kind.*`.
    client: bool,
    /// The Instance UID of its Client Agent — its own, for the Client Agent — or empty when the
    /// Server cannot tell.
    client_agent: String,
    /// Behind a Gateway, the machine it is grouped by (`host.id=…`, else `host.name=…`); empty on a
    /// direct connection.
    machine: String,
    /// Its group holds more than one Client Agent, so it inherits nothing.
    ambiguous: bool,
    connected: bool,
}

/// Whether a host is a Gateway.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct GatewayRequest {
    gateway: bool,
}

/// A certificate by the CA that issued it and its serial.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct CertificateRef {
    /// `client` for the client CA, `bootstrap` for the bootstrap CA of `[enrolment]`.
    authority: String,
    /// The serial in hex, as `openssl x509 -noout -serial` prints it; colons, spaces, case and
    /// leading zeros are ignored.
    serial: String,
}

/// What to revoke: a certificate (ADR-0021 clause 34).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    certificate: CertificateRef,
}

/// One revocation (ADR-0021 clause 38).
#[derive(Serialize, ToSchema)]
struct RevocationView {
    /// What `DELETE` names.
    id: String,
    /// `certificate`.
    kind: &'static str,
    revoked_ms: u64,
    certificate: CertificateRef,
}

impl RevocationView {
    fn of(entry: crate::revocation::Revocation) -> Self {
        let crate::revocation::Revoked::Certificate {
            authority, serial, ..
        } = entry.revoked;
        RevocationView {
            id: entry.id,
            kind: "certificate",
            revoked_ms: entry.revoked_ms,
            certificate: CertificateRef { authority, serial },
        }
    }
}

/// Records what an operator act did, beside the act itself (ADR-0022 clause 1). The act was
/// already recorded before it ran, so a detail that cannot be recorded changes nothing.
fn note(state: &AppState, entry: crate::audit::Entry) {
    if let Some(audit) = state.audit() {
        audit.refusal(entry);
    }
}

fn revocation_entry(
    event: &str,
    outcome: &str,
    entry: &crate::revocation::Revocation,
) -> crate::audit::Entry {
    let crate::revocation::Revoked::Certificate {
        authority, serial, ..
    } = &entry.revoked;
    crate::audit::Entry::new(event, outcome)
        .with("id", entry.id.clone())
        .with("kind", "certificate")
        .with("authority", authority.clone())
        .with("serial", serial.clone())
}

fn revocation_off() -> Response {
    error(StatusCode::NOT_FOUND, "revocation is not configured")
}

/// Every certificate the client CA signed that has not yet expired, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/certificates",
    tag = "revocation",
    responses(
        (status = 200, description = "Every unexpired certificate the client CA signed, oldest first", body = Vec<CertificateView>),
        (status = 404, description = "Revocation is not configured", body = ErrorBody)
    )
)]
async fn list_certificates(State(state): State<Arc<AppState>>) -> Response {
    let Some(revocations) = state.revocations() else {
        return revocation_off();
    };
    let authority = |id: &crate::revocation::CertId| {
        revocations
            .authority_of(&id.issuer)
            .map_or_else(|| "unknown".to_string(), |a| a.role.clone())
    };
    let issued: Vec<CertificateView> = revocations
        .issued()
        .into_iter()
        .map(|issued| CertificateView {
            authority: authority(&issued.facts.id),
            issuer: issued.facts.issuer_name,
            serial: issued.facts.id.serial,
            subject: issued.facts.subject,
            key_fingerprint: issued.facts.key_fingerprint,
            not_after_ms: issued.facts.not_after_ms,
            instance_uid: issued.instance_uid,
            issued_ms: issued.issued_ms,
            predecessor: issued.predecessor.map(|id| CertificateRef {
                authority: authority(&id),
                serial: id.serial,
            }),
            host: issued.facts.host,
        })
        .collect();
    Json(issued).into_response()
}

/// Every Host, by host id, with its subject values and the Agents that arrived over it.
#[utoipa::path(
    get,
    path = "/api/v1/hosts",
    tag = "revocation",
    responses(
        (status = 200, description = "Every Host, by host id, with its subject values and the Agents that arrived over it (ADR-0035)", body = Vec<HostView>),
        (status = 404, description = "Revocation is not configured", body = ErrorBody)
    )
)]
async fn list_hosts(State(state): State<Arc<AppState>>) -> Response {
    let Some(revocations) = state.revocations() else {
        return revocation_off();
    };
    let mut carried = state.host_agents();
    let hosts: Vec<HostView> = revocations
        .hosts()
        .into_iter()
        .map(|(host, entry, certificates)| {
            let agents = carried.remove(&host).unwrap_or_default();
            HostView {
                name: agents.name.unwrap_or_else(|| host.clone()),
                host,
                gateway: entry.gateway,
                instance_uids: entry.instance_uids.into_iter().collect(),
                certificates,
                subject: entry.subject.into(),
                approved_ms: entry.approved_ms,
                agents: agents
                    .agents
                    .into_iter()
                    .map(|agent| HostAgent {
                        instance_uid: agent.instance_uid,
                        service_name: agent.service_name,
                        service_instance_name: agent.service_instance_name,
                        host_name: agent.host_name,
                        client: agent.client,
                        client_agent: agent.client_agent,
                        machine: agent.machine,
                        ambiguous: agent.ambiguous,
                        connected: agent.connected,
                    })
                    .collect(),
            }
        })
        .collect();
    Json(hosts).into_response()
}

/// Marks a host as a Gateway, which speaks for the Agents behind it, or takes the mark away.
#[utoipa::path(
    put,
    path = "/api/v1/hosts/{host}/gateway",
    tag = "revocation",
    params(("host" = String, Path, description = "the host, as its certificates name it")),
    request_body = GatewayRequest,
    responses(
        (status = 204, description = "Set"),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such host, or revocation is not configured", body = ErrorBody)
    )
)]
async fn set_gateway(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(host): Path<String>,
    Json(request): Json<GatewayRequest>,
) -> Response {
    if state.revocations().is_none() {
        return revocation_off();
    }
    match state.set_gateway(&host, request.gateway) {
        Ok(true) => {
            info!(%host, gateway = request.gateway, "gateway mark set");
            note(
                &state,
                crate::audit::Entry::new(
                    "host.gateway",
                    if request.gateway { "set" } else { "cleared" },
                )
                .with("host", host),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no host {host:?}")),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The revocation list, oldest first.
#[utoipa::path(
    get,
    path = "/api/v1/revocations",
    tag = "revocation",
    responses(
        (status = 200, description = "The revocation list, oldest first", body = Vec<RevocationView>),
        (status = 404, description = "Revocation is not configured", body = ErrorBody)
    )
)]
async fn list_revocations(State(state): State<Arc<AppState>>) -> Response {
    let Some(revocations) = state.revocations() else {
        return revocation_off();
    };
    let list: Vec<RevocationView> = revocations
        .list()
        .into_iter()
        .map(RevocationView::of)
        .collect();
    Json(list).into_response()
}

/// Revokes a certificate, and every renewal of it. Every session it admitted ends at once, and no
/// new one is admitted. There is no credential to revoke: the Agent plane admits by client
/// certificate alone (ADR-0021 clause 36).
#[utoipa::path(
    post,
    path = "/api/v1/revocations",
    tag = "revocation",
    request_body = RevokeRequest,
    responses(
        (status = 201, description = "Revoked; the new entry of the list", body = RevocationView),
        (status = 400, description = "No certificate named, a field this route does not know, an authority this Server does not have, a serial that is not hex, or a credential named, which the Agent plane does not have", body = ErrorBody),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "Revocation is not configured", body = ErrorBody),
        (status = 507, description = "The list is full", body = ErrorBody)
    )
)]
async fn revoke(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Json(body): Json<serde_json::Value>,
) -> Response {
    use crate::revocation::RevokeError;
    let Some(revocations) = state.revocations() else {
        return revocation_off();
    };
    // Named before the body is read as a request, so the answer says why rather than that the
    // field is unknown.
    if body.get("credential").is_some() {
        return error(
            StatusCode::BAD_REQUEST,
            "credential is refused — the Agent plane admits by client certificate alone, so \
             there is no credential to revoke; name a certificate",
        );
    }
    let request = match serde_json::from_value::<RevokeRequest>(body) {
        Ok(request) => request,
        Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let outcome =
        revocations.revoke_certificate(&request.certificate.authority, &request.certificate.serial);
    match outcome {
        Ok(entry) => {
            info!(revocation = %entry.id, "revoked");
            // A revoked bootstrap certificate's PKCS#12 file goes before the answer (ADR-0029
            // clause 4); the download refuses it either way.
            let crate::revocation::Revoked::Certificate {
                authority, serial, ..
            } = &entry.revoked;
            let mut withdrawn = 0;
            if authority == "bootstrap" {
                // The requests it carried wait no longer (ADR-0021 clause 35); approving one is
                // refused either way.
                withdrawn = state.enrolment().map_or(0, |enrolment| {
                    enrolment.withdraw(&|bootstrap| revocations.is_certificate_revoked(bootstrap))
                });
                if let Some(Err(e)) = state.bootstrap().map(|b| b.forget_p12(serial)) {
                    // Said, not swallowed: lifting this revocation would make the file
                    // downloadable again.
                    warn!(serial = %serial, "cannot remove the revoked PKCS#12 file: {e}");
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "revoked as {}, but its PKCS#12 file could not be removed: {e}",
                            entry.id
                        ),
                    );
                }
            }
            note(
                &state,
                revocation_entry("revocation.revoked", "revoked", &entry)
                    .with("withdrawn_requests", withdrawn),
            );
            (StatusCode::CREATED, Json(RevocationView::of(entry))).into_response()
        }
        Err(RevokeError::Invalid(e)) => error(StatusCode::BAD_REQUEST, e),
        Err(RevokeError::Full) => error(
            StatusCode::INSUFFICIENT_STORAGE,
            format!(
                "the revocation list holds {} entries already",
                crate::revocation::MAX_REVOCATIONS
            ),
        ),
        Err(RevokeError::Store(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// Lifts one revocation. It takes effect at the next connection.
#[utoipa::path(
    delete,
    path = "/api/v1/revocations/{id}",
    tag = "revocation",
    params(("id" = String, Path, description = "the revocation's id")),
    responses(
        (status = 204, description = "Lifted"),
        (status = 403, description = "Refused as a cross-site request (Sec-Fetch-Site)", body = ErrorBody),
        (status = 404, description = "No such revocation, or revocation is not configured", body = ErrorBody)
    )
)]
async fn lift_revocation(
    State(state): State<Arc<AppState>>,
    _csrf: SameOrigin,
    Path(id): Path<String>,
) -> Response {
    let Some(revocations) = state.revocations() else {
        return revocation_off();
    };
    match revocations.lift(&id) {
        Ok(true) => {
            info!(revocation = %id, "revocation lifted");
            note(
                &state,
                crate::audit::Entry::new("revocation.lifted", "lifted").with("id", id.clone()),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, format!("no revocation {id:?}")),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
