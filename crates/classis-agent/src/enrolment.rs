//! A host's enrolment: `state.json`, the `enrol` command that writes it, and the
//! renewal of the token it holds.
//!
//! `enrol <base-url> <key>` registers this host as a client of the Server with the Space's key
//! (RFC 7591, [`oauth_registration`]), asks for its first token with the credentials it received
//! (RFC 6749 §4.4, [`oauth_token`]), and writes `state.json` once in the state directory,
//! owner-only: `endpoint` (the base URL), `space`, `device_id`, `client_secret` and `access_token`.
//! Nothing but `access_token` changes in it afterwards, and only [`renew`] changes it.
//!
//! A host without `state.json` runs nothing: [`required`] is what the run asks first, and the
//! error it gives names this command.
//!
//! What `enrol` does to the service, and what `revoke` ([`crate::revoke`]) does, goes through a
//! [`ServiceHost`]: the machine's service manager in the program, a test's own in a test.

use std::path::{Path, PathBuf};

use opamp::client::ClientTls;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::ClientConfig;
use crate::credentials::Credentials;
use crate::nofollow::HeldDir;
use crate::service::run_as::{RunAs, Source};
use crate::service::{manager, ServiceControl, ServiceLevel};

/// The file in the state directory that makes a host what it is to its Server.
pub const STATE_FILE: &str = "state.json";

/// Where the Server registers a client, resolved against the base URL.
const ENROL_PATH: &str = "/v1/enrol";

/// Where the Server issues a token, resolved against the base URL.
const TOKEN_PATH: &str = "/v1/token";

/// What `state.json` holds, as it is read.
#[derive(Deserialize)]
struct Stored {
    endpoint: String,
    space: String,
    device_id: String,
    client_secret: String,
    access_token: String,
}

/// What `state.json` holds, as it is written: the five values and nothing else.
#[derive(Serialize)]
struct Written<'a> {
    endpoint: &'a str,
    space: &'a str,
    device_id: &'a str,
    client_secret: &'a str,
    access_token: &'a str,
}

/// Where `state.json` is.
#[must_use]
pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}

/// What `state.json` holds, or `None` where there is none.
///
/// # Errors
/// Returns an error naming the file when it exists and cannot be read or is not the file `enrol`
/// writes; what it holds is never part of the message.
pub fn load(state_dir: &Path) -> Result<Option<Credentials>, String> {
    let path = state_path(state_dir);
    let bytes = match crate::nofollow::read(&path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let stored: Stored = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "{} is not the file `supervisor enrol` writes (line {}, column {})",
            path.display(),
            e.line(),
            e.column()
        )
    })?;
    Ok(Some(Credentials {
        endpoint: stored.endpoint,
        space: stored.space,
        device_id: stored.device_id,
        client_secret: Zeroizing::new(stored.client_secret),
        access_token: Zeroizing::new(stored.access_token),
    }))
}

/// Refuses an endpoint that would carry the access token in cleartext although the host enrolled
/// over TLS: `enrol` records where the host enrolled but not the OpAMP endpoint, which stays at
/// its default, a plaintext loopback address that anything on the machine may be listening on.
///
/// # Errors
/// Returns an error naming `endpoint` when the host enrolled at an `https://` address and
/// `endpoint` is `ws://` or `http://`.
pub fn check_endpoint_matches_enrolment(
    credentials: &Credentials,
    endpoint: &str,
) -> Result<(), String> {
    let plaintext = endpoint.starts_with("ws://") || endpoint.starts_with("http://");
    if credentials.endpoint.starts_with("https://") && plaintext {
        return Err(format!(
            "endpoint {endpoint} is plaintext, but this host enrolled at {} and would send its \
             access token there unencrypted; set `endpoint` to the Server's `wss://` or `https://` \
             address",
            credentials.endpoint
        ));
    }
    Ok(())
}

/// What `state.json` holds, for a host that must have enrolled before it runs.
///
/// # Errors
/// Returns an error naming `enrol` when there is no `state.json`, and as [`load`] does when there
/// is a bad one.
pub fn required(state_dir: &Path) -> Result<Credentials, String> {
    load(state_dir)?.ok_or_else(|| {
        format!(
            "this host is not enrolled: {} does not exist, and the Client runs nothing without it. \
             Enrol it with `supervisor enrol <base-url> <key>`",
            state_path(state_dir).display()
        )
    })
}

/// The bytes of a `state.json`, in a buffer wiped when it is dropped.
fn encode(credentials: &Credentials) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer_pretty(
        &mut *bytes,
        &Written {
            endpoint: &credentials.endpoint,
            space: &credentials.space,
            device_id: &credentials.device_id,
            client_secret: &credentials.client_secret,
            access_token: &credentials.access_token,
        },
    )
    .map_err(|e| format!("cannot encode {STATE_FILE}: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Writes `state.json` for the first time, owner-only and never through a link, creating the state
/// directory where it is missing and leaving it as it is where it exists: an install made it, and
/// shared it with the accounts that need it. A `state.json` that appears while this run enrols is
/// never replaced: the write fails, and the other run's file stands.
///
/// # Errors
/// Returns an error when the file exists already, or cannot be written.
fn create(state_dir: &Path, credentials: &Credentials) -> Result<(), String> {
    let path = state_path(state_dir);
    let failed = |e: std::io::Error| format!("cannot write {}: {e}", path.display());
    let dir = match HeldDir::open(state_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            HeldDir::create(state_dir, 0o700).map_err(failed)?
        }
        Err(e) => return Err(failed(e)),
    };
    match dir.open_file(STATE_FILE) {
        Ok(_) => return Err(already_enrolled(&path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(failed(e)),
    }
    // The check above is for a plain message; this is what decides it: a `state.json` another run
    // wrote meanwhile is never replaced.
    dir.write_new(STATE_FILE, &encode(credentials)?, 0o600)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                already_enrolled(&path)
            } else {
                failed(e)
            }
        })
}

/// What `enrol` says of a host that has a `state.json` already.
fn already_enrolled(path: &Path) -> String {
    format!(
        "this host is enrolled already: {} exists. `supervisor revoke` ends the enrolment first",
        path.display()
    )
}

/// Replaces `access_token` in `state.json` and nothing else, keeping the file's owner and its mode.
/// The file is written whole to a new name and renamed over the old one, so a crash leaves one or
/// the other and never half a credential.
///
/// # Errors
/// Returns an error when the file cannot be read, is not what `enrol` writes, or cannot be
/// replaced.
fn replace_access_token(state_dir: &Path, access_token: &Zeroizing<String>) -> Result<(), String> {
    let path = state_path(state_dir);
    let failed = |e: std::io::Error| format!("cannot rewrite {}: {e}", path.display());
    let mut credentials = required(state_dir)?;
    credentials.access_token = access_token.clone();
    let dir = HeldDir::open(state_dir).map_err(failed)?;
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt as _;
        let before = dir.open_file(STATE_FILE).and_then(|file| file.metadata());
        before
            .map(|before| (before.uid(), before.gid()))
            .map_err(failed)?
    };
    dir.replace(STATE_FILE, &encode(&credentials)?, 0o600)
        .map_err(failed)?;
    // A renewal by an account other than the file's owner — a foreground run as root over a file
    // the service's account owns — leaves the file with the owner it had.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let file = dir.open_for_writing(STATE_FILE).map_err(failed)?;
        let now = file.metadata().map_err(failed)?;
        if (now.uid(), now.gid()) != owner {
            std::os::unix::fs::fchown(&file, Some(owner.0), Some(owner.1)).map_err(failed)?;
        }
    }
    Ok(())
}

/// The URL of `path` under the base URL `base`: the Server's origin, and a path prefix a reverse
/// proxy may put in front of the routes.
///
/// # Errors
/// Returns an error when `base` is not an `https://` URL, or an `http://` URL to a loopback
/// literal, with no credentials, query or fragment (specification Q-1).
pub fn route(base: &str, path: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(base).map_err(|e| format!("the base URL {base}: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "the base URL {base} must start with https:// (http:// only to 127.0.0.1 or ::1)"
        ));
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(format!(
            "the base URL {base} must be a scheme, a host and perhaps a path, and nothing else"
        ));
    }
    opamp::endpoint::check_url(base)?;
    Ok(format!("{}{path}", base.trim_end_matches('/')))
}

/// The HTTP client of `enrol` and of the renewal: the Client's TLS trust, TLS 1.3, and no redirect
/// — a redirect would resend the key, or the client secret, wherever it points.
fn http(tls: ClientTls) -> Result<reqwest::Client, String> {
    crate::packages::download_client(tls)
}

/// What the Server said of a refused request, for a message: the status and the OAuth error code,
/// never a credential.
fn refusal(what: &str, base: &str, error: &dyn std::fmt::Display) -> String {
    format!("cannot {what} at {base}: {error}")
}

/// The service that runs the Client over a state directory, as `enrol` and `revoke` find it.
pub trait ServiceHost {
    /// The service registered to run the Client with `state_dir`, or `None` where none is.
    ///
    /// # Errors
    /// Returns an error when the registration cannot be read.
    fn registered(&self, state_dir: &Path) -> Result<Option<Installed>, String>;
}

/// A registered service, and the account it runs as.
pub struct Installed {
    /// What starts, enables, disables and asks after the service.
    pub control: Box<dyn ServiceControl>,
    /// The account the service runs as, which `state.json` is handed over to; `None` where the
    /// registration names none.
    pub run_as: Option<RunAs>,
}

/// The machine's own service manager.
pub struct NativeHost;

impl ServiceHost for NativeHost {
    /// The system service this product registers, where its registration names `state_dir` as the
    /// Client's. A user-scope service names no state directory a registration could be matched
    /// on, and is not found.
    fn registered(&self, state_dir: &Path) -> Result<Option<Installed>, String> {
        let level = ServiceLevel::System;
        let Some(registered) = manager::registered_state_dir(level)? else {
            return Ok(None);
        };
        if !same_directory(&registered, state_dir) {
            return Ok(None);
        }
        let run_as = match manager::registration(level)? {
            Some(registration) => registration
                .account
                .map(|account| {
                    RunAs::resolve(
                        &account,
                        manager::service_name(),
                        &Source::Registered(registration.file.clone()),
                        state_dir,
                    )
                })
                .transpose()?,
            None => None,
        };
        Ok(Some(Installed {
            control: Box::new(manager::NativeService::new(level)),
            run_as,
        }))
    }
}

/// Whether two paths name the same directory, as far as the file system says: each as it resolves
/// where it exists, as it is written absolutely where it does not.
fn same_directory(a: &Path, b: &Path) -> bool {
    let resolved = |path: &Path| {
        std::fs::canonicalize(path)
            .or_else(|_| std::path::absolute(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    resolved(a) == resolved(b)
}

/// What `enrol` did.
#[derive(Debug)]
pub struct Enrolled {
    /// The Space the Server put the host in.
    pub space: String,
    /// The host's Device ID.
    pub device_id: String,
    /// The file written.
    pub state_file: PathBuf,
    /// Whether a registered service was started, and lets the host start at boot.
    pub service_started: bool,
    /// What the hand-over of `state.json` left as it was, as warnings.
    pub warnings: Vec<String>,
}

/// Enrols this host: registers at `<base_url>/v1/enrol` with `key`, asks for a
/// token at `<base_url>/v1/token`, writes `state.json` in `state_dir`, and, where the service is
/// registered for that state directory, hands the file to the account it runs as, lets it start at
/// boot and starts it.
///
/// Everything that can be asked of this machine before the Server is asked — the base URL, a
/// `state.json` already there, the service and its account — is asked first, so that a refusal
/// leaves no client behind at the Server.
///
/// # Errors
/// Returns why the host could not be enrolled. Once `state.json` is written the host is enrolled,
/// and an error after it says so and what is left to do.
pub async fn enrol(
    base_url: &str,
    key: &str,
    state_dir: &Path,
    tls: ClientTls,
    host: &dyn ServiceHost,
) -> Result<Enrolled, String> {
    let enrol_url = route(base_url, ENROL_PATH)?;
    let token_url = route(base_url, TOKEN_PATH)?;
    if load(state_dir)?.is_some() {
        return Err(already_enrolled(&state_path(state_dir)));
    }
    let installed = host.registered(state_dir)?;
    let http = http(tls)?;

    let registered = oauth_registration::client::register(&http, enrol_url, key)
        .await
        .map_err(|e| refusal("enrol", base_url, &e))?;
    let space = registered
        .fields
        .get("space")
        .and_then(serde_json::Value::as_str)
        .filter(|space| !space.is_empty())
        .ok_or_else(|| format!("cannot enrol at {base_url}: the Server named no Space"))?
        .to_string();
    let issued = oauth_token::client::request_token(
        &http,
        token_url,
        &registered.client_id,
        &registered.client_secret,
    )
    .await
    .map_err(|e| refusal("get a token", base_url, &e))?;

    let credentials = Credentials {
        endpoint: base_url.to_string(),
        space: space.clone(),
        device_id: registered.client_id,
        client_secret: registered.client_secret,
        access_token: issued.access_token,
    };
    create(state_dir, &credentials)?;
    let state_file = state_path(state_dir);

    let mut enrolled = Enrolled {
        space,
        device_id: credentials.device_id.clone(),
        state_file: state_file.clone(),
        service_started: false,
        warnings: Vec::new(),
    };
    let Some(installed) = installed else {
        return Ok(enrolled);
    };
    let after = |step: &str, e: String| {
        format!(
            "this host is enrolled ({} is written) but {step}: {e}. `supervisor service start` \
             starts it; `supervisor revoke` ends the enrolment",
            state_file.display()
        )
    };
    if let Some(run_as) = &installed.run_as {
        for skipped in run_as
            .hand_over(&[state_file.as_path()], None)
            .map_err(|e| after("it could not be handed over to the service's account", e))?
        {
            enrolled.warnings.push(skipped.warning(run_as.account()));
        }
    }
    installed
        .control
        .enable()
        .map_err(|e| after("the service could not be let start at boot", e))?;
    installed
        .control
        .start()
        .map_err(|e| after("the service could not be started", e))?;
    enrolled.service_started = true;
    Ok(enrolled)
}

/// Asks the token endpoint for a new token with the host's client credentials, keeps it in
/// `state.json` — which it alone changes after `enrol` — and in `config`.
///
/// This is what a `401` with `error="invalid_token"` asks for and nothing else does: the Client
/// keeps no expiry and never renews ahead of time. A new token ends the sessions
/// admitted with the old one, which is why a renewal is a decision of the caller's and not a
/// precaution.
///
/// # Errors
/// Returns why no new token was kept: the host is not enrolled, the Server refused its client
/// credentials or could not be reached, or the file cannot be rewritten. The old token stays in
/// `config` and in the file until a new one has been written to both.
pub async fn renew(config: &mut ClientConfig) -> Result<(), String> {
    let credentials = config
        .credentials
        .as_ref()
        .ok_or_else(|| "this host is not enrolled".to_string())?;
    let token_url = route(&credentials.endpoint, TOKEN_PATH)?;
    let http = http(crate::tls::trust(config)?)?;
    let issued = oauth_token::client::request_token(
        &http,
        token_url,
        &credentials.device_id,
        &credentials.client_secret,
    )
    .await
    .map_err(|e| refusal("get a new token", &credentials.endpoint, &e))?;
    replace_access_token(&config.state_dir, &issued.access_token)?;
    if let Some(credentials) = config.credentials.as_mut() {
        credentials.access_token = issued.access_token;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host that enrolled over TLS is not left sending its token in cleartext to the default
    /// loopback endpoint; one that enrolled in plaintext, or whose endpoint is TLS, is untouched.
    /// Verifies: Q-1
    #[test]
    fn a_tls_enrolment_refuses_a_plaintext_endpoint() {
        let tls = credentials();
        let err = check_endpoint_matches_enrolment(&tls, "ws://127.0.0.1:4320/v1/opamp")
            .expect_err("plaintext after a TLS enrolment");
        assert!(
            err.contains("endpoint ws://127.0.0.1:4320/v1/opamp"),
            "{err}"
        );
        assert!(!err.contains("the-access-token"), "{err}");
        assert!(check_endpoint_matches_enrolment(&tls, "http://127.0.0.1:4320/v1/opamp").is_err());
        assert!(check_endpoint_matches_enrolment(&tls, "wss://fleet.example/v1/opamp").is_ok());
        assert!(check_endpoint_matches_enrolment(&tls, "https://fleet.example/v1/opamp").is_ok());
        let local = Credentials {
            endpoint: "http://127.0.0.1:4320".to_string(),
            ..credentials()
        };
        assert!(check_endpoint_matches_enrolment(&local, "ws://127.0.0.1:4320/v1/opamp").is_ok());
    }

    fn credentials() -> Credentials {
        Credentials {
            endpoint: "https://fleet.example".to_string(),
            space: "lab".to_string(),
            device_id: "0193a6f0-0000-7000-8000-000000000000".to_string(),
            client_secret: Zeroizing::new("the-client-secret".to_string()),
            access_token: Zeroizing::new("the-access-token".to_string()),
        }
    }

    /// `state.json` holds its five values and nothing else, and reads back as written.
    #[test]
    fn state_json_holds_five_values_and_reads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        create(dir.path(), &credentials()).expect("written");
        let text = std::fs::read_to_string(state_path(dir.path())).expect("read");
        let parsed: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&text).expect("json");
        let mut keys: Vec<&str> = parsed.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "access_token",
                "client_secret",
                "device_id",
                "endpoint",
                "space"
            ]
        );
        let read = load(dir.path()).expect("loads").expect("there");
        assert_eq!(read.space, "lab");
        assert_eq!(read.device_id, credentials().device_id);
        assert_eq!(read.access_token.as_str(), "the-access-token");
        assert_eq!(read.client_secret.as_str(), "the-client-secret");
    }

    /// The file is written owner-only, and a second `create` refuses.
    #[cfg(unix)]
    #[test]
    fn state_json_is_owner_only_and_written_once() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        create(&state, &credentials()).expect("written");
        let mode = std::fs::metadata(state_path(&state))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let error = create(&state, &credentials()).expect_err("a second write");
        assert!(error.contains("enrolled already"), "{error}");
    }

    /// `enrol` keeps a state directory a Client with a process account laid out as it is — `0710`,
    /// in the process account's group — and writes `state.json` `0600`; a state directory it makes
    /// itself is the Client's alone, `0700`.
    #[cfg(unix)]
    #[test]
    fn an_enrolment_keeps_a_shared_state_directory_shared() {
        use std::os::unix::fs::MetadataExt as _;
        let mode_and_group = |path: &Path| {
            let meta = std::fs::symlink_metadata(path).expect("metadata");
            (meta.mode() & 0o7777, meta.gid())
        };
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: getegid(2) cannot fail and touches no memory.
        let group = crate::supervisor::ports::ProcessAccountGroup(unsafe { libc::getegid() });
        let shared = dir.path().join("shared");
        crate::storage::Storage::client(shared.clone(), Some(group))
            .expect("laid out with a process account");
        create(&shared, &credentials()).expect("written");
        assert_eq!(mode_and_group(&shared), (0o710, group.0));
        assert_eq!(mode_and_group(&state_path(&shared)).0, 0o600);

        let private = dir.path().join("private");
        create(&private, &credentials()).expect("written");
        assert_eq!(mode_and_group(&private).0, 0o700);
    }

    /// A renewal changes `access_token` and nothing else, and the file keeps its mode.
    #[test]
    fn a_renewal_rewrites_only_the_access_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        create(dir.path(), &credentials()).expect("written");
        replace_access_token(dir.path(), &Zeroizing::new("a-new-token".to_string()))
            .expect("replaced");
        let read = load(dir.path()).expect("loads").expect("there");
        assert_eq!(read.access_token.as_str(), "a-new-token");
        assert_eq!(read.client_secret.as_str(), "the-client-secret");
        assert_eq!(read.device_id, credentials().device_id);
        assert_eq!(read.space, "lab");
        assert_eq!(read.endpoint, "https://fleet.example");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(state_path(dir.path()))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// A host without `state.json` is told to enrol, and a bad file is named without being quoted.
    #[test]
    fn a_missing_state_json_names_enrol_and_a_bad_one_leaks_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = required(dir.path()).expect_err("no file");
        assert!(error.contains("supervisor enrol"), "{error}");
        std::fs::write(
            state_path(dir.path()),
            r#"{"endpoint": 1, "access_token": "super-secret"}"#,
        )
        .expect("write");
        let error = load(dir.path()).expect_err("a bad file");
        assert!(!error.contains("super-secret"), "{error}");
        assert!(error.contains(STATE_FILE), "{error}");
    }

    /// The routes resolve against the base URL as the Server's origin and path prefix, and the
    /// transport rule of the specification holds for them (Q-1).
    #[test]
    fn the_routes_follow_the_transport_rule() {
        assert_eq!(
            route("https://fleet.example/", ENROL_PATH).expect("https"),
            "https://fleet.example/v1/enrol"
        );
        assert_eq!(
            route("https://fleet.example/fleet", TOKEN_PATH).expect("a prefix"),
            "https://fleet.example/fleet/v1/token"
        );
        assert!(route("http://127.0.0.1:4320", ENROL_PATH).is_ok());
        for refused in [
            "http://fleet.example",
            "http://localhost:4320",
            "wss://fleet.example/v1/opamp",
            "https://user:password@fleet.example",
            "https://fleet.example/?key=1",
            "fleet.example",
        ] {
            assert!(route(refused, ENROL_PATH).is_err(), "{refused}");
        }
    }
}
