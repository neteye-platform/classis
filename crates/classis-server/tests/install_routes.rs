//! The install routes of the Agent plane: what a host that holds no credential fetches to put the
//! Client on itself — the two scripts, and this Server's own Client archive, signed or nothing. The
//! package download beside them still asks for a token.

mod support;

use std::sync::Arc;

use classis_server::enrolment::Enrolment;
use classis_server::throttle::{Limits, Throttle};

/// The Agent type of the Client's own Package, as this project's release packs it.
const CLIENT: &str = "supervisor";

/// The bytes of one Client archive.
const ARCHIVE: &[u8] = b"the-client-archive";

/// Refusals no test here reaches.
const GENEROUS: Limits = Limits {
    max_failures: u32::MAX,
    window_secs: 60,
    backoff_secs: 300,
};

/// One request per bucket, refilling one a second — the limit the test of the install routes' own
/// meets on its second request.
const ONE_PER_PEER: classis_server::agent_rate::Limits = classis_server::agent_rate::Limits {
    messages_per_sec: 1,
    burst: 1,
};

/// The release this build belongs to — the identity the Server serves its own archive under, which
/// is why no test chooses it.
fn release() -> String {
    classis_core::version::identity(classis_core::version::current())
        .expect("this build's version identifies a release")
        .to_string()
}

/// The enrolment the Agent plane admits by: no Space, tokens that never expire, limits no test
/// meets — none of these tests enrols a host.
fn enrolment_on(data_dir: &std::path::Path) -> Arc<Enrolment> {
    classis_server::fs::open_data_dir(data_dir, true).expect("the data directory");
    let records = classis_server::Records::Files(data_dir.to_path_buf());
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    Arc::new(
        Enrolment::on(
            &records,
            oauth_token::server::Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(GENEROUS, clock)),
        )
        .expect("the enrolment"),
    )
}

/// The two planes as the binary builds them, the Agent plane admitting by bearer token. No host is
/// enrolled, and none need be: what these routes serve, a host with nothing to present.
async fn served() -> support::TestServer {
    // What main() does at startup: without a process provider, reqwest refuses to build a client.
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(support::state_on(dir.path()));
    let (addr, rest_addr) =
        support::serve_enrolled(state.clone(), enrolment_on(&dir.path().join("data")), None).await;
    support::TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    }
}

/// The two planes as `served`, with the Agent plane's rate limit armed on a clock the test moves.
/// No install route carries a token, so the bucket each one draws on is its peer's address.
async fn served_with_rate() -> (support::TestServer, Arc<support::ManualClock>) {
    opamp::tls::install_ring_provider();
    let clock = support::ManualClock::new();
    let rate = Arc::new(classis_server::agent_rate::AgentRate::new(
        ONE_PER_PEER,
        clock.clone(),
    ));
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(support::state_on(dir.path()).with_agent_rate(Some(rate)));
    let (addr, rest_addr) =
        support::serve_enrolled(state.clone(), enrolment_on(&dir.path().join("data")), None).await;
    (
        support::TestServer {
            addr,
            rest_addr,
            state,
            _dir: dir,
        },
        clock,
    )
}

/// Puts the Client's Package into the store through the REST API: this release's Set, its
/// Linux artifact, and — with `sign` — the signature that makes it offerable.
async fn store_client(server: &support::TestServer, version: &str, sign: bool) {
    use sha2::Digest as _;
    let set = format!(
        "http://{}/api/v1/packages/{CLIENT}/{version}",
        server.rest_addr
    );
    let created = reqwest::Client::new()
        .put(set.clone())
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("put set");
    assert_eq!(created.status(), 200, "the set is created");
    let uploaded = reqwest::Client::new()
        .put(format!("{set}/entries/linux/amd64"))
        .body(ARCHIVE.to_vec())
        .send()
        .await
        .expect("put entry");
    assert_eq!(uploaded.status(), 200, "the artifact is stored");
    if !sign {
        return;
    }
    let signature = support::signature_hex(CLIENT, version, &sha2::Sha256::digest(ARCHIVE));
    let signed = reqwest::Client::new()
        .put(format!("{set}/entries/linux/amd64/signature"))
        .json(&serde_json::json!({ "signature": signature }))
        .send()
        .await
        .expect("put signature");
    assert_eq!(signed.status(), 200, "the entry takes the signature");
}

async fn get(url: String) -> reqwest::Response {
    reqwest::Client::new().get(url).send().await.expect("get")
}

async fn status(server: &support::TestServer, path: &str) -> u16 {
    get(format!("http://{}{path}", server.addr))
        .await
        .status()
        .as_u16()
}

/// The scripts are the first thing a host fetches, before it holds a token: both answer `200` with
/// the bytes the Server ships with, on the Agent plane and on no other.
#[tokio::test]
async fn the_scripts_answer_a_host_that_holds_no_token() {
    let served = served().await;
    for (path, shipped) in [
        ("/v1/install.sh", include_str!("../install/install.sh")),
        ("/v1/install.ps1", include_str!("../install/install.ps1")),
    ] {
        assert!(!shipped.is_empty(), "{path} ships a script");
        let response = get(format!("http://{}{path}", served.addr)).await;
        assert_eq!(response.status(), 200, "{path}");
        let body = response.bytes().await.expect("body");
        assert_eq!(
            &body[..],
            shipped.as_bytes(),
            "{path} serves the shipped script byte for byte"
        );
        assert_eq!(
            get(format!("http://{}{path}", served.rest_addr))
                .await
                .status(),
            404,
            "{path}: the Operator plane serves no script"
        );
    }
}

/// The archive a host installs is this Server's own Client, signed: byte for byte what the store
/// holds for this release, for every spelling of a platform the release ships.
#[tokio::test]
async fn the_signed_client_archive_of_this_release_is_served() {
    let served = served().await;
    store_client(&served, &release(), true).await;
    let size = ARCHIVE.len().to_string();
    for path in [
        "/v1/install/linux/amd64",
        "/v1/install/linux/x86_64",
        "/v1/install/Linux/AMD64",
    ] {
        let response = get(format!("http://{}{path}", served.addr)).await;
        assert_eq!(response.status(), 200, "{path}");
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some(size.as_str()),
            "{path}: the host can size the download"
        );
        let body = response.bytes().await.expect("body");
        assert_eq!(&body[..], ARCHIVE, "{path}");
    }
}

/// An unsigned artifact of the right identity reaches no host: the route answers the same as it
/// does to a platform it holds nothing for, so it says nothing about what the store holds.
#[tokio::test]
async fn an_unsigned_client_archive_is_not_served() {
    let served = served().await;
    store_client(&served, &release(), false).await;
    assert_eq!(status(&served, "/v1/install/linux/amd64").await, 404);
}

/// Another version's artifact, however well signed, is not this Server's Client — and the route
/// cannot be pointed at it, since it takes no identity from the caller.
#[tokio::test]
async fn no_other_identity_is_served() {
    let served = served().await;
    store_client(&served, "9.9.9", true).await;
    assert_eq!(status(&served, "/v1/install/linux/amd64").await, 404);
}

/// Only the Linux and Windows targets of the release: macOS ships a Client and is no platform this
/// route installs onto, and an unknown token is the same answer whatever the store holds.
#[tokio::test]
async fn only_the_platforms_the_client_installs_on() {
    let served = served().await;
    store_client(&served, &release(), true).await;
    for platform in [
        "darwin/arm64",
        "darwin/amd64",
        "windows/arm64",
        "linux/riscv64",
        "plan9/amd64",
    ] {
        assert_eq!(
            status(&served, &format!("/v1/install/{platform}")).await,
            404,
            "{platform}"
        );
    }
    assert_eq!(
        get(format!(
            "http://{}/v1/install/linux/amd64",
            served.rest_addr
        ))
        .await
        .status(),
        404,
        "the Operator plane serves no Client archive"
    );
}

/// A Server with no package store armed serves no archive: `404`, the answer it gives for a
/// platform it holds nothing for.
#[tokio::test]
async fn a_server_without_a_package_store_serves_no_archive() {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let state = Arc::new(
        classis_server::fleet::AppState::new(dir.path().join("fleet-configs")).expect("configs"),
    );
    let (addr, rest_addr) =
        support::serve_enrolled(state.clone(), enrolment_on(&dir.path().join("data")), None).await;
    let server = support::TestServer {
        addr,
        rest_addr,
        state,
        _dir: dir,
    };
    assert_eq!(status(&server, "/v1/install/linux/amd64").await, 404);
}

/// The token still guards the package download: the Server that hands its Client archive to a
/// stranger refuses the very same bytes on `/api/v1/packages/…` without one.
#[tokio::test]
async fn the_package_download_still_asks_for_a_token() {
    let served = served().await;
    let version = release();
    store_client(&served, &version, true).await;
    assert_eq!(status(&served, "/v1/install/linux/amd64").await, 200);
    let refused = get(format!(
        "http://{}/api/v1/packages/{CLIENT}/{version}/file?os=linux&arch=amd64",
        served.addr
    ))
    .await;
    assert_eq!(refused.status(), 401, "the download route asks for a token");
    assert!(refused
        .headers()
        .contains_key(reqwest::header::WWW_AUTHENTICATE));
}

/// The install routes give a whole Client archive to anyone, so they draw on the download rate
/// limit beside them: the second fetch of one peer before its bucket refills is `429` with
/// `Retry-After` and no bytes, the scripts share that peer's bucket rather than get one of their
/// own, another peer keeps its own bucket, and the refill serves the archive again.
#[tokio::test]
async fn the_install_routes_are_limited_per_peer() {
    let (served, clock) = served_with_rate().await;
    store_client(&served, &release(), true).await;
    let archive = format!("http://{}/v1/install/linux/amd64", served.addr);

    let first = get(archive.clone()).await;
    assert_eq!(first.status(), 200, "the archive of this release, as ever");
    assert_eq!(first.bytes().await.expect("bytes").as_ref(), ARCHIVE);

    let over = get(archive.clone()).await;
    assert_eq!(over.status(), 429, "one token, and no clock advanced");
    assert_eq!(
        over.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("30"),
        "the rate limit's 30 s"
    );
    assert_ne!(over.bytes().await.expect("body").as_ref(), ARCHIVE);

    assert_eq!(
        get(format!("http://{}/v1/install.sh", served.addr))
            .await
            .status(),
        429,
        "one bucket per peer, not one per route"
    );

    let other = reqwest::Client::new()
        .get(archive.clone())
        .header("x-forwarded-for", "192.0.2.7")
        .send()
        .await
        .expect("fetch as another peer");
    assert_eq!(other.status(), 200, "another peer has a bucket of its own");
    assert_eq!(other.bytes().await.expect("bytes").as_ref(), ARCHIVE);

    clock.advance(std::time::Duration::from_secs(1));
    let again = get(archive).await;
    assert_eq!(again.status(), 200, "the refusal was the rate, not a block");
    assert_eq!(again.bytes().await.expect("bytes").as_ref(), ARCHIVE);
}

/// The command an operator pastes, run for real: `classis_admin::render::install_command` renders
/// it, `sh -c` runs it, and its `curl` and the script's own `curl` and `tar` are the host's real
/// ones talking to a Server of the test's own over loopback. Only the programs that would touch the
/// host — `sudo`, `id`, `uname`, `getent`, `useradd`, `ln` — are stubs on a temporary `PATH`. The
/// `sudo` stub rewrites the registration path in the script's stdin the way `install_script.rs`
/// rewrites it in the script text, then runs the arguments it was given untouched. No account is
/// created, no service registered, no `PATH` entry laid, nothing written outside the tempdir.
#[cfg(target_os = "linux")]
mod the_one_liner {
    use super::{enrolment_on, release, status, support, CLIENT};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::Duration;

    /// The registration the script refuses to overwrite, rewritten to a path of the test's own.
    const UNIT: &str = "/etc/systemd/system/classis.service";

    /// The `sudo` stub: rewrite the registration path in the piped script — the replacement comes
    /// from `$UNIT`, never from this file — then run the arguments it was given untouched.
    const SUDO: &str = "#!/bin/sh\nsed \"s|UNIT_PATH|$UNIT|\" | exec \"$@\"\n";

    /// Writes an executable `path` from `body`.
    fn program(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write the stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// A program that records its arguments and succeeds.
    fn recorder(dir: &Path, name: &str) {
        program(
            dir,
            name,
            &format!("#!/bin/sh\nprintf '%s %s\\n' {name} \"$*\" >> \"$CLASSIS_LOG\"\n"),
        );
    }

    /// A `.tar.gz` holding one harmless `supervisor` stub that records what it is run for, built
    /// with the host's real `tar` so the script's archive check reads a real archive. The member's
    /// source goes into the archive and off the disk with it: a stub that ran can only have run
    /// from what the Server served.
    fn archive(dir: &Path) -> Vec<u8> {
        let src = dir.join("src");
        std::fs::create_dir_all(&src).expect("src");
        program(
            &src,
            "supervisor",
            "#!/bin/sh\nprintf 'supervisor %s\\n' \"$*\" >> \"$CLASSIS_LOG\"\n",
        );
        let out = dir.join("client.tar.gz");
        let made = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&out)
            .arg("-C")
            .arg(&src)
            .arg("supervisor")
            .status()
            .expect("build the archive");
        assert!(made.success(), "tar could not build the archive");
        std::fs::remove_dir_all(&src).expect("remove the member's source");
        std::fs::read(&out).expect("read the archive")
    }

    /// `store_client` with arbitrary bytes: the archive of the test's own, signed for this release.
    async fn store_bytes(server: &support::TestServer, version: &str, arch: &str, bytes: &[u8]) {
        use sha2::Digest as _;
        let set = format!(
            "http://{}/api/v1/packages/{CLIENT}/{version}",
            server.rest_addr
        );
        let created = reqwest::Client::new()
            .put(&set)
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("put set");
        assert_eq!(created.status(), 200, "the set is created");
        let uploaded = reqwest::Client::new()
            .put(format!("{set}/entries/linux/{arch}"))
            .body(bytes.to_vec())
            .send()
            .await
            .expect("put entry");
        assert_eq!(uploaded.status(), 200, "the artifact is stored");
        let signature = support::signature_hex(CLIENT, version, &sha2::Sha256::digest(bytes));
        let signed = reqwest::Client::new()
            .put(format!("{set}/entries/linux/{arch}/signature"))
            .json(&serde_json::json!({ "signature": signature }))
            .send()
            .await
            .expect("put signature");
        assert_eq!(signed.status(), 200, "the entry takes the signature");
    }

    /// The Server with a real Space in its data directory, and that Space's enrolment key — what
    /// the operator's tooling pastes beside this Server's address.
    async fn served_with_space() -> (support::TestServer, String) {
        opamp::tls::install_ring_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        let key = support::create_space(&data, "lab");
        let state = std::sync::Arc::new(support::state_on(dir.path()));
        let (addr, rest_addr) =
            support::serve_enrolled(state.clone(), enrolment_on(&data), None).await;
        (
            support::TestServer {
                addr,
                rest_addr,
                state,
                _dir: dir,
            },
            key,
        )
    }

    /// One thin path through the real Server's install routes: fetch the script, fetch the signed
    /// archive of this release, unpack it, and run the Client it holds — which reports the
    /// `service install` endpoint the script derived and the `enrol` of the base URL and key —
    /// while the package download beside the install routes stays token-guarded.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_pasted_one_liner_installs_from_the_server_that_served_it() {
        let (machine, build) = ("x86_64", "amd64");
        for tool in ["curl", "tar"] {
            let found = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("command -v {tool} >/dev/null"))
                .status()
                .expect("sh");
            assert!(found.success(), "{tool} is required for the bootstrap test");
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let archive = archive(dir.path());
        let (served, key) = served_with_space().await;
        let version = release();
        store_bytes(&served, &version, build, &archive).await;

        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("bin");
        let unit = dir.path().join("host-unit.service");
        program(&bin, "sudo", &SUDO.replace("UNIT_PATH", UNIT));
        program(&bin, "id", "#!/bin/sh\necho 0\n");
        program(&bin, "uname", &format!("#!/bin/sh\necho {machine}\n"));
        // Neither the account nor a group of its name exists yet.
        program(&bin, "getent", "#!/bin/sh\nexit 1\n");
        recorder(&bin, "useradd");
        recorder(&bin, "ln");

        let base = format!("http://{}", served.addr);
        let command =
            classis_admin::render::install_command(&base, &key, classis_admin::render::Os::Linux);
        let log = dir.path().join("log");
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("CLASSIS_LOG", &log)
            .env("UNIT", &unit)
            .env("TMPDIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("run the one-liner");
        let output = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("the install finishes within the timeout")
            .expect("wait on the install");
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(output.status.success(), "stdout: {out}\nstderr: {err}");
        let log: Vec<String> = std::fs::read_to_string(&log)
            .expect("the record of every stubbed program")
            .lines()
            .map(str::to_string)
            .collect();
        // The Client installed by its own two commands against this Server — and the only copy of
        // its bytes left on disk is the one that came over the wire.
        let endpoint = format!("ws://{}/v1/opamp", served.addr);
        let client: Vec<&str> = log
            .iter()
            .filter_map(|l| l.strip_prefix("supervisor "))
            .collect();
        assert_eq!(client.len(), 2, "expected install and enrol commands");
        assert_eq!(
            client[0],
            format!("service install --endpoint {endpoint} --run-as classis")
        );
        assert!(
            client[1] == format!("enrol {base} {key}"),
            "incorrect enrol arguments"
        );
        assert!(out.contains("Installed and enrolled"), "{out}");
        let adds: Vec<&String> = log.iter().filter(|l| l.starts_with("useradd ")).collect();
        assert_eq!(adds.len(), 1, "expected one useradd invocation");
        assert!(adds[0].contains("--system --user-group"), "{adds:?}");
        assert!(
            log.iter()
                .any(|l| l == "ln -sfn /opt/classis/current/supervisor /usr/bin/classis"),
            "{log:#?}"
        );
        assert!(!unit.exists(), "the script wrote a registration");
        // The key stays out of every URL: the command carries it once, after `--key`, and the
        // script URL beside it does not hold it.
        assert_eq!(command.matches(key.as_str()).count(), 1);
        let script_url = command
            .split_whitespace()
            .find(|word| word.contains("/v1/install.sh"))
            .expect("the script URL of the one-liner");
        assert!(!script_url.contains(key.as_str()));
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read the directory")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("tmp."))
            .collect();
        assert!(
            left.is_empty(),
            "the script left its temporary directory: {left:?}"
        );
        // What the install route handed to a stranger, the package route still refuses one.
        assert_eq!(
            status(
                &served,
                &format!("/api/v1/packages/{CLIENT}/{version}/file?os=linux&arch={build}")
            )
            .await,
            401,
            "the install took the token-guarded download"
        );
    }
}
