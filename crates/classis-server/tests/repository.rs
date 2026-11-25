//! A Server that reads its Packages from a Package Repository: it lists and offers them as it does
//! uploaded ones, refuses every write to them through the REST API, follows the repository at each
//! listing — a Package that leaves it is missing, not deleted — and never starts beside records
//! that hold an uploaded Package.

mod support;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use classis_server::config::{RepositoryConfig, RootsVerifier};
use classis_server::fleet::{AppState, PackageOffering};
use classis_server::packages::PackageStore;
use classis_server::repository::Repository;
use opamp::proto::{
    AgentCapabilities, AgentToServer, PackageStatus, PackageStatusEnum, PackageStatuses,
    ServerCapabilities, ServerToAgent,
};
use opamp::uid::InstanceUid;
use prost::Message as _;
use sha2::{Digest, Sha256};
use support::{full_report, TestServer};

const PROTOBUF: &str = "application/x-protobuf";

/// Writes `bytes` at `key` under `root` as a writer of the repository does: a temporary file,
/// renamed into place.
fn put(root: &Path, key: &str, bytes: &[u8]) {
    let path = root.join(key);
    let dir = path.parent().expect("a key has a directory");
    std::fs::create_dir_all(dir).expect("create the directory");
    let staged = dir.join(".staged");
    std::fs::write(&staged, bytes).expect("write");
    std::fs::rename(&staged, &path).expect("rename");
}

/// Publishes one Package of the test fleet's Agent type, signed by the test Package Signer for
/// each of `platforms`: its Blobs first, its manifest last.
fn publish(root: &Path, version: &str, platforms: &[(&str, &str, &[u8])]) {
    let mut entries = Vec::new();
    for (os, arch, artifact) in platforms {
        let hash = Sha256::digest(artifact);
        put(root, &format!("blobs/{}", hex::encode(hash)), artifact);
        entries.push(serde_json::json!({
            "os": os,
            "arch": arch,
            "sha256": hex::encode(hash),
            "size": artifact.len(),
            "signature_hex": support::signature_hex(support::AGENT_TYPE, version, &hash),
        }));
    }
    let manifest = serde_json::json!({
        "agent_type": support::AGENT_TYPE,
        "version": version,
        "entries": entries,
    });
    put(
        root,
        &format!("packages/{}@{version}.json", support::AGENT_TYPE),
        &serde_json::to_vec_pretty(&manifest).expect("manifest"),
    );
}

/// A Server on the repository in `root`, its signatures checked up to the test Root, as the binary
/// opens one, and the repository, for a test to run the next listing.
async fn spawn_on(root: &Path) -> (TestServer, Repository) {
    opamp::tls::install_ring_provider();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut repository = Repository::open_directory(root).expect("open the repository");
    let store = PackageStore::from_repository(
        repository.read().expect("read the repository"),
        Box::new(repository.blob_store()),
    )
    .with_verifier(Box::new(RootsVerifier::new(support::test_root().0.roots())));
    let state = Arc::new(
        AppState::new(dir.path().join("fleet-configs"))
            .expect("configs")
            .with_packages(Some(
                PackageOffering::new(dir.path(), store).expect("deployments"),
            )),
    );
    let (addr, rest_addr) =
        support::serve(state.clone(), classis_server::transport::Admission::open()).await;
    (
        TestServer {
            addr,
            rest_addr,
            state,
            _dir: dir,
        },
        repository,
    )
}

/// One listing, as the Server runs one at each interval.
fn listing(server: &TestServer, repository: &mut Repository) {
    server
        .state
        .packages()
        .expect("package delivery")
        .replace(repository.read().expect("read the repository"))
        .expect("replace");
}

async fn exchange(server: &TestServer, msg: &opamp::proto::AgentToServer) -> ServerToAgent {
    let response = reqwest::Client::new()
        .post(format!("http://{}/v1/opamp", server.addr))
        .header("content-type", PROTOBUF)
        .body(msg.encode_to_vec())
        .send()
        .await
        .expect("post");
    assert_eq!(response.status(), 200);
    ServerToAgent::decode(response.bytes().await.expect("body").as_ref()).expect("decode")
}

/// Every file under `root` with its bytes: what the repository holds.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                let key = path.strip_prefix(root).expect("under root");
                files.insert(
                    key.display().to_string(),
                    std::fs::read(&path).expect("read"),
                );
            }
        }
    }
    files
}

/// A signed Package for two platforms is listed with both entries valid, and offered.
#[tokio::test]
async fn a_server_on_a_repository_lists_its_packages_and_offers_them() {
    let root = tempfile::tempdir().expect("repository");
    publish(
        root.path(),
        "1.0.0",
        &[
            ("linux", "amd64", b"linux build"),
            ("windows", "amd64", b"windows build"),
        ],
    );
    let (server, _) = spawn_on(root.path()).await;

    let listed: serde_json::Value =
        reqwest::get(format!("http://{}/api/v1/packages", server.rest_addr))
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
    let packages = listed.as_array().expect("a list");
    assert_eq!(packages.len(), 1, "{listed}");
    assert_eq!(packages[0]["version"], "1.0.0", "{listed}");
    let states: Vec<(String, String)> = packages[0]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| {
            (
                format!(
                    "{}/{}",
                    entry["os"].as_str().expect("os"),
                    entry["arch"].as_str().expect("arch")
                ),
                entry["signature_state"]
                    .as_str()
                    .expect("state")
                    .to_string(),
            )
        })
        .collect();
    assert_eq!(
        states,
        vec![
            ("linux/amd64".to_string(), "valid".to_string()),
            ("windows/amd64".to_string(), "valid".to_string()),
        ]
    );

    let reply = exchange(&server, &full_report(&InstanceUid::default(), "host", 1)).await;
    assert_ne!(
        reply.capabilities & ServerCapabilities::OffersPackages as u64,
        0,
        "the Server declares OffersPackages"
    );
}

/// Every REST write to a Package, an entry or a signature is a `409` naming the repository, and
/// the repository is as its writer left it.
#[tokio::test]
async fn every_write_to_a_package_is_refused_naming_the_repository() {
    let root = tempfile::tempdir().expect("repository");
    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    let before = tree(root.path());
    let (server, _) = spawn_on(root.path()).await;

    let base = format!(
        "http://{}/api/v1/packages/{}",
        server.rest_addr,
        support::AGENT_TYPE
    );
    let signature = serde_json::json!({
        "signature": support::signature_hex(
            support::AGENT_TYPE,
            "1.0.0",
            &Sha256::digest(b"linux build"),
        ),
    });
    let client = reqwest::Client::new();
    let requests = [
        (
            "create a Package",
            client
                .put(format!("{base}/2.0.0"))
                .json(&serde_json::json!({})),
        ),
        (
            "create a Package it holds",
            client
                .put(format!("{base}/1.0.0"))
                .json(&serde_json::json!({})),
        ),
        ("delete a Package", client.delete(format!("{base}/1.0.0"))),
        (
            "upload an entry",
            client
                .put(format!("{base}/1.0.0/entries/linux/arm64"))
                .body("bytes"),
        ),
        (
            "replace an entry",
            client
                .put(format!("{base}/1.0.0/entries/linux/amd64"))
                .body("bytes"),
        ),
        (
            "delete an entry",
            client.delete(format!("{base}/1.0.0/entries/linux/amd64")),
        ),
        (
            "sign an entry",
            client
                .put(format!("{base}/1.0.0/entries/linux/amd64/signature"))
                .json(&signature),
        ),
        (
            "delete a signature",
            client.delete(format!("{base}/1.0.0/entries/linux/amd64/signature")),
        ),
    ];
    for (what, request) in requests {
        let response = request.send().await.expect(what);
        assert_eq!(response.status(), 409, "{what}");
        let body: serde_json::Value = response.json().await.expect("json");
        let refusal = body["error"].as_str().expect("an error");
        assert!(refusal.contains("Package Repository"), "{what}: {refusal}");
    }

    assert_eq!(tree(root.path()), before, "the repository does not change");
    let listed: serde_json::Value =
        reqwest::get(format!("http://{}/api/v1/packages", server.rest_addr))
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
    assert_eq!(listed.as_array().expect("a list").len(), 1, "{listed}");
    assert_eq!(
        listed[0]["entries"][0]["signature_state"], "valid",
        "{listed}"
    );
}

/// The REST client of the operator.
fn rest(server: &TestServer, path: &str) -> String {
    format!("http://{}{path}", server.rest_addr)
}

/// A report of the one test Agent that accepts packages, with what it says it has installed.
fn agent_report(uid: &InstanceUid, sequence_num: u64, installed: Option<&[u8]>) -> AgentToServer {
    let mut report = full_report(uid, "collector", sequence_num);
    report.capabilities |= AgentCapabilities::AcceptsPackages as u64
        | AgentCapabilities::ReportsPackageStatuses as u64;
    if let Some(hash) = installed {
        report.package_statuses = Some(PackageStatuses {
            packages: [(
                support::AGENT_TYPE.to_string(),
                PackageStatus {
                    name: support::AGENT_TYPE.to_string(),
                    agent_has_version: "1.0.0".to_string(),
                    status: PackageStatusEnum::Installed as i32,
                    ..Default::default()
                },
            )]
            .into(),
            server_provided_all_packages_hash: hash.to_vec(),
            error_message: String::new(),
        });
    }
    report
}

/// A Server with an empty repository declares `OffersPackages` from the listing that finds the
/// first Package.
#[tokio::test]
async fn the_first_package_written_declares_offers_packages() {
    let root = tempfile::tempdir().expect("repository");
    let (server, mut repository) = spawn_on(root.path()).await;
    let uid = InstanceUid::default();
    let offers =
        |reply: &ServerToAgent| reply.capabilities & ServerCapabilities::OffersPackages as u64 != 0;

    assert!(!offers(
        &exchange(&server, &agent_report(&uid, 1, None)).await
    ));
    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    listing(&server, &mut repository);
    assert!(offers(
        &exchange(&server, &agent_report(&uid, 2, None)).await
    ));
}

/// A Package that a Deployment holds and an Agent's assignment pins leaves the repository: the
/// list loses it, the Deployment marks it missing, a rollout is refused naming it, the Agent is
/// offered nothing and keeps what it runs, and the download is `404`. Once the manifest is back,
/// all of it works again with no other act.
#[tokio::test]
async fn a_package_that_leaves_the_repository_is_missing_until_it_is_back() {
    let root = tempfile::tempdir().expect("repository");
    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    let (server, mut repository) = spawn_on(root.path()).await;
    let client = reqwest::Client::new();
    let uid = InstanceUid::default();
    let deployment = rest(&server, "/api/v1/deployments/stable");
    let download = format!(
        "http://{}/api/v1/packages/{}/1.0.0/file?os=linux&arch=amd64",
        server.addr,
        support::AGENT_TYPE
    );
    let availability = || async {
        let view: serde_json::Value = client
            .get(&deployment)
            .send()
            .await
            .expect("get deployment")
            .json()
            .await
            .expect("json");
        view["packages"][0]["availability"]
            .as_str()
            .expect("availability")
            .to_string()
    };
    let rollout = || async {
        client
            .post(format!("{deployment}/rollout"))
            .send()
            .await
            .expect("rollout")
    };

    // The Agent is known, the Deployment holds the Package, and the rollout pins it.
    exchange(&server, &agent_report(&uid, 1, None)).await;
    let aimed = client
        .put(&deployment)
        .json(&serde_json::json!({ "selector": { "service.name": support::AGENT_TYPE } }))
        .send()
        .await
        .expect("put deployment");
    assert_eq!(aimed.status(), 200);
    let held = client
        .put(format!(
            "{deployment}/packages/{}/1.0.0",
            support::AGENT_TYPE
        ))
        .send()
        .await
        .expect("put package");
    assert_eq!(held.status(), 200);
    assert_eq!(rollout().await.status(), 200);
    let offer = exchange(&server, &agent_report(&uid, 2, None))
        .await
        .packages_available
        .expect("an offer");
    let installed = offer.all_packages_hash.clone();
    assert!(exchange(&server, &agent_report(&uid, 3, Some(&installed)))
        .await
        .packages_available
        .is_none());
    assert_eq!(availability().await, "present");
    assert_eq!(
        client
            .get(&download)
            .send()
            .await
            .expect("download")
            .status(),
        200
    );

    std::fs::remove_file(
        root.path()
            .join(format!("packages/{}@1.0.0.json", support::AGENT_TYPE)),
    )
    .expect("remove the manifest");
    listing(&server, &mut repository);

    let listed: serde_json::Value = client
        .get(rest(&server, "/api/v1/packages"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(
        listed,
        serde_json::json!([]),
        "the Package is absent from the list"
    );
    assert_eq!(availability().await, "missing");
    let refused = rollout().await;
    assert_eq!(refused.status(), 409);
    let why: serde_json::Value = refused.json().await.expect("json");
    let why = why["error"].as_str().expect("an error");
    assert!(
        why.contains("missing from the Package Repository") && why.contains("1.0.0"),
        "{why}"
    );
    for (n, installed) in [(4, None), (5, Some(installed.as_slice()))] {
        assert!(
            exchange(&server, &agent_report(&uid, n, installed))
                .await
                .packages_available
                .is_none(),
            "the Agent is offered nothing, so it keeps what it runs"
        );
    }
    assert_eq!(
        client
            .get(&download)
            .send()
            .await
            .expect("download")
            .status(),
        404
    );

    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    listing(&server, &mut repository);
    assert_eq!(availability().await, "present");
    assert_eq!(rollout().await.status(), 200, "the rollout succeeds again");
    assert!(
        exchange(&server, &agent_report(&uid, 6, Some(&installed)))
            .await
            .packages_available
            .is_none(),
        "the Agent runs what it is assigned"
    );
    assert_eq!(
        client
            .get(&download)
            .send()
            .await
            .expect("download")
            .status(),
        200
    );
}

/// Uploaded Packages are not hidden: records that hold one stop the startup on a repository,
/// naming the Package and the migration.
#[test]
fn records_that_hold_an_uploaded_package_stop_the_startup() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let uploaded = support::open_store(data_dir.path());
    let id = classis_server::packages::PackageId::new(support::AGENT_TYPE, "1.0.0").expect("id");
    uploaded.create(&id).expect("create");
    drop(uploaded);
    let root = tempfile::tempdir().expect("repository");

    let refused = PackageStore::on_repository(
        &classis_server::Records::Files(data_dir.path().to_path_buf()),
        &RepositoryConfig {
            path: Some(root.path().to_path_buf()),
            s3: None,
            rescan_secs: 60,
        },
    )
    .err()
    .expect("refused");
    assert!(
        refused.contains(&id.to_string())
            && refused.contains("Moving uploaded Packages into a Package Repository"),
        "{refused}"
    );

    let empty = tempfile::tempdir().expect("data dir");
    let store = PackageStore::on_repository(
        &classis_server::Records::Files(empty.path().to_path_buf()),
        &RepositoryConfig {
            path: Some(root.path().to_path_buf()),
            s3: None,
            rescan_secs: 60,
        },
    )
    .expect("records without Packages")
    .0;
    assert!(store.is_empty());
}

/// The Server under test, killed when the test ends.
struct ServerUnderTest(std::process::Child);

impl Drop for ServerUnderTest {
    fn drop(&mut self) {
        // The process may have stopped already, and a drop has no one to tell of a failure.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Two ports free on the loopback: the Agent plane's and the Operator plane's.
fn free_ports() -> (u16, u16) {
    let bind = || std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    let (first, second) = (bind(), bind());
    let port = |listener: &std::net::TcpListener| listener.local_addr().expect("addr").port();
    (port(&first), port(&second))
}

/// What became of a Server started on a configuration: it serves, or it stopped with this log.
enum Started {
    Serving(ServerUnderTest),
    Stopped(String),
}

/// Starts the binary on `config` and waits until it serves or stops. Its log is read to the end
/// on a thread of its own, so a Server that serves never waits on a full pipe.
fn start(config: &Path) -> Started {
    use std::io::{BufRead as _, BufReader};
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_server"))
        .arg("--config")
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start the server");
    let stderr = child.stderr.take().expect("stderr");
    let (lines, logged) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            // Once the test has what it waited for, nobody receives the rest of the log.
            let _ = lines.send(line);
        }
    });
    let mut log = Vec::new();
    while let Ok(line) = logged.recv_timeout(std::time::Duration::from_secs(30)) {
        let up = line.contains("serving the REST API");
        log.push(line);
        if up {
            return Started::Serving(ServerUnderTest(child));
        }
    }
    // A Server that never said it serves is stopped; one that stopped on its own is reaped.
    let _ = child.kill();
    let _ = child.wait();
    Started::Stopped(log.join("\n"))
}

/// [`start`] on a blocking thread, so the test's runtime is never held while it waits.
async fn started(config: &Path) -> Started {
    let config = config.to_path_buf();
    tokio::task::spawn_blocking(move || start(&config))
        .await
        .expect("the start of the server runs to its end")
}

/// The binary reads the repository its configuration names, and refuses one beside `[blobs]` or
/// beside records that hold an uploaded Package, naming what is in the way.
#[tokio::test]
async fn the_binary_reads_the_repository_its_configuration_names() {
    opamp::tls::install_ring_provider();
    let root = tempfile::tempdir().expect("repository");
    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    let dir = tempfile::tempdir().expect("tempdir");
    let data_dir = dir.path().join("data");
    let (agent_port, operator_port) = free_ports();
    let config = dir.path().join("server.toml");
    let write = |extra: &str| {
        std::fs::write(
            &config,
            format!(
                "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\n\n\
                 [rest]\nlisten = \"127.0.0.1:{operator_port}\"\n\n\
                 [packages.repository]\npath = {}\n{extra}",
                toml::Value::String(data_dir.display().to_string()),
                toml::Value::String(root.path().display().to_string()),
            ),
        )
        .expect("write server.toml");
    };

    write("\n[blobs]\nstore = \"fs\"\n");
    match started(&config).await {
        Started::Stopped(log) => assert!(
            log.contains("[packages.repository]") && log.contains("[blobs]"),
            "{log}"
        ),
        Started::Serving(_) => panic!("a repository beside [blobs] started"),
    }

    write("");
    let Started::Serving(running) = started(&config).await else {
        panic!("the server did not start on its repository");
    };
    let listed: serde_json::Value =
        reqwest::get(format!("http://127.0.0.1:{operator_port}/api/v1/packages"))
            .await
            .expect("list")
            .json()
            .await
            .expect("json");
    assert_eq!(listed[0]["version"], "1.0.0", "{listed}");
    assert!(
        !data_dir.join("blobs").exists(),
        "the Server keeps no artifact of its own"
    );
    drop(running);

    let uploaded = support::open_store(&data_dir);
    let id = classis_server::packages::PackageId::new(support::AGENT_TYPE, "2.0.0").expect("id");
    uploaded.create(&id).expect("create");
    drop(uploaded);
    match started(&config).await {
        Started::Stopped(log) => assert!(log.contains(&id.to_string()), "{log}"),
        Started::Serving(_) => panic!("records holding an uploaded Package started"),
    }
}

/// The binary reads its repository again at `rescan_secs`: a Package written after the startup is
/// listed within one interval and one listing, with no restart.
#[tokio::test]
async fn the_binary_lists_a_package_written_after_its_startup() {
    opamp::tls::install_ring_provider();
    let root = tempfile::tempdir().expect("repository");
    let dir = tempfile::tempdir().expect("tempdir");
    let (agent_port, operator_port) = free_ports();
    let config = dir.path().join("server.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:{agent_port}\"\ndata_dir = {}\n\n\
             [rest]\nlisten = \"127.0.0.1:{operator_port}\"\n\n\
             [packages.repository]\npath = {}\nrescan_secs = 10\n",
            toml::Value::String(dir.path().join("data").display().to_string()),
            toml::Value::String(root.path().display().to_string()),
        ),
    )
    .expect("write server.toml");
    let Started::Serving(_running) = started(&config).await else {
        panic!("the server did not start on its repository");
    };
    let list = || async {
        reqwest::get(format!("http://127.0.0.1:{operator_port}/api/v1/packages"))
            .await
            .expect("list")
            .json::<serde_json::Value>()
            .await
            .expect("json")
    };
    assert_eq!(list().await, serde_json::json!([]));

    publish(root.path(), "1.0.0", &[("linux", "amd64", b"linux build")]);
    let written = std::time::Instant::now();
    loop {
        let listed = list().await;
        if listed[0]["version"] == "1.0.0" {
            break;
        }
        assert!(
            written.elapsed() < std::time::Duration::from_secs(25),
            "not listed within one interval and one listing: {listed}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}
