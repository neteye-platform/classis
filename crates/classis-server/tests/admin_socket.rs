//! `classis-cli` against the Server's own Spaces: the real command tree, over the real
//! socket of `classis_server::admin::bind`, answered through the `Enrolment` the running Server
//! would hold, on the filesystem records.
#![cfg(unix)]

use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::path::Path;
use std::sync::Arc;

use classis_server::admin::{bind, AdminSpaces};
use classis_server::clock::SystemClock;
use classis_server::enrolment::Enrolment;
use classis_server::throttle::{Limits, Throttle};
use classis_server::Records;

const NO_ENDPOINT: &str =
    "classis-cli: the public endpoint hosts reach the Server at is not configured yet\n";

struct Outcome {
    code: u8,
    out: String,
    err: String,
}

/// A Server's enrolment on a temporary data directory, with the operator's socket served beside it.
struct Rig {
    enrolment: Arc<Enrolment>,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    classis_server::fs::open_data_dir(&data, true).expect("the data directory");
    let records = Records::Files(data);
    let clock = Arc::new(SystemClock);
    let enrolment = Arc::new(
        Enrolment::on(
            &records,
            oauth_token::server::Lifetime::Never,
            clock.clone(),
            Arc::new(Throttle::new(
                Limits {
                    max_failures: 10,
                    window_secs: 60,
                    backoff_secs: 300,
                },
                clock,
            )),
        )
        .expect("the enrolment"),
    );
    let socket = dir.path().join("admin.sock");
    let listener = bind(&socket).expect("the operator's socket");
    tokio::spawn(classis_admin::server::serve(
        listener,
        Arc::new(AdminSpaces::new(enrolment.clone())),
    ));
    Rig {
        enrolment,
        socket,
        _dir: dir,
    }
}

impl Rig {
    /// Runs `classis-cli --socket <socket> <args…>` off the async runtime, so the socket server
    /// can answer it.
    async fn cli(&self, args: &[&str]) -> Outcome {
        let mut argv = vec![
            "classis-cli".to_owned(),
            "--socket".to_owned(),
            self.socket.to_str().expect("utf-8").to_owned(),
        ];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        tokio::task::spawn_blocking(move || {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = classis_admin::cli::run(argv, &mut out, &mut err);
            Outcome {
                code,
                out: String::from_utf8(out).expect("utf-8"),
                err: String::from_utf8(err).expect("utf-8"),
            }
        })
        .await
        .expect("the command ran")
    }

    fn key_of(&self, name: &str) -> String {
        self.enrolment
            .spaces()
            .key(name)
            .expect("the space exists")
            .to_string()
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn space_create_prints_the_key_the_servers_own_spaces_holds() {
    let rig = rig();

    let outcome = rig.cli(&["space", "create", "acme"]).await;

    assert_eq!(outcome.code, 0, "{}", outcome.err);
    assert_eq!(outcome.err, "");
    assert!(outcome.out.starts_with("cle1_acme_"), "{}", outcome.out);
    assert_eq!(outcome.out, format!("{}\n", rig.key_of("acme")));
}

#[tokio::test(flavor = "multi_thread")]
async fn space_list_prints_the_names_in_order() {
    let rig = rig();
    assert_eq!(rig.cli(&["space", "create", "beta"]).await.code, 0);
    assert_eq!(rig.cli(&["space", "create", "acme"]).await.code, 0);

    let outcome = rig.cli(&["space", "list"]).await;

    assert_eq!(outcome.code, 0, "{}", outcome.err);
    assert_eq!(outcome.out, "acme\nbeta\n");
    assert_eq!(outcome.err, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn space_rotate_key_replaces_the_key_the_servers_own_spaces_holds() {
    let rig = rig();
    let first = rig.cli(&["space", "create", "acme"]).await.out;

    let rotated = rig.cli(&["space", "rotate-key", "acme"]).await;

    assert_eq!(rotated.code, 0, "{}", rotated.err);
    assert_eq!(rotated.err, "");
    assert!(rotated.out.starts_with("cle1_acme_"), "{}", rotated.out);
    assert_ne!(rotated.out, first);
    assert_eq!(rotated.out, format!("{}\n", rig.key_of("acme")));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_of_the_spaces_reaches_the_cli_as_exit_1() {
    let rig = rig();
    assert_eq!(rig.cli(&["space", "create", "acme"]).await.code, 0);

    let existing = rig.cli(&["space", "create", "acme"]).await;
    assert_eq!(existing.code, 1);
    assert_eq!(existing.out, "");
    assert_eq!(
        existing.err,
        "classis-cli: a space of that name exists, ignoring case\n"
    );

    let unknown = rig.cli(&["space", "rotate-key", "ghost"]).await;
    assert_eq!(unknown.code, 1);
    assert_eq!(unknown.out, "");
    assert_eq!(unknown.err, "classis-cli: no such space\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn enrol_command_refuses_while_the_public_endpoint_is_not_configured() {
    let rig = rig();
    assert_eq!(rig.cli(&["space", "create", "acme"]).await.code, 0);

    let outcome = rig
        .cli(&["enrol-command", "--space", "acme", "--os", "linux"])
        .await;

    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.out, "");
    assert_eq!(outcome.err, NO_ENDPOINT);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_creates_a_missing_parent_directory_owner_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("run").join("classis");
    let socket = parent.join("admin.sock");

    let _listener = bind(&socket).expect("binds");

    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&socket), 0o600);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_leaves_an_existing_directory_as_it_is() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let _listener = bind(&dir.path().join("admin.sock")).expect("binds");

    assert_eq!(mode(dir.path()), 0o755);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_refuses_a_socket_owned_by_a_running_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("admin.sock");
    let _listener = bind(&socket).expect("first Server binds");

    let error = bind(&socket).expect_err("a live socket must not be replaced");

    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    std::os::unix::net::UnixStream::connect(&socket).expect("first Server remains reachable");
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_replaces_a_socket_an_earlier_run_left_behind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("admin.sock");
    drop(bind(&socket).expect("binds"));
    assert!(socket.exists(), "the earlier run left its socket");

    let _listener = bind(&socket).expect("binds over the leftover");

    assert_eq!(mode(&socket), 0o600);
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_refuses_what_is_not_a_socket_and_removes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");

    let file = dir.path().join("file.sock");
    std::fs::write(&file, "mine").expect("write");
    let directory = dir.path().join("directory.sock");
    std::fs::create_dir(&directory).expect("mkdir");
    let link = dir.path().join("link.sock");
    symlink(&file, &link).expect("symlink");

    for path in [&file, &directory, &link] {
        let error = bind(path).expect_err("not the Server's to remove");
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
        assert!(
            std::fs::symlink_metadata(path).is_ok(),
            "{}",
            path.display()
        );
    }
    assert_eq!(std::fs::read_to_string(&file).expect("read"), "mine");
}
