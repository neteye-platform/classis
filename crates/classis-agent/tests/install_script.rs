//! The install scripts the Server serves (`crates/classis-server/install/`), read as text the way
//! `msi_exe_command.rs` reads the WiX source: neither script is fetched from a running Server here,
//! so what an operator pastes is held to by `cargo test` on every platform. The shell script is run
//! too, on Linux, from a copy whose registration path and every external program are stubbed inside
//! a temporary directory — nothing installs on the host running the test.
//!
//! The two scripts are one design in two dialects, so the properties that matter are asserted of
//! both: the enrolment key never enters a URL or a network request, TLS is floored at 1.3 off the
//! loopback, no redirect is followed, no certificate check is relaxed and no CA is created, the
//! archive contributes exactly the Client executable, and the Client is installed by its own
//! `service install` and `enrol` and by nothing else.

use std::path::{Path, PathBuf};

const SHELL_SCRIPT: &str = "install.sh";
const POWERSHELL_SCRIPT: &str = "install.ps1";

fn install_script_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../classis-server/install")
        .join(name)
}

fn install_script(name: &str) -> String {
    let path = install_script_path(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn shell() -> String {
    install_script(SHELL_SCRIPT)
}

fn powershell() -> String {
    install_script(POWERSHELL_SCRIPT)
}

fn post_install() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/linux/postinst");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every line that carries the key, in either dialect.
fn key_lines(script: &str) -> Vec<&str> {
    script
        .lines()
        .filter(|line| line.contains("$key") || line.contains("$Key"))
        .collect()
}

/// `useradd` command lines, `\` continuations joined and runs of whitespace collapsed, so two
/// scripts that create the same account read the same whatever their indentation.
fn useradd_lines(script: &str) -> Vec<String> {
    script
        .replace("\\\n", " ")
        .lines()
        .filter(|line| line.trim_start().starts_with("useradd "))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

#[test]
fn both_scripts_exist() {
    for name in [SHELL_SCRIPT, POWERSHELL_SCRIPT] {
        assert!(!install_script(name).trim().is_empty(), "{name} is empty");
    }
}

/// The key reaches the Client as an argument of `enrol` and nowhere else: no line that carries it
/// also carries a request, or a scheme a URL could be built from. That is what keeps it out of the
/// Server's access log and out of any proxy's.
#[test]
fn the_key_is_an_argument_and_never_part_of_a_request() {
    for (name, script) in [("install.sh", shell()), ("install.ps1", powershell())] {
        let lines = key_lines(&script);
        assert!(!lines.is_empty(), "{name} never passes the key");
        for line in &lines {
            for network in ["curl", "Invoke-WebRequest", "://", "Uri"] {
                assert!(!line.contains(network), "{name}: {line}");
            }
        }
        assert!(
            lines.iter().any(|line| line.contains("enrol")),
            "{name}: the key never reaches enrol — {lines:#?}"
        );
    }
}

/// The download URL is built from the base URL the operator was given, so a Server behind a
/// reverse-proxy path prefix is fetched from that prefix: no line that spells the download path
/// spells an origin too.
#[test]
fn the_download_comes_from_the_server_the_script_was_given() {
    for (script, path) in [
        (shell(), "/v1/install/linux/"),
        (powershell(), "/v1/install/windows/"),
    ] {
        let line = script
            .lines()
            .find(|line| line.contains(path))
            .unwrap_or_else(|| panic!("no download of {path}"));
        assert!(
            !line.contains("://"),
            "{path} names an origin of its own: {line}"
        );
    }
}

/// TLS 1.3 is the floor of the one off-host fetch, and no lower floor, no disabled verification and
/// no pinned CA rides along with it.
#[test]
fn the_fetch_pins_tls_1_3_and_relaxes_nothing() {
    let sh = shell();
    assert!(sh.contains("--tlsv1.3"), "no TLS floor");
    for weaker in [
        "--tlsv1 ",
        "--tlsv1.0",
        "--tlsv1.1",
        "--tlsv1.2",
        "--insecure",
        "--cacert",
    ] {
        assert!(!sh.contains(weaker), "{weaker}");
    }
    let ps = powershell();
    assert!(
        ps.contains("[Net.SecurityProtocolType]::Tls13"),
        "no TLS floor"
    );
    assert!(ps.contains("if ($Base -like 'https://*') { Assert-Tls13 }"));
    for weaker in ["Tls12", "Tls11", "SkipCertificateCheck"] {
        assert!(!ps.contains(weaker), "{weaker}");
    }
}

/// Neither script terminates TLS or provisions a CA: the host already trusts its Server, which is
/// what let it fetch the script at all.
#[test]
fn neither_script_touches_a_certificate_authority() {
    for (name, script) in [("install.sh", shell()), ("install.ps1", powershell())] {
        for absent in [
            "openssl",
            "New-SelfSignedCertificate",
            "certutil",
            "ca_file",
            "server-ca",
        ] {
            assert!(!script.contains(absent), "{name} names {absent}");
        }
    }
}

/// No redirect is followed, in either dialect: a redirect would resend the request for the Client
/// binary wherever it points.
#[test]
fn neither_script_follows_a_redirect() {
    let sh = shell();
    for line in sh.lines().filter(|line| line.contains("curl ")) {
        assert!(
            !line.contains("-L") && !line.contains("--location"),
            "{line}"
        );
    }
    assert!(
        sh.contains("200"),
        "a 3xx that curl answers as a success is not refused by a status check"
    );
    let ps = powershell();
    assert!(
        ps.contains("AllowAutoRedirect = $false"),
        "a redirect is followed"
    );
    assert!(ps.contains("200"), "the status code is never checked");
}

/// A shell reading a pipe parses one command at a time, so a truncated download must not have been
/// able to run anything: everything is a definition until the last line calls `main`.
#[test]
fn the_shell_script_runs_nothing_until_it_is_whole() {
    let sh = shell();
    assert_eq!(sh.matches("main \"$@\"").count(), 1, "main is called twice");
    let code: Vec<&str> = sh
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(
        code.last().copied(),
        Some("main \"$@\""),
        "main is not last"
    );
}

/// The download lands in a directory only this process can read, and it is taken away again on
/// every way out of the script.
#[test]
fn the_shell_script_downloads_privately_and_cleans_up() {
    let sh = shell();
    assert!(sh.contains("set -eu"), "no errexit or nounset");
    assert!(
        sh.contains("umask 077"),
        "the temporary directory is not private"
    );
    assert!(sh.contains("mktemp -d"), "no private temporary directory");
    assert!(sh.contains("trap 'rm -rf -- \"$tmp\"' EXIT"), "no cleanup");
}

/// Windows runs no process and looks away from a nonzero one: every program the script starts has
/// its exit status checked, and elevation is asked for before anything is written.
#[test]
fn the_powershell_script_stops_on_every_failing_process() {
    let ps = powershell();
    assert!(
        ps.contains("$ErrorActionPreference = 'Stop'"),
        "errors are not fatal"
    );
    assert!(ps.contains("IsInRole("), "no elevation check");
    let calls = ps
        .lines()
        .filter(|line| line.trim_start().starts_with("& "))
        .collect::<Vec<_>>();
    assert_eq!(
        calls.len(),
        3,
        "tar once from a line of its own and the Client twice — {calls:#?}"
    );
    assert!(
        ps.lines()
            .filter(|line| line.contains("$LASTEXITCODE"))
            .count()
            >= calls.len(),
        "a started process is left unchecked"
    );
}

/// In an expandable string a name straight before a colon reads as a scope specifier and fails the
/// parse of the whole script, which is what an operator pasting it would get instead of an install
/// (`about_Quoting_Rules`). The name is delimited with braces instead.
#[test]
fn the_powershell_script_delimits_a_variable_before_a_colon() {
    assert!(
        !powershell().contains("\"$Url:"),
        "the variable name before the colon is not delimited"
    );
}

/// Both scripts refuse a host that already carries a registration rather than swinging the
/// `current` pointer out from under the operator who made it.
#[test]
fn both_scripts_refuse_an_installed_service() {
    assert!(
        shell().contains("if [ -e /etc/systemd/system/classis.service ]; then"),
        "the shell script does not refuse a registration"
    );
    assert!(
        powershell().contains("Get-Service -Name 'classis'"),
        "the powershell script does not refuse a registration"
    );
}

/// The architecture decides which build is fetched, from what the host says it is: the two names
/// the release matrix builds for Linux, and the one it builds for Windows.
#[test]
fn both_scripts_pick_the_build_of_their_own_machine() {
    let sh = shell();
    assert!(sh.contains("uname -m"), "no architecture probe");
    for (machine, build) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
        assert!(
            sh.contains(machine) && sh.contains(build),
            "{machine} → {build}"
        );
    }
    let ps = powershell();
    assert!(
        ps.contains("Is64BitOperatingSystem") && ps.contains("PROCESSOR_ARCHITECTURE"),
        "no architecture probe"
    );
}

/// The Client is installed by the Client: `service install --endpoint` and `enrol`, the two commands
/// every other install path uses, and no service registration of their own.
#[test]
fn both_scripts_install_through_the_client_itself() {
    for (name, script) in [("install.sh", shell()), ("install.ps1", powershell())] {
        assert!(
            script.contains("service install --endpoint"),
            "{name} registers nothing through the Client"
        );
        assert!(script.contains(" enrol "), "{name} does not enrol");
        for second_path in ["systemctl", "sc.exe", "launchctl", "reg add"] {
            assert!(!script.contains(second_path), "{name} names {second_path}");
        }
    }
}

/// Only the one member the release workflow packs is unpacked, in either dialect, and the archive is
/// refused before that.
#[test]
fn both_scripts_unpack_only_the_client() {
    assert!(
        shell().contains("[ \"$members\" = supervisor ]"),
        "the shell script takes any member"
    );
    assert!(
        powershell().contains("@($members).Count -ne 1"),
        "the powershell script takes any member"
    );
}

/// The account and the `PATH` symlink are the ones the packages lay, word for word: a host installed
/// from a URL and one installed from a `.deb` must not differ in who runs the service or what
/// answers on `PATH`.
#[test]
fn the_shell_script_lays_what_the_packages_lay() {
    let sh = shell();
    let post = post_install();
    let link = "ln -sfn /opt/classis/current/supervisor /usr/bin/classis";
    assert!(post.contains(link), "the post-install no longer lays it");
    assert!(sh.contains(link), "the script does not lay it");
    assert_eq!(
        useradd_lines(&sh),
        useradd_lines(&post),
        "the account one install path creates is not the account the other creates"
    );
}

/// The shell script run for real, with every program it starts stubbed inside a temporary
/// directory: `curl` hands back a fixture archive and records the URL it was asked for, and the
/// `supervisor` inside that archive records what the script asked the Client to do. Nothing reaches
/// the host — no account is created, no service registered, no `PATH` entry laid, and the
/// registration the script looks for is a file of the test's own.
#[cfg(target_os = "linux")]
mod the_shell_script_run {
    use super::shell;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// The registration the script refuses to overwrite, rewritten to a path of the test's own —
    /// the reading `linux_post_install.rs` gives a payload path.
    const UNIT: &str = "/etc/systemd/system/classis.service";
    /// A Server behind a reverse-proxy path prefix, which the fetch and the endpoint must both keep.
    const BASE: &str = "https://fleet.example.test/neteye/classis";

    fn key() -> String {
        format!("cle1_lab_{}", "A".repeat(43))
    }

    struct Run {
        status: std::process::ExitStatus,
        out: String,
        err: String,
        log: Vec<String>,
    }

    impl Run {
        /// The URLs the script asked `curl` for, in order.
        fn urls(&self) -> Vec<&str> {
            self.log
                .iter()
                .filter_map(|l| l.strip_prefix("curl "))
                .collect()
        }

        /// What the script asked the Client to do, in order.
        fn client(&self) -> Vec<&str> {
            self.log
                .iter()
                .filter_map(|l| l.strip_prefix("supervisor "))
                .collect()
        }
    }

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

    /// A `.tar.gz` holding `members`, built with the host's own `tar` so the script's archive check
    /// runs against a real archive rather than a description of one.
    fn archive(dir: &Path, name: &str, members: &[&str]) -> PathBuf {
        let src = dir.join("src");
        std::fs::create_dir_all(&src).expect("src");
        for member in members {
            recorder(&src, member);
        }
        let out = dir.join(name);
        let made = Command::new("tar")
            .arg("-czf")
            .arg(&out)
            .arg("-C")
            .arg(&src)
            .args(members)
            .status()
            .expect("build the fixture");
        assert!(made.success(), "tar could not build {name}");
        out
    }

    /// The script with its registration path pointed at `unit`, so the test decides whether a host
    /// is registered already without reading the host's `/etc`.
    fn source(unit: &Path) -> String {
        shell().replace(UNIT, &unit.display().to_string())
    }

    /// Runs the script. `machine` is what `uname -m` answers and `uid` what `id -u` does; `getent`
    /// says the account is missing, and `curl` answers every request with `fixture` and a 200.
    fn run(dir: &Path, text: &str, args: &[&str], fixture: &Path, machine: &str, uid: &str) -> Run {
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("bin");
        recorder(&bin, "useradd");
        recorder(&bin, "ln");
        program(&bin, "id", &format!("#!/bin/sh\necho {uid}\n"));
        program(&bin, "uname", &format!("#!/bin/sh\necho {machine}\n"));
        // Neither the account nor a group of its name exists yet.
        program(&bin, "getent", "#!/bin/sh\nexit 1\n");
        program(
            &bin,
            "curl",
            concat!(
                "#!/bin/sh\ndest=''\nurl=''\nwhile [ $# -gt 0 ]; do\n",
                "case \"$1\" in\n--output) dest=$2; shift 2 ;;\n",
                "--write-out|--proto) shift 2 ;;\n-*) shift ;;\n*) url=$1; shift ;;\nesac\ndone\n",
                "printf 'curl %s\\n' \"$url\" >> \"$CLASSIS_LOG\"\n",
                "cp \"$CLASSIS_FIXTURE\" \"$dest\"\necho 200\n",
            ),
        );
        let path = dir.join("install.sh");
        std::fs::write(&path, text).expect("write the script");
        let log = dir.join("log");
        let _ = std::fs::remove_file(&log);
        let output = Command::new("sh")
            .arg(&path)
            .args(args)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("CLASSIS_LOG", &log)
            .env("CLASSIS_FIXTURE", fixture)
            .env("TMPDIR", dir)
            .stdin(Stdio::null())
            .output()
            .expect("run the script");
        Run {
            status: output.status,
            out: String::from_utf8_lossy(&output.stdout).into_owned(),
            err: String::from_utf8_lossy(&output.stderr).into_owned(),
            log: std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect(),
        }
    }

    /// The value that follows `name` in a recorded command line.
    fn flag<'a>(line: &'a str, name: &str) -> &'a str {
        let mut next = false;
        for word in line.split_whitespace() {
            if next {
                return word;
            }
            if word == name {
                next = true;
            }
        }
        panic!("{name} is not in {line}");
    }

    /// One thin path through every layer of the script: fetch, unpack, account, registration,
    /// `PATH` link, enrolment — in that order, with the arguments the Client's own install expects,
    /// and with the reverse-proxy prefix kept in both the download and the written endpoint.
    #[test]
    fn it_installs_and_enrols_in_the_order_the_packages_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "one.tar.gz", &["supervisor"]);
        let unit = dir.path().join("no-such-unit.service");
        let secret = key();
        let run = run(
            dir.path(),
            &source(&unit),
            &["--url", BASE, "--key", secret.as_str()],
            &fixture,
            "aarch64",
            "0",
        );
        assert!(run.status.success(), "{}", run.err);
        assert_eq!(
            run.urls().join(" "),
            format!("{BASE}/v1/install/linux/arm64"),
            "{:?}",
            run.log
        );
        assert!(
            !run.log
                .iter()
                .any(|l| l.starts_with("curl ") && l.contains(secret.as_str())),
            "the key reached a URL"
        );
        let wanted_endpoint = "wss://fleet.example.test/neteye/classis/v1/opamp";
        let client: Vec<String> = run.client().iter().map(|l| l.to_string()).collect();
        assert_eq!(
            client,
            [
                format!("service install --endpoint {wanted_endpoint} --run-as classis"),
                format!("enrol {BASE} {secret}"),
            ]
        );
        // Written by the script, read back by the real parser: a command line the Client would
        // refuse is an install that dies on the host.
        let endpoint = flag(&client[0], "--endpoint");
        classis_agent::cli::parse_from([
            "supervisor",
            "service",
            "install",
            "--endpoint",
            endpoint,
        ])
        .expect("the script writes an endpoint the Client refuses");
        classis_agent::cli::parse_from(["supervisor", "enrol", BASE, secret.as_str()])
            .expect("the script's enrol command line does not parse");
        let link = "ln -sfn /opt/classis/current/supervisor /usr/bin/classis";
        assert!(run.log.iter().any(|l| l == link), "{:?}", run.log);
        let adds: Vec<&String> = run
            .log
            .iter()
            .filter(|l| l.starts_with("useradd "))
            .collect();
        assert_eq!(adds.len(), 1, "{:?}", run.log);
        assert!(adds[0].contains("--system --user-group"), "{adds:?}");
        assert!(run.out.contains("enrolled"), "{}", run.out);
        let left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read the directory")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("tmp."))
            .collect();
        assert!(
            left.is_empty(),
            "the temporary directory survives: {left:?}"
        );
    }

    /// Every bad argument is refused before the network is touched, so a typo cannot start a
    /// download — and so a key can never be smuggled into a URL or a command.
    #[test]
    fn it_refuses_bad_input_before_it_touches_the_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "one.tar.gz", &["supervisor"]);
        let unit = dir.path().join("no-such-unit.service");
        let secret = key();
        let bad: Vec<Vec<&str>> = vec![
            vec!["--key", secret.as_str()],
            vec!["--url", BASE],
            vec!["--url", BASE, "--key", secret.as_str(), "--force"],
            vec![
                "--url",
                "http://fleet.example.test",
                "--key",
                secret.as_str(),
            ],
            vec!["--url", "http://localhost:8443", "--key", secret.as_str()],
            vec!["--url", "ftp://127.0.0.1:21", "--key", secret.as_str()],
            vec![
                "--url",
                "https://fleet.example.test/?key=x",
                "--key",
                secret.as_str(),
            ],
            vec![
                "--url",
                "https://operator@fleet.example.test",
                "--key",
                secret.as_str(),
            ],
            vec![
                "--url",
                "https://fleet.example.test /x",
                "--key",
                secret.as_str(),
            ],
            vec![
                "--url",
                "https://fleet.example.test/../x",
                "--key",
                secret.as_str(),
            ],
            vec!["--url", BASE, "--key", ""],
            vec!["--url", BASE, "--key", "not a key"],
            vec!["--url", BASE, "--key", "-cle1_lab_x"],
            vec!["--url", BASE, "--key", "cle1_lab_secret; rm -rf /"],
        ];
        for args in bad {
            let run = run(dir.path(), &source(&unit), &args, &fixture, "aarch64", "0");
            assert!(!run.status.success(), "{args:?} was accepted: {}", run.out);
            assert!(run.urls().is_empty(), "{args:?} fetched {:?}", run.urls());
        }
    }

    /// Account creation, a system registration and a `PATH` link are root's work; the script asks
    /// for it instead of failing halfway through it.
    #[test]
    fn it_refuses_to_run_unprivileged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "one.tar.gz", &["supervisor"]);
        let unit = dir.path().join("no-such-unit.service");
        let secret = key();
        let run = run(
            dir.path(),
            &source(&unit),
            &["--url", BASE, "--key", secret.as_str()],
            &fixture,
            "aarch64",
            "1000",
        );
        assert!(!run.status.success(), "{}", run.out);
        assert!(run.err.contains("root"), "{}", run.err);
        assert!(run.urls().is_empty(), "{:?}", run.urls());
    }

    /// A host an operator already manages keeps its own registration: this script delivers a
    /// program, and swinging a managed host's `current` pointer is not its business.
    #[test]
    fn it_refuses_a_host_that_is_registered_already() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "one.tar.gz", &["supervisor"]);
        let unit = dir.path().join("classis.service");
        std::fs::write(&unit, "[Unit]\n").expect("unit");
        let secret = key();
        let run = run(
            dir.path(),
            &source(&unit),
            &["--url", BASE, "--key", secret.as_str()],
            &fixture,
            "aarch64",
            "0",
        );
        assert!(!run.status.success(), "{}", run.out);
        assert!(run.err.contains("registered already"), "{}", run.err);
        assert!(run.urls().is_empty(), "{:?}", run.urls());
    }

    /// An archive that holds more than the Client is refused, and nothing of it runs: the member an
    /// archive names is never a path this script writes.
    #[test]
    fn it_refuses_an_archive_that_holds_more_than_the_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "two.tar.gz", &["supervisor", "extra"]);
        let unit = dir.path().join("no-such-unit.service");
        let secret = key();
        let run = run(
            dir.path(),
            &source(&unit),
            &["--url", BASE, "--key", secret.as_str()],
            &fixture,
            "aarch64",
            "0",
        );
        assert!(!run.status.success(), "{}", run.out);
        assert_eq!(run.urls().len(), 1, "{:?}", run.urls());
        assert!(run.client().is_empty(), "{:?}", run.client());
    }

    /// The build is chosen from the machine, and a machine outside the release matrix gets a
    /// refusal instead of a binary that cannot run.
    #[test]
    fn it_fetches_the_build_of_the_machine_it_runs_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = archive(dir.path(), "one.tar.gz", &["supervisor"]);
        let unit = dir.path().join("no-such-unit.service");
        let secret = key();
        for (machine, build) in [("x86_64", "amd64"), ("aarch64", "arm64")] {
            let run = run(
                dir.path(),
                &source(&unit),
                &["--url", BASE, "--key", secret.as_str()],
                &fixture,
                machine,
                "0",
            );
            assert!(run.status.success(), "{machine}: {}", run.err);
            assert_eq!(
                run.urls().join(" "),
                format!("{BASE}/v1/install/linux/{build}"),
                "{machine}"
            );
        }
        let run = run(
            dir.path(),
            &source(&unit),
            &["--url", BASE, "--key", secret.as_str()],
            &fixture,
            "riscv64",
            "0",
        );
        assert!(!run.status.success(), "{}", run.out);
        assert!(run.urls().is_empty(), "{:?}", run.urls());
    }
}

/// `Get-Archive` run for real on Windows, against a Server of the test's own on `127.0.0.1`: the two
/// answers that settle the download — a 200 whose bytes must arrive whole, and a redirect that must
/// be refused and not followed. The harness is the script's own `Get-Archive` and the `Stop-Install`
/// it refuses through, taken out of its text so nothing here re-types either. No service, no
/// elevation, no third program beyond `powershell.exe`. The module parses the whole shipped script
/// too, which no fragment pulled out of it can settle.
#[cfg(windows)]
mod the_windows_download_run {
    use super::{install_script_path, powershell};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::thread::JoinHandle;

    /// What the script asks the Server for, and the archive a 200 answers with.
    const PATH: &str = "/v1/install/windows/amd64";
    const ARCHIVE: &[u8] = b"the archive, byte for byte";
    /// The request that frees the accept loop, and its answer.
    const STOP: &[u8] = b"GET /__stop HTTP/1.1\r\nConnection: close\r\n\r\n";
    const STOPPED: &[u8] = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";

    /// The text of `function <name>` through the brace that closes it at column 0. The script indents
    /// every inner brace, so that brace belongs to the function alone.
    fn function_text(script: &str, name: &str) -> &str {
        let open = format!("function {name} {{\n");
        let start = script
            .find(&open)
            .unwrap_or_else(|| panic!("install.ps1 has no function {name}"));
        let body = &script[start + open.len()..];
        let end = body
            .find("\n}\n")
            .unwrap_or_else(|| panic!("function {name} does not close at column 0"));
        &script[start..start + open.len() + end + 2]
    }

    /// A minimal HTTP/1.1 answer: a 200 carrying `ARCHIVE`, or a 302 to a path of this Server's own.
    /// `Connection: close` ends every answer with its body, so the client reads it whole.
    fn answer(addr: SocketAddr, redirect: bool) -> Vec<u8> {
        let status = if redirect {
            "HTTP/1.1 302 Found"
        } else {
            "HTTP/1.1 200 OK"
        };
        let location = if redirect {
            format!("Location: http://{addr}/elsewhere\r\nContent-Length: 0\r\n")
        } else {
            format!("Content-Length: {}\r\n", ARCHIVE.len())
        };
        let mut bytes = format!("{status}\r\n{location}Connection: close\r\n\r\n").into_bytes();
        if !redirect {
            bytes.extend_from_slice(ARCHIVE);
        }
        bytes
    }

    /// The target of the request line. The headers after it are read and dropped with it: a socket
    /// closed with unread request bytes in it resets the connection, and a reset mid-answer is a
    /// flaky test.
    fn request_target(stream: &mut TcpStream) -> Option<String> {
        let mut lines = BufReader::new(stream).lines();
        let request = lines.next()?.ok()?;
        for header in lines.by_ref().take(64) {
            if header.ok()?.is_empty() {
                break;
            }
        }
        request.split_whitespace().nth(1).map(str::to_string)
    }

    /// A Server on a loopback port the OS chose. It answers every request, records what it was asked
    /// for, and hands those targets back when it is stopped — which is the proof of whether a
    /// redirect was followed.
    struct Server {
        addr: SocketAddr,
        worker: Option<JoinHandle<Vec<String>>>,
    }

    impl Server {
        fn start(redirect: bool) -> Server {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            let addr = listener.local_addr().expect("the port it bound");
            let worker = std::thread::spawn(move || {
                let mut targets = Vec::new();
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let Some(target) = request_target(&mut stream) else {
                        continue;
                    };
                    if target == "/__stop" {
                        let _ = stream.write_all(STOPPED);
                        break;
                    }
                    targets.push(target);
                    let _ = stream.write_all(&answer(addr, redirect));
                    let _ = stream.flush();
                }
                targets
            });
            Server {
                addr,
                worker: Some(worker),
            }
        }

        /// The URL of `path` on this Server.
        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.addr)
        }

        /// Wakes the accept loop, waits for the thread, and returns every target the Server saw. A
        /// target is recorded before its answer is written, so what the thread returns is complete
        /// once the thread has ended.
        fn stop(&mut self) -> Vec<String> {
            let mut probe = TcpStream::connect(self.addr).expect("reaches the test server");
            probe.write_all(STOP).expect("wakes the accept loop");
            let mut ignored = Vec::new();
            let _ = probe.read_to_end(&mut ignored);
            self.worker
                .take()
                .expect("the test server runs")
                .join()
                .expect("the test server thread ends")
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // Woken here too: a test that dies before `stop` must not leave the test binary waiting
            // on an accept nobody intends to wake.
            if let Ok(mut probe) = TcpStream::connect(self.addr) {
                let _ = probe.write_all(STOP);
            }
        }
    }

    /// Runs the script's own `Get-Archive` for one URL, in a harness of nothing but that function
    /// and the refusal it calls, both copied out of the script text.
    fn fetch(dir: &Path, url: &str, destination: &Path) -> std::process::Output {
        let script = powershell();
        let harness = format!(
            "$ErrorActionPreference = 'Stop'\n{}\n{}\nGet-Archive -Uri '{}' -Destination '{}'\n",
            function_text(&script, "Stop-Install"),
            function_text(&script, "Get-Archive"),
            url,
            destination.display(),
        );
        let path = dir.join("get-archive.ps1");
        std::fs::write(&path, harness).expect("write the harness");
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&path)
            .stdin(Stdio::null())
            .output()
            .expect("run powershell.exe")
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// A 200 arrives whole. `Invoke-WebRequest -OutFile` gave back no object to read a status off,
    /// and `-PassThru` — the way out of that — is documented to leave the file empty, so what is
    /// asserted here is the file, not a status code.
    #[test]
    fn a_200_writes_the_archive_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut server = Server::start(false);
        let destination = dir.path().join("client.tar.gz");
        let out = fetch(dir.path(), &server.url(PATH), &destination);
        let targets = server.stop();
        assert!(out.status.success(), "stderr: {}", text(&out.stderr));
        assert_eq!(targets, [PATH], "the archive came from somewhere else");
        let written = std::fs::read(&destination).expect("no archive was written");
        assert!(!written.is_empty(), "the archive file is empty");
        assert_eq!(
            written, ARCHIVE,
            "the archive is not the bytes the Server sent"
        );
    }

    /// A redirect is refused where it stands: the script stops with the status in its message, the
    /// Server sees no second request, and nothing is written where the archive would have gone.
    #[test]
    fn a_redirect_is_refused_and_not_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut server = Server::start(true);
        let destination = dir.path().join("client.tar.gz");
        let out = fetch(dir.path(), &server.url(PATH), &destination);
        let targets = server.stop();
        assert!(!out.status.success(), "a redirect was accepted");
        assert_eq!(targets, [PATH], "the redirect was followed");
        assert!(
            text(&out.stderr).contains("answered 302"),
            "the refusal does not name the status: {}",
            text(&out.stderr)
        );
        assert!(!destination.exists(), "the refused answer left a file");
    }

    /// The whole shipped script, parsed by PowerShell itself and never run: a quoting mistake fails
    /// the parse of the file, so an operator pasting it would get a parse error where the script
    /// should have refused them. Parsing needs no elevation and touches no network.
    #[test]
    fn the_shipped_script_parses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let harness = dir.path().join("parse.ps1");
        let script = install_script_path(super::POWERSHELL_SCRIPT);
        std::fs::write(
            &harness,
            r"param([string]$Path)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Output ('{0}:{1} {2}' -f $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message) }
    exit 1
}
",
        )
        .expect("write the harness");
        let out = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&harness)
            .arg(&script)
            .stdin(Stdio::null())
            .output()
            .expect("run powershell.exe");
        assert!(
            out.status.success(),
            "{} does not parse:\nstdout: {}\nstderr: {}",
            script.display(),
            text(&out.stdout),
            text(&out.stderr)
        );
    }
}
