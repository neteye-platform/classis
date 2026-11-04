//! `service install` and `service config` run as root or as an Administrator, and write into the
//! state directory and the executable layout, which belong to the service's account (ADR-0054). A link that account put at a name the install writes, or at a directory on the way to
//! it, must never carry a privileged write, rename, mode change or owner change somewhere else:
//! each case here plants one and checks that the install refused it or replaced it, and that what
//! it pointed at is as it was.

use std::path::Path;

use fleet_agent::config::ClientConfig;
use fleet_agent::connection::{self, SETTINGS_FILE};
use fleet_agent::csr;
use fleet_agent::service::layout::{self, Layout};
use fleet_agent::storage::Storage;
use opamp::proto::ConnectionSettingsOffers;

const UNTOUCHED: &[u8] = b"what the link points at\n";

fn config(state_dir: &Path) -> ClientConfig {
    ClientConfig {
        state_dir: state_dir.to_path_buf(),
        ..ClientConfig::default()
    }
}

/// Whether `path` is a link of any kind.
fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use fleet_agent::service::layout::BINARY_FILENAME;
    use fleet_agent::storage::UID_FILE;
    use fleet_agent::supervisor::ports::AgentStorage as _;
    use fleet_agent::tls::{
        ISSUED_CERT_FILE, ISSUED_KEY_FILE, PENDING_CERT_FILE, PENDING_CSR_FILE, PENDING_KEY_FILE,
    };

    use super::*;

    /// Signs `csr` the way a Server does.
    fn sign(csr: &[u8]) -> String {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["test-ca".to_string()]).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca");
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_key).expect("issuer");
        rcgen::CertificateSigningRequestParams::from_pem(std::str::from_utf8(csr).expect("utf-8"))
            .expect("csr")
            .signed_by(&issuer)
            .expect("signed")
            .pem()
    }

    /// A file outside the account's directories, with a mode the install would change.
    fn victim(outside: &Path, name: &str) -> PathBuf {
        let path = outside.join(name);
        std::fs::write(&path, UNTOUCHED).expect("write the victim");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("mode");
        path
    }

    fn assert_untouched(victim: &Path) {
        assert_eq!(
            std::fs::read(victim).expect("read the victim"),
            UNTOUCHED,
            "{} was written through the link",
            victim.display()
        );
        let mode = victim.metadata().expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "{} had its mode changed", victim.display());
    }

    /// The account plants `name` in `dir` as a link to a victim file of its own; returns the victim.
    fn plant(dir: &Path, outside: &Path, name: &str) -> PathBuf {
        let victim = victim(outside, name);
        std::os::unix::fs::symlink(&victim, dir.join(name)).expect("plant the link");
        victim
    }

    /// The pending key and the request, each written over a link at its name: the link is
    /// replaced by the file, and the file it pointed at keeps its bytes and its mode.
    /// Verifies: ADR-0054
    #[test]
    fn a_certificate_request_writes_through_no_link() {
        for name in [PENDING_KEY_FILE, PENDING_CSR_FILE] {
            let state = tempfile::tempdir().expect("state");
            let outside = tempfile::tempdir().expect("outside");
            let victim = plant(state.path(), outside.path(), name);

            let request = csr::request(&config(state.path()));

            assert_untouched(&victim);
            assert!(request.is_some(), "a request is made beside {name}");
            assert!(
                !is_link(&state.path().join(name)),
                "{name} is the file now, not the link"
            );
        }
    }

    /// An issued certificate is staged and put in force over links at every name it passes
    /// through, its temporary names included; nothing they point at changes, and the pair in
    /// force is the one issued.
    /// Verifies: ADR-0054
    #[test]
    fn an_issued_certificate_is_stored_through_no_link() {
        let state = tempfile::tempdir().expect("state");
        let outside = tempfile::tempdir().expect("outside");
        let request = csr::request(&config(state.path())).expect("a request");
        let names = [
            PENDING_CERT_FILE,
            "client-cert.pending.tmp",
            "client-cert.pending.pem.tmp",
            "client-cert.pending.pem~",
            ISSUED_CERT_FILE,
            ISSUED_KEY_FILE,
        ];
        let victims: Vec<PathBuf> = names
            .iter()
            .map(|name| plant(state.path(), outside.path(), name))
            .collect();

        csr::accept(state.path(), sign(&request).as_bytes()).expect("accept");

        for victim in &victims {
            assert_untouched(victim);
        }
        assert!(config(state.path()).is_enrolled());
        for name in [ISSUED_CERT_FILE, ISSUED_KEY_FILE] {
            assert!(!is_link(&state.path().join(name)), "{name} is a file");
        }
    }

    /// The instance identity and the connection settings, the other two files an enrolment
    /// writes into the state directory.
    /// Verifies: ADR-0054
    #[test]
    fn the_identity_and_the_connection_settings_are_written_through_no_link() {
        let state = tempfile::tempdir().expect("state");
        let outside = tempfile::tempdir().expect("outside");
        let uid = plant(state.path(), outside.path(), UID_FILE);
        let settings = plant(state.path(), outside.path(), SETTINGS_FILE);

        Storage::new(state.path().to_path_buf())
            .expect("storage")
            .load_or_create_uid()
            .expect("an identity");
        connection::store(state.path(), None, &ConnectionSettingsOffers::default())
            .expect("settings stored");

        assert_untouched(&uid);
        assert_untouched(&settings);
        assert!(!is_link(&state.path().join(UID_FILE)));
        assert!(!is_link(&state.path().join(SETTINGS_FILE)));
    }

    /// A state directory the account replaced with a link is refused by everything an enrolment
    /// does there: nothing is created behind the link, and the directory it points at keeps its
    /// mode.
    /// Verifies: ADR-0054
    #[test]
    fn a_state_directory_that_is_a_link_is_refused() {
        let root = tempfile::tempdir().expect("data root");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o750))
            .expect("mode");
        let state = root.path().join("state");
        std::os::unix::fs::symlink(outside.path(), &state).expect("plant the link");

        assert!(csr::recover(&state).is_err(), "recovery refuses it");
        assert!(
            Storage::new(state.clone()).is_err(),
            "the storage refuses it"
        );
        assert!(
            csr::request(&config(&state)).is_none(),
            "no request is made"
        );
        assert!(
            connection::store(&state, None, &ConnectionSettingsOffers::default()).is_err(),
            "no settings are stored"
        );

        let entries: Vec<_> = std::fs::read_dir(outside.path())
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "nothing is written behind it: {entries:?}"
        );
        let mode = outside
            .path()
            .metadata()
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750, "the directory behind it keeps its mode");
    }

    /// The layout root belongs to the account too: a `versions` directory it replaced with a link
    /// is refused, and a link at the staged program or its manifest is replaced without the file it
    /// pointed at being written or made executable.
    /// Verifies: ADR-0054
    #[test]
    fn staging_the_program_writes_through_no_link() {
        let root = tempfile::tempdir().expect("layout root");
        let outside = tempfile::tempdir().expect("outside");
        let layout = Layout::new(root.path());
        std::os::unix::fs::symlink(outside.path(), layout.versions_dir()).expect("plant");
        assert!(layout::stage_current_exe(&layout).is_err(), "refused");
        assert_eq!(
            std::fs::read_dir(outside.path()).expect("list").count(),
            0,
            "nothing is staged behind the link"
        );

        let root = tempfile::tempdir().expect("layout root");
        let layout = Layout::new(root.path());
        let version_dir =
            layout.version_dir(&layout::version_dir_name(fleet_core::version::current()));
        std::fs::create_dir_all(&version_dir).expect("version dir");
        let binary = plant(&version_dir, outside.path(), BINARY_FILENAME);
        let manifest = plant(&version_dir, outside.path(), "manifest.toml");

        layout::stage_current_exe(&layout).expect("staged");

        assert_untouched(&binary);
        assert_untouched(&manifest);
        let staged = version_dir.join(BINARY_FILENAME);
        assert!(!is_link(&staged), "the program is a file");
        let mode = staged.metadata().expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o755, "and executable");
    }

    /// `service config` gives what it wrote to the configuration's owner, by name. A state
    /// directory that is a link is refused rather than walked through, and a file with a second
    /// hard link — another name for it may stand anywhere — keeps its owner.
    /// Verifies: ADR-0054
    #[test]
    fn handing_the_written_files_over_follows_no_link() {
        let root = tempfile::tempdir().expect("data root");
        let outside = tempfile::tempdir().expect("outside");
        let like = root.path().join("supervisor.toml");
        std::fs::write(&like, "").expect("config");
        victim(outside.path(), ISSUED_KEY_FILE);
        let state = root.path().join("state");
        std::os::unix::fs::symlink(outside.path(), &state).expect("plant");

        let through = state.join(ISSUED_KEY_FILE);
        assert!(
            fleet_agent::service::run_as::match_owner(&like, root.path(), &[&through]).is_err(),
            "a file behind a linked state directory is refused"
        );

        std::fs::remove_file(&state).expect("unplant");
        std::fs::create_dir(&state).expect("state");
        let linked = state.join(ISSUED_CERT_FILE);
        std::fs::hard_link(outside.path().join(ISSUED_KEY_FILE), &linked).expect("hard link");
        let skipped =
            fleet_agent::service::run_as::match_owner(&like, root.path(), &[&state, &linked])
                .expect("handed over");
        assert_eq!(skipped, vec![linked], "the second hard link is left alone");

        // The data root the administrator named is reached as its path says, even through a link
        // and with the configuration named elsewhere.
        let elsewhere = tempfile::tempdir().expect("config dir");
        let named = elsewhere.path().join("supervisor.toml");
        std::fs::write(&named, "").expect("config");
        let data_root = elsewhere.path().join("data");
        std::os::unix::fs::symlink(root.path(), &data_root).expect("data root link");
        fleet_agent::service::run_as::match_owner(&named, &data_root, &[&data_root.join("state")])
            .expect("the state directory is re-owned through the named data root");
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    /// A directory junction at `link` to `target` — what any account can make, no privilege
    /// needed.
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run mklink");
        assert!(status.success(), "mklink /J failed with {status}");
    }

    fn assert_empty(dir: &Path) {
        let entries: Vec<_> = std::fs::read_dir(dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "nothing is written behind the junction: {entries:?}"
        );
    }

    /// A state directory the account replaced with a junction is refused by everything an
    /// enrolment does there, and nothing is created behind it.
    /// Verifies: ADR-0054
    #[test]
    fn a_state_directory_that_is_a_junction_is_refused() {
        let root = tempfile::tempdir().expect("data root");
        let outside = tempfile::tempdir().expect("outside");
        let state = root.path().join("state");
        junction(&state, outside.path());

        assert!(csr::recover(&state).is_err(), "recovery refuses it");
        assert!(
            Storage::new(state.clone()).is_err(),
            "the storage refuses it"
        );
        assert!(
            csr::request(&config(&state)).is_none(),
            "no request is made"
        );
        assert!(
            connection::store(&state, None, &ConnectionSettingsOffers::default()).is_err(),
            "no settings are stored"
        );
        assert_empty(outside.path());
        std::fs::remove_dir(&state).expect("remove the junction");
    }

    /// A `versions` directory the account replaced with a junction is refused by the staging.
    /// Verifies: ADR-0054
    #[test]
    fn staging_refuses_a_versions_junction() {
        let root = tempfile::tempdir().expect("layout root");
        let outside = tempfile::tempdir().expect("outside");
        let layout = Layout::new(root.path());
        junction(&layout.versions_dir(), outside.path());
        assert!(layout::stage_current_exe(&layout).is_err(), "refused");
        assert_empty(outside.path());
        std::fs::remove_dir(layout.versions_dir()).expect("remove the junction");
    }

    /// On Windows the account may hold delete on the layout root itself and put a junction at its
    /// name: a root that is a reparse point is refused too.
    /// Verifies: ADR-0054
    #[test]
    fn staging_refuses_a_layout_root_that_is_a_junction() {
        let parent = tempfile::tempdir().expect("parent");
        let outside = tempfile::tempdir().expect("outside");
        let root = parent.path().join("root");
        junction(&root, outside.path());
        assert!(
            layout::stage_current_exe(&Layout::new(&root)).is_err(),
            "refused"
        );
        assert_empty(outside.path());
        std::fs::remove_dir(&root).expect("remove the junction");
    }

    /// A file symbolic link at a name an enrolment writes is replaced, never written through.
    /// Creating one needs the symbolic-link privilege or Developer Mode, which an elevated run —
    /// a GitHub-hosted Windows runner — holds; without it the test fails rather than deciding
    /// nothing.
    /// Verifies: ADR-0054
    #[test]
    fn a_file_symbolic_link_in_the_state_directory_is_replaced() {
        let state = tempfile::tempdir().expect("state");
        let outside = tempfile::tempdir().expect("outside");
        let victim = outside.path().join("victim");
        std::fs::write(&victim, UNTOUCHED).expect("victim");
        std::os::windows::fs::symlink_file(&victim, state.path().join(SETTINGS_FILE))
            .expect("plant a file symbolic link — this needs an elevated run or Developer Mode");
        connection::store(state.path(), None, &ConnectionSettingsOffers::default())
            .expect("stored");
        assert_eq!(std::fs::read(&victim).expect("read"), UNTOUCHED);
        assert!(!is_link(&state.path().join(SETTINGS_FILE)));
    }
}
