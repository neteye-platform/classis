//! `supervisor.toml` on disk (ADR-0010): reading the file, the directories it names made absolute
//! against the working directory, and the identity the state directory holds. What the file must
//! say is [`config`](crate::config)'s; this is only where it comes from, and how its text is
//! redacted before it is reported.

use std::path::{Path, PathBuf};

use crate::config::{ClientConfig, LEGACY_CONFIG_FILE_NAME, SECRET_KEYS};

impl ClientConfig {
    /// Loads the file, or the defaults when it does not exist. A file that exists but does not
    /// parse is an error — never silently ignored.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            legacy_name_beside(path)?;
            let default = ClientConfig::default();
            return Ok(ClientConfig {
                path: Some(path.to_path_buf()),
                state_dir: absolute(&default.state_dir),
                ..default
            });
        }
        // The file may hold `[packages] archive_key`: its text is wiped when it is dropped
        // (ADR-0057).
        let text = std::fs::read_to_string(path)
            .map(zeroize::Zeroizing::new)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut config: ClientConfig =
            toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
        // Redacted once, here, so no later reader can reach for the unredacted text by mistake:
        // everything downstream — the effective-configuration report above all — sees the mask.
        config.source = Some(redact_secrets(&text));
        config.path = Some(path.to_path_buf());
        // **Every directory this Client derives is made absolute here**, and this is the one place
        // it can be done once. A Managed Process starts in its own directory (ADR-0017), so a path
        // the Client hands it — its program, a `--config` a plugin builds, a `${config_dir}` it
        // substitutes — is resolved by that process against a directory the Client has left.
        // `state_dir` defaults to the relative `client-state`, so leaving these relative would make
        // the ordinary configuration the broken one: the program would be looked for under itself,
        // and a Collector that did start could not find the configuration written for it.
        config.state_dir_as_written = config.state_dir.clone();
        config.state_dir = absolute(&config.state_dir);
        config.supervisor_dir = config.supervisor_dir.as_deref().map(absolute);
        config.checked(path)
    }

    /// The state directory a service installed from this file runs with (ADR-0053 clause 3):
    /// `--state-dir`, else the one the service's registration carries, else the absolute one the
    /// file names, else `<data root>/state`.
    ///
    /// The file is the service account's to rewrite (ADR-0042 clause 2), and the install that reads
    /// it runs as root or an Administrator and hands the state directory over to that account. So
    /// a directory the file names is taken only beneath the data root or the layout root, and one
    /// from any source that lies beneath them is reached through directories only, as
    /// [`beneath`](crate::service::layout::beneath) decides (ADR-0053 clause 4). The flag and the
    /// registration are an administrator's word and may name one outside them.
    ///
    /// Decided on the value as written, because [`state_dir`](Self::state_dir) is already resolved
    /// against the installing shell's working directory, which the service never shares. Meaningful
    /// only on a configuration returned by [`load`](Self::load).
    ///
    /// # Errors
    /// Returns a refusal naming the directory, why it is refused, and `--state-dir`.
    pub fn service_state_dir(
        &self,
        roots: &crate::service::layout::Roots,
    ) -> Result<PathBuf, String> {
        let bounds = [roots.data.as_path(), roots.layout.as_path()];
        let (dir, source) = self.state_dir_candidate(roots);
        if source == StateDirSource::File || bounds.iter().any(|root| dir.starts_with(root)) {
            crate::service::layout::beneath(&dir, &bounds).map_err(|why| {
                let rule = if source == StateDirSource::File {
                    "The configuration is the service account's to rewrite, so a state directory \
                     is taken from it only beneath the data root or the layout root, and reached \
                     there through directories only; name one with --state-dir"
                } else {
                    "Beneath the data root or the layout root a state directory is reached through \
                     directories only, because the service's account owns what lies there; remove \
                     the link, or name another with --state-dir"
                };
                format!(
                    "refusing the state directory {} that {} names: {why}. {rule}",
                    dir.display(),
                    source.describe()
                )
            })?;
        }
        Ok(dir)
    }

    /// Where [`service_state_dir`](Self::service_state_dir) takes the state directory from, in the
    /// words the install prints after it.
    #[must_use]
    pub fn service_state_dir_source(&self, roots: &crate::service::layout::Roots) -> &'static str {
        self.state_dir_candidate(roots).1.describe()
    }

    /// The state directory ADR-0053 clause 3 names, before it is checked, and its source.
    fn state_dir_candidate(
        &self,
        roots: &crate::service::layout::Roots,
    ) -> (PathBuf, StateDirSource) {
        match (&roots.named, &roots.registered) {
            (Some(dir), _) => (dir.clone(), StateDirSource::Flag),
            (None, Some(dir)) => (dir.clone(), StateDirSource::Registration),
            (None, None) if self.state_dir_as_written.is_absolute() => {
                (self.state_dir_as_written.clone(), StateDirSource::File)
            }
            (None, None) => (
                roots.data.join(crate::service::layout::STATE_DIR_NAME),
                StateDirSource::Default,
            ),
        }
    }

    /// What this Client must hold before it connects (ADR-0021, ADR-0019): a client certificate —
    /// the one the Server issued, or the one `[tls]` names, a bootstrap certificate included. It is
    /// the one proof the Server admits a peer by, so without it the Client refuses to start, naming
    /// what is missing.
    ///
    /// # Errors
    /// Returns a sentence naming the missing setting.
    pub fn check_admission(&self) -> Result<(), String> {
        if self.client_identity().is_none() {
            return Err(
                "[tls] cert_file and key_file are required — the Server admits no Agent without \
                 a client certificate; enrol this host with `supervisor service config`, or name \
                 a bootstrap certificate there"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Whether the state directory holds a certificate the Server issued, with its key — what
    /// makes this Client a member of the fleet rather than a host still to enrol (ADR-0021). The
    /// questionnaire asks for a bootstrap pair only while this is `false` (ADR-0019 clause 17).
    #[must_use]
    pub fn is_enrolled(&self) -> bool {
        self.state_dir.join(crate::tls::ISSUED_CERT_FILE).exists()
            && self.state_dir.join(crate::tls::ISSUED_KEY_FILE).exists()
    }

    /// The client certificate and key this Client presents on both transports (ADR-0021), or
    /// `None` when it has no identity to present.
    ///
    /// A pair the Server issued outranks the configured one, the same precedence persisted
    /// connection settings have over `supervisor.toml` (ADR-0014): the file stays what the operator
    /// wrote, and deleting the stored pair reverts to it. That is also what retires a bootstrap
    /// certificate — it keeps standing in `supervisor.toml`, unused, once a real one has been issued.
    pub fn client_identity(&self) -> Option<(PathBuf, PathBuf)> {
        if self.is_enrolled() {
            return Some((
                self.state_dir.join(crate::tls::ISSUED_CERT_FILE),
                self.state_dir.join(crate::tls::ISSUED_KEY_FILE),
            ));
        }
        let tls = self.tls.as_ref()?;
        Some((tls.cert_file.clone()?, tls.key_file.clone()?))
    }
}

/// Where an installed Client's state directory comes from (ADR-0053 clause 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateDirSource {
    /// `--state-dir`.
    Flag,
    /// The service's system registration.
    Registration,
    /// The absolute `state_dir` of `supervisor.toml`.
    File,
    /// `<data root>/state`.
    Default,
}

impl StateDirSource {
    fn describe(self) -> &'static str {
        match self {
            Self::Flag => "--state-dir",
            Self::Registration => "the service's registration",
            Self::File => "the configuration",
            Self::Default => "the default",
        }
    }
}

/// Refuses to carry on when the file this Client looks for is absent and a `client.toml` sits
/// beside where it would be (ADR-0019 clause 29).
///
/// Everywhere else a missing configuration is not an error: a Client comes up on defaults, says so,
/// and manages nothing until one exists (ADR-0019). That is exactly the wrong answer here, and the
/// dangerous one: an upgraded host would go on running, connect to the development endpoint, report
/// none of its Agents, and nothing about it would look like a failure. So this one case fails
/// closed, naming both paths and the single command that fixes it.
fn legacy_name_beside(path: &Path) -> Result<(), String> {
    let legacy = path.with_file_name(LEGACY_CONFIG_FILE_NAME);
    if path
        .file_name()
        .is_some_and(|name| name == LEGACY_CONFIG_FILE_NAME)
        || !legacy.exists()
    {
        return Ok(());
    }
    Err(format!(
        "no configuration at {}, but {} is beside it: the file was renamed in this release. \
         Rename it — `mv {} {}` — and start the service again. Nothing else about it \
         changed.",
        path.display(),
        legacy.display(),
        legacy.display(),
        path.display()
    ))
}

/// `path` against the current working directory when it is relative, unchanged when it is not.
///
/// Lexical rather than `canonicalize`: that needs the file to exist, and these directories are
/// named before they are created. It also follows symbolic links, which would be wrong here — the
/// versioned install layout (ADR-0019) points at its current version *with* a link, and resolving
/// it would freeze a path that stops being true at the next update.
pub(crate) fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        // Nothing to be relative to: hand the path over as written and let the failure name the
        // real reason rather than inventing a directory.
        Err(_) => path.to_path_buf(),
    }
}

/// The file's text with every secret value replaced by `***`, for reporting it off the host —
/// the Server persists effective configurations to disk, so a credential must never be in one.
///
/// The text is parsed with `toml_edit`, which keeps the operator's comments, ordering and layout —
/// half of what a configuration file says — though line endings become `\n`, and a table written
/// only as the parent of a masked one comes out written as its own. A secret key is found wherever
/// and however it is written (a table, a dotted or quoted key, an inline table, an array of tables)
/// and its whole value is replaced, a multi-line string to its closing quotes, together with a
/// comment beside it. A leftover `[auth]` section, which the Client ignores (ADR-0021 clause 3),
/// has every value masked, whatever its keys are called. Text that does not parse cannot be taken
/// apart, so it is reported as a placeholder — over-redaction is the cheap failure here, a leaked
/// credential the expensive one.
pub fn redact_secrets(text: &str) -> String {
    let Ok(mut doc) = text.parse::<toml_edit::DocumentMut>() else {
        return "# (configuration redacted: it does not parse)\n".to_owned();
    };
    if let Some(auth) = doc.get_mut("auth") {
        mask_every_value_in_item(auth);
    }
    mask_secrets_in(doc.as_table_mut());
    doc.to_string()
}

/// Masks every value under `item`, whatever its key: a section nothing reads may hold anything.
fn mask_every_value_in_item(item: &mut toml_edit::Item) {
    match item {
        toml_edit::Item::Table(table) => {
            table
                .iter_mut()
                .for_each(|(_, item)| mask_every_value_in_item(item));
        }
        toml_edit::Item::ArrayOfTables(tables) => tables.iter_mut().for_each(|table| {
            table
                .iter_mut()
                .for_each(|(_, item)| mask_every_value_in_item(item));
        }),
        toml_edit::Item::Value(_) => *item = toml_edit::value("***"),
        toml_edit::Item::None => {}
    }
}

/// Masks every secret key of `table` and of every table nested in it.
fn mask_secrets_in(table: &mut dyn toml_edit::TableLike) {
    for (key, item) in table.iter_mut() {
        if SECRET_KEYS.contains(&key.get()) {
            *item = toml_edit::value("***");
        } else {
            mask_secrets_in_item(item);
        }
    }
}

fn mask_secrets_in_item(item: &mut toml_edit::Item) {
    match item {
        toml_edit::Item::Table(table) => mask_secrets_in(table),
        toml_edit::Item::ArrayOfTables(tables) => {
            tables.iter_mut().for_each(|table| mask_secrets_in(table));
        }
        toml_edit::Item::Value(value) => mask_secrets_in_value(value),
        toml_edit::Item::None => {}
    }
}

fn mask_secrets_in_value(value: &mut toml_edit::Value) {
    match value {
        toml_edit::Value::InlineTable(table) => mask_secrets_in(table),
        toml_edit::Value::Array(array) => array.iter_mut().for_each(mask_secrets_in_value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The file's text is reported off the host as the effective configuration, and the Server
    /// persists what it receives — so a credential value must never survive the redaction, while
    /// the operator's comments and layout must (they are half of what the file says). A leftover
    /// `[auth]` section is masked whole, whatever its keys are called.
    /// Verifies: ADR-0017, ADR-0021
    #[test]
    fn redaction_masks_credential_values_and_keeps_everything_else() {
        let text = "# the fleet endpoint\nendpoint = \"wss://fleet:4320/v1/opamp\"\n\n\
                    [auth]\n  bearer_token = \"s3cret\"\n\
                    [packages]\narchive_key = \"p4ss\"\nverification_key = \"aabb\"\n";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("s3cret"), "{redacted}");
        assert!(!redacted.contains("p4ss"), "{redacted}");
        assert!(redacted.contains("  bearer_token = \"***\""), "{redacted}");
        assert!(redacted.contains("archive_key = \"***\""), "{redacted}");
        assert!(
            redacted.contains("# the fleet endpoint"),
            "comments stay: {redacted}"
        );
        assert!(
            redacted.contains("endpoint = \"wss://fleet:4320/v1/opamp\""),
            "{redacted}"
        );
        assert!(
            redacted.contains("verification_key = \"aabb\""),
            "the public half of the signing pair is no secret: {redacted}"
        );

        // An inline table hides a credential no better than a line of its own.
        let inline = redact_secrets("auth = { username = \"op\", password = \"hunter2\" }\n");
        assert!(!inline.contains("hunter2"), "{inline}");
        let renamed = redact_secrets("[auth]\nPassword = \"hunter2\"\ntoken = \"t0ken\"\n");
        assert!(!renamed.contains("hunter2"), "{renamed}");
        assert!(!renamed.contains("t0ken"), "{renamed}");
        assert!(renamed.contains("token = \"***\""), "{renamed}");
    }

    /// A secret is masked whatever TOML spelling carries it: a multi-line string, basic or
    /// literal, must not leave its continuation lines behind, and a dotted key, a quoted key, an
    /// inline table or an array of tables hides it no better. What is not secret stays as written.
    /// Verifies: ADR-0017, ADR-0026
    #[test]
    fn redaction_masks_every_spelling_of_a_secret_value() {
        let spellings = [
            "[packages]\narchive_key = \"\"\"\nleak-basic\"\"\"\n",
            "[packages]\narchive_key = '''\nleak-literal\n'''\n",
            "[packages]\narchive_key = \"\"\"\\\n  leak-continued \\\n  \"\"\"\n",
            "[packages]\narchive_key = 'leak-literal-single'\n",
            "[packages]\narchive_key = \"leak\\u002descaped\"\n",
            "[packages]\n\"archive_key\" = \"leak-quoted-key\"\n",
            "packages.archive_key = \"leak-dotted\"\n",
            "packages = { archive_key = \"\"\"leak-\ninline\"\"\" }\n",
            "[auth]\nbearer_token = \"leak-commented\" # rotated monthly, was leak-old\n",
            "[[x]]\npassword = '''\nleak-array\n'''\n",
            "[auth.password]\nvalue = \"leak-table\"\n",
        ];
        for text in spellings {
            let redacted = redact_secrets(text);
            assert!(
                !redacted.contains("leak"),
                "{text:?} redacted to {redacted:?}"
            );
            assert!(
                redacted.contains("***"),
                "{text:?} redacted to {redacted:?}"
            );
            assert!(
                redacted.parse::<toml_edit::DocumentMut>().is_ok(),
                "the redacted text still parses: {redacted:?}"
            );
        }

        let text = "# head\n[packages]\nverification_key = \"\"\"\naabb\"\"\" # public\n\
                    archive_key = '''\nsecret\n'''\nself_update = false\n";
        assert_eq!(
            redact_secrets(text),
            "# head\n[packages]\nverification_key = \"\"\"\naabb\"\"\" # public\n\
             archive_key = \"***\"\nself_update = false\n"
        );
        assert_eq!(
            redact_secrets("packages = { self_update = false, archive_key = '''\nsecret''' }\n"),
            "packages = { self_update = false, archive_key = \"***\" }\n"
        );
    }

    /// Text that does not parse cannot be taken apart, so it is reported as a placeholder.
    /// Verifies: ADR-0017, ADR-0026
    #[test]
    fn redaction_replaces_text_that_does_not_parse_whole() {
        let redacted = redact_secrets("archive_key = \"\"\"\nleak\nnot = closed\n");
        assert!(!redacted.contains("leak"), "{redacted}");
        assert!(!redacted.contains("closed"), "{redacted}");
    }

    /// The client identity is all a Client needs to start: a file naming one passes with no
    /// `[auth]`, and a file without one is refused, naming `[tls] cert_file` and `key_file` — the
    /// Server would refuse it in the handshake anyway.
    /// Verifies: ADR-0021, ADR-0019, Q-1
    #[test]
    fn admission_needs_a_client_identity_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        std::fs::write(&cert, "cert").expect("write");
        std::fs::write(&key, "key").expect("write");
        let state = dir.path().join("state").display().to_string();

        let bare: ClientConfig =
            toml::from_str(&format!("state_dir = {state:?}\n")).expect("parse");
        let err = bare.check_admission().expect_err("no certificate");
        assert!(err.contains("cert_file and key_file are required"), "{err}");

        let complete: ClientConfig = toml::from_str(&format!(
            "state_dir = {state:?}\n[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
            cert.display().to_string(),
            key.display().to_string()
        ))
        .expect("parse");
        complete
            .check_admission()
            .expect("a certificate and nothing else");

        // A leftover [auth] is no reason to refuse, or to warn at install: it is ignored.
        let leftover: ClientConfig = toml::from_str(&format!(
            "state_dir = {state:?}\n[auth]\nbearer_token = \"t\"\n[tls]\ncert_file = {:?}\nkey_file = {:?}\n",
            cert.display().to_string(),
            key.display().to_string()
        ))
        .expect("parse");
        leftover
            .check_admission()
            .expect("a leftover [auth] beside a certificate");
    }

    use crate::service::layout::Roots;

    /// The roots under `dir`, with what an administrator named.
    fn roots(dir: &Path, named: Option<&Path>, registered: Option<&Path>) -> Roots {
        Roots {
            named: named.map(Path::to_path_buf),
            registered: registered.map(Path::to_path_buf),
            data: dir.join("data"),
            layout: dir.join("layout"),
        }
    }

    /// An installed service keeps its state in `<data root>/state` unless the file names an
    /// absolute directory beneath the data root or the layout root — whatever the working
    /// directory of the shell that installs. `load` resolves a relative `state_dir` against that
    /// directory; the install must not take it.
    /// Verifies: ADR-0053, ADR-0019
    #[test]
    fn an_installed_service_keeps_its_state_under_the_data_root_unless_named_absolutely() {
        let dir = tempfile::tempdir().expect("tempdir");
        let roots = roots(dir.path(), None, None);
        let path = dir.path().join("supervisor.toml");
        let installed = |text: &str| {
            std::fs::write(&path, text).expect("write");
            ClientConfig::load(&path)
                .expect("load")
                .service_state_dir(&roots)
                .expect("beneath the roots")
        };

        // The file the questionnaire writes names none: the default `client-state` is relative.
        assert_eq!(installed(""), roots.data.join("state"));
        assert_eq!(
            installed("state_dir = \"elsewhere\"\n"),
            roots.data.join("state")
        );
        // Absent file, defaults: the same.
        assert_eq!(
            ClientConfig::load(&dir.path().join("absent.toml"))
                .expect("defaults")
                .service_state_dir(&roots)
                .expect("the default"),
            roots.data.join("state")
        );

        for named in [roots.data.join("other/state"), roots.layout.join("state")] {
            assert_eq!(
                installed(&format!("state_dir = '{}'\n", named.display())),
                named,
                "an absolute state_dir beneath a root is kept"
            );
        }
    }

    /// `supervisor.toml` is the service account's to rewrite (ADR-0042 clause 2), and the install
    /// that reads it runs as root or an Administrator and hands the state directory over to that
    /// account. With nothing registered and no `--state-dir`, a state directory the file names
    /// outside the data root and the layout root, or one that leaves them by `..`, is refused, so
    /// the account cannot have another tree handed over to itself. The operator's `--state-dir`
    /// names one anywhere.
    /// Verifies: ADR-0053, ADR-0042
    #[test]
    fn a_state_directory_the_file_names_outside_the_installs_roots_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let outside = dir.path().join("elsewhere");
        let loaded = |state_dir: &Path| {
            std::fs::write(&path, format!("state_dir = '{}'\n", state_dir.display()))
                .expect("write");
            ClientConfig::load(&path).expect("load")
        };

        let unregistered = roots(dir.path(), None, None);
        for state_dir in [
            outside.clone(),
            unregistered.data.join("..").join("elsewhere"),
        ] {
            let err = loaded(&state_dir)
                .service_state_dir(&unregistered)
                .expect_err("outside the roots");
            assert!(err.contains(&state_dir.display().to_string()), "{err}");
            assert!(err.contains("--state-dir"), "{err}");
        }

        assert_eq!(
            loaded(&outside)
                .service_state_dir(&roots(dir.path(), Some(&outside), None))
                .expect("named by the operator"),
            outside,
            "the operator's --state-dir is taken wherever it lies"
        );
    }

    /// A re-registration keeps the state directory its registration carries, whatever the file
    /// now says — outside the roots, beneath them, or nothing — so an upgrade never moves it and
    /// the service's account cannot move it. Only `--state-dir` names another.
    /// Verifies: ADR-0053
    #[test]
    fn a_reregistration_keeps_the_registered_state_directory_whatever_the_file_says() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("supervisor.toml");
        let registered = dir.path().join("relocated");
        let kept = roots(dir.path(), None, Some(&registered));
        for text in [
            format!("state_dir = '{}'\n", dir.path().join("elsewhere").display()),
            format!("state_dir = '{}'\n", kept.data.join("state").display()),
            String::new(),
        ] {
            std::fs::write(&path, &text).expect("write");
            assert_eq!(
                ClientConfig::load(&path)
                    .expect("load")
                    .service_state_dir(&kept)
                    .expect("registered"),
                registered,
                "{text}"
            );
        }

        let moved = dir.path().join("moved");
        assert_eq!(
            ClientConfig::load(&path)
                .expect("load")
                .service_state_dir(&roots(dir.path(), Some(&moved), Some(&registered)))
                .expect("named"),
            moved,
            "an administrator's --state-dir outranks the registration"
        );
    }

    /// A link the service's account planted beneath the data root would carry the state directory
    /// out of it, so a component that is a link is refused — the default `<data root>/state` and a
    /// registered directory beneath the root included.
    /// Verifies: ADR-0053, ADR-0042
    #[cfg(unix)]
    #[test]
    fn a_state_directory_reached_through_a_link_beneath_the_root_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unregistered = roots(dir.path(), None, None);
        let outside = dir.path().join("elsewhere");
        std::fs::create_dir_all(&unregistered.data).expect("data root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, unregistered.data.join("link")).expect("link");
        let path = dir.path().join("supervisor.toml");

        let through = unregistered.data.join("link").join("state");
        std::fs::write(&path, format!("state_dir = '{}'\n", through.display())).expect("write");
        let err = ClientConfig::load(&path)
            .expect("load")
            .service_state_dir(&unregistered)
            .expect_err("through a link");
        assert!(err.contains("is a link"), "{err}");
        ClientConfig::load(&path)
            .expect("load")
            .service_state_dir(&roots(dir.path(), None, Some(&through)))
            .expect_err("registered, through a link");

        std::fs::write(&path, "").expect("write");
        std::os::unix::fs::symlink(&outside, unregistered.data.join("state")).expect("link");
        ClientConfig::load(&path)
            .expect("load")
            .service_state_dir(&unregistered)
            .expect_err("the default, planted as a link");
    }
}
