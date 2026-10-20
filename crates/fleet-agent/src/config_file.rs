//! `supervisor.toml` on disk (ADR-0010): reading the file, the directories it names made absolute
//! against the working directory, and the identity the state directory holds. What the file must
//! say is [`config`](crate::config)'s; this is only where it comes from.

use std::path::{Path, PathBuf};

use crate::config::{redact_secrets, ClientConfig, LEGACY_CONFIG_FILE_NAME};

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
        let text = std::fs::read_to_string(path)
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

    /// The state directory a service installed from this file runs with (ADR-0019): the one the
    /// file names when it names an absolute one, and `<data root>/state` otherwise.
    ///
    /// Decided on the value as written, because [`state_dir`](Self::state_dir) is already resolved
    /// against the installing shell's working directory, which the service never shares. Meaningful
    /// only on a configuration returned by [`load`](Self::load).
    pub fn service_state_dir(&self, data_root: &Path) -> PathBuf {
        if self.state_dir_as_written.is_absolute() {
            self.state_dir_as_written.clone()
        } else {
            data_root.join(crate::service::layout::STATE_DIR_NAME)
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// An installed service keeps its state in `<data root>/state` unless the file names an
    /// absolute directory — whatever the working directory of the shell that installs. `load`
    /// resolves a relative `state_dir` against that directory; the install must not take it.
    /// Verifies: ADR-0019
    #[test]
    fn an_installed_service_keeps_its_state_under_the_data_root_unless_named_absolutely() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_root = dir.path().join("data");
        let path = dir.path().join("supervisor.toml");
        let installed = |text: &str| {
            std::fs::write(&path, text).expect("write");
            ClientConfig::load(&path)
                .expect("load")
                .service_state_dir(&data_root)
        };

        // The file the questionnaire writes names none: the default `client-state` is relative.
        assert_eq!(installed(""), data_root.join("state"));
        assert_eq!(
            installed("state_dir = \"elsewhere\"\n"),
            data_root.join("state")
        );
        // Absent file, defaults: the same.
        assert_eq!(
            ClientConfig::load(&dir.path().join("absent.toml"))
                .expect("defaults")
                .service_state_dir(&data_root),
            data_root.join("state")
        );

        let named = dir.path().join("named-state");
        assert_eq!(
            installed(&format!("state_dir = '{}'\n", named.display())),
            named,
            "an absolute state_dir is the operator's choice and is kept"
        );
    }
}
