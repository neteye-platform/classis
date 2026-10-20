//! The configuration file the questionnaire writes and edits — `service install --interactive`
//! and `service config` (ADR-0019).
//!
//! A release artifact is the bare binary (ADR-0019), so a fresh host has nothing to copy from, and
//! [`ClientConfig::load`](crate::config::ClientConfig::load) answers a missing file with the
//! development defaults — a service that installs, starts, dials `127.0.0.1`, and manages nothing.
//! This module is the way out of that state: it asks the handful of questions a fresh host cannot
//! answer for itself, offering what the file already holds as each default, and writes the file
//! or edits the keys it asked about. The bootstrap identity it asks for on a host not yet enrolled —
//! a PEM pair, or a `bootstrap.p12` and its password (ADR-0029) — is handed back, not written:
//! [`enrol`](crate::service::enrol) carries the host to its first certificate with it.
//!
//! The split here is deliberate. [`ask`] is the only part that touches a terminal; [`render`] and
//! [`edit`] are pure functions from answers to TOML, and [`write_new`] is the one that refuses to
//! overwrite. The parts that decide what lands on disk are therefore testable without a tty — and
//! they are what [`run_with_endpoint`] reuses to serve a packaged install, which has an answer but
//! no terminal.

use std::io::{IsTerminal, Write as _};
use std::path::{Path, PathBuf};

use dialoguer::{Input, Password};

use crate::config::ClientConfig;

/// The file name written inside the install root when the operator named no `--config` path
/// (ADR-0019): one rule for systemd, launchd, and the SCM instead of an `/etc` vs `/Library` vs
/// `%ProgramData%` policy per platform.
pub const FILE_NAME: &str = "supervisor.toml";

/// The name the questionnaire copies the answered Server CA to, beside [`FILE_NAME`] (ADR-0019),
/// and the name the install looks for beside its program (ADR-0020).
pub const SERVER_CA_FILE: &str = "server-ca.pem";

/// The bootstrap certificate the install looks for beside its program (ADR-0020).
pub const BOOTSTRAP_CERT_FILE: &str = "bootstrap.pem";

/// The bootstrap certificate's private key the install looks for beside its program (ADR-0020).
pub const BOOTSTRAP_KEY_FILE: &str = "bootstrap-key.pem";

/// The package verification key, in hex, the install looks for beside its program (ADR-0020).
pub const VERIFICATION_KEY_FILE: &str = "package-signing-key.pub";

/// The bootstrap certificate and its key in one password-protected file, which the install looks
/// for beside its program (ADR-0029 clause 6).
pub const BOOTSTRAP_P12_FILE: &str = fleet_core::pkcs12::FILE_NAME;

/// The fleet's files that lie beside the program the install runs from, or in the directory
/// `--fleet-files` names (ADR-0029 clause 6): the questionnaire's defaults, and what a
/// non-interactive install takes without a question.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Beside {
    /// `server-ca.pem`.
    pub ca_file: Option<PathBuf>,
    /// `bootstrap.pem` and `bootstrap-key.pem` only as a pair, or `bootstrap.p12` — never both.
    pub bootstrap: Option<BootstrapFiles>,
    /// The content of `package-signing-key.pub`, when it is a key.
    pub verification_key: Option<String>,
    /// What was there and not taken, each said once by the install.
    pub warnings: Vec<String>,
}

impl Beside {
    /// What lies beside the running executable. Nothing when its directory cannot be told.
    #[must_use]
    pub fn the_program() -> Self {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
            .map(|dir| Self::in_dir(&dir))
            .unwrap_or_default()
    }

    /// What lies in the directory `--fleet-files` names, looked in instead of beside the program
    /// (ADR-0029 clause 6).
    ///
    /// # Errors
    /// Returns an error naming the flag when `dir` is not a readable directory.
    pub fn in_named_dir(dir: &Path) -> Result<Self, String> {
        std::fs::read_dir(dir).map_err(|e| {
            format!(
                "--fleet-files {}: not a readable directory ({e})",
                dir.display()
            )
        })?;
        Ok(Self::in_dir(dir))
    }

    /// What lies in `dir` under the fleet's file names.
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        let file = |name: &str| Some(dir.join(name)).filter(|path| path.is_file());
        let mut warnings = Vec::new();
        let pair = match (file(BOOTSTRAP_CERT_FILE), file(BOOTSTRAP_KEY_FILE)) {
            (Some(cert), Some(key)) => Some(BootstrapFiles::Pair { cert, key }),
            (Some(alone), None) | (None, Some(alone)) => {
                warnings.push(format!(
                    "{} lies there without the other half of the bootstrap pair \
                     ({BOOTSTRAP_CERT_FILE} and {BOOTSTRAP_KEY_FILE}); not used",
                    alone.display()
                ));
                None
            }
            (None, None) => None,
        };
        // Two identities would leave the install to guess which one is meant (ADR-0029 clause 6).
        let bootstrap = match (file(BOOTSTRAP_P12_FILE), pair) {
            (Some(p12), None)
                if file(BOOTSTRAP_CERT_FILE).is_none() && file(BOOTSTRAP_KEY_FILE).is_none() =>
            {
                Some(BootstrapFiles::Pkcs12(p12))
            }
            (Some(p12), _) => {
                warnings.push(format!(
                    "{} lies beside {BOOTSTRAP_CERT_FILE} or {BOOTSTRAP_KEY_FILE}; neither bootstrap \
                     identity is used — leave one",
                    p12.display()
                ));
                None
            }
            (None, pair) => pair,
        };
        let verification_key = file(VERIFICATION_KEY_FILE).and_then(|path| {
            let key = std::fs::read_to_string(&path)
                .map(|text| text.trim().to_string())
                .unwrap_or_default();
            if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
                Some(key)
            } else {
                warnings.push(format!(
                    "{} holds no hex Ed25519 public key; not used",
                    path.display()
                ));
                None
            }
        });
        Beside {
            ca_file: file(SERVER_CA_FILE),
            bootstrap,
            verification_key,
            warnings,
        }
    }

    /// The bootstrap identity a non-interactive install enrols with (ADR-0029 clause 10): the one
    /// beside the program, when `config` reaches its Server over TLS and its state directory
    /// holds no issued certificate. A `bootstrap.p12` is opened here, with `password` — what
    /// `--bootstrap-password-file` read — so a file that does not open stops the install before
    /// anything is written.
    ///
    /// # Errors
    /// Returns an error naming `--bootstrap-password-file` when a `bootstrap.p12` would be taken
    /// without it or does not open under it, and when it is given with no `bootstrap.p12` there.
    pub fn unasked_enrolment(
        &self,
        config: &ClientConfig,
        password: Option<&str>,
    ) -> Result<Option<Bootstrap>, String> {
        let p12 = match &self.bootstrap {
            Some(BootstrapFiles::Pkcs12(file)) => Some(file),
            _ => None,
        };
        if password.is_some() && p12.is_none() {
            return Err(format!(
                "--bootstrap-password-file names the password of a {BOOTSTRAP_P12_FILE}, and \
                 there is none to open"
            ));
        }
        if !is_tls_endpoint(&config.endpoint) || config.is_enrolled() {
            return Ok(None);
        }
        match &self.bootstrap {
            None => Ok(None),
            Some(BootstrapFiles::Pair { cert, key }) => Ok(Some(Bootstrap::Pair {
                cert: cert.clone(),
                key: key.clone(),
            })),
            Some(BootstrapFiles::Pkcs12(file)) => {
                let Some(password) = password else {
                    return Err(format!(
                        "{} is a bootstrap identity under a password: name a file holding it \
                         with --bootstrap-password-file",
                        file.display()
                    ));
                };
                let identity = crate::tls::pkcs12_identity(file, password)
                    .map_err(|e| format!("{}: {e} (--bootstrap-password-file)", file.display()))?;
                Ok(Some(Bootstrap::Pkcs12 {
                    file: file.clone(),
                    identity,
                }))
            }
        }
    }

    /// Prints what lies beside the program and is not taken.
    fn report(&self) {
        for warning in &self.warnings {
            println!("warning: {warning}");
        }
    }
}

/// What the questionnaire writes into the file. Everything else in `supervisor.toml` has a default
/// that is right on a fresh host, and is written as a comment rather than as a value (ADR-0019).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    /// The Server's OpAMP endpoint; its scheme selects the transport (ADR-0013).
    pub endpoint: String,
    /// The operator's name for this Client, reported as `service.instance.name` (ADR-0016) — which
    /// of the fleet's Clients this is. Not its `service.name`: that is the Agent *type*, the
    /// constant `supervisor` (ADR-0019), the same on every host and nothing to ask about.
    pub name: String,
    /// The CA that signed the Server's certificate, for a `wss://` / `https://` endpoint (ADR-0013).
    /// The questionnaire always asks for it there; `None` for a loopback `ws://` / `http://`
    /// endpoint, or where no question was put — a packaged install.
    pub ca_file: Option<PathBuf>,
    /// The hex Ed25519 key packages are verified against (ADR-0026); `None` takes no package until
    /// one is set.
    pub verification_key: Option<String>,
    /// `[packages] self_update` (ADR-0018): whether the Server may replace this Client's own
    /// binary. The questionnaire does not ask — a new file says `true`, and the verification key
    /// decides whether that takes effect; only `--no-self-update` and the MSI's checkbox write
    /// `false`. A new file says which of the two it is; an edited file keeps what it says.
    pub self_update: bool,
}

/// A bootstrap identity found on this host, not yet opened (ADR-0029 clause 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapFiles {
    /// `bootstrap.pem` and `bootstrap-key.pem`.
    Pair { cert: PathBuf, key: PathBuf },
    /// `bootstrap.p12`.
    Pkcs12(PathBuf),
}

/// The bootstrap identity (ADR-0021) the Client enrols with. Asked for only while the Client is
/// not enrolled, and never copied or written into the file: the questionnaire's enrolment presents
/// it once, to obtain the certificate the Server issues (ADR-0019 clause 17, ADR-0029 clause 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootstrap {
    /// The bootstrap certificate and its private key, PEM, where they lie on this host.
    Pair { cert: PathBuf, key: PathBuf },
    /// A `bootstrap.p12`, opened under its password: the identity is held in memory only.
    Pkcs12 {
        file: PathBuf,
        identity: crate::config::BootstrapIdentity,
    },
}

impl Bootstrap {
    /// The files it was read from, for what the install prints.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Bootstrap::Pair { cert, key } => format!("{} and {}", cert.display(), key.display()),
            Bootstrap::Pkcs12 { file, .. } => file.display().to_string(),
        }
    }
}

/// What the questionnaire left behind: the files it wrote beside the configuration, which an
/// install hands over to the service account with the file, and the bootstrap identity to enrol
/// with.
#[derive(Debug, Default)]
pub struct Written {
    /// The copy of the answered Server CA, when one was answered.
    pub copies: Vec<PathBuf>,
    /// The identity to enrol with; `None` on an enrolled Client, which was not asked.
    pub bootstrap: Option<Bootstrap>,
}

/// Ask, write, and report — the whole of `--interactive` and `service config` (ADR-0019).
///
/// `current` is what the file at `path` holds, or the defaults where there is none yet, and offers
/// each question its default; where it holds nothing, what lies `beside` the program does
/// (ADR-0020 clause 2). A new file is rendered whole; an existing one is edited in place,
/// the asked keys changed and everything else — comments, `[[supervisor]]` blocks, the
/// self-update consent — kept as written. `enrolled` says whether the state directory already
/// holds an issued certificate, in which case no bootstrap identity is asked for. `password` is
/// what `--bootstrap-password-file` read, which opens an answered `bootstrap.p12` instead of a
/// question (ADR-0029 clause 8).
///
/// The answered CA is copied beside the file first, and the file names the copy
/// ([`copy_ca_beside`]).
///
/// # Errors
/// Returns an error when stdin is not a terminal, when a prompt fails, or when a file cannot be
/// copied, created or replaced.
pub fn run(
    path: &Path,
    current: &ClientConfig,
    enrolled: bool,
    beside: &Beside,
    password: Option<&str>,
) -> Result<Written, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "the questionnaire needs a terminal on stdin, and there is none. Write {} by hand \
             instead — a provisioning run must not block on a question nobody can answer.",
            path.display()
        ));
    }
    let existing = path.exists();
    if existing {
        println!(
            "Editing {} — Enter keeps the value shown (everything not asked stays as it is).",
            path.display()
        );
    } else {
        println!(
            "No configuration at {} — answering these writes it (everything else keeps its \
             default).",
            path.display()
        );
    }
    beside.report();
    let (answers, bootstrap) = ask(current, enrolled, beside, password)?;
    let (answers, copies) = copy_ca_beside(answers, path)?;
    for copy in &copies {
        println!("copied {}", copy.display());
    }
    if existing {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        replace(path, &edit(&text, &answers)?)?;
    } else {
        write_new(path, &render(&answers))?;
    }
    println!("wrote {}", path.display());
    Ok(Written { copies, bootstrap })
}

/// Copy the answered CA into the directory of the configuration at `config`, under
/// [`SERVER_CA_FILE`], and return the answers naming the copy together with the copy's path.
///
/// The configuration then depends on nothing outside its own directory for its trust: the copy
/// survives the removal of wherever the operator brought the CA from, and it lives where the file
/// and the state do — in the data root, which the install hands over and an uninstall keeps
/// (ADR-0019). It is written owner-only to a temporary name and renamed into place, so a later
/// answer replaces a copy left by an earlier one, and an answer that already names the copy — the
/// default an edit offers — is read before anything is written there.
///
/// # Errors
/// Returns an error naming the file that could not be read or written.
pub fn copy_ca_beside(answers: Answers, config: &Path) -> Result<(Answers, Vec<PathBuf>), String> {
    let Some(ca) = &answers.ca_file else {
        return Ok((answers, Vec::new()));
    };
    let dir = std::path::absolute(config)
        .map_err(|e| format!("cannot resolve {}: {e}", config.display()))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{} names no directory", config.display()))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let to = dir.join(SERVER_CA_FILE);
    let bytes = std::fs::read(ca).map_err(|e| format!("cannot read {}: {e}", ca.display()))?;
    write_owner_only(&to, &bytes, None)?;
    Ok((
        Answers {
            ca_file: Some(to.clone()),
            ..answers
        },
        vec![to],
    ))
}

/// Write `bytes` to `to`, owner-only on Unix, through a temporary name beside it, so the file is
/// never seen half-written and a file already there is replaced in one rename.
///
/// `owner` (Unix) is set on the open file before the rename, never on the path after it: the
/// directory may belong to the service's account, which could put a link where the path was.
fn write_owner_only(to: &Path, bytes: &[u8], owner: Option<(u32, u32)>) -> Result<(), String> {
    let mut partial = to.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    // A leftover from an interrupted run would make `create_new` refuse.
    let _ = std::fs::remove_file(&partial);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(&partial)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            #[cfg(unix)]
            if let Some((uid, gid)) = owner {
                std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
            }
            #[cfg(not(unix))]
            let _ = owner;
            Ok(())
        })
        .and_then(|()| std::fs::rename(&partial, to))
        .map_err(|e| {
            let _ = std::fs::remove_file(&partial);
            format!("cannot write {}: {e}", to.display())
        })
}

/// Replace the configuration at `path` with `contents`, keeping who owns it.
///
/// Through a temporary name and a rename, so a Client starting meanwhile reads the old file or the
/// new one, never half of either. The new file is owner-only like the one it replaces (ADR-0019
/// clause 18), and on Unix it is given back to the old file's owner: the file of a service that
/// runs as its own account belongs to that account (ADR-0019 clause 13), and the administrator
/// editing it must not take it away.
fn replace(path: &Path, contents: &str) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    // A link would be replaced by a plain file, and its owner is not the configuration's.
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symbolic link — run the questionnaire with --config naming its target",
            path.display()
        ));
    }
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt as _;
        Some((meta.uid(), meta.gid()))
    };
    #[cfg(not(unix))]
    let owner = None;
    write_owner_only(path, contents.as_bytes(), owner)
}

/// Edit the answers into an existing configuration's text, changing only the keys the
/// questionnaire asks about. Pure, so what lands on disk is testable without a tty.
///
/// `toml_edit` keeps everything else byte for byte — comments, ordering, the `[[supervisor]]`
/// blocks, the self-update consent. A CA is written only when one was answered: a loopback
/// endpoint asks for none, and an edit that switches to one leaves the CA the file names standing.
/// An answered verification key replaces the one in the file, and a removed one is removed.
///
/// # Errors
/// Returns an error if the text is not TOML, or names `[tls]` or `[packages]` as something other
/// than a table.
pub fn edit(text: &str, answers: &Answers) -> Result<String, String> {
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("cannot parse the configuration: {e}"))?;
    doc["endpoint"] = toml_edit::value(answers.endpoint.as_str());
    doc["name"] = toml_edit::value(answers.name.as_str());
    if let Some(ca) = &answers.ca_file {
        table(&mut doc, "tls")?.insert(
            "ca_file",
            toml_edit::value(ca.to_string_lossy().into_owned()),
        );
    }
    match &answers.verification_key {
        Some(key) => {
            table(&mut doc, "packages")?.insert("verification_key", toml_edit::value(key.as_str()));
        }
        None => {
            if let Some(packages) = doc
                .get_mut("packages")
                .and_then(toml_edit::Item::as_table_like_mut)
            {
                packages.remove("verification_key");
            }
        }
    }
    Ok(doc.to_string())
}

/// The table `name` of `doc`, created at the end of the file when it is not there.
fn table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    name: &str,
) -> Result<&'a mut dyn toml_edit::TableLike, String> {
    doc.entry(name)
        .or_insert(toml_edit::table())
        .as_table_like_mut()
        .ok_or_else(|| format!("[{name}] in the configuration is not a table"))
}

/// Write the first configuration from an endpoint *given* rather than asked for — the whole of
/// `--endpoint` (ADR-0019 clause 42).
///
/// This is the half of ADR-0019 a packaged install can reach. An MSI dialog and a `%post` script
/// both have an answer and no terminal, and [`run`] is deliberately an error without one; the file
/// they need is the same file, rendered by the same [`render`] and created by the same
/// [`write_new`], so the never-overwrite rule and the `0600` mode are not restated here.
///
/// The endpoint and the self-update consent are taken, and for a `wss://` / `https://` endpoint
/// the Server CA and the verification key that lie `beside` the program, the CA copied beside the
/// file as the questionnaire's answer would be (ADR-0020 clause 3). The client identity comes from
/// an enrolment an operator approves, which the install runs with a bootstrap pair beside the
/// program (ADR-0020 clause 4); a file written without one fails the install's validation and
/// stays on disk to be completed (ADR-0019).
///
/// # Errors
/// Returns an error if the endpoint is not one the loader would accept, or if the file cannot be
/// created.
pub fn run_with_endpoint(
    path: &Path,
    endpoint: &str,
    self_update: bool,
    beside: &Beside,
) -> Result<Vec<PathBuf>, String> {
    beside.report();
    if keeping_existing(path) {
        return Ok(Vec::new());
    }
    // Before the file is created, not after: an install that wrote an unusable file and then failed
    // to load it would leave the operator correcting a file they never typed.
    validate_endpoint(endpoint)?;
    let endpoint = endpoint.trim().to_string();
    // Trust and package keys belong to a Server reached over TLS; a loopback `ws://` has neither.
    let tls = is_tls_endpoint(&endpoint);
    let answers = Answers {
        name: ClientConfig::default().name,
        ca_file: beside.ca_file.clone().filter(|_| tls),
        verification_key: beside.verification_key.clone().filter(|_| tls),
        self_update,
        endpoint,
    };
    if let Some(key) = &answers.verification_key {
        println!("took the package verification key {key} from beside the program");
    }
    let (answers, copies) = copy_ca_beside(answers, path)?;
    for copy in &copies {
        println!("copied {}", copy.display());
    }
    write_new(path, &render(&answers))?;
    println!("wrote {} for {}", path.display(), answers.endpoint);
    Ok(copies)
}

/// Whether a configuration is already there — in which case an installer's answer keeps it.
///
/// ADR-0019's rule is that a file somebody answered or edited is never overwritten by a later
/// install, and a packaged re-install is exactly the later install it had in mind. A leftover
/// `[auth]` in it is no reason to fail or to warn: the Client ignores the section.
fn keeping_existing(path: &Path) -> bool {
    if path.exists() {
        println!("keeping the configuration already at {}", path.display());
        return true;
    }
    false
}

/// Put the questions to the operator, each offering what `current` holds as its default. The only
/// function here that reads a terminal.
///
/// The bootstrap identity is asked for only when `enrolled` is `false` (ADR-0019 clause 17), and
/// comes back beside the answers rather than in them: it is enrolled with, not written.
///
/// # Errors
/// Returns an error if a prompt cannot be read, or an answered `bootstrap.p12` does not open under
/// the `password` given.
pub fn ask(
    current: &ClientConfig,
    enrolled: bool,
    beside: &Beside,
    password: Option<&str>,
) -> Result<(Answers, Option<Bootstrap>), String> {
    let defaults = Defaults::of(current, beside);

    let endpoint: String = Input::new()
        .with_prompt("Server OpAMP endpoint")
        .default(defaults.endpoint)
        .validate_with(|input: &String| validate_endpoint(input))
        .interact_text()
        .map_err(prompt_failed)?;

    let name: String = Input::new()
        .with_prompt("This Agent's name (service.instance.name)")
        .default(defaults.name)
        .validate_with(|input: &String| {
            if input.trim().is_empty() {
                Err("the name cannot be empty".to_string())
            } else {
                Ok(())
            }
        })
        .interact_text()
        .map_err(prompt_failed)?;

    // The Server's CA, asked for wherever TLS applies: the Server always presents a certificate of
    // the fleet's own CA. A loopback `ws://` endpoint has no certificate to trust.
    let ca_file = if is_tls_endpoint(&endpoint) {
        Some(ask_path(
            "CA certificate of the Server — the CA that signed its certificate (PEM path)",
            defaults.ca_file,
        )?)
    } else {
        None
    };

    // The bootstrap identity (ADR-0021) a host not yet enrolled enrols with: a PEM certificate and
    // its key, or a PKCS#12 file and its password (ADR-0029 clause 8). There is no answer without
    // one, and no question asks for a credential (ADR-0019) — the password opens a file on this
    // host and is sent nowhere. An enrolled host renews what it was issued and is not asked.
    let bootstrap = if enrolled {
        println!("enrolled: this Client holds a certificate the Server issued");
        None
    } else {
        Some(ask_bootstrap(
            defaults.cert_file,
            defaults.key_file,
            password,
        )?)
    };

    // Without it nothing is installed, the Client's own updates included (ADR-0026); an empty
    // answer is allowed and said so. A key the file holds is the default, so Enter keeps it and a
    // single `-` is how it is removed.
    let mut prompt = Input::<String>::new().allow_empty(true);
    prompt = match defaults.verification_key {
        Some(key) => prompt
            .with_prompt("Package verification key (hex Ed25519 public key; - removes it)")
            .default(key),
        None => prompt.with_prompt(
            "Package verification key (hex Ed25519 public key; empty takes no packages)",
        ),
    };
    let key_hex = prompt.interact_text().map_err(prompt_failed)?;
    let key_hex = key_hex.trim();
    let verification_key = (!key_hex.is_empty() && key_hex != "-").then(|| key_hex.to_string());
    if verification_key.is_none() {
        println!("no verification key: this Client installs no package until one is set");
    }

    Ok((
        Answers {
            endpoint: endpoint.trim().to_string(),
            name: name.trim().to_string(),
            ca_file,
            verification_key,
            // Not asked (ADR-0018): the key above decides whether the consent takes effect, and an
            // edited file keeps the consent it states.
            self_update: current.self_update_package().is_some(),
        },
        bootstrap,
    ))
}

/// The bootstrap identity: its certificate first, then the key of a PEM certificate, or the
/// password of a PKCS#12 file — asked with input hidden, and again until the file opens. A file
/// that is no bootstrap identity sends the question back to its path.
fn ask_bootstrap(
    cert_default: Option<String>,
    key_default: Option<String>,
    password: Option<&str>,
) -> Result<Bootstrap, String> {
    use fleet_core::pkcs12::file::OpenError;
    let mut cert_default = cert_default;
    loop {
        let cert = ask_path(
            "Bootstrap certificate this Client enrols with (PEM, or a PKCS#12 .p12 path)",
            cert_default.clone(),
        )?;
        if !is_pkcs12_path(&cert) {
            let key = ask_path(
                "Private key of the bootstrap certificate (PEM path)",
                key_default,
            )?;
            return Ok(Bootstrap::Pair { cert, key });
        }
        if let Some(password) = password {
            let identity = crate::tls::pkcs12_identity(&cert, password)
                .map_err(|e| format!("{}: {e} (--bootstrap-password-file)", cert.display()))?;
            return Ok(Bootstrap::Pkcs12 {
                file: cert,
                identity,
            });
        }
        loop {
            let typed = Password::new()
                .with_prompt(format!("Password of {}", cert.display()))
                .interact()
                .map_err(prompt_failed)?;
            match crate::tls::pkcs12_identity(&cert, &typed) {
                Ok(identity) => {
                    return Ok(Bootstrap::Pkcs12 {
                        file: cert,
                        identity,
                    })
                }
                Err(OpenError::WrongPassword) => {
                    println!("that password does not open {}", cert.display());
                }
                Err(OpenError::Invalid(why)) => {
                    println!("{why}");
                    cert_default = None;
                    break;
                }
            }
        }
    }
}

/// Whether an answered path is read as PKCS#12: by its extension, `.p12` or `.pfx` in any case
/// (ADR-0029 clause 8).
#[must_use]
pub fn is_pkcs12_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("p12") || e.eq_ignore_ascii_case("pfx"))
}

/// The password a password file holds: its first line, without its `\n` or `\r\n` (ADR-0029
/// clause 10). The file is read once, at most 4 KiB of it, and left as it is. `flag` is the option
/// that named it, `--bootstrap-password-file` here, for the error.
///
/// # Errors
/// Returns an error naming the flag when the file cannot be read or its first line is empty.
pub fn read_password_file(path: &Path, flag: &str) -> Result<String, String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(4096).read_to_end(&mut bytes))
        .map_err(|e| format!("{flag} {}: {e}", path.display()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("{flag} {}: not UTF-8 text", path.display()))?;
    let line = text.split('\n').next().unwrap_or_default();
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return Err(format!(
            "{flag} {}: its first line is empty",
            path.display()
        ));
    }
    Ok(line.to_string())
}

/// A path to a readable file, offering `default` when there is one.
fn ask_path(prompt: &str, default: Option<String>) -> Result<PathBuf, String> {
    let mut input = Input::<String>::new()
        .with_prompt(prompt)
        .validate_with(|input: &String| {
            if Path::new(input.trim()).is_file() {
                Ok(())
            } else {
                Err("no readable file at that path".to_string())
            }
        });
    if let Some(default) = default {
        input = input.default(default);
    }
    let answer = input.interact_text().map_err(prompt_failed)?;
    Ok(PathBuf::from(answer.trim()))
}

/// The default of each question: what the configuration holds (ADR-0019 clause 16), else what
/// lies beside the program (ADR-0020 clause 2). On a fresh host `current` is the loader's
/// defaults, so the endpoint and name are suggested, and the files and the key are where the
/// program found them.
#[derive(Debug, PartialEq, Eq)]
struct Defaults {
    endpoint: String,
    name: String,
    ca_file: Option<String>,
    cert_file: Option<String>,
    key_file: Option<String>,
    verification_key: Option<String>,
}

impl Defaults {
    fn of(current: &ClientConfig, beside: &Beside) -> Self {
        let tls = current.tls.as_ref();
        let path = |p: Option<&PathBuf>| p.map(|p| p.to_string_lossy().into_owned());
        let (beside_cert, beside_key) = match &beside.bootstrap {
            Some(BootstrapFiles::Pair { cert, key }) => (Some(cert), Some(key)),
            Some(BootstrapFiles::Pkcs12(file)) => (Some(file), None),
            None => (None, None),
        };
        Defaults {
            endpoint: current.endpoint.clone(),
            name: current.name.clone(),
            ca_file: path(tls.and_then(|t| t.ca_file.as_ref()))
                .or_else(|| path(beside.ca_file.as_ref())),
            cert_file: path(tls.and_then(|t| t.cert_file.as_ref())).or_else(|| path(beside_cert)),
            key_file: path(tls.and_then(|t| t.key_file.as_ref())).or_else(|| path(beside_key)),
            verification_key: current
                .packages
                .as_ref()
                .and_then(|p| p.verification_key.clone())
                .or_else(|| beside.verification_key.clone()),
        }
    }
}

/// Render the answers as `supervisor.toml`. Pure, so what lands on disk is testable without a tty.
///
/// Values go through `toml`'s own string encoder rather than into `"{}"`: a name may contain a
/// quote, and a Windows path is full of backslashes. The file has no `[auth]` section: the Client
/// sends no credential (ADR-0019 clause 17).
#[must_use]
pub fn render(answers: &Answers) -> String {
    let mut out = String::new();
    out.push_str(
        "# OpAMP Fleet Client configuration, written by\n\
         # `supervisor service install`. It is an ordinary file from here on:\n\
         # edit it by hand, and restart the service to apply.\n\n",
    );
    out.push_str(&format!("endpoint = {}\n", toml_string(&answers.endpoint)));
    out.push_str(&format!("name = {}\n", toml_string(&answers.name)));
    out.push_str(commented_top_level_keys());

    if let Some(ca) = &answers.ca_file {
        out.push_str(
            "\n# TLS toward the Server. ca_file *replaces* the built-in webpki roots. This\n\
             # Client's identity is the certificate the Server issued it, which the state\n\
             # directory holds; `supervisor service config` enrols a host that has none.\n[tls]\n",
        );
        out.push_str(&format!(
            "ca_file = {}\n",
            toml_string(&ca.to_string_lossy())
        ));
    }

    out.push_str(if answers.self_update {
        "\n# self_update: consent for the Server to replace this Client's own binary, with\n\
         # the package named after its Agent type alone. Write `false` to withdraw it.\n\
         # Every package, this Client's own included, is verified against\n\
         # verification_key; without the key nothing is installed.\n\
         [packages]\n\
         self_update = true\n"
    } else {
        "\n# The Server may NOT replace this Client's own binary. Written out because the\n\
         # consent otherwise stands by default: this Client is then the one program in the\n\
         # fleet that has to be updated by hand on this host. Every package is verified\n\
         # against verification_key; without the key nothing is installed.\n\
         [packages]\n\
         self_update = false\n"
    });
    match &answers.verification_key {
        Some(key) => out.push_str(&format!("verification_key = {}\n", toml_string(key))),
        None => out.push_str("# verification_key = \"<hex-encoded Ed25519 public key>\"\n"),
    }

    out.push_str(
        "\n# Machine-level attributes the Server's Selectors match on:\n\
         # [attributes]\n\
         # env = \"prod\"\n\
         \n\
         # Processes this Client manages are added by hand, one [[supervisor]] block\n\
         # each; see docs/manual/client.md for the blocks and what each key means.\n",
    );
    out
}

/// The top-level keys that are right on a fresh host, as comments — and they are emitted **before
/// the first table**, which is not cosmetic: a top-level key written after `[tls]` or
/// `[packages]` belongs to that table, so an operator who uncomments `poll_interval_secs` under
/// one would be setting a key the section does not have and the load would refuse the file. The
/// commented *tables* at the end of `render` are safe wherever they stand, being tables themselves.
fn commented_top_level_keys() -> &'static str {
    "\n# Not asked, because these are right on a fresh host. Uncomment to change:\n\
     # poll_interval_secs = 30          # plain-HTTP polling only; WebSocket is pushed\n\
     # heartbeat_interval_secs = 30     # 0 disables heartbeats\n\
     # max_message_size_bytes = 67108864\n\
     # state_dir = \"/absolute/path\"     # an absolute path here is what the service unit\n\
     #                                  # carries; otherwise the install root's state/ is used\n\
     # supervisor_dir = \"/opt/opamp-fleet/supervisors\"\n"
}

/// Create the file, never replacing one that is there, and never wider than its owner on Unix.
///
/// `create_new` is what makes "do not overwrite" a property of the syscall rather than of a check
/// that raced. The mode is set in the same call for the same reason: the file names where the
/// private key lies and may hold `[packages] archive_key` (ADR-0019 clause 18), before any later
/// `set_permissions` could narrow it.
///
/// # Errors
/// Returns an error if the parent cannot be created or the file already exists.
pub fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Whether TLS applies to this endpoint, and the Server's CA is therefore asked for.
#[must_use]
pub fn is_tls_endpoint(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    endpoint.starts_with("wss://") || endpoint.starts_with("https://")
}

/// Reuse the loader's own rule for what an endpoint may look like, so the questionnaire cannot
/// accept a value the next step rejects.
fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    ClientConfig {
        endpoint: endpoint.trim().to_string(),
        ..ClientConfig::default()
    }
    .transport()
    .map(|_| ())
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn prompt_failed(e: dialoguer::Error) -> String {
    format!("cannot read the answer: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The baseline: everything optional declined, except the self-update consent, which since
    /// ADR-0018 is what declining nothing means.
    fn answers() -> Answers {
        Answers {
            endpoint: "wss://fleet.example.com/v1/opamp".to_string(),
            name: "host-01".to_string(),
            ca_file: None,
            verification_key: None,
            self_update: true,
        }
    }

    /// What the questionnaire writes names no client identity — the bootstrap pair is enrolled
    /// with, not written — and the Client starts with it once the enrolment has put the issued
    /// certificate into the state directory, which an install does before it registers the
    /// service (ADR-0019 clauses 17, 19).
    /// Verifies: ADR-0019
    #[test]
    fn a_complete_answer_writes_a_file_the_client_starts_with() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let given = Answers {
            verification_key: Some(hex::encode([7u8; 32])),
            ..answers()
        };
        write_new(&path, &render(&given)).expect("write");
        let mut loaded = ClientConfig::load(&path).expect("the written file loads");
        assert!(loaded.tls.is_none(), "no identity and no CA was written");

        loaded.state_dir = dir.path().join("state");
        std::fs::create_dir_all(&loaded.state_dir).expect("state dir");
        for file in [crate::tls::ISSUED_CERT_FILE, crate::tls::ISSUED_KEY_FILE] {
            std::fs::write(loaded.state_dir.join(file), "issued").expect("write");
        }
        loaded
            .check_admission()
            .expect("the Client would start with it");
        assert_eq!(
            loaded.package_key(),
            Some(&[7u8; 32][..]),
            "the key as answered"
        );
    }

    /// The questionnaire suggests the loader's default, and that default is one its own endpoint
    /// rule accepts: TLS, to the loopback literal — never a plaintext or a host-name answer.
    /// Verifies: ADR-0019
    #[test]
    fn the_suggested_endpoint_is_tls_on_the_loopback() {
        let suggested = ClientConfig::default().endpoint;
        assert_eq!(suggested, "wss://127.0.0.1:4320/v1/opamp");
        assert!(is_tls_endpoint(&suggested));
        validate_endpoint(&suggested).expect("the suggestion passes the questionnaire's rule");
    }

    /// A packaged install has an endpoint and no terminal: the file it writes carries no identity,
    /// fails the validation the Client applies at startup, and stays on disk to be completed rather
    /// than answered again (ADR-0019).
    /// Verifies: ADR-0019
    #[test]
    fn installer_answers_alone_fail_validation_and_stay_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        run_with_endpoint(
            &path,
            "wss://fleet.example.com/v1/opamp",
            false,
            &Beside::default(),
        )
        .expect("write");
        let loaded = ClientConfig::load(&path).expect("it parses");
        let err = loaded.check_admission().expect_err("no identity");
        assert!(err.contains("cert_file and key_file"), "{err}");
        assert!(path.exists(), "left on disk to be completed");
    }

    /// The endpoint rule is the startup rule: plaintext only to a loopback literal, and the name
    /// `localhost` is not one (ADR-0019).
    /// Verifies: ADR-0019
    #[test]
    fn a_plaintext_endpoint_is_accepted_only_on_a_loopback_literal() {
        let dir = tempfile::tempdir().expect("tempdir");
        for refused in [
            "ws://fleet.example.com/v1/opamp",
            "http://localhost:4320/v1/opamp",
        ] {
            let path = dir.path().join(format!("{}.toml", refused.len()));
            let err =
                run_with_endpoint(&path, refused, false, &Beside::default()).expect_err(refused);
            assert!(err.starts_with("endpoint"), "the setting is named: {err}");
            assert!(!path.exists(), "nothing written for {refused}");
        }
        let path = dir.path().join("loopback.toml");
        run_with_endpoint(
            &path,
            "ws://127.0.0.1:4320/v1/opamp",
            false,
            &Beside::default(),
        )
        .expect("loopback literal");
    }

    /// The point of the whole exercise: what the questionnaire writes must load, and must load as
    /// the answers that were given.
    /// Verifies: ADR-0019
    #[test]
    fn the_rendered_file_loads_as_what_was_answered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let given = Answers {
            ca_file: Some(PathBuf::from("/etc/ssl/private-ca.pem")),
            verification_key: Some(hex::encode([7u8; 32])),
            ..answers()
        };
        write_new(&path, &render(&given)).expect("write");

        let loaded = ClientConfig::load(&path).expect("the written file loads");
        assert_eq!(loaded.endpoint, given.endpoint);
        assert_eq!(loaded.name, given.name);
        assert_eq!(loaded.package_key(), Some(&[7u8; 32][..]));
        assert_eq!(loaded.self_update_package(), Some("supervisor"));
        assert_eq!(
            loaded.tls.expect("tls").ca_file,
            Some(PathBuf::from("/etc/ssl/private-ca.pem"))
        );
    }

    /// No answer puts an `[auth]` section in the file: the questionnaire asks for no credential,
    /// and the Client sends none (ADR-0019 clause 17).
    /// Verifies: ADR-0019
    #[test]
    fn a_rendered_file_has_no_auth_section() {
        let given = Answers {
            ca_file: Some(PathBuf::from("/etc/ssl/private-ca.pem")),
            verification_key: Some(hex::encode([7u8; 32])),
            ..answers()
        };
        for rendered in [
            render(&given),
            render(&answers()),
            render(&Answers {
                self_update: false,
                ..given.clone()
            }),
        ] {
            assert!(!rendered.contains("[auth]"), "{rendered}");
            for key in ["bearer_token", "username", "password"] {
                assert!(!rendered.contains(key), "{key} in {rendered}");
            }
        }
    }

    /// ADR-0019 clause 42: the packaged path has to produce a file the loader accepts, carrying the
    /// endpoint that was given — the same guarantee the questionnaire has, without a terminal.
    /// Verifies: ADR-0019
    #[test]
    fn an_endpoint_given_is_written_and_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);

        run_with_endpoint(
            &path,
            "wss://fleet.example.com/v1/opamp",
            true,
            &Beside::default(),
        )
        .expect("write");

        let loaded = ClientConfig::load(&path).expect("the written file loads");
        assert_eq!(loaded.endpoint, "wss://fleet.example.com/v1/opamp");
        // The self-update consent the installer passed is written, standing by default (ADR-0018).
        assert_eq!(loaded.self_update_package(), Some("supervisor"));
    }

    /// The withdrawal has a non-interactive twin too (`--no-self-update`, the MSI's cleared
    /// checkbox): it writes `[packages] self_update = false` rather than omitting the key, because
    /// an omitted key is the consent.
    /// Verifies: ADR-0018
    #[test]
    fn an_installer_can_withhold_the_self_update_consent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);

        run_with_endpoint(
            &path,
            "wss://fleet.example.com/v1/opamp",
            false,
            &Beside::default(),
        )
        .expect("write");

        let text = std::fs::read_to_string(&path).expect("read back");
        assert!(
            text.contains("\n[packages]\nself_update = false\n"),
            "{text}"
        );
        let loaded = ClientConfig::load(&path).expect("the written file loads");
        assert_eq!(loaded.self_update_package(), None);
    }

    /// The file is validated *before* it exists, not after. An install that wrote an unusable file
    /// and then failed to load it would leave the operator fixing a file they never typed.
    /// Verifies: ADR-0019
    #[test]
    fn a_bad_endpoint_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);

        let err = run_with_endpoint(&path, "fleet.example.com", false, &Beside::default())
            .expect_err("no scheme");
        assert!(!err.is_empty());
        assert!(!path.exists(), "nothing may be left behind");
    }

    /// ADR-0019 clause 16 holds on the packaged path too: a `.deb` reinstalled over a configured
    /// host must not eat what somebody answered into the first install, or edited since.
    /// Verifies: ADR-0019
    #[test]
    fn an_endpoint_given_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        write_new(&path, "endpoint = \"wss://kept/v1/opamp\"\n").expect("first write");

        run_with_endpoint(
            &path,
            "wss://fleet.example.com/v1/opamp",
            false,
            &Beside::default(),
        )
        .expect("kept, not an error");

        let loaded = ClientConfig::load(&path).expect("load");
        assert_eq!(loaded.endpoint, "wss://kept/v1/opamp");
    }

    /// An answer is not a well-behaved identifier. Rendering it into `"{}"` would produce a file
    /// that either fails to parse or parses as a different value.
    #[test]
    fn quotes_and_backslashes_in_an_answer_survive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let nasty = r#"a"b\c	d"#;
        let given = Answers {
            name: nasty.to_string(),
            ca_file: Some(PathBuf::from(r"C:\ProgramData\opamp\ca.pem")),
            ..answers()
        };
        write_new(&path, &render(&given)).expect("write");

        let loaded = ClientConfig::load(&path).expect("load");
        assert_eq!(loaded.name, nasty);
        assert_eq!(
            loaded.tls.expect("tls").ca_file,
            Some(PathBuf::from(r"C:\ProgramData\opamp\ca.pem"))
        );
    }

    /// A declined section is absent rather than empty — a bare `[tls]` would say nothing.
    /// `[packages]` is the one exception and it is the point of ADR-0018: an absent `self_update`
    /// *means* consent, so both answers are written out, `self_update = true` or `= false`, with the
    /// verification key or a commented line for it. A reader of the file can tell which it is.
    /// Verifies: ADR-0018
    #[test]
    fn declined_sections_are_absent_rather_than_empty_and_the_consent_is_always_written() {
        let rendered = render(&answers());
        assert!(!rendered.contains("\n[auth]"));
        assert!(!rendered.contains("\n[tls]"));
        assert!(
            rendered.contains("\n[packages]\nself_update = true\n"),
            "{rendered}"
        );
        assert!(!rendered.contains("\n[self_update]"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        write_new(&path, &rendered).expect("write");
        let loaded = ClientConfig::load(&path).expect("load");
        assert!(loaded.leftover_auth.is_none());
        assert!(loaded.tls.is_none());
        assert_eq!(loaded.self_update_package(), Some("supervisor"));

        // The other answer, spelled out rather than omitted.
        let withdrawn = render(&Answers {
            self_update: false,
            ..answers()
        });
        assert!(
            withdrawn.contains("\n[packages]\nself_update = false\n"),
            "{withdrawn}"
        );
        let path = dir.path().join("withdrawn.toml");
        write_new(&path, &withdrawn).expect("write");
        assert_eq!(
            ClientConfig::load(&path)
                .expect("load")
                .self_update_package(),
            None
        );
    }

    /// The commented tail must stay comments: an operator who never touches it has a file that
    /// still loads, and the keys named there must be spelled the way the loader knows them
    /// (`deny_unknown_fields` would catch a typo the moment they uncomment one).
    #[test]
    fn the_commented_tail_is_inert_and_uncommenting_it_works() {
        // Every table this file can carry, present at once. That is the combination the ordering
        // has to survive: a commented top-level key written *after* a table belongs to that table,
        // so uncommenting `poll_interval_secs` under `[tls]` or `[packages]` would set a key
        // those sections do not have and `deny_unknown_fields` would refuse the whole file. The
        // rendered order — scalars, commented scalars, then tables — is what keeps it inert.
        let given = Answers {
            ca_file: Some(PathBuf::from("/etc/ssl/private-ca.pem")),
            ..answers()
        };
        let rendered = render(&given);
        let uncommented: String = rendered
            .lines()
            .map(|line| match line.strip_prefix("# ") {
                // Only the key lines, not the prose: the prose is indented under a key or ends in
                // a full sentence, and none of it starts with a known key.
                Some(rest)
                    if rest.starts_with("poll_interval_secs")
                        || rest.starts_with("heartbeat_interval_secs")
                        || rest.starts_with("max_message_size_bytes") =>
                {
                    rest.split('#').next().unwrap_or(rest).trim().to_string()
                }
                _ => line.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let loaded: ClientConfig = toml::from_str(&uncommented).expect("the tail's keys are real");
        assert_eq!(loaded.poll_interval_secs, 30);
        assert_eq!(loaded.heartbeat_interval_secs, 30);
        assert_eq!(loaded.max_message_size_bytes, 67_108_864);
        // The keys landed at the top level, not inside whichever table happened to precede them.
        assert!(loaded.tls.is_some());
        assert_eq!(loaded.self_update_package(), Some("supervisor"));
    }

    /// The refusal that protects answers typed once (ADR-0019).
    /// Verifies: ADR-0019
    #[test]
    fn an_existing_file_is_never_overwritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        write_new(&path, "endpoint = \"ws://first/v1/opamp\"\n").expect("first write");

        let err = write_new(&path, "endpoint = \"ws://second/v1/opamp\"\n")
            .expect_err("the second write is refused");
        assert!(err.contains("cannot create"), "{err}");
        let kept = std::fs::read_to_string(&path).expect("read");
        assert!(kept.contains("first"), "the original survives: {kept}");
    }

    /// Without a terminal there is nobody to answer, and blocking a provisioning run forever is
    /// the failure mode this refuses (ADR-0019). Under `cargo test` stdin is not a tty, which is
    /// exactly the condition being asserted.
    /// Verifies: ADR-0019
    #[test]
    fn interactive_without_a_terminal_fails_instead_of_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let err = run(
            &path,
            &ClientConfig::default(),
            false,
            &Beside::default(),
            None,
        )
        .expect_err("no terminal, no questionnaire");
        assert!(err.contains("needs a terminal"), "{err}");
        assert!(!path.exists(), "nothing was written");
    }

    /// Verifies: ADR-0019
    #[test]
    fn the_file_is_not_readable_by_the_rest_of_the_machine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        write_new(&path, "endpoint = \"ws://x/v1/opamp\"\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a file naming the private key is the owner's alone"
            );
        }
    }

    const KEY_HEX: &str = "7752550dc567225658fcb0a91322f52497b26c2a65cfc4cff14145fcf8857d4b";

    /// A directory holding what the operator copies beside the program.
    fn fleet_files(dir: &Path) {
        for (name, content) in [
            (SERVER_CA_FILE, "ca"),
            (BOOTSTRAP_CERT_FILE, "cert"),
            (BOOTSTRAP_KEY_FILE, "key"),
            (VERIFICATION_KEY_FILE, &format!("{KEY_HEX}\n")[..]),
        ] {
            std::fs::write(dir.join(name), content).expect("write");
        }
    }

    /// The fleet's files are found by their exact names; half a bootstrap pair and a public key
    /// file that holds no key are said and not taken (ADR-0020 clause 1).
    /// Verifies: ADR-0020
    #[test]
    fn the_fleets_files_are_found_beside_the_program_by_their_names() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(Beside::in_dir(dir.path()), Beside::default());
        fleet_files(dir.path());
        let beside = Beside::in_dir(dir.path());
        assert_eq!(beside.ca_file, Some(dir.path().join(SERVER_CA_FILE)));
        assert_eq!(
            beside.bootstrap,
            Some(BootstrapFiles::Pair {
                cert: dir.path().join(BOOTSTRAP_CERT_FILE),
                key: dir.path().join(BOOTSTRAP_KEY_FILE),
            })
        );
        assert_eq!(beside.verification_key.as_deref(), Some(KEY_HEX));
        assert!(beside.warnings.is_empty(), "{:?}", beside.warnings);

        std::fs::remove_file(dir.path().join(BOOTSTRAP_KEY_FILE)).expect("remove");
        std::fs::write(dir.path().join(VERIFICATION_KEY_FILE), "not a key").expect("write");
        let beside = Beside::in_dir(dir.path());
        assert_eq!(beside.bootstrap, None, "half a pair is no pair");
        assert_eq!(beside.verification_key, None);
        assert_eq!(beside.warnings.len(), 2, "{:?}", beside.warnings);
    }

    /// Each default is what the file holds, else what lies beside the program (ADR-0020
    /// clause 2).
    /// Verifies: ADR-0020
    #[test]
    fn a_default_is_what_the_file_holds_else_what_lies_beside_the_program() {
        let dir = tempfile::tempdir().expect("tempdir");
        fleet_files(dir.path());
        let beside = Beside::in_dir(dir.path());
        let text = |name: &str| Some(dir.path().join(name).to_string_lossy().into_owned());

        let fresh = Defaults::of(&ClientConfig::default(), &beside);
        assert_eq!(fresh.ca_file, text(SERVER_CA_FILE));
        assert_eq!(fresh.cert_file, text(BOOTSTRAP_CERT_FILE));
        assert_eq!(fresh.key_file, text(BOOTSTRAP_KEY_FILE));
        assert_eq!(fresh.verification_key.as_deref(), Some(KEY_HEX));

        let held = ClientConfig {
            tls: Some(crate::config::TlsConfig {
                ca_file: Some(PathBuf::from("/held/ca.pem")),
                cert_file: None,
                key_file: None,
            }),
            ..ClientConfig::default()
        };
        let edited = Defaults::of(&held, &beside);
        assert_eq!(
            edited.ca_file.as_deref(),
            Some("/held/ca.pem"),
            "the file wins"
        );
        assert_eq!(edited.cert_file, text(BOOTSTRAP_CERT_FILE));
    }

    /// `--endpoint` writes the CA and the verification key it finds beside the program, the CA as
    /// a copy beside the file; a loopback `ws://` takes neither, and a file that exists is kept
    /// (ADR-0020 clause 3).
    /// Verifies: ADR-0020
    #[test]
    fn an_endpoint_install_takes_the_ca_and_the_key_beside_the_program() {
        let program = tempfile::tempdir().expect("tempdir");
        fleet_files(program.path());
        let beside = Beside::in_dir(program.path());
        let data = tempfile::tempdir().expect("tempdir");
        let path = data.path().join(FILE_NAME);

        let copies = run_with_endpoint(&path, "wss://fleet.example.com/v1/opamp", true, &beside)
            .expect("write");
        let copy = data.path().join(SERVER_CA_FILE);
        assert_eq!(copies, vec![copy.clone()]);
        let loaded = ClientConfig::load(&path).expect("loads");
        assert_eq!(
            loaded.tls.expect("tls").ca_file.as_deref(),
            Some(copy.as_path())
        );
        assert_eq!(
            loaded.packages.and_then(|p| p.verification_key).as_deref(),
            Some(KEY_HEX)
        );
        assert!(
            !data.path().join(BOOTSTRAP_CERT_FILE).exists(),
            "the bootstrap pair is not copied"
        );

        let before = std::fs::read(&path).expect("read");
        assert!(
            run_with_endpoint(&path, "wss://other.example.com/v1/opamp", true, &beside)
                .expect("kept")
                .is_empty()
        );
        assert_eq!(std::fs::read(&path).expect("read"), before);

        let loopback = tempfile::tempdir().expect("tempdir");
        let path = loopback.path().join(FILE_NAME);
        let copies =
            run_with_endpoint(&path, "ws://127.0.0.1:4320/v1/opamp", true, &beside).expect("write");
        assert!(copies.is_empty());
        let loaded = ClientConfig::load(&path).expect("loads");
        assert!(loaded.tls.and_then(|t| t.ca_file).is_none());
        assert!(loaded.packages.and_then(|p| p.verification_key).is_none());
    }

    /// Unasked, the pair beside the program enrols a Client over TLS that holds no issued
    /// certificate, and only such a one (ADR-0020 clause 4).
    /// Verifies: ADR-0020
    #[test]
    fn an_unasked_install_enrols_with_the_pair_beside_the_program_until_enrolled() {
        let program = tempfile::tempdir().expect("tempdir");
        fleet_files(program.path());
        let beside = Beside::in_dir(program.path());
        let state = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            endpoint: "wss://fleet.example.com/v1/opamp".to_string(),
            state_dir: state.path().to_path_buf(),
            ..ClientConfig::default()
        };
        assert_eq!(
            beside.unasked_enrolment(&config, None),
            Ok(Some(Bootstrap::Pair {
                cert: program.path().join(BOOTSTRAP_CERT_FILE),
                key: program.path().join(BOOTSTRAP_KEY_FILE),
            }))
        );

        let loopback = ClientConfig {
            endpoint: "ws://127.0.0.1:4320/v1/opamp".to_string(),
            ..config.clone()
        };
        assert_eq!(beside.unasked_enrolment(&loopback, None), Ok(None));

        for name in [crate::tls::ISSUED_CERT_FILE, crate::tls::ISSUED_KEY_FILE] {
            std::fs::write(state.path().join(name), "issued").expect("write");
        }
        assert_eq!(
            beside.unasked_enrolment(&config, None),
            Ok(None),
            "enrolled already"
        );
        assert_eq!(
            Beside::default().unasked_enrolment(&ClientConfig::default(), None),
            Ok(None)
        );
    }

    const P12_PASSWORD: &str = "a password of the operator";

    /// A `bootstrap.p12` sealed as the Server seals one, with the PEM of its certificate.
    fn p12_in(dir: &Path) -> String {
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["bootstrap".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        let file = fleet_core::pkcs12::file::seal(cert.der(), &key.serialize_der(), P12_PASSWORD)
            .expect("sealed");
        std::fs::write(dir.join(BOOTSTRAP_P12_FILE), file).expect("write");
        cert.pem()
    }

    /// A `bootstrap.p12` is found as a bootstrap identity; lying beside a file of the pair,
    /// neither is taken; `--fleet-files` names a directory that must be one (ADR-0029 clause 6).
    /// Verifies: ADR-0029
    #[test]
    fn a_bootstrap_p12_is_found_alone_and_never_beside_the_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        p12_in(dir.path());
        let beside = Beside::in_named_dir(dir.path()).expect("a directory");
        assert_eq!(
            beside.bootstrap,
            Some(BootstrapFiles::Pkcs12(dir.path().join(BOOTSTRAP_P12_FILE)))
        );
        assert!(beside.warnings.is_empty(), "{:?}", beside.warnings);
        let defaults = Defaults::of(&ClientConfig::default(), &beside);
        assert_eq!(
            defaults.cert_file,
            Some(
                dir.path()
                    .join(BOOTSTRAP_P12_FILE)
                    .to_string_lossy()
                    .into_owned()
            ),
            "offered as the certificate's default"
        );
        assert_eq!(defaults.key_file, None);

        std::fs::write(dir.path().join(BOOTSTRAP_KEY_FILE), "key").expect("write");
        let both = Beside::in_dir(dir.path());
        assert_eq!(both.bootstrap, None, "the install never guesses");
        assert!(
            both.warnings.iter().any(|w| w.contains(BOOTSTRAP_P12_FILE)),
            "{:?}",
            both.warnings
        );

        // `--endpoint` takes the CA from the directory named, as it would from beside the program.
        std::fs::write(dir.path().join(SERVER_CA_FILE), "ca").expect("write");
        let named = Beside::in_named_dir(dir.path()).expect("a directory");
        let data = tempfile::tempdir().expect("tempdir");
        let copies = run_with_endpoint(
            &data.path().join(FILE_NAME),
            "wss://fleet.example.com/v1/opamp",
            true,
            &named,
        )
        .expect("write");
        assert_eq!(copies, vec![data.path().join(SERVER_CA_FILE)]);

        let missing = dir.path().join("no such directory");
        let refused = Beside::in_named_dir(&missing).expect_err("refused");
        assert!(refused.contains("--fleet-files"), "{refused}");
        let a_file = dir.path().join(BOOTSTRAP_KEY_FILE);
        assert!(
            Beside::in_named_dir(&a_file).is_err(),
            "a file is no directory"
        );
    }

    /// Unasked, a `bootstrap.p12` enrols with the password `--bootstrap-password-file` gives, and
    /// fails the install without it, under a password that does not open it, or when the flag has
    /// no file to open (ADR-0029 clause 10).
    /// Verifies: ADR-0029
    #[test]
    fn an_unasked_install_opens_a_bootstrap_p12_with_the_password_file_or_fails() {
        let program = tempfile::tempdir().expect("tempdir");
        let cert_pem = p12_in(program.path());
        let beside = Beside::in_dir(program.path());
        let state = tempfile::tempdir().expect("tempdir");
        let config = ClientConfig {
            endpoint: "wss://fleet.example.com/v1/opamp".to_string(),
            state_dir: state.path().to_path_buf(),
            ..ClientConfig::default()
        };
        let without = beside
            .unasked_enrolment(&config, None)
            .expect_err("no password");
        assert!(without.contains("--bootstrap-password-file"), "{without}");
        let wrong = beside
            .unasked_enrolment(&config, Some("not the password"))
            .expect_err("wrong password");
        assert!(wrong.contains("--bootstrap-password-file"), "{wrong}");
        match beside.unasked_enrolment(&config, Some(P12_PASSWORD)) {
            Ok(Some(Bootstrap::Pkcs12 { file, identity })) => {
                assert_eq!(file, program.path().join(BOOTSTRAP_P12_FILE));
                assert_eq!(
                    identity.cert_pem,
                    cert_pem.replace("\r\n", "\n").into_bytes()
                );
                opamp::tls::private_key(&identity.key_pem).expect("a key");
            }
            other => panic!("expected the opened file, got {other:?}"),
        }

        let pair_only = tempfile::tempdir().expect("tempdir");
        fleet_files(pair_only.path());
        let refused = Beside::in_dir(pair_only.path())
            .unasked_enrolment(&config, Some(P12_PASSWORD))
            .expect_err("no file to open");
        assert!(refused.contains("--bootstrap-password-file"), "{refused}");

        for name in [crate::tls::ISSUED_CERT_FILE, crate::tls::ISSUED_KEY_FILE] {
            std::fs::write(state.path().join(name), "issued").expect("write");
        }
        assert_eq!(
            beside.unasked_enrolment(&config, None),
            Ok(None),
            "an enrolled Client takes no bootstrap identity, and needs no password"
        );
    }

    /// The password is the file's first line without its line ending; an empty one is refused
    /// (ADR-0029 clause 10). `.p12` and `.pfx` are read as PKCS#12 (clause 8).
    /// Verifies: ADR-0029
    #[test]
    fn a_password_file_gives_its_first_line_and_a_p12_path_is_known_by_its_extension() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("bootstrap.pass");
        for (content, expected) in [
            ("secret password\n", "secret password"),
            ("secret password\r\nsecond line\n", "secret password"),
            ("secret password", "secret password"),
        ] {
            std::fs::write(&file, content).expect("write");
            assert_eq!(
                read_password_file(&file, "--bootstrap-password-file").as_deref(),
                Ok(expected)
            );
        }
        std::fs::write(&file, "\nsecret").expect("write");
        assert!(
            read_password_file(&file, "--bootstrap-password-file").is_err(),
            "an empty first line"
        );
        assert!(read_password_file(&dir.path().join("none"), "--bootstrap-password-file").is_err());

        for (path, p12) in [
            ("bootstrap.p12", true),
            ("/x/BOOTSTRAP.PFX", true),
            ("bootstrap.pem", false),
            ("p12", false),
        ] {
            assert_eq!(is_pkcs12_path(Path::new(path)), p12, "{path}");
        }
    }

    /// The answered CA lands beside the configuration under a fixed name, owner-only, and the
    /// rendered file names the copy — so it loads with the original gone.
    /// Verifies: ADR-0019
    #[test]
    fn the_answered_ca_is_copied_beside_the_configuration() {
        let from = tempfile::tempdir().expect("tempdir");
        let to = tempfile::tempdir().expect("tempdir");
        let ca = from.path().join("my-ca.pem");
        std::fs::write(&ca, "ca").expect("write");
        let path = to.path().join(FILE_NAME);
        let (copied, copies) = copy_ca_beside(
            Answers {
                ca_file: Some(ca),
                ..answers()
            },
            &path,
        )
        .expect("copy");

        let expected = to.path().join(SERVER_CA_FILE);
        assert_eq!(copies, vec![expected.clone()]);
        assert_eq!(std::fs::read_to_string(&expected).expect("read"), "ca");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&expected)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        drop(from);
        write_new(&path, &render(&copied)).expect("write");
        let loaded = ClientConfig::load(&path).expect("the written file loads");
        assert_eq!(
            loaded.tls.expect("tls").ca_file.as_deref(),
            Some(expected.as_path())
        );
        assert_eq!(
            std::fs::read_dir(to.path()).expect("list").count(),
            2,
            "the configuration and the CA, nothing else"
        );
    }

    /// The default an edit offers for the CA is the copy itself: answering it reads the file
    /// before the copy is written, so it is kept rather than truncated. A copy left by an earlier
    /// answer is replaced by a new one.
    /// Verifies: ADR-0019
    #[test]
    fn a_copy_onto_itself_keeps_the_file_and_an_old_copy_is_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let copy = dir.path().join(SERVER_CA_FILE);
        std::fs::write(&copy, "ca").expect("write");

        copy_ca_beside(
            Answers {
                ca_file: Some(copy.clone()),
                ..answers()
            },
            &path,
        )
        .expect("copy onto itself");
        assert_eq!(std::fs::read_to_string(&copy).expect("read"), "ca");

        let elsewhere = dir.path().join("new-ca.pem");
        std::fs::write(&elsewhere, "new ca").expect("write");
        copy_ca_beside(
            Answers {
                ca_file: Some(elsewhere),
                ..answers()
            },
            &path,
        )
        .expect("copy");
        assert_eq!(std::fs::read_to_string(&copy).expect("read"), "new ca");
    }

    /// An edit changes the keys the questionnaire asked about and nothing else: the operator's
    /// comments, a `[[supervisor]]` block, the self-update consent and a key not asked about stay
    /// byte for byte (ADR-0019 clause 16).
    /// Verifies: ADR-0019
    #[test]
    fn an_edit_changes_the_asked_keys_and_keeps_the_rest() {
        let before = "# my notes\n\
                      endpoint = \"wss://old.example/v1/opamp\"\n\
                      name = \"old\"\n\
                      heartbeat_interval_secs = 15 # tuned\n\
                      \n\
                      [tls]\n\
                      cert_file = \"/etc/boot.pem\"\n\
                      key_file = \"/etc/boot-key.pem\"\n\
                      \n\
                      [packages]\n\
                      self_update = false\n\
                      verification_key = \"aa\"\n\
                      \n\
                      [[supervisor]]\n\
                      name = \"collector\"\n\
                      kind = \"opentelemetry-collector\"\n";
        let after = edit(
            before,
            &Answers {
                endpoint: "wss://new.example/v1/opamp".to_string(),
                name: "new".to_string(),
                ca_file: Some(PathBuf::from("/data/server-ca.pem")),
                verification_key: None,
                self_update: true,
            },
        )
        .expect("edit");

        for kept in [
            "# my notes\n",
            "heartbeat_interval_secs = 15 # tuned\n",
            "cert_file = \"/etc/boot.pem\"\n",
            "self_update = false\n",
            "[[supervisor]]\nname = \"collector\"\nkind = \"opentelemetry-collector\"\n",
        ] {
            assert!(after.contains(kept), "{kept:?} lost from:\n{after}");
        }
        let doc: toml::Table = toml::from_str(&after).expect("still TOML");
        assert_eq!(doc["endpoint"].as_str(), Some("wss://new.example/v1/opamp"));
        assert_eq!(doc["name"].as_str(), Some("new"));
        assert_eq!(doc["tls"]["ca_file"].as_str(), Some("/data/server-ca.pem"));
        assert!(
            doc["packages"].get("verification_key").is_none(),
            "a removed key is removed"
        );
        assert_eq!(
            doc["packages"]["self_update"].as_bool(),
            Some(false),
            "the consent the file states is not the questionnaire's to change"
        );
    }

    /// An edit of a file that has no `[tls]` or `[packages]` yet adds them as tables, and the
    /// file still loads — the top-level keys stay top-level.
    /// Verifies: ADR-0019
    #[test]
    fn an_edit_adds_what_the_file_did_not_have_and_it_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(FILE_NAME);
        let given = Answers {
            ca_file: Some(PathBuf::from("/data/server-ca.pem")),
            verification_key: Some(hex::encode([7u8; 32])),
            ..answers()
        };
        let edited = edit("[logging]\nenabled = true\n", &given).expect("edit");
        write_new(&path, &edited).expect("write");
        let loaded = ClientConfig::load(&path).expect("the edited file loads");
        assert_eq!(loaded.endpoint, given.endpoint);
        assert_eq!(loaded.name, given.name);
        assert_eq!(loaded.package_key(), Some(&[7u8; 32][..]));
        assert_eq!(
            loaded.tls.expect("tls").ca_file,
            Some(PathBuf::from("/data/server-ca.pem"))
        );
    }

    /// Every question offers what the file holds; a fresh host gets the loader's defaults, which
    /// suggest an endpoint and a name and no file or key (ADR-0019 clause 16).
    /// Verifies: ADR-0019
    #[test]
    fn the_defaults_are_what_the_file_holds() {
        let fresh = Defaults::of(&ClientConfig::default(), &Beside::default());
        assert_eq!(fresh.endpoint, ClientConfig::default().endpoint);
        assert_eq!(
            (
                fresh.ca_file,
                fresh.cert_file,
                fresh.key_file,
                fresh.verification_key
            ),
            (None, None, None, None)
        );

        let held: ClientConfig = toml::from_str(
            "endpoint = \"wss://fleet.example/v1/opamp\"\n\
             name = \"web-01\"\n\
             [tls]\n\
             ca_file = \"/d/server-ca.pem\"\n\
             cert_file = \"/d/boot.pem\"\n\
             key_file = \"/d/boot-key.pem\"\n\
             [packages]\n\
             verification_key = \"abcd\"\n",
        )
        .expect("config");
        assert_eq!(
            Defaults::of(&held, &Beside::default()),
            Defaults {
                endpoint: "wss://fleet.example/v1/opamp".to_string(),
                name: "web-01".to_string(),
                ca_file: Some("/d/server-ca.pem".to_string()),
                cert_file: Some("/d/boot.pem".to_string()),
                key_file: Some("/d/boot-key.pem".to_string()),
                verification_key: Some("abcd".to_string()),
            }
        );
    }

    /// The bootstrap pair is asked for while the state directory holds no issued certificate, and
    /// not after — a bootstrap certificate the file names does not count as enrolled, the issued
    /// pair alone does (ADR-0019 clause 17). `ask` reads exactly this predicate.
    /// Verifies: ADR-0019
    #[test]
    fn the_bootstrap_pair_is_asked_only_before_enrolment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config: ClientConfig =
            toml::from_str("[tls]\ncert_file = \"/d/boot.pem\"\nkey_file = \"/d/boot-key.pem\"\n")
                .expect("config");
        config.state_dir = dir.path().to_path_buf();
        assert!(!config.is_enrolled(), "a bootstrap pair is no membership");

        std::fs::write(dir.path().join(crate::tls::ISSUED_CERT_FILE), "c").expect("write");
        assert!(
            !config.is_enrolled(),
            "a certificate without its key is not one"
        );

        std::fs::write(dir.path().join(crate::tls::ISSUED_KEY_FILE), "k").expect("write");
        assert!(config.is_enrolled());
    }

    /// Verifies: ADR-0019
    #[test]
    fn an_endpoint_is_validated_by_the_loaders_own_rule() {
        assert!(validate_endpoint("wss://fleet.example.com/v1/opamp").is_ok());
        assert!(validate_endpoint("  http://127.0.0.1:4320/v1/opamp  ").is_ok());
        let err = validate_endpoint("fleet.example.com").expect_err("no scheme");
        assert!(err.contains("must start with"), "{err}");
    }

    /// Verifies: ADR-0019
    #[test]
    fn the_server_ca_is_asked_for_where_tls_applies() {
        assert!(is_tls_endpoint("wss://x/v1/opamp"));
        assert!(is_tls_endpoint("https://x/v1/opamp"));
        assert!(!is_tls_endpoint("ws://x/v1/opamp"));
        assert!(!is_tls_endpoint("http://x/v1/opamp"));
    }
}
