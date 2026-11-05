//! The command-line surface (ADR-0019).
//!
//! A `clap` subcommand CLI that stays deliberately thin: it only parses arguments and hands off.
//! A bare invocation with no subcommand defaults to `run`, so `supervisor --config <path>` keeps
//! working unchanged. The Client is file-configured (ADR-0010) — there are no environment
//! fallbacks; the flags only say where the file and the state directory are.
//!
//! There is no `--instance` (ADR-0019 clause 6). One build installs one service under the
//! product's name, so the service verbs have nothing to look up and take no name at all; a second
//! installation is a second build. The *grammar* that flag used survives as
//! [`parse_instance_name`], because `[[supervisor]]` block names still need it.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::parser::ValueSource;
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};

/// The OpAMP Fleet Client command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "supervisor",
    // The git-derived version baked in at build time (ADR-0012) — never clap's default, which
    // would silently report the static crate version.
    version = fleet_core::version::current(),
    about = "OpAMP Fleet Client — runs standalone or as a native OS service"
)]
pub struct Cli {
    // ADR-0010: the file is the whole configuration; the flag only says where it is.
    /// Path to the TOML configuration file; defaults apply if it does not exist.
    #[arg(long, global = true, default_value = "supervisor.toml")]
    pub config: PathBuf,
    /// Overrides the configuration file's state directory. `service install` bakes this into the
    /// unit so an installed service never depends on a relative path, and every later install
    /// keeps the one the unit names unless this flag names another (ADR-0053). It is how an
    /// operator names a state directory outside the data root and the layout root: one the file
    /// names there is refused.
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,
    /// The subcommand to run. Absent means `run` (foreground daemon).
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// A parsed command line, plus the one thing the parsed struct cannot say: whether `--config`
/// carries a path the operator named or the default that stands in for one (ADR-0019).
///
/// The distinction is load-bearing exactly once. `service install` bakes an absolute config path
/// into the service unit, and when nobody named a path, the right one is not the default resolved
/// against a working directory the service manager will not have — it is the data root, which is
/// derived per platform and scope.
#[derive(Debug)]
pub struct Parsed {
    /// The command line as declared.
    pub cli: Cli,
    /// `true` when `--config` appeared on the command line, at any level.
    pub config_named: bool,
}

/// Parse the process arguments, exiting with clap's own message and exit code on a bad one.
#[must_use]
pub fn parse() -> Parsed {
    match parse_from(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(e) => e.exit(),
    }
}

/// Parse an explicit argument list — what [`parse`] does, minus the exit, so tests can reach it.
///
/// # Errors
/// Returns clap's error for an argument list it refuses (including `--help` and `--version`,
/// which clap reports the same way).
pub fn parse_from<I, T>(args: I) -> Result<Parsed, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = Cli::command().try_get_matches_from(args)?;
    let config_named = config_named(&matches);
    let cli = Cli::from_arg_matches(&matches)?;
    // Clap sees a conflict only on the level a flag was written on; a global one written before
    // `run` is caught here.
    if let Some(Command::Run(run)) = &cli.command {
        if run.agents.is_some() && (config_named || cli.state_dir.is_some()) {
            return Err(Cli::command().error(
                clap::error::ErrorKind::ArgumentConflict,
                "--agents runs the second service, which reads neither --config nor --state-dir",
            ));
        }
    }
    Ok(Parsed { cli, config_named })
}

/// Whether `--config` was given on the command line. A global argument may be parsed at the level
/// it was written on, so both `client --config x service install` and
/// `client service install --config x` have to count — hence the walk down the subcommands.
fn config_named(matches: &ArgMatches) -> bool {
    if matches.value_source("config") == Some(ValueSource::CommandLine) {
        return true;
    }
    matches
        .subcommand()
        .is_some_and(|(_, sub)| config_named(sub))
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the Client in the foreground (the default when no subcommand is given).
    Run(RunArgs),
    /// Install, control, or remove this Client instance as a native OS service.
    Service {
        /// The service lifecycle action to perform.
        #[command(subcommand)]
        action: ServiceAction,
    },
    // ADR-0018.
    /// Prove that this executable is an OpAMP Fleet Client and say which version.
    ///
    /// Run as a child process on a freshly staged binary before the `current` pointer moves to
    /// it. Two things are being asked at once: *does it run at all* on this host — the failure
    /// class no post-restart mechanism can catch, because a binary that cannot exec never gets
    /// far enough to notice anything — and *is it this program*, since a package offered under
    /// the configured name is still only a name until something answers for it. Hidden, because
    /// it is a machine-to-machine handshake and not an operator command.
    #[command(hide = true)]
    SelfCheck,
}

/// Arguments for `run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Set by `service install` on every platform. On Windows it routes into the SCM dispatcher;
    /// everywhere it says the machine's service manager started this process and no terminal is
    /// watching, which is what turns on the log file (ADR-0019).
    #[arg(long, hide = true)]
    pub service: bool,
    /// Run as the second service instead of the Client (ADR-0059): listen on this socket and
    /// start, signal and stop programs for the Client alone. Hidden, because the registration
    /// writes it and no operator types it.
    /// It reads neither the configuration nor the state directory and is no Client, so the flags
    /// that would say otherwise are refused alongside it rather than ignored. On Windows it is a
    /// named pipe, and the service always runs under the SCM.
    #[cfg_attr(
        unix,
        arg(
            long,
            hide = true,
            value_name = "SOCKET",
            requires = "client_uid",
            conflicts_with_all = ["service", "config", "state_dir"]
        )
    )]
    #[cfg_attr(
        windows,
        arg(
            long,
            hide = true,
            value_name = "PIPE",
            requires = "client_sid",
            conflicts_with_all = ["service", "config", "state_dir"]
        )
    )]
    pub agents: Option<PathBuf>,
    /// The uid of the Client's account, the one peer the second service serves (ADR-0059
    /// clause 4). Never root's (ADR-0059 clause 1); the service refuses its own as well.
    #[cfg(unix)]
    #[arg(
        long,
        hide = true,
        value_name = "UID",
        requires = "agents",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub client_uid: Option<u32>,
    /// The SID of the Client's account, the one client the second service serves on Windows
    /// (ADR-0059 clause 4). The service refuses `LocalSystem` and its own.
    #[cfg(windows)]
    #[arg(
        long,
        hide = true,
        value_name = "SID",
        requires = "agents",
        value_parser = parse_sid
    )]
    pub client_sid: Option<crate::win32::Sid>,
    /// The second service's socket, through which the Client starts every Managed Process
    /// (ADR-0059 clause 3). Hidden: `service install --process-account` writes it into the
    /// Client's unit, and it is how the running Client learns that a process account is
    /// registered. On Windows it is the second service's named pipe.
    #[cfg_attr(
        unix,
        arg(
            long,
            hide = true,
            value_name = "SOCKET",
            requires = "process_uid",
            conflicts_with = "agents"
        )
    )]
    #[cfg_attr(
        windows,
        arg(
            long,
            hide = true,
            value_name = "PIPE",
            requires = "process_sid",
            conflicts_with = "agents"
        )
    )]
    pub agents_socket: Option<PathBuf>,
    /// The uid of the process account, the one the Client accepts as the socket's peer (ADR-0059
    /// clause 4). Never root's.
    #[cfg(unix)]
    #[arg(
        long,
        hide = true,
        value_name = "UID",
        requires = "agents_socket",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub process_uid: Option<u32>,
    /// The SID of the process account, the one the Client accepts as the owner of the second
    /// service's pipe on Windows (ADR-0059 clause 4).
    #[cfg(windows)]
    #[arg(
        long,
        hide = true,
        value_name = "SID",
        requires = "agents_socket",
        value_parser = parse_sid
    )]
    pub process_sid: Option<crate::win32::Sid>,
}

impl RunArgs {
    /// `--agents` and the Client's account it serves: the second service, where this run is it.
    #[must_use]
    pub fn agents_service(&self) -> Option<(PathBuf, crate::supervisor::channel::Account)> {
        #[cfg(unix)]
        let client = self.client_uid;
        #[cfg(windows)]
        let client = self.client_sid.clone();
        self.agents.clone().zip(client)
    }

    /// `--agents-socket` and the process account that serves it: the second service every Managed
    /// Process of this Client is started through, where one is registered.
    #[must_use]
    pub fn agents_channel(&self) -> Option<(PathBuf, crate::supervisor::channel::Account)> {
        #[cfg(unix)]
        let process = self.process_uid;
        #[cfg(windows)]
        let process = self.process_sid.clone();
        self.agents_socket.clone().zip(process)
    }
}

/// A SID on the command line, written as the system writes it.
#[cfg(any(windows, test))]
fn parse_sid(text: &str) -> Result<crate::win32::Sid, String> {
    crate::win32::Sid::parse(text)
}

/// Service-lifecycle actions (`service install|config|uninstall|start|stop|status`).
#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    // ADR-0019 decides the layout this lays out.
    /// Register this instance as a system (or `--user`) service and lay out the versioned
    /// install.
    Install(InstallArgs),
    // ADR-0019 clauses 15–17.
    /// Ask the questionnaire of `install --interactive` again, offering what the configuration
    /// holds as the defaults, and enrol with the Server if this Client holds no certificate yet.
    ///
    /// Registers nothing. Restart the service afterwards to apply what changed.
    Config(ConfigArgs),
    /// Deregister the service (the install layout and state are never deleted).
    Uninstall(ScopeArgs),
    /// Start the installed service.
    Start(ScopeArgs),
    /// Stop the installed service.
    Stop(ScopeArgs),
    /// Report whether the service is installed and running.
    Status(ScopeArgs),
}

/// Arguments for `service install`.
#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// System or `--user` scope.
    #[command(flatten)]
    pub scope: ScopeArgs,
    /// The layout root, holding `versions/` and the `current` pointer. Defaults to
    /// `<base>/<PRODUCT_NAME>` for the scope — no path is ever fixed (ADR-0019 clause 7).
    ///
    /// Given **alone** it collapses layout and data into the one directory it names, exactly as
    /// ADR-0019 defined it, and the labeling and permissions of that directory are then yours to
    /// manage.
    #[arg(long)]
    pub root: Option<PathBuf>,
    // ADR-0019 clause 8.
    /// The data root, holding `supervisor.toml` and the state directory — everything a reinstall
    /// cannot recreate.
    ///
    /// It exists because Linux at system scope must not execute from `/var/lib`: the layout goes
    /// to `/opt/<PRODUCT_NAME>` and the data stays behind. Naming it beside `--root` is how an
    /// operator keeps the two halves apart anywhere else. Left alone, it follows `--root` when
    /// that is given and the platform default otherwise.
    #[arg(long)]
    pub data_root: Option<PathBuf>,
    // ADR-0019.
    /// Ask for the settings a fresh host cannot guess, write the configuration file, and enrol
    /// this host with the Server if it holds no certificate yet, before registering the service.
    ///
    /// Off by default, because `install` is the command a provisioning run invokes and it must
    /// never block on a question. An existing file is edited in place, each question offering what
    /// it holds. With no terminal on stdin this fails rather than waiting for an answer that cannot
    /// come.
    #[arg(long)]
    pub interactive: bool,
    // ADR-0019.
    /// Write the configuration file with this Server endpoint instead of asking for it.
    ///
    /// The non-interactive half of `--interactive`, for an install driven by a packaged installer:
    /// the MSI's endpoint dialog and a `.deb`/`.rpm` post-install both have an answer and no
    /// terminal. An existing file is kept, never overwritten.
    ///
    /// Only the endpoint. The client identity comes from an enrolment, with the bootstrap identity
    /// beside the program or in `--fleet-files`; or name a bootstrap certificate and its key in the
    /// file afterwards as `[tls] cert_file` and `key_file`, or run `service config`.
    #[arg(long, value_name = "URL", conflicts_with = "interactive")]
    pub endpoint: Option<String>,
    // ADR-0018.
    /// Withdraw the Client's consent to be updated by the Server, in the configuration this
    /// install writes.
    ///
    /// The consent stands by default (ADR-0018): without this flag the written file says
    /// `[packages] self_update = true` and the fleet can replace this Client like any other
    /// program once a verification key is set. With it, the file says `self_update = false` and
    /// this Client becomes the one program on the host that has to be updated by hand. The other non-interactive half of `--interactive`, for the same
    /// installers `--endpoint` serves — the MSI's checkbox, and a `.deb`/`.rpm` post-install.
    ///
    /// Only ever affects a file this install *creates*; an existing configuration is kept
    /// untouched, as it is for every other answer here.
    #[arg(long, conflicts_with = "interactive")]
    pub no_self_update: bool,
    // ADR-0029.
    /// Look for the fleet's files in this directory instead of beside the program:
    /// `server-ca.pem`, `package-signing-key.pub`, and the bootstrap identity — `bootstrap.pem` with
    /// `bootstrap-key.pem`, or `bootstrap.p12`.
    ///
    /// What a host installed from a `.deb` or `.rpm` needs: its program lies where nobody puts
    /// these files. The install never looks in both places.
    #[arg(long, value_name = "DIR")]
    pub fleet_files: Option<PathBuf>,
    // ADR-0029.
    /// Read the password of a `bootstrap.p12` from the first line of this file, instead of asking
    /// for it.
    ///
    /// Required when an install without `--interactive` enrols with a `bootstrap.p12`. The file is
    /// read once and left as it is; the password is never written anywhere and never sent. There
    /// is no way to give it on the command line or in the environment.
    #[arg(long, value_name = "PATH")]
    pub bootstrap_password_file: Option<PathBuf>,
    // ADR-0019, ADR-0042.
    /// Run the service as this account, and hand this installation's files — both roots — over
    /// to it.
    ///
    /// Without it, a re-registration keeps the account the existing registration names, and a
    /// first one runs as root (`LocalSystem` on Windows). `--run-as root` chooses root on Linux
    /// and macOS, and the unit records it.
    ///
    /// System scope only: a `--user` service already runs as its user. On Linux and macOS the
    /// account must exist. On Windows only passwordless account forms are accepted — the
    /// service's own virtual account (`NT SERVICE\<service name>`), a gMSA (`name$`), or
    /// `NT AUTHORITY\LocalService`/`NetworkService`; a password is never taken here — it would
    /// stand in the process list and in the installer log (ADR-0019).
    #[arg(long, value_name = "ACCOUNT", conflicts_with = "user")]
    pub run_as: Option<String>,
    // ADR-0059.
    /// Run every Managed Process under this account, through a second service,
    /// `<PRODUCT_NAME>-agents`, that runs under it and starts them on the Client's request.
    ///
    /// System scope only: under systemd on Linux, launchd on macOS and the SCM on Windows. On Linux
    /// and macOS the account must exist, must be neither root nor the account the Client runs as,
    /// and its primary group must be its own and a supplementary group of the Client's account,
    /// with no other member; the Client must not run as root. On Windows it is a passwordless
    /// form — `NT SERVICE\<PRODUCT_NAME>-agents`, a gMSA, or `LocalService` / `NetworkService` —
    /// and the Client runs under an account of its own. A re-registration without the flag keeps
    /// the account the second service's registration names.
    #[arg(long, value_name = "ACCOUNT", conflicts_with = "user")]
    pub process_account: Option<String>,
    // ADR-0059.
    /// Drop the process account: stop and deregister the second service, and let the Client
    /// start its Managed Processes itself again.
    #[arg(long, conflicts_with = "process_account")]
    pub no_process_account: bool,
}

/// Arguments for `service config`: where the installed configuration is, named as `install`
/// named it (ADR-0019 clause 15).
#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    /// System or `--user` scope.
    #[command(flatten)]
    pub scope: ScopeArgs,
    /// The `--root` the Client was installed with; alone it is also the data root.
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// The `--data-root` the Client was installed with.
    #[arg(long)]
    pub data_root: Option<PathBuf>,
}

impl ConfigArgs {
    /// The data root these flags name, if they name one: `--data-root`, else `--root`, the way
    /// `install` resolves them (ADR-0019 clause 8).
    #[must_use]
    pub fn data_root(&self) -> Option<&PathBuf> {
        self.data_root.as_ref().or(self.root.as_ref())
    }
}

/// Whether an action targets the system service or the current user's service.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct ScopeArgs {
    /// Target a user-level service instead of the system service.
    #[arg(long)]
    pub user: bool,
}

impl From<ScopeArgs> for crate::service::ServiceLevel {
    fn from(scope: ScopeArgs) -> Self {
        if scope.user {
            Self::User
        } else {
            Self::System
        }
    }
}

pub use crate::config::{parse_instance_name, InstanceName};

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("valid CLI arguments")
    }

    /// The `service install` arguments of a command line that must have them.
    fn install(args: &[&str]) -> InstallArgs {
        match parse(args).command {
            Some(Command::Service {
                action: ServiceAction::Install(install),
            }) => install,
            other => panic!("expected `service install`, parsed {other:?}"),
        }
    }

    /// Verifies: ADR-0019
    #[test]
    fn bare_invocation_has_no_subcommand() {
        // No subcommand → the caller (main) defaults to `run`.
        let cli = parse(&["client"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.config, PathBuf::from("supervisor.toml"));
    }

    /// ADR-0019 clause 6: removed, not hidden and not accepted-and-ignored. A unit written by an
    /// older install would carry it, and this is what makes that fail loudly instead of running a
    /// Client whose paths silently mean something else.
    /// Verifies: ADR-0019
    #[test]
    fn instance_is_not_a_flag_any_more() {
        assert!(
            Cli::try_parse_from(["supervisor", "--instance", "prod"]).is_err(),
            "--instance must be rejected outright"
        );
        for verb in ["uninstall", "start", "stop", "status"] {
            assert!(
                Cli::try_parse_from(["supervisor", "service", verb, "--instance", "prod"]).is_err(),
                "`service {verb}` takes no instance name — there is nothing to look up"
            );
        }
    }

    #[test]
    fn todays_invocation_still_parses() {
        // The command line without a subcommand: `client --config <path>`.
        let cli = parse(&["client", "--config", "config/supervisor.toml"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.config, PathBuf::from("config/supervisor.toml"));
    }

    #[test]
    fn run_is_explicit_too_and_config_is_global() {
        // `--config` is a global flag: valid before and after the subcommand.
        let cli = parse(&["client", "run", "--config", "x.toml"]);
        assert!(matches!(cli.command, Some(Command::Run(_))));
        assert_eq!(cli.config, PathBuf::from("x.toml"));
    }

    /// Verifies: ADR-0019
    #[test]
    fn the_installed_command_line_parses() {
        // What `service install` writes into the unit (ADR-0019).
        let cli = parse(&[
            "client",
            "run",
            "--service",
            "--config",
            "/var/lib/opamp-fleet/supervisor.toml",
            "--state-dir",
            "/var/lib/opamp-fleet/state",
        ]);
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run");
        };
        assert!(args.service);
        assert_eq!(
            cli.config,
            PathBuf::from("/var/lib/opamp-fleet/supervisor.toml")
        );
        assert_eq!(
            cli.state_dir,
            Some(PathBuf::from("/var/lib/opamp-fleet/state"))
        );
    }

    /// The second service is `run` with a flag, not a subcommand of its own (ADR-0059 clause 2),
    /// and names the one uid it serves; neither half parses without the other.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_agents_service_is_run_with_its_socket_and_the_clients_uid() {
        let cli = parse(&[
            "client",
            "run",
            "--agents",
            "/run/opamp-fleet-agents/agents.sock",
            "--client-uid",
            "998",
        ]);
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run");
        };
        assert_eq!(
            args.agents,
            Some(PathBuf::from("/run/opamp-fleet-agents/agents.sock"))
        );
        assert_eq!(args.client_uid, Some(998));
        assert!(Cli::try_parse_from(["client", "run", "--agents", "/x.sock"]).is_err());
        assert!(Cli::try_parse_from(["client", "run", "--client-uid", "998"]).is_err());
    }

    /// The second service is no Client: a flag that only means something to the Client is
    /// refused next to `--agents`, not silently ignored, and root is never the Client's account
    /// it serves (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_agents_service_refuses_the_clients_flags_and_root() {
        let agents = [
            "client",
            "run",
            "--agents",
            "/x.sock",
            "--client-uid",
            "998",
        ];
        for extra in [
            &["--service"][..],
            &["--config", "/etc/supervisor.toml"],
            &["--state-dir", "/var/lib/x"],
        ] {
            let mut args = agents.to_vec();
            args.extend_from_slice(extra);
            assert!(
                Cli::try_parse_from(&args).is_err(),
                "{extra:?} was accepted"
            );
            // A global flag counts before the subcommand too.
            if extra != ["--service"] {
                let mut args = vec!["client"];
                args.extend_from_slice(extra);
                args.extend_from_slice(&agents[1..]);
                assert!(parse_from(&args).is_err(), "{extra:?} was accepted");
            }
        }
        assert!(
            Cli::try_parse_from(["client", "run", "--agents", "/x.sock", "--client-uid", "0"])
                .is_err()
        );
    }

    /// The Client's unit names the second service's socket and the process account's uid; the
    /// Client learns from them that a process account is registered (ADR-0059 clause 3). Neither
    /// half parses without the other, root is never the process account, and the Client is not
    /// the second service.
    /// Verifies: ADR-0059
    #[cfg(unix)]
    #[test]
    fn the_client_is_told_the_second_services_socket_and_uid() {
        let client = [
            "client",
            "--config",
            "/var/lib/opamp-fleet/supervisor.toml",
            "run",
            "--service",
            "--agents-socket",
            "/run/opamp-fleet-agents/agents.sock",
            "--process-uid",
            "997",
        ];
        let parsed = parse_from(client).expect("the Client's command line");
        let Some(Command::Run(args)) = parsed.cli.command else {
            panic!("expected run");
        };
        assert_eq!(
            args.agents_socket,
            Some(PathBuf::from("/run/opamp-fleet-agents/agents.sock"))
        );
        assert_eq!(args.process_uid, Some(997));
        assert!(Cli::try_parse_from(["client", "run", "--agents-socket", "/x.sock"]).is_err());
        assert!(Cli::try_parse_from(["client", "run", "--process-uid", "997"]).is_err());
        assert!(Cli::try_parse_from([
            "client",
            "run",
            "--agents-socket",
            "/x.sock",
            "--process-uid",
            "0"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "client",
            "run",
            "--agents",
            "/x.sock",
            "--client-uid",
            "998",
            "--agents-socket",
            "/x.sock",
            "--process-uid",
            "997"
        ])
        .is_err());
    }

    /// On Windows the second service is the pipe and the Client's SID, and the Client is told the
    /// pipe and the process account's SID; each half needs the other, a SID is read as the system
    /// writes it, and the two ends are never one run (ADR-0059 clauses 2 to 4).
    /// Verifies: ADR-0059
    #[cfg(windows)]
    #[test]
    fn on_windows_the_two_ends_are_told_the_pipe_and_a_sid() {
        let pipe = r"\\.\pipe\opamp-fleet-agents";
        let cli = parse(&[
            "client",
            "run",
            "--agents",
            pipe,
            "--client-sid",
            "s-1-5-80-01-2-3-4-5",
        ]);
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run");
        };
        let (agents, client) = args.agents_service().expect("the second service");
        assert_eq!(agents, PathBuf::from(pipe));
        assert_eq!(client.as_str(), "S-1-5-80-1-2-3-4-5");
        assert!(Cli::try_parse_from(["client", "run", "--agents", pipe]).is_err());
        assert!(
            Cli::try_parse_from(["client", "run", "--agents", pipe, "--client-sid", "998"])
                .is_err()
        );
        assert!(Cli::try_parse_from([
            "client",
            "run",
            "--agents",
            pipe,
            "--client-sid",
            "S-1-5-18",
            "--service"
        ])
        .is_err());

        let cli = parse(&[
            "client",
            "run",
            "--service",
            "--agents-socket",
            pipe,
            "--process-sid",
            "S-1-5-80-6-7-8-9-10",
        ]);
        let Some(Command::Run(args)) = cli.command else {
            panic!("expected run");
        };
        let (socket, process) = args.agents_channel().expect("the channel");
        assert_eq!(socket, PathBuf::from(pipe));
        assert_eq!(process.as_str(), "S-1-5-80-6-7-8-9-10");
        assert!(Cli::try_parse_from(["client", "run", "--agents-socket", pipe]).is_err());
        assert!(Cli::try_parse_from([
            "client",
            "run",
            "--agents",
            pipe,
            "--client-sid",
            "S-1-5-80-1-2-3-4-5",
            "--agents-socket",
            pipe,
            "--process-sid",
            "S-1-5-80-6-7-8-9-10",
        ])
        .is_err());
    }

    /// A SID on either end's command line is read as the system writes it, and anything else is
    /// refused before the run begins.
    /// Verifies: ADR-0059
    #[test]
    fn a_sid_on_the_command_line_is_read_canonically() {
        assert_eq!(
            parse_sid("s-1-5-80-01-2-3-4-5").expect("sid").as_str(),
            "S-1-5-80-1-2-3-4-5"
        );
        assert!(parse_sid("NT SERVICE\\opamp-fleet").is_err());
        assert!(parse_sid("998").is_err());
    }

    /// `--process-account` names the account at system scope only (ADR-0059 clause 1).
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_conflicts_with_user() {
        let cli = parse(&[
            "client",
            "service",
            "install",
            "--run-as",
            "opamp-fleet",
            "--process-account",
            "opamp-fleet-agents",
        ]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = cli.command
        else {
            panic!("expected service install");
        };
        assert_eq!(args.process_account.as_deref(), Some("opamp-fleet-agents"));
        assert!(Cli::try_parse_from([
            "client",
            "service",
            "install",
            "--user",
            "--process-account",
            "opamp-fleet-agents"
        ])
        .is_err());
    }

    /// `--no-process-account` drops the process account, and conflicts with naming one (ADR-0059
    /// clause 1).
    /// Verifies: ADR-0059
    #[test]
    fn no_process_account_conflicts_with_naming_one() {
        let cli = parse(&["client", "service", "install", "--no-process-account"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = cli.command
        else {
            panic!("expected service install");
        };
        assert!(args.no_process_account);
        assert!(Cli::try_parse_from([
            "client",
            "service",
            "install",
            "--no-process-account",
            "--process-account",
            "opamp-fleet-agents"
        ])
        .is_err());
    }

    /// The process account's flags are in the help: the Managed Processes' files are split from
    /// the Client's (ADR-0059 clause 6), so the separation they name holds.
    /// Verifies: ADR-0059
    #[test]
    fn the_process_account_flags_are_shown() {
        let mut command = <Cli as clap::CommandFactory>::command();
        let install = command
            .find_subcommand_mut("service")
            .and_then(|service| service.find_subcommand_mut("install"))
            .expect("service install");
        for flag in ["process_account", "no_process_account"] {
            let arg = install
                .get_arguments()
                .find(|arg| arg.get_id() == flag)
                .unwrap_or_else(|| panic!("no {flag}"));
            assert!(!arg.is_hide_set(), "{flag} is hidden");
        }
    }

    /// Verifies: ADR-0019
    #[test]
    fn service_verbs_parse_with_scope_and_root() {
        let cli = parse(&["client", "service", "install", "--user", "--root", "/opt/x"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = cli.command
        else {
            panic!("expected service install");
        };
        assert!(args.scope.user);
        assert_eq!(args.root, Some(PathBuf::from("/opt/x")));
        assert_eq!(args.data_root, None, "it follows --root unless named");

        let cli = parse(&["client", "service", "status"]);
        assert!(matches!(
            cli.command,
            Some(Command::Service {
                action: ServiceAction::Status(ScopeArgs { user: false })
            })
        ));
    }

    /// ADR-0019 clause 8: the two halves can be named apart, which is what the Linux system-scope
    /// split needs and what the manual tells an operator to do on a host that wants them apart.
    /// Verifies: ADR-0019
    #[test]
    fn both_roots_can_be_named() {
        let args = install(&[
            "client",
            "service",
            "install",
            "--root",
            "/opt/opamp-fleet",
            "--data-root",
            "/var/lib/opamp-fleet",
        ]);
        assert_eq!(args.root, Some(PathBuf::from("/opt/opamp-fleet")));
        assert_eq!(args.data_root, Some(PathBuf::from("/var/lib/opamp-fleet")));
    }

    /// `service config` finds the configuration with the flags `install` took, `--data-root`
    /// winning over `--root` exactly as there.
    /// Verifies: ADR-0019
    #[test]
    fn config_takes_the_install_roots() {
        let config = |args: &[&str]| match parse(args).command {
            Some(Command::Service {
                action: ServiceAction::Config(config),
            }) => config,
            other => panic!("expected `service config`, parsed {other:?}"),
        };
        let bare = config(&["client", "service", "config"]);
        assert!(!bare.scope.user);
        assert_eq!(bare.data_root(), None);

        let root = config(&["client", "service", "config", "--user", "--root", "/opt/x"]);
        assert!(root.scope.user);
        assert_eq!(root.data_root(), Some(&PathBuf::from("/opt/x")));

        let both = config(&[
            "client",
            "service",
            "config",
            "--root",
            "/opt/x",
            "--data-root",
            "/var/lib/x",
        ]);
        assert_eq!(both.data_root(), Some(&PathBuf::from("/var/lib/x")));
    }

    /// ADR-0019: interactivity is something the operator asks for. Every invocation that existed
    /// before this flag keeps meaning what it meant.
    /// Verifies: ADR-0019
    #[test]
    fn install_is_not_interactive_unless_asked() {
        let quiet = parse(&["client", "service", "install"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = quiet.command
        else {
            panic!("expected service install");
        };
        assert!(!args.interactive);

        let asked = parse(&["client", "service", "install", "--interactive"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = asked.command
        else {
            panic!("expected service install");
        };
        assert!(args.interactive);
        assert_eq!(args.endpoint, None);
    }

    /// ADR-0018: the withdrawal travels on the same non-interactive path the endpoint does, and
    /// the consent stands unless the install withdraws it. No flag names the package — it is the
    /// Client's own Agent type — and the withdrawal may not ride `--interactive`, which writes the
    /// consent and leaves its effect to the verification key.
    /// Verifies: ADR-0018
    #[test]
    fn install_carries_the_self_update_answer_without_a_terminal() {
        let standing = install(&[
            "client",
            "service",
            "install",
            "--endpoint",
            "ws://h/v1/opamp",
        ]);
        assert!(!standing.no_self_update, "the consent stands by default");

        let withdrawn = install(&[
            "client",
            "service",
            "install",
            "--endpoint",
            "ws://h/v1/opamp",
            "--no-self-update",
        ]);
        assert!(withdrawn.no_self_update);

        for refused in [
            vec![
                "client",
                "service",
                "install",
                "--endpoint",
                "ws://h/v1/opamp",
                "--self-update-package",
                "x",
            ],
            vec![
                "client",
                "service",
                "install",
                "--interactive",
                "--no-self-update",
            ],
        ] {
            assert!(
                super::Cli::try_parse_from(&refused).is_err(),
                "{refused:?} must be refused"
            );
        }
    }

    /// ADR-0019 clause 42: a packaged install passes the answer it collected. The endpoint is not
    /// validated here — the loader's own rule does that, once, in `config_init`.
    /// Verifies: ADR-0019
    #[test]
    fn install_takes_an_endpoint_without_a_terminal() {
        let told = parse(&[
            "client",
            "service",
            "install",
            "--endpoint",
            "wss://fleet.example.com/v1/opamp",
        ]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = told.command
        else {
            panic!("expected service install");
        };
        assert!(!args.interactive);
        assert_eq!(
            args.endpoint.as_deref(),
            Some("wss://fleet.example.com/v1/opamp")
        );
    }

    /// The two ways of writing the first configuration cannot both be asked for: one blocks on a
    /// terminal and the other exists precisely because there is none.
    /// Verifies: ADR-0019
    #[test]
    fn an_endpoint_and_interactive_are_refused_together() {
        let err = Cli::try_parse_from([
            "client",
            "service",
            "install",
            "--interactive",
            "--endpoint",
            "wss://fleet.example.com/v1/opamp",
        ])
        .expect_err("mutually exclusive");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// ADR-0019: the account is named at install time and nowhere else. No password parameter
    /// exists beside it — the accepted Windows forms are all passwordless.
    #[test]
    fn install_takes_a_run_as_account() {
        let cli = parse(&["client", "service", "install", "--run-as", "opamp-fleet"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = cli.command
        else {
            panic!("expected service install");
        };
        assert_eq!(args.run_as.as_deref(), Some("opamp-fleet"));

        let none = parse(&["client", "service", "install"]);
        let Some(Command::Service {
            action: ServiceAction::Install(args),
        }) = none.command
        else {
            panic!("expected service install");
        };
        assert_eq!(
            args.run_as, None,
            "an absent flag names nothing: the install keeps the registration's account (ADR-0042)"
        );
    }

    /// ADR-0019: `--run-as` is system scope only — a `--user` service already runs as its user,
    /// so naming an account beside it could only contradict it.
    #[test]
    fn run_as_and_user_scope_are_refused_together() {
        let err = Cli::try_parse_from([
            "client",
            "service",
            "install",
            "--user",
            "--run-as",
            "opamp-fleet",
        ])
        .expect_err("mutually exclusive");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// The default value of `--config` must not be mistaken for a path someone chose: it decides
    /// whether `install` writes into the install root or where the operator pointed (ADR-0019).
    #[test]
    fn a_named_config_is_told_apart_from_the_default() {
        let default = parse_from(["client", "service", "install"]).expect("parse");
        assert!(!default.config_named);
        assert_eq!(default.cli.config, PathBuf::from("supervisor.toml"));

        // A global argument counts from either side of the subcommand.
        for args in [
            [
                "client",
                "--config",
                "/etc/opamp/supervisor.toml",
                "service",
                "install",
            ],
            [
                "client",
                "service",
                "install",
                "--config",
                "/etc/opamp/supervisor.toml",
            ],
        ] {
            let named = parse_from(args).expect("parse");
            assert!(named.config_named, "{args:?}");
            assert_eq!(
                named.cli.config,
                PathBuf::from("/etc/opamp/supervisor.toml")
            );
        }

        // Even spelled with the same value as the default: what counts is that it was written.
        let same = parse_from([
            "client",
            "service",
            "install",
            "--config",
            "supervisor.toml",
        ])
        .expect("parse");
        assert!(same.config_named);
    }

    #[test]
    fn instance_names_are_validated() {
        for valid in ["default", "prod", "a", "web-1", "x2", &"a".repeat(32)] {
            assert!(parse_instance_name(valid).is_ok(), "{valid:?} should parse");
        }
        for invalid in [
            "",
            "Prod",
            "with space",
            "über",
            "-lead",
            "trail-",
            "dot.name",
            "path/name",
            "con",
            "com7",
            "lpt1",
            &"a".repeat(33),
        ] {
            assert!(
                parse_instance_name(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    #[test]
    fn state_dir_is_a_global_override() {
        let cli = parse(&["client", "run", "--state-dir", "/var/lib/x"]);
        assert_eq!(cli.state_dir, Some(PathBuf::from("/var/lib/x")));
        // Absent by default: the configuration file's value applies.
        assert_eq!(parse(&["client"]).state_dir, None);
    }

    #[test]
    fn the_version_flag_reports_the_baked_in_version() {
        let err = Cli::try_parse_from(["client", "--version"]).unwrap_err();
        assert!(err.to_string().contains(fleet_core::version::current()));
    }
}
