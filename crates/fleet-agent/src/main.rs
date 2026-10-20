//! Entry point: parse the CLI (ADR-0019) and hand off — `run` to the daemon runtime, the
//! `service` verbs to the cross-platform lifecycle. The daemon loads `supervisor.toml`, restores the
//! Agent's identity, and runs the transport the endpoint selects (ADR-0013) until stopped.

use std::path::{Path, PathBuf};

use fleet_agent::cli::{self, Command, ConfigArgs, InstallArgs, ServiceAction};
use fleet_agent::config::ClientConfig;
use fleet_agent::config_init;
use fleet_agent::service::runtime::{self, RunSpec};
use fleet_agent::service::{
    enrol, layout, manager, run_as, windows_rights, ServiceControl, ServiceLevel,
};
use fleet_agent::update;

fn main() {
    // stderr as always, plus two empty slots the OTLP exporters are dropped into once the Server
    // names a destination: the log bridge for events (ADR-0016) and the span layer for traces
    // (ADR-0016). Both have to exist from the start: `tracing` takes one subscriber for the
    // process, and it is installed long before any destination is known.
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let (spans, span_handle) = tracing_subscriber::reload::Layer::new(None);
    fleet_agent::telemetry::hold_span_layer(span_handle);
    let (bridge, bridge_handle) = tracing_subscriber::reload::Layer::new(None);
    fleet_agent::telemetry::hold_log_bridge(bridge_handle);
    // The slots go on first, spans before logs: a reloadable layer is typed for the subscriber it
    // attaches to, and the registry is the only one of these that stays the same shape when a slot
    // is filled — so the layer that carries that subscriber in its own type goes on the bare one.
    tracing_subscriber::registry()
        .with(spans)
        .with(bridge)
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // Colour only when stderr is a real terminal: under a service manager stderr is a pipe to
        // journald or the SCM, and ANSI escapes there are noise in the syslog, not colour.
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
        )
        // The log file (ADR-0019), which discards everything until a service run opens it — the
        // state directory is not known until the command line is parsed, a few lines below. No
        // colour: this one is read with a pager, not a terminal.
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(fleet_agent::logging::LogFile),
        )
        .init();

    // One TLS provider for the whole process (ADR-0013): ring, never a system library.
    opamp::tls::install_ring_provider();

    let cli::Parsed { cli, config_named } = cli::parse();
    let result = match cli.command {
        // A bare invocation defaults to `run`, preserving the pre-subcommand contract.
        // A bare invocation is a person at a terminal, so it writes no log file (ADR-0019).
        None => runtime::run_foreground(RunSpec {
            config_path: cli.config,
            state_dir: cli.state_dir,
            service: false,
        }),
        Some(Command::Run(args)) => {
            let spec = RunSpec {
                config_path: cli.config,
                state_dir: cli.state_dir,
                service: args.service,
            };
            run_command(spec, args)
        }
        Some(Command::Service { action }) => service_command(&cli.config, config_named, &action),
        // Answer for this executable so a self-update can prove it before pointing at it
        // (ADR-0018). Deliberately does nothing else: it must work on a binary that has no
        // configuration, no state directory, and no Server.
        Some(Command::SelfCheck) => {
            println!(
                "{}{}",
                update::SELF_CHECK_TOKEN,
                fleet_core::version::current()
            );
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// `run`: the foreground daemon — except under the Windows SCM, where the hidden `--service`
/// marker set by `service install` routes into the dispatcher shim (ADR-0019). The runtime (or
/// the shim) owns the tokio runtime; `main` stays synchronous.
fn run_command(spec: RunSpec, args: cli::RunArgs) -> Result<(), String> {
    #[cfg(windows)]
    if args.service {
        return fleet_agent::service::windows::run_as_service(spec);
    }
    let _ = args;
    runtime::run_foreground(spec)
}

/// Dispatch a `service` verb (ADR-0019).
fn service_command(
    config_path: &Path,
    config_named: bool,
    action: &ServiceAction,
) -> Result<(), String> {
    match action {
        ServiceAction::Install(args) => install(config_path, config_named, args),
        ServiceAction::Config(args) => configure(config_path, config_named, args),
        ServiceAction::Uninstall(scope) => {
            manager::uninstall(ServiceLevel::from(*scope))?;
            println!(
                "service {} uninstalled (the install layout and state remain)",
                manager::service_name()
            );
            Ok(())
        }
        ServiceAction::Start(scope) => {
            manager::NativeService::new(ServiceLevel::from(*scope)).start()
        }
        ServiceAction::Stop(scope) => {
            manager::NativeService::new(ServiceLevel::from(*scope)).stop()
        }
        ServiceAction::Status(scope) => {
            let state = manager::NativeService::new(ServiceLevel::from(*scope)).state()?;
            println!("{}", state.describe());
            Ok(())
        }
    }
}

/// `service install`: write the configuration if asked to (ADR-0019), validate it, lay out the
/// versioned install at the chosen root, and register the service against the `current` pointer
/// (ADR-0019).
fn install(config_path: &Path, config_named: bool, args: &InstallArgs) -> Result<(), String> {
    let level = ServiceLevel::from(args.scope);

    // Ask whether this process may register a service at all, before the first thing is written.
    // On Windows the SCM refuses a non-elevated process and nothing here can raise its own rights,
    // while `%ProgramData%` happily takes the layout — so without this the install staged a version
    // and swung `current` at it and only then failed (ADR-0019: fail with a clear message).
    windows_rights::ensure_can_register(level)?;

    // Two roots and two flags (ADR-0019 clause 8). The executable layout and the data default to
    // different places on Linux at system scope — and only there — because systemd may not execute
    // from `/var/lib` under SELinux. `--root` alone keeps ADR-0019's meaning and collapses both
    // halves into the one directory the operator named, whose labeling and permissions are then
    // the operator's business; `--data-root` names the other half when they must stay apart.
    let (layout_root, data_root) = match (&args.root, &args.data_root) {
        (Some(root), Some(data)) => (absolute(root)?, absolute(data)?),
        (Some(root), None) => {
            let root = absolute(root)?;
            (root.clone(), root)
        }
        (None, Some(data)) => (manager::default_layout_root(level)?, absolute(data)?),
        (None, None) => (
            manager::default_layout_root(level)?,
            manager::default_root(level)?,
        ),
    };

    // The account, decided and resolved with the same before-anything-is-written rule (ADR-0042
    // clause 2): `--run-as`, else the account the existing unit or plist names, else the owner of
    // a data root that unit lost its account on, else root. A name that does not exist, or a
    // Windows form that would need a password, fails here.
    let account = run_as::decide(
        level,
        args.run_as.as_deref(),
        manager::registration(level)?.as_ref(),
        &data_root,
        manager::service_name(),
    )?;
    let run_as = account.run_as;

    // Everything baked into the unit is absolute: a service's working directory is `/` or
    // `System32`, so a relative path would silently point nowhere. An operator who named no path
    // gets one inside the install root rather than one resolved against this shell's working
    // directory, which the service manager will not share (ADR-0019).
    let config_path = if config_named {
        absolute(config_path)?
    } else {
        data_root.join(config_init::FILE_NAME)
    };

    // The fleet's files the operator put beside this program, before it is staged anywhere else,
    // or in the directory `--fleet-files` names (ADR-0029 clause 6).
    let beside = match &args.fleet_files {
        Some(dir) => config_init::Beside::in_named_dir(&absolute(dir)?)?,
        None => config_init::Beside::the_program(),
    };
    let password = args
        .bootstrap_password_file
        .as_deref()
        .map(|path| config_init::read_password_file(path, "--bootstrap-password-file"))
        .transpose()?;
    // Not asked, the bootstrap identity found enrols a Client that holds no issued certificate,
    // over TLS (ADR-0029 clause 10) — decided, and a `bootstrap.p12` opened, before anything is
    // written, against the file this install is about to write or keep.
    let unasked = if args.interactive {
        None
    } else {
        // An absent file loads as the defaults; `--endpoint` then writes its endpoint, and an
        // existing file is kept.
        let mut about_to_run = ClientConfig::load(&config_path)?;
        if let (false, Some(endpoint)) = (config_path.exists(), &args.endpoint) {
            about_to_run.endpoint.clone_from(endpoint);
        }
        about_to_run.state_dir = about_to_run.service_state_dir(&data_root);
        beside.unasked_enrolment(&about_to_run, password.as_deref())?
    };
    let mut written = config_init::Written::default();
    if args.interactive {
        written = ask(&config_path, &data_root, &beside, password.as_deref())?;
    } else if let Some(endpoint) = &args.endpoint {
        // The same file, from an answer given rather than asked for (ADR-0019): this is the branch
        // the MSI's custom action and a `%post` script take. The self-update consent travels with
        // it — standing unless this install was told to withdraw it (ADR-0018) — and so do the CA
        // and the verification key beside the program (ADR-0020 clause 3).
        let self_update = !args.no_self_update;
        written.copies =
            config_init::run_with_endpoint(&config_path, endpoint, self_update, &beside)?;
    } else if !config_path.exists() {
        // Not an error — automation must not break — but never silent: without this file the
        // service refuses to start.
        println!(
            "warning: no configuration at {} — the Client refuses to start until it exists with \
             a client identity (write it, or re-run with --interactive)",
            config_path.display()
        );
    }

    // Fail on a broken configuration now, not at the service's first start. After the write, so
    // that a file just answered into existence is held to the same rule as any other.
    let mut config = ClientConfig::load(&config_path)?;
    // The state directory the service will run with — where an issued certificate counts.
    let state_dir = config.service_state_dir(&data_root);
    config.state_dir.clone_from(&state_dir);
    // On Windows every local user inherits read access under %ProgramData%; the data root, a state
    // directory placed elsewhere, and a Supervisors' root this install creates outside both are cut
    // off from it before anyone is granted anything (H8) — and before an enrolment writes its
    // private key there. Decided before anything is created. Unix needs nothing here: the Client writes its
    // secrets owner-only itself.
    let restrictions = windows_rights::plan(
        &data_root,
        args.root.is_some() || args.data_root.is_some(),
        &state_dir,
        &config.supervisors_root(),
        Path::exists,
    );
    std::fs::create_dir_all(&data_root)
        .map_err(|e| format!("cannot create {}: {e}", data_root.display()))?;
    if !state_dir.starts_with(&data_root) {
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| format!("cannot create the state directory: {e}"))?;
    }
    let created_outside = windows_rights::restrict(level, &restrictions)?;
    if let Some(bootstrap) = unasked {
        println!("enrolling with {}", bootstrap.describe());
        written.bootstrap = Some(bootstrap);
    }
    // Before anything is staged or registered (ADR-0020 clause 5): an enrolment that is stopped
    // leaves the answered file and nothing else.
    if let Some(bootstrap) = &written.bootstrap {
        enrol::run(&config, bootstrap)?;
    }
    // And held to what the Client needs at startup. A packaged install registers the service even
    // so — it has an endpoint and no client identity to write — but never starts it, and the
    // service refuses to run until the file names one (ADR-0019). Said loudly here.
    if let Err(e) = config.check_admission() {
        println!(
            "warning: {}: {e}. The service is registered, and refuses to start until this is set \
             (or re-run with --interactive).",
            config_path.display()
        );
    }

    let layout = layout::Layout::new(&layout_root);
    let program = layout::stage_current_exe(&layout)?;

    manager::install(&manager::InstallSpec {
        level,
        program: program.clone(),
        config_path: config_path.clone(),
        state_dir: state_dir.clone(),
        run_as: run_as.as_ref().map(|r| r.account().to_string()),
    })?;

    // The handover (ADR-0042 clause 2), on every registration that runs under an account — a kept
    // one and root included: both roots belong to it — config and state because the service reads
    // and rewrites them (ADR-0017), the executable layout because the self-update that stages into
    // it *is* the service (ADR-0018). The state directory is created first: the daemon must not
    // need rights on its parent to begin.
    if let Some(run_as) = &run_as {
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| format!("cannot create the state directory: {e}"))?;
        let mut skipped =
            run_as.hand_over(&[&layout_root, &data_root, &state_dir, &config_path])?;
        // A Supervisors' root this install created and cut on Windows is the service's to write
        // too (ADR-0017 clause 21); none is created on Unix.
        skipped.extend(
            run_as.hand_over(
                &created_outside
                    .iter()
                    .filter(|dir| **dir != state_dir)
                    .map(PathBuf::as_path)
                    .collect::<Vec<_>>(),
            )?,
        );
        // The copy beside a configuration named outside the data root is not under it.
        skipped.extend(
            run_as.hand_over(
                &written
                    .copies
                    .iter()
                    .map(PathBuf::as_path)
                    .collect::<Vec<_>>(),
            )?,
        );
        for file in skipped {
            println!(
                "warning: {} has a second hard link and was not handed over to {}",
                file.display(),
                run_as.account()
            );
        }
    }

    println!("installed {}", manager::service_name());
    println!("  program:   {}", program.display());
    println!("  config:    {}", config_path.display());
    println!("  state dir: {}", state_dir.display());
    if let Some(run_as) = &run_as {
        println!(
            "  runs as:   {} ({})",
            run_as.account(),
            account.source.describe()
        );
    }
    // Since service-manager 0.10, launchd installs do not auto-start; say the next step instead
    // of pretending.
    let user = if args.scope.user { " --user" } else { "" };
    println!("start it with: supervisor service start{user}");
    Ok(())
}

/// `service config`: the questionnaire of `install --interactive` against an installed Client, and
/// its enrolment when it holds no certificate yet — registering nothing (ADR-0019 clause 15).
fn configure(config_path: &Path, config_named: bool, args: &ConfigArgs) -> Result<(), String> {
    let level = ServiceLevel::from(args.scope);
    // The file and the state directory, found as `install` laid them out.
    let data_root = match args.data_root() {
        Some(data) => absolute(data)?,
        None => manager::default_root(level)?,
    };
    let config_path = if config_named {
        absolute(config_path)?
    } else {
        data_root.join(config_init::FILE_NAME)
    };
    // The installed copy runs from the layout, where no fleet files lie (ADR-0020, out of scope).
    let written = ask(
        &config_path,
        &data_root,
        &config_init::Beside::default(),
        None,
    )?;

    let mut config = ClientConfig::load(&config_path)?;
    let state_dir = config.service_state_dir(&data_root);
    config.state_dir.clone_from(&state_dir);
    if let Some(bootstrap) = &written.bootstrap {
        enrol::run(&config, bootstrap)?;
    }
    // What this run created belongs to whoever owns the configuration — the service's account when
    // it runs as one (ADR-0019 clause 13) — not to the administrator who ran it.
    let mut created = enrol::written(&state_dir);
    created.extend(written.copies.iter().cloned());
    run_as::match_owner(
        &config_path,
        &created.iter().map(PathBuf::as_path).collect::<Vec<_>>(),
    )?;
    if let Err(e) = config.check_admission() {
        println!("warning: {}: {e}", config_path.display());
    }

    let user = if args.scope.user { " --user" } else { "" };
    println!(
        "restart the service to apply: supervisor service stop{user} && \
         supervisor service start{user}"
    );
    Ok(())
}

/// The questionnaire against the file at `config_path`, offering what it holds and asking for the
/// bootstrap identity only while the state directory under `data_root` holds no issued certificate
/// (ADR-0019 clauses 16, 17).
fn ask(
    config_path: &Path,
    data_root: &Path,
    beside: &config_init::Beside,
    password: Option<&str>,
) -> Result<config_init::Written, String> {
    let current = ClientConfig::load(config_path)?;
    let mut in_service = current.clone();
    in_service.state_dir = current.service_state_dir(data_root);
    config_init::run(
        config_path,
        &current,
        in_service.is_enrolled(),
        beside,
        password,
    )
}

/// Absolutize without requiring existence (`canonicalize` would fail for a config file that
/// legitimately does not exist yet — defaults then apply, as in `ClientConfig::load`).
fn absolute(path: &Path) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|e| format!("cannot absolutize {}: {e}", path.display()))
}
