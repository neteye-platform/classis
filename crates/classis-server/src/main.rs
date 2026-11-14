//! Entry point: load the configuration from `server.toml` and the environment (ADR-0051), bind the
//! two listeners — the Agent plane and the Operator plane (ADR-0013) — and serve both until
//! interrupted.
//!
//! Both planes speak plain HTTP: a reverse proxy in front of the Server terminates TLS (ADR-0064).
//! What bounds a connection before it becomes a request is `opamp`'s listener (ADR-0013).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use classis_server::config::{Layered, ServerConfig};
use classis_server::fleet::AppState;
use classis_server::listen;
use opamp::server::listen::Handle;
use tracing::{info, warn};

fn usage() -> ! {
    eprintln!(
        "Usage: server [--config <server.toml>] [--version]\n       \
         server hash-credential --basic   (reads the password from standard input)\n       \
         server migrate --config-dir <old> --packages-dir <old> --data-dir <new>\n       \
         server migrate-to-postgres --from <data_dir> --data-dir <new> [--config <server.toml>]"
    );
    std::process::exit(2);
}

/// The configuration every command that reads one reads (ADR-0051 clause 2): the file `--config`
/// or `CLASSIS_SERVER_CONFIG` names, or `server.toml` in the working directory when it exists, with
/// the environment over it. The keys the environment set are logged by name. Stops the process on
/// an error.
fn load_config(named: Option<PathBuf>) -> Layered {
    let layered = classis_server::config::config_file(
        named,
        std::env::var_os(classis_server::config::CONFIG_FILE_VARIABLE),
        std::path::Path::new("server.toml"),
    )
    .and_then(|file| {
        let variables = classis_server::config::server_variables()?;
        ServerConfig::load_layered(file.as_deref(), variables)
    })
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    layered
}

/// Logs the keys the environment set, by name (ADR-0051 clause 7), once the log is set up.
fn announce_environment(layered: &Layered) {
    if let Some(notice) = layered.environment_notice() {
        info!("{notice}");
    }
}

/// Sets up the log on standard error, so that stdout carries only what a command prints as its
/// result: `RUST_LOG` chooses the level (default `info`), `[log] format` the form of a line.
fn init_logging(format: classis_server::config::LogFormat) {
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        );
    match format {
        classis_server::config::LogFormat::Text => builder.init(),
        classis_server::config::LogFormat::Json => builder.json().init(),
    }
}

/// `server pki` is gone (ADR-0064): the Server holds no certificate, so there is no ending to
/// report. Said by name, so a script that still calls it is not left guessing.
fn pki(_args: impl Iterator<Item = String>) -> ! {
    eprintln!(
        "server pki is removed — the Server speaks plain HTTP behind a reverse proxy and holds no \
         certificate (ADR-0064)"
    );
    std::process::exit(2);
}

/// `server migrate --config-dir <old> --packages-dir <old> --data-dir <new>` (ADR-0037 clause 14):
/// moves the state an older Server kept under `config_dir` and `packages_dir` into a new, empty
/// `data_dir`, copying, so the old directories stay as the backup. It is run while the Server is
/// stopped — a Server still writing the old directories would be copied half-way — and that is the
/// operator's to ensure: the older Server takes no lock this could test. Prints what it carried,
/// dropped and listed, and exits non-zero when trust data could not be carried.
fn migrate(mut args: impl Iterator<Item = String>) -> ! {
    init_logging(classis_server::config::LogFormat::Text);
    let (mut config_dir, mut packages_dir, mut data_dir) = (None, None, None);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--config-dir" => &mut config_dir,
            "--packages-dir" => &mut packages_dir,
            "--data-dir" => &mut data_dir,
            _ => usage(),
        };
        match args.next() {
            Some(path) if slot.is_none() => *slot = Some(PathBuf::from(path)),
            _ => usage(),
        }
    }
    let (Some(config_dir), Some(packages_dir), Some(data_dir)) =
        (config_dir, packages_dir, data_dir)
    else {
        usage()
    };
    match classis_server::migrate::run(&config_dir, &packages_dir, &data_dir) {
        Ok(report) => {
            for line in &report.lines {
                println!("{line}");
            }
            if report.trust_failed {
                eprintln!(
                    "the trust data was not carried whole — do not start a Server on {}; fix what \
                     is named above, empty it, and migrate again",
                    data_dir.display()
                );
                std::process::exit(1);
            }
            println!(
                "migrated into {} — set data_dir to it in server.toml, remove config_dir and \
                 packages_dir, and start the Server",
                data_dir.display()
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// `server migrate-to-postgres --from <data_dir> --data-dir <new> [--config <server.toml>]`
/// (ADR-0050 clause 15): copies the records of `data_dir` into the database the configuration
/// names, and its filesystem blobs into a new, empty `data_dir`, leaving the old one as the
/// backup. It is run while the Server is stopped; it takes the database's lock, so a
/// Server still running against it stops the copy. Prints what it copied, and exits non-zero when
/// it could not copy all of it, leaving the database without the Server's tables.
fn migrate_to_postgres(mut args: impl Iterator<Item = String>) -> ! {
    let (mut from, mut data_dir, mut config) = (None, None, None);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "--from" => &mut from,
            "--data-dir" => &mut data_dir,
            "--config" => &mut config,
            _ => usage(),
        };
        match args.next() {
            Some(path) if slot.is_none() => *slot = Some(PathBuf::from(path)),
            _ => usage(),
        }
    }
    let (Some(from), Some(data_dir)) = (from, data_dir) else {
        usage()
    };
    let layered = load_config(config);
    init_logging(layered.config.log.format);
    announce_environment(&layered);
    let config = layered.config;
    let Some(database) = config.database.postgres() else {
        eprintln!(
            "the configuration names no database — set [database] store = \"postgres\" and \
             [database.postgres], then copy again"
        );
        std::process::exit(1);
    };
    match classis_server::postgres::import::run(
        &from,
        &data_dir,
        database,
        config.blobs.s3().is_none(),
    ) {
        Ok(report) => {
            for line in &report.lines {
                println!("{line}");
            }
            println!(
                "copied into the database {} and into {} — set data_dir to it in server.toml, keep [database] \
                 store = \"postgres\", and start the Server; {} stays as the backup",
                database.dbname,
                data_dir.display(),
                from.display()
            );
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// What makes the entry `server.toml` keeps from a secret.
type Hasher = fn(&str) -> Result<String, String>;

/// The hash `server hash-credential` makes for a scheme: Basic, for an operator's password in
/// `[rest.auth]`, and nothing else — the Agent plane has no credential (ADR-0021 clause 26).
fn hasher(scheme: Option<&str>) -> Option<Hasher> {
    match scheme {
        Some("--basic") => Some(classis_server::credentials::hash_basic),
        _ => None,
    }
}

/// `server hash-credential --basic` (ADR-0021 clause 26): reads the password from standard input —
/// without echo on a terminal — and prints the entry `server.toml` keeps instead of it.
fn hash_credential(scheme: Option<String>) -> ! {
    let Some(hash) = hasher(scheme.as_deref()) else {
        usage()
    };
    let secret = match read_secret() {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("cannot read the secret: {e}");
            std::process::exit(1);
        }
    };
    let hashed = hash(&secret);
    // `exit` runs no destructor: the secret is wiped before it (ADR-0057).
    drop(secret);
    match hashed {
        Ok(entry) => {
            println!("{entry}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// One line from standard input, the trailing newline dropped. On a Unix terminal echo is off while
/// it is typed, so the secret does not stand on the screen. It is held in a buffer wiped when it is
/// dropped, sized for any password a person types so it is not grown and left behind (ADR-0057).
/// The copy in the buffer of the process-wide standard input, which the standard library keeps,
/// is not wiped.
fn read_secret() -> std::io::Result<zeroize::Zeroizing<String>> {
    use std::io::{BufRead as _, IsTerminal as _};
    let stdin = std::io::stdin();
    let terminal = stdin.is_terminal();
    if terminal {
        eprint!("secret: ");
    }
    let _echo = terminal.then(EchoOff::new).flatten();
    let mut line = zeroize::Zeroizing::new(String::with_capacity(4096));
    stdin.lock().read_line(&mut line)?;
    if terminal {
        eprintln!();
    }
    let kept = line.trim_end_matches(['\r', '\n']).len();
    line.truncate(kept);
    Ok(line)
}

/// Terminal echo switched off for as long as it lives.
struct EchoOff {
    #[cfg(unix)]
    saved: libc::termios,
}

impl EchoOff {
    #[cfg(unix)]
    fn new() -> Option<Self> {
        // SAFETY: tcgetattr/tcsetattr on standard input with a termios this function owns.
        unsafe {
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return None;
            }
            let mut silent = saved;
            silent.c_lflag &= !libc::ECHO;
            (libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &silent) == 0)
                .then_some(EchoOff { saved })
        }
    }

    #[cfg(not(unix))]
    fn new() -> Option<Self> {
        None
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        // SAFETY: restores the termios read in `new`.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
        }
    }
}

/// The file `--config` names, if it does.
fn parse_args() -> Option<PathBuf> {
    let mut config = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "hash-credential" => hash_credential(args.next()),
            "pki" => pki(args),
            "migrate" => migrate(args),
            "migrate-to-postgres" => migrate_to_postgres(args),
            "--config" => match args.next() {
                Some(path) => config = Some(PathBuf::from(path)),
                None => usage(),
            },
            "--version" => {
                // The baked version, not `CARGO_PKG_VERSION` (ADR-0012): the number in the file is
                // the release this build is *heading for*, and only `classis_core::version::current` knows
                // whether this is it.
                println!("server {}", classis_core::version::current());
                std::process::exit(0);
            }
            _ => usage(),
        }
    }
    config
}

/// Binds one plane's listener, or explains which one could not be bound and stops. A busy port is
/// an operator's mistake, not a panic — and with two listeners the message has to say *which*.
///
/// Bound up front, before either plane starts serving, so a busy port is reported as the message
/// above rather than as a failure out of a running server — and the TLS case gets that too, which
/// it did not while it bound lazily inside `serve`.
fn bind(address: SocketAddr, plane: &str) -> std::net::TcpListener {
    match std::net::TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("cannot bind {plane} on {address}: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    // One TLS provider for the whole process (ADR-0013): ring, never a system library. The Server
    // terminates no TLS (ADR-0064), but its outbound connections — PostgreSQL, S3 — still use it.
    opamp::tls::install_ring_provider();

    let layered = load_config(parse_args());
    init_logging(layered.config.log.format);
    announce_environment(&layered);
    let Layered { config, origin, .. } = layered;

    // Where the records live (ADR-0050): the data directory, its layout created owner-only and
    // checked before any store opens (ADR-0037), and with PostgreSQL the database, its lock taken
    // and its schema applied.
    let records = match classis_server::Records::open(&config) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let classis_server::Records::Postgres(database) = &records {
        info!(database = %database.name(), "keeping the records in PostgreSQL");
    }
    let clock: Arc<dyn classis_server::fleet::Clock> = Arc::new(classis_server::clock::SystemClock);
    let limits = config.admission_throttle.limits();

    let connection_offer = config
        .connection_offer
        .as_ref()
        .map(classis_server::fleet::ConnectionOffer::from_config);
    if connection_offer.is_some() {
        // ADR-0014.
        info!("offering connection settings to the fleet");
    }
    // What Agents enrol with, and what the Server signs for them, is NEAG-34's (ADR-0064): nothing
    // here issues a certificate.
    let telemetry_offer = config
        .telemetry_offer
        .as_ref()
        .map(classis_server::fleet::TelemetryOffer::from_config)
        .unwrap_or_default();
    if config.telemetry_offer.is_some() {
        // ADR-0016.
        info!("offering the fleet somewhere to send its own telemetry");
    }
    if let Some(warning) = config.packages.ignored_key_warning() {
        warn!("{warning}");
    }
    let roots = classis_core::package::chain::compiled();
    if let Some(path) = classis_core::package::chain::debug_root() {
        // ADR-0063 clause 1: a debug build only.
        warn!(
            "a debug build: also trusting the Package Root in {} ({})",
            path.display(),
            classis_core::package::DEBUG_ROOT_ENV
        );
    }
    // ADR-0063 clause 1.
    info!(
        roots = roots.len(),
        "checking package signatures up to the compiled-in Package Roots"
    );
    let packages =
        classis_server::packages::PackageStore::open_on(&records, &config.data_dir, &config.blobs)
            .map(|store| {
                store.with_verifier(Box::new(classis_server::config::RootsVerifier::new(roots)))
            })
            .and_then(|store| {
                if !store.is_empty() {
                    // ADR-0026.
                    info!("offering software packages to the fleet");
                }
                classis_server::fleet::PackageOffering::on(&records, store)
            });
    let packages = match packages {
        Ok(offering) => Some(offering),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // What the client CA signed and what is revoked (ADR-0021), kept beside the fleet's records.
    let revocations = match records.ledger().and_then(|store| {
        classis_server::revocation::Revocations::open(store, clock.clone(), Vec::new())
    }) {
        Ok(revocations) => Arc::new(revocations),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let Some(warning) = config.rate_limit_warning() {
        // ADR-0013 clause 20.
        warn!("{warning}");
    }
    let agent_rate = Arc::new(classis_server::agent_rate::AgentRate::new(
        config.agent_rate_limit.limits(),
        config.max_agents,
        clock.clone(),
    ));
    let records_ready: Option<classis_server::fleet::RecordsReady> = match &records {
        classis_server::Records::Postgres(database) => {
            let database = database.clone();
            Some(Arc::new(move || database.ready()))
        }
        classis_server::Records::Files(_) => None,
    };
    let state = match AppState::on(&records) {
        Ok(state) => Arc::new(
            state
                .with_records_ready(records_ready)
                .with_agent_rate(Some(agent_rate))
                .with_connection_offer(connection_offer)
                .with_revocations(Some(revocations.clone()))
                .with_telemetry_offer(telemetry_offer)
                .with_packages(packages)
                .with_max_message_size(config.max_message_size_bytes)
                .with_max_package_size(config.max_package_size_bytes)
                .with_max_total_package_bytes(config.max_total_package_bytes)
                .with_stale_after(std::time::Duration::from_secs(config.stale_after_secs))
                .with_max_agents(config.max_agents),
        ),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // The Server authenticates no Agent (ADR-0064): the proxy in front of it does, and the Agent
    // port must be reachable through it alone. `AdmitEveryone` is the seam an authenticating
    // library plugs into later.
    info!("the OpAMP endpoint admits every request: the Agent port must be reachable only through the authenticating proxy");
    // Two planes, two listeners (ADR-0013): Agents reach the OpAMP endpoint and the package
    // downloads their offers point at; operators reach the REST API, its docs, and the UI.
    let agents = classis_server::agent_app(
        state.clone(),
        classis_server::transport::Admission::open()
            .with_authenticator(Arc::new(classis_server::agent_auth::AdmitEveryone))
            .with_revocations(Some(revocations))
            .with_throttle(Arc::new(classis_server::throttle::Throttle::new(
                limits,
                clock.clone(),
            ))),
    );
    let operator_auth = match config
        .rest
        .auth
        .as_ref()
        .map(classis_server::api::OperatorAuth::from_config)
        .transpose()
    {
        Ok(auth) => auth.map(|auth| {
            auth.with_throttle(Arc::new(classis_server::throttle::Throttle::new(
                limits,
                clock.clone(),
            )))
        }),
        Err(e) => {
            eprintln!("{origin}: {e}");
            std::process::exit(1);
        }
    };
    if operator_auth.is_some() {
        // ADR-0021. Both planes speak plain HTTP (ADR-0064): the password crosses the network
        // between the proxy and the Server in clear.
        info!("the REST API and the UI require authentication");
    }
    let operators = classis_server::operator_app(state.clone(), operator_auth);

    let agent_listener = bind(config.listen, "the Agent plane");
    let operator_listener = bind(config.rest.listen, "the Operator plane");
    // One signal, both planes: the interrupt is watched once, and the handle both servers hold
    // drains them together within a bounded window (ADR-0013).
    let handle = Handle::new();
    let signalled = shutdown_signal();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            signalled.await;
            info!("shutting down");
            listen::shut_down(&handle);
        }
    });

    info!(listen = %config.listen, "serving the OpAMP endpoint and package downloads over HTTP");
    info!(listen = %config.rest.listen, "serving the REST API, the API docs, and the UI over HTTP");
    let (agents, operators) = tokio::join!(
        listen::plain_plane(agent_listener, config.max_connections, handle.clone()).serve(agents),
        listen::plain_plane(operator_listener, config.rest.max_connections, handle)
            .serve(operators),
    );
    agents.expect("serve the Agent plane");
    operators.expect("serve the Operator plane");
    // The graceful-shutdown flush (ADR-0024): every record's current timestamp and sequence
    // number, so the ordinary restart restores a fleet without gaps or false silence.
    state.flush_agents();
}

/// The shutdown signal: `SIGTERM`, which a service manager sends on stop, or `SIGINT` from a
/// terminal. Either one drains both planes and saves the fleet before the process exits. Both
/// handlers are installed when this is called, not when the future is first polled, so a signal
/// that arrives while the Server is still starting is not left to its default of ending the process.
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate =
            signal(SignalKind::terminate()).expect("installing the SIGTERM handler");
        let mut interrupt = signal(SignalKind::interrupt()).expect("installing the SIGINT handler");
        async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        }
    }
    #[cfg(not(unix))]
    {
        async {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hash-credential` makes an operator's Basic entry and nothing else: the Agent plane has no
    /// credential to hash.
    /// Verifies: ADR-0021
    #[test]
    fn hash_credential_hashes_a_basic_password_alone() {
        let basic = hasher(Some("--basic")).expect("--basic is a scheme");
        let entry = basic("s3cret").expect("hash");
        classis_server::credentials::check_basic(&entry).expect("an entry server.toml keeps");
        assert!(!entry.contains("s3cret"));
        assert!(hasher(Some("--bearer")).is_none(), "--bearer is gone");
        assert!(hasher(None).is_none());
    }
}
