//! The Windows Service Control Manager (SCM) runtime shim (ADR-0019), compiled only on Windows.
//!
//! Unlike systemd and launchd — which supervise an ordinary foreground process — the Windows SCM
//! launches the service and then expects it to register a control handler and report `Running`
//! within a bounded time, or it kills the process with error 1053. This shim does exactly that:
//! it reports `StartPending` → `Running`, runs the same daemon body as the foreground path, and
//! reports `StopPending` → `Stopped` around a stop. It is entered via the `run --service` marker
//! argument set by `service install`; a bare `run` never reaches here
//! (`StartServiceCtrlDispatcher` fails with error 1063 when the process was *not* SCM-launched,
//! which is why the path is a marker, not auto-detection).

use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

use tracing::error;
use windows_service::service::{
    ServiceControl as ScmControl, ServiceControlAccept, ServiceExitCode, ServiceState as ScmState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::runtime::{self, RunSpec};

/// The own-process service name handed to the dispatcher. For an `OWN_PROCESS` service the SCM
/// does not match on this string — the installed service is registered under the product's name
/// (ADR-0019 clause 3) — so it only needs to be stable.
const SERVICE_NAME: &str = "supervisor";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// The spec handed from [`run_as_service`] to the SCM-invoked `service_main`, which the
/// `define_windows_service!` entry point cannot receive as a parameter.
static SPEC: OnceLock<RunSpec> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Enter the SCM dispatcher (called from `main` when started with `run --service`). Blocks until
/// the service stops.
///
/// # Errors
/// Returns an error if the dispatcher cannot be started.
pub fn run_as_service(spec: RunSpec) -> Result<(), String> {
    // Stash the spec for `service_main`, which the SCM invokes without our arguments.
    let _ = SPEC.set(spec);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("cannot start the Windows service control dispatcher: {e}"))
}

/// The SCM entry point. Errors cannot propagate out of here, so they are logged.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "Windows service exited with an error");
    }
}

fn run_service() -> Result<(), String> {
    // The control handler runs on an SCM thread; a watch channel carries the stop request into
    // the async runtime — the same `Shutdown` handle the transports select on.
    let (shutdown_tx, shutdown) = crate::shutdown::shutdown_channel();

    // `ServiceStatusHandle` is `Copy`; the handler uses its own copy to report `StopPending`
    // (with a wait hint) the moment a stop arrives, per ADR-0019.
    let handle_cell: &'static OnceLock<service_control_handler::ServiceStatusHandle> =
        Box::leak(Box::new(OnceLock::new()));
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ScmControl::Stop | ScmControl::Shutdown => {
                if let Some(handle) = handle_cell.get() {
                    let _ = handle.set_service_status(status(
                        ScmState::StopPending,
                        ServiceControlAccept::empty(),
                    ));
                }
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ScmControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .map_err(|e| format!("cannot register the service control handler: {e}"))?;
    let _ = handle_cell.set(status_handle);

    // Report that startup is in progress (runtime construction below may take a moment).
    status_handle
        .set_service_status(status(
            ScmState::StartPending,
            ServiceControlAccept::empty(),
        ))
        .map_err(|e| format!("cannot report StartPending: {e}"))?;

    let spec = SPEC
        .get()
        .cloned()
        .ok_or_else(|| "the service spec was not initialised".to_string())?;
    let tokio_runtime = runtime::daemon_runtime()?;

    // Now serving: accept Stop and Shutdown.
    status_handle
        .set_service_status(status(
            ScmState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))
        .map_err(|e| format!("cannot report Running: {e}"))?;

    let result = tokio_runtime.block_on(runtime::on_a_worker(runtime::run_until_shutdown(
        spec, shutdown,
    )));

    // Report the *outcome*, not a blanket success. The SCM decides whether to run the recovery
    // actions from the exit code in this final status: a `Stopped` carrying `Win32(0)` is a clean
    // stop and is never retried, whatever went wrong. Reporting zero here is what made the
    // `RestartPolicy::OnFailure` of ADR-0019 unreachable on Windows even once failure actions
    // exist, and it is what a self-update — which ends its run deliberately — depends on.
    if let Err(e) = &result {
        error!(error = %e, "the daemon exited with an error; reporting it to the SCM");
    }
    let exit_code = match &result {
        Ok(runtime::Exit::Normal) => ServiceExitCode::Win32(0),
        // A self-update is not a failure, but the SCM's recovery actions are the only way to be
        // restarted, and they run on a failure (ADR-0018).
        Ok(runtime::Exit::RestartForUpdate) => {
            error!("exiting so the SCM starts the newly installed version");
            ServiceExitCode::ServiceSpecific(
                crate::update::EXIT_RESTART_FOR_UPDATE
                    .try_into()
                    .unwrap_or(SERVICE_SPECIFIC_FAILURE),
            )
        }
        Err(_) => ServiceExitCode::ServiceSpecific(SERVICE_SPECIFIC_FAILURE),
    };
    status_handle
        .set_service_status(ServiceStatus {
            exit_code,
            ..status(ScmState::Stopped, ServiceControlAccept::empty())
        })
        .map_err(|e| format!("cannot report Stopped: {e}"))?;
    result.map(|_| ())
}

/// The service-specific exit code reported when the daemon body returns an error. Any non-zero
/// value marks the stop as a failure; a service-specific one keeps it from being read as a Win32
/// error code that means something else.
const SERVICE_SPECIFIC_FAILURE: u32 = 1;

/// Build a `ServiceStatus` for the given state and accepted controls. The wait hint bounds how
/// long the SCM grants for a pending transition; the shutdown path finishes well inside it
/// (system shutdown grants ~5 s total — `WaitToKillServiceTimeout`).
///
/// The exit code is success; the one place a failure is reported overrides it explicitly, because
/// every *other* status here is a transition rather than an outcome.
fn status(current_state: ScmState, controls_accepted: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}
