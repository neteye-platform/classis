//! What `service-manager` leaves undone on Windows: the recovery actions that make ADR-0019's
//! "restart on failure" true there as well, the display name of ADR-0019, and the logon account
//! of ADR-0019.
//!
//! On systemd and launchd the restart policy handed to `service-manager` is written straight into
//! the unit (`Restart=on-failure`) or the plist (`KeepAlive{SuccessfulExit:false}`). Its Windows
//! backend is the `sc.exe` wrapper, whose `install` matches on the policy **only to log a
//! warning** — *"sc.exe does not support automatic restart policies through 'sc create'; service
//! '…' will not restart automatically"* — and registers no recovery actions at all. A Windows
//! Client therefore never came back from any failure, which contradicts ADR-0019 on one of its
//! three platforms.
//!
//! Two calls close that, both on the `windows-service` crate already used for the SCM runtime
//! shim, so nothing new is depended on:
//!
//! 1. **`update_failure_actions`** — one `Restart` action after a delay. The SCM repeats the last
//!    action for every further failure, so a single entry with no reset period is the unbounded
//!    retry that `RestartPolicy::OnFailure { max_retries: None }` asks for.
//! 2. **`set_failure_actions_on_non_crash_failures`** — without it the recovery actions run only
//!    when the process dies *without* reporting `SERVICE_STOPPED`. A service that stops cleanly
//!    while reporting a non-zero exit code — a Client that failed to start on a bad configuration,
//!    or one deliberately ending its run — is otherwise treated as a clean stop and never
//!    restarted. The flag is false by default.
//!
//! The display name is the third gap. The backend's `sc create` sets `displayname=` to the service
//! name, so the Windows services list would read `supervisor` where ADR-0019 promised
//! the product's display name — a promise never actually kept. It is set afterwards with
//! `sc.exe config`, deliberately **not** with the crate's `Service::change_config`: that call maps
//! onto `ChangeServiceConfigW` with every field supplied from a `ServiceInfo`, so setting one field
//! means restating the executable path, the launch arguments, the start type and the account
//! exactly as registered — and getting any of them wrong rewrites the registration rather than the
//! name. `sc config` changes the one field it is given and leaves the rest alone. This is also how
//! the service was created: the backend is the `sc.exe` wrapper.
//!
//! The **description** is a fourth, and is not the display name under another word: the services
//! list has a Description column of its own, nothing that registers the service fills it, and a
//! service with a display name still shows an empty one. It is set the same way, with the one
//! `sc.exe` verb that carries it.
//!
//! Everything here is a no-op on Unix.

/// Configure what the Windows backend does not: failure recovery, the display name, the
/// description — and, when `--run-as` named one, the logon account (ADR-0019).
///
/// # Errors
/// Returns an error if the service cannot be opened or reconfigured. On Unix this never fails —
/// the service manager already carries the policy and the account (`User=`/`UserName`), and
/// neither systemd nor launchd has a display name or a description column to fill.
#[cfg(not(windows))]
pub fn configure(
    _service_name: &str,
    _display_name: &str,
    _description: &str,
    _run_as: Option<&str>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
pub fn configure(
    service_name: &str,
    display_name: &str,
    description: &str,
    run_as: Option<&str>,
) -> Result<(), String> {
    use std::time::Duration;

    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
        ServiceFailureResetPeriod,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("cannot open the service control manager: {e}"))?;
    let service = manager
        .open_service(
            service_name,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
        )
        .map_err(|e| format!("cannot open the service {service_name}: {e}"))?;

    service
        .update_failure_actions(ServiceFailureActions {
            // Never reset the failure count: a Client that fails once a week must still be
            // restarted the second time, and the count is not otherwise interesting.
            reset_period: ServiceFailureResetPeriod::Never,
            reboot_msg: None,
            command: None,
            // One action, repeated by the SCM for every subsequent failure.
            actions: Some(vec![ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(super::manager::RESTART_DELAY_SECS.into()),
            }]),
        })
        .map_err(|e| format!("cannot set the recovery actions of {service_name}: {e}"))?;

    // Without this the actions above cover a crash but not a reported failure — see the module
    // documentation.
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| {
            format!("cannot enable recovery on reported failures for {service_name}: {e}")
        })?;

    // The name the services list shows (ADR-0019). `sc.exe` wants `displayname=` with the space
    // **after** the equals sign: the token is the option and the *next* argument is its value, so
    // `displayname=x` as one word is parsed as an option nobody knows and silently changes nothing.
    sc(
        &["config", service_name, "displayname="],
        display_name,
        &format!("display name of {service_name}"),
    )?;

    // The Description column beside it. `sc description` takes its text **positionally** — there is
    // no `description=` token, and adding one would write the token into the field. The two verbs
    // disagreeing about this is exactly why each call says which shape it uses.
    sc(
        &["description", service_name],
        description,
        &format!("description of {service_name}"),
    )?;

    // The logon account (ADR-0019). `service-manager`'s `sc.exe` backend ignores the ctx's
    // `username`, so the account is set here — and set *without* a `password=`, which every form
    // `run_as` admits (the service's virtual account, a gMSA, the built-ins) is defined not to
    // need. No *Log on as a service* grant follows: the default security policy grants it to
    // `NT SERVICE\ALL SERVICES` (covering the virtual account), the built-ins carry it
    // inherently, and a gMSA receives it from its domain's group policy — the manual says so.
    if let Some(account) = run_as {
        sc(
            &["config", service_name, "obj="],
            account,
            &format!("logon account of {service_name}"),
        )?;
    }
    Ok(())
}

/// Runs `sc.exe` with a trailing value argument — the shape both fields above are set with, so
/// neither can be the one that forgets to check whether `sc.exe` actually accepted it.
///
/// A refusal for want of rights is **not** retried through a UAC prompt here, and cannot usefully
/// be: by the time these calls run the service is registered, which needed Administrator, so a
/// process that got this far already has the rights — and one that does not never gets here,
/// because [`windows_rights`](super::windows_rights) stops the install before it writes anything.
/// Asking per `sc.exe` verb would in any case prompt twice for one install, and could not cover the
/// `CHANGE_CONFIG` handle above, which is refused before either verb runs.
///
/// `what` names the field for the error, because `sc.exe` reports failure through an exit code and
/// a line on stdout rather than through anything a caller could tell apart.
#[cfg(windows)]
fn sc(args: &[&str], value: &str, what: &str) -> Result<(), String> {
    let output = std::process::Command::new("sc.exe")
        .args(args)
        .arg(value)
        .output()
        .map_err(|e| format!("cannot run sc.exe to set the {what}: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "cannot set the {what}: sc.exe exited with {} ({})",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}
