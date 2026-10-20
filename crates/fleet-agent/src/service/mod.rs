//! Everything that makes the Client an OS service (ADR-0019) lives in this module: the daemon
//! runtime with graceful shutdown ([`runtime`]), the versioned install layout ([`layout`]), and
//! the cross-platform service lifecycle ([`manager`]), and the questionnaire's enrolment
//! ([`enrol`]). The Windows SCM runtime shim joins as a `cfg(windows)` submodule.
//!
//! The [`ServiceControl`] trait is the deliberate seam: a future self-update stops, switches, and
//! starts the service through these three calls only, never through service internals.

pub mod enrol;
pub mod layout;
pub mod manager;
pub mod run_as;
pub mod runtime;
#[cfg(windows)]
pub mod windows;
mod windows_config;
pub mod windows_rights;

/// Whether an action targets the machine's service manager or the current user's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLevel {
    /// systemd system unit / launchd `LaunchDaemon` / Windows `LocalSystem` — the default: a
    /// fleet client must run without a logged-in user and start at boot.
    System,
    /// The development opt-in (`--user`).
    User,
}

/// The observable state of the installed service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// No service is registered under the product's label.
    NotInstalled,
    /// Registered but not running.
    Stopped,
    /// Running.
    Running,
}

impl ServiceState {
    /// A short human-readable description for `service status`.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            ServiceState::NotInstalled => "not installed",
            ServiceState::Stopped => "installed, stopped",
            ServiceState::Running => "running",
        }
    }
}

/// The narrow lifecycle seam (ADR-0019): everything a future updater needs, and nothing more.
pub trait ServiceControl {
    /// Start the installed service.
    ///
    /// # Errors
    /// Returns an error if the platform manager refuses.
    fn start(&self) -> Result<(), String>;

    /// Stop the installed service (and keep it stopped — the restart policy only covers
    /// crashes, never explicit stops).
    ///
    /// # Errors
    /// Returns an error if the platform manager refuses.
    fn stop(&self) -> Result<(), String>;

    /// The service's current state.
    ///
    /// # Errors
    /// Returns an error if the platform manager cannot be queried.
    fn state(&self) -> Result<ServiceState, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seam must stay object-safe and implementable by a test double — that is the contract
    /// the future updater's tests rely on.
    struct FakeControl(std::cell::Cell<ServiceState>);

    impl ServiceControl for FakeControl {
        fn start(&self) -> Result<(), String> {
            self.0.set(ServiceState::Running);
            Ok(())
        }
        fn stop(&self) -> Result<(), String> {
            self.0.set(ServiceState::Stopped);
            Ok(())
        }
        fn state(&self) -> Result<ServiceState, String> {
            Ok(self.0.get())
        }
    }

    #[test]
    fn the_seam_is_object_safe_and_fakeable() {
        let fake = FakeControl(std::cell::Cell::new(ServiceState::Stopped));
        let control: &dyn ServiceControl = &fake;
        control.start().expect("start");
        assert_eq!(control.state().expect("state"), ServiceState::Running);
        control.stop().expect("stop");
        assert_eq!(control.state().expect("state"), ServiceState::Stopped);
        assert_eq!(ServiceState::NotInstalled.describe(), "not installed");
    }
}
