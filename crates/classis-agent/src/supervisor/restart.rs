//! Whether a Managed Process that failed is started again or held instead (ADR-0026): the
//! crash-loop policy, apart from the process it is applied to. The runner reads the clock, waits
//! out its backoff and starts the process; this decides.

use std::time::{Duration, Instant};

/// How many times in a row a Managed Process may fail to stay up before the Runner stops restarting
/// it and holds until something changes — a new configuration, a new package, or a restart (ADR-0026).
/// It is the self-update's give-up (three attempts, ADR-0018), so the two update paths behave alike.
/// A restart loop is a denial of service against the fleet's own Server; this bounds it.
pub const MAX_CRASH_RESTARTS: usize = 3;

/// A process that stayed up at least this long counts as *stable*: a later exit is ordinary
/// supervision, not a start loop, so it clears the streak. Below the floor a zero-grace Supervisor
/// would treat every restart as stable; above it, one that survives its grace comfortably resets.
pub const STABLE_RUN_FLOOR: Duration = Duration::from_secs(10);

/// What to do after the process failed to stay up.
#[derive(Debug, PartialEq, Eq)]
pub enum AfterFailure {
    /// Start it again, after the runner's backoff.
    Retry,
    /// Leave it down: it failed this many times in a row.
    Hold(usize),
}

/// The streak of failed starts, and when the current process started.
pub struct RestartPolicy {
    streak: usize,
    started: Instant,
    /// How long a started process must survive before its exit no longer counts as a failed start.
    stable_after: Duration,
}

impl RestartPolicy {
    /// A policy for a process whose apply grace is `apply_grace`, started at `now`.
    #[must_use]
    pub fn new(apply_grace: Duration, now: Instant) -> Self {
        RestartPolicy {
            streak: 0,
            started: now,
            stable_after: apply_grace.max(STABLE_RUN_FLOOR),
        }
    }

    /// A new configuration, a new package, or an operator's restart: a fresh chance, which clears
    /// the streak.
    pub fn fresh_chance(&mut self) {
        self.streak = 0;
    }

    /// The process was (re)started at `now`.
    pub fn started(&mut self, now: Instant) {
        self.started = now;
    }

    /// The process exited unexpectedly at `now`. One that had been up a while is ordinary
    /// supervision, not a start loop, so its exit clears the streak.
    pub fn exited(&mut self, now: Instant) {
        if now.saturating_duration_since(self.started) >= self.stable_after {
            self.streak = 0;
        }
    }

    /// The process failed to stay up: retried, or held once it has failed [`MAX_CRASH_RESTARTS`]
    /// times in a row.
    pub fn failed(&mut self) -> AfterFailure {
        self.streak += 1;
        if self.streak >= MAX_CRASH_RESTARTS {
            AfterFailure::Hold(self.streak)
        } else {
            AfterFailure::Retry
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-0026: a process that keeps failing to start is held after a few tries rather than
    /// restarted forever.
    #[test]
    fn a_process_that_keeps_failing_is_held_after_three_tries() {
        let start = Instant::now();
        let mut policy = RestartPolicy::new(Duration::ZERO, start);
        assert!(policy.failed() == AfterFailure::Retry);
        assert!(policy.failed() == AfterFailure::Retry);
        assert_eq!(policy.failed(), AfterFailure::Hold(MAX_CRASH_RESTARTS));
    }

    /// A fresh chance — configuration, package, restart — clears the streak.
    #[test]
    fn a_fresh_chance_clears_the_streak() {
        let mut policy = RestartPolicy::new(Duration::ZERO, Instant::now());
        policy.failed();
        policy.failed();
        policy.fresh_chance();
        assert!(policy.failed() == AfterFailure::Retry);
        assert!(policy.failed() == AfterFailure::Retry);
    }

    /// An exit after a stable run is supervision, not a start loop; a quick one keeps counting.
    /// Stable means the longer of the apply grace and the floor.
    #[test]
    fn only_an_exit_after_a_stable_run_clears_the_streak() {
        let start = Instant::now();
        let grace = Duration::from_secs(30);
        let mut policy = RestartPolicy::new(grace, start);
        policy.failed();
        policy.failed();

        policy.exited(start + STABLE_RUN_FLOOR);
        assert_eq!(
            policy.failed(),
            AfterFailure::Hold(MAX_CRASH_RESTARTS),
            "past the floor but inside the grace is still a quick exit"
        );

        let mut policy = RestartPolicy::new(grace, start);
        policy.failed();
        policy.failed();
        policy.exited(start + grace);
        assert!(policy.failed() == AfterFailure::Retry);
    }

    /// The stable run is measured from the latest start, not the first.
    #[test]
    fn the_stable_run_counts_from_the_latest_start() {
        let start = Instant::now();
        let mut policy = RestartPolicy::new(Duration::ZERO, start);
        policy.failed();
        policy.failed();
        let restarted = start + Duration::from_secs(60);
        policy.started(restarted);
        policy.exited(restarted + Duration::from_secs(1));
        assert_eq!(policy.failed(), AfterFailure::Hold(MAX_CRASH_RESTARTS));
    }
}
