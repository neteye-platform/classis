//! The system clock: the adapter behind [`Clock`](crate::fleet::Clock).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::fleet::Clock;

/// The host's wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}
