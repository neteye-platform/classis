//! When a certificate counts as ending (ADR-0028 clause 11): one rule, plain date arithmetic on
//! Unix seconds, so the operator tool's `pki status`, the Server's `pki status` and the running
//! Server judge alike. Each program reads the certificate itself; this module only judges the
//! dates.

/// How far ahead an end is announced, in days — or, for a certificate whose whole life is shorter
/// than three times this, the last third of its life.
pub const WARN_DAYS: i64 = 30;

const DAY: i64 = 86_400;

/// Where an end stands against a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// More left than the warning reaches.
    Fine,
    /// Ends within [`WARN_DAYS`], or within the last third of a shorter life.
    Ending,
    /// Has ended.
    Ended,
}

/// Where a certificate valid from `not_before` to `not_after` stands at `now`, all in Unix seconds.
#[must_use]
pub fn standing(not_before: i64, not_after: i64, now: i64) -> Standing {
    let warning = (WARN_DAYS * DAY).min(not_after.saturating_sub(not_before) / 3);
    if not_after <= now {
        Standing::Ended
    } else if not_after - now <= warning {
        Standing::Ending
    } else {
        Standing::Fine
    }
}

/// The exit code of a `pki status` command (ADR-0028 clause 12): `0` when nothing is ending, `1`
/// when something is, `2` when something has ended.
#[must_use]
pub fn exit_code(standings: impl IntoIterator<Item = Standing>) -> i32 {
    standings
        .into_iter()
        .map(|standing| match standing {
            Standing::Fine => 0,
            Standing::Ending => 1,
            Standing::Ended => 2,
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn lived(lived: i64, left: i64) -> Standing {
        standing(NOW - lived * DAY, NOW + left * DAY, NOW)
    }

    // Verifies: ADR-0028
    #[test]
    fn thirty_days_ahead_or_the_last_third_of_a_shorter_life() {
        assert_eq!(lived(0, 400), Standing::Fine);
        assert_eq!(lived(380, 20), Standing::Ending);
        assert_eq!(lived(30, -1), Standing::Ended);
        // A fresh 10-day bootstrap certificate is not ending; its last third is.
        assert_eq!(lived(0, 10), Standing::Fine);
        assert_eq!(lived(7, 3), Standing::Ending);
    }

    // Verifies: ADR-0028
    #[test]
    fn status_exits_by_the_worst_end() {
        assert_eq!(exit_code([lived(0, 400)]), 0);
        assert_eq!(exit_code([lived(0, 400), lived(380, 20)]), 1);
        assert_eq!(exit_code([lived(380, 20), lived(30, -1)]), 2);
        assert_eq!(exit_code([]), 0);
    }
}
