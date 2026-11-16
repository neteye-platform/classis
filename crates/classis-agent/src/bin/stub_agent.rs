//! A stub Managed Process for tests (ADR-0017): pure Rust so it behaves identically on Linux,
//! macOS, and Windows CI — no shell scripts.
//!
//! Behaviour, driven entirely by arguments:
//! - `--version` — print a version line the way real agents do (free text around a SemVer),
//!   then exit; what the plugins' version probe invokes.
//! - `--touch <path>` — write a marker file, then keep running. The marker holds this run's
//!   process id and every argument, one per line, so a test observes both *that* the stub ran
//!   and *with what*; a restart rewrites it with a fresh pid.
//! - `--exit-code <n> --exit-after-ms <m>` — exit with code `n` after `m` milliseconds, for
//!   crash-path tests. Without them the stub sleeps until it is killed.
//! - `--ignore-hup` (Unix only) — ignore `SIGHUP`, the way a daemon that reloads on it survives
//!   the signal; without the flag the default disposition terminates the stub. What the reload
//!   tests (ADR-0017) use for both sides of `reload-or-restart`.

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(unix)]
    if args.iter().any(|a| a == "--ignore-hup") {
        // SAFETY: installs SIG_IGN for SIGHUP; no memory is touched.
        unsafe {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
    }
    if args.iter().any(|a| a == "--version") {
        println!("stub_agent version 9.9.9 (test build)");
        return;
    }
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
    };

    if let Some(path) = flag("--touch") {
        let mut marker = format!("pid={}\n", std::process::id());
        if let Ok(token) = std::env::var("OPAMP_SUPERVISOR_TOKEN") {
            marker.push_str(&format!("token={token}\n"));
        }
        for arg in &args {
            marker.push_str(arg);
            marker.push('\n');
        }
        std::fs::write(path, marker).expect("write the marker file");
    }

    let exit_code: Option<i32> = flag("--exit-code").and_then(|v| v.parse().ok());
    let exit_after: Option<u64> = flag("--exit-after-ms").and_then(|v| v.parse().ok());
    if let Some(code) = exit_code {
        std::thread::sleep(Duration::from_millis(exit_after.unwrap_or(0)));
        std::process::exit(code);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
