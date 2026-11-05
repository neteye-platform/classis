#!/usr/bin/env bash
#
# Builds, tests and lints the Cargo workspace: the commands of README.md → "Build, Test & Run",
# with the lockfile held as it is (ADR-0010 clause 15). scripts/check-all.sh runs it as the local
# gate, and the 'rust' job of .github/workflows/checks.yml runs it in CI, so the build and the
# tests are part of what a push and a merge wait for (AGENTS.md §5).
#
# The opamp crate is linted once per feature as well: inside the workspace Cargo builds it with
# every feature any crate asks for, so only a build of each feature on its own shows that it
# stands alone (ADR-0010).
#
# fleet-agent is linted without any wrapped Supervisor kind and with each one alone, and tested
# without any: the default build carries every kind, so only these show that a build leaving one
# out still compiles and refuses the kind as unknown (ADR-0017 clause 2).
#
# Needs the Rust toolchain of rust-toolchain.toml; the Dev Container provides it.
#
# Usage:
#     scripts/check-rust.sh
# Exit code 0 when everything passes; the first failing command ends the run.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v cargo >/dev/null || { echo "cargo is required (rust-toolchain.toml names the toolchain)" >&2; exit 1; }

cargo build --workspace --locked
cargo test --workspace --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
for feature in "" client server; do
  cargo clippy -p opamp --all-targets --locked --no-default-features --features "$feature" -- -D warnings
done
cargo clippy -p fleet-agent --all-targets --locked --no-default-features -- -D warnings
cargo test -p fleet-agent --locked --no-default-features
