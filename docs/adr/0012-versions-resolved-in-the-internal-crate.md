# ADR-0012: `Cargo.toml` decides the product's version, the internal crate's build stamps it with git's provenance, and the commit is compared nowhere

- **Status:** 🟢 accepted
- **Date:** 2026-10-03
- **Deciders:** Markus Brigl
- **Applies to:** `Cargo.toml` `[workspace.package] version`, `crates/fleet-core/build.rs`, `crates/fleet-core/src/version.rs`, the `version` job of `.github/workflows/release.yml`, and every surface that states, compares or displays a version

## Context

The version resolution and its helper do not belong in the publishable `opamp` crate
([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)),
which carries the protocol and nothing of this project's own.

The version a binary carries is load-bearing in several places at once: the OpAMP `service.version`
identifying attribute tells the Server which build it is talking to, both CLIs print it, the
Client's install layout names its version directories after it
([ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)), and the self-update compares an offered
version against what a staged binary reports
([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)).

Forces:

- **Every build must be identifiable**, not only releases. A fleet view, a bug report or an
  install directory must tell two development builds apart and any development build from a
  release. That needs a SemVer pre-release marker for non-releases and build metadata naming the
  exact commit.
- **The number should be decided once, in a reviewed file.** `Cargo.toml` is where a Rust project's
  version lives and where a reviewer sees it change. A tag typed by hand at the end of a working
  day is the thing that names a release forever, and the typing is the failure. But a file and a
  tag are two places a version appears, so their disagreement has to be refused, never resolved
  by silence.
- **The version must be baked in at compile time.** A runtime lookup (git, an environment
  variable, a sidecar file) would make the reported version a property of the deployment rather
  than of the binary.
- **`cargo:rustc-env` reaches only the crate whose build script emitted it**, so the resolution
  has to run in a crate both binaries depend on, or it is implemented twice and drifts.
- **One string carries three jobs.** *Which release is this?* needs `MAJOR.MINOR.PATCH` and the
  pre-release; *which build is on that host?* needs the commit; *what goes in a column headed
  "Version"?* needs something scannable. The commit hash is also the one part an operator neither
  knows nor can type when uploading a release, and `+` in a URL query decodes to a space.

## Decision

We will take the version number from `Cargo.toml`, resolve the full version string once at compile
time in the build script of the internal shared crate, `fleet-core` — the number, a `-dev`
pre-release unless HEAD carries the matching `version/*` tag, and the commit as build metadata —
read it everywhere through `fleet_core::version::current()`, let the release pipeline create the
tag from the file, and treat the build metadata as provenance that is recorded everywhere and
compared nowhere.

1. **`Cargo.toml` decides the number.** The base is `[workspace.package] version` — the product's
   release number, which the `opamp` crate does not carry (ADR-0010) — and Cargo hands it to the
   build script as `CARGO_PKG_VERSION`. Bumping it is an ordinary reviewed commit. The
   grammar is strict semantic versioning: exactly three non-negative integers without leading
   zeros, no pre-release, no build metadata; a value that breaks it fails the build. The
   environment variable `OPAMP_PRODUCT_VERSION` overrides the base, held to the same grammar.

2. **Git says only what is around the number.**

   | HEAD | Version string |
   |---|---|
   | carries `version/<base>` | `<base>+<hash>` — a release build |
   | carries no `version/*` tag | `<base>-dev+<hash>` — a build heading for `<base>` |
   | carries a `version/*` tag naming another version | **the build fails**: the file and the tag disagree and neither wins |

   Only tags pointing at HEAD itself count, lightweight or annotated. A tag name is `version/`
   followed by three components in the clause-1 grammar, separated by `.` or `/` (mixed
   permitted), normalised to dots. A development build therefore names the release it is heading
   for, and SemVer ordering `0.1.0-dev` before `0.1.0` is simply true. A build outside a git
   repository fails: it can neither cite a commit nor tell a release from a development build.

3. **The build metadata is the commit and nothing else.** `+<hash>` is the first 7 hex characters
   of HEAD's commit id. Nothing time-dependent enters the string, so rebuilding a commit reproduces
   the byte-identical version.

4. **The resolution runs in `crates/fleet-core/build.rs`, through `git2`, with no `git` binary.** The
   script discovers the repository upward from the manifest directory, reads HEAD and the
   `refs/tags/version/*` references, and emits `cargo:rustc-env=OPAMP_PRODUCT_RELEASE=<full string>`
   with `rerun-if-changed` on the repository's `HEAD`, `refs` and `packed-refs` and
   `rerun-if-env-changed=OPAMP_PRODUCT_VERSION`. `git2` (libgit2, vendored and statically built) is a
   **build**-dependency of `fleet-core` only: nothing of it reaches a shipped binary, nothing parses CLI
   output, and the result does not vary with the host's git version or locale.

5. **`fleet_core::version::current()` is the one version helper, on both ends.** Every surface that
   states a version calls it, so all agree: the OpAMP `service.version` attribute, both CLIs'
   `--version` (clap's `version` is wired to it explicitly, because clap's default would report
   `CARGO_PKG_VERSION`), the Client's version directories and their manifest, and the self-check
   token. Nothing reads `env!("CARGO_PKG_VERSION")` to state a version.

6. **The release pipeline creates the tag from the file.** The release run reads the version with
   `cargo metadata`, creates `version/<version>` at the commit being released and pushes it with
   the workflow's own token before it builds — so `build.rs` finds the tag on HEAD. Events from
   `GITHUB_TOKEN` start no second run. The version job needs `contents: write` for this push and
   nothing else does.

7. **A spent number and a disagreement are refused, never resolved.** Before anything is built,
   the run fails if the tag `version/<version>` or a release of that name already exists — both
   are asked, because either can exist without the other — except the tag that started a run
   pushed by hand. The guard runs on a dry run too: whether a version can still be released is a
   property of the version. A run started by a hand-pushed `version/*` tag fails unless the tag and
   `Cargo.toml` agree. After building, the binary must report exactly `<version>+<hash>`. A release
   is therefore never re-run: a run that dies after the tag is pushed is finished by hand, or the
   version is skipped.

8. **A dry run neither tags nor publishes.** `workflow_dispatch` takes a `dry_run` input, `true` by
   default: it builds and packs every target and stops. A `-dev` version is expected there and only
   there.

9. **One parser, in the internal shared crate.** `fleet_core::version::parse` splits a version
   string into its `MAJOR.MINOR.PATCH` base, an optional pre-release and optional build metadata. It
   refuses a string that does not begin with three numeric components, leading zeros, and any
   pre-release or metadata that is not dot-separated, non-empty identifiers of `[0-9A-Za-z-]` — the
   gate that keeps a version from naming a path outside the install layout. Beside it: `identity`
   (clause 10), `same_release`, and `precedence`, SemVer ordering with build metadata ignored, which
   the self-update's downgrade refusal ([ADR-0018](0018-the-client-updates-itself-under-its-own-agent-type.md)) and the
   rollout ([ADR-0025](0025-rollout-and-what-reaches-an-agent.md)) order by. It lives in
   `fleet-core` because the Client writes these strings and the Server displays them, and it is
   this project's grammar, not OpAMP's.

10. **A version's identity is its base and its pre-release; the build metadata is compared
    nowhere.** The self-update probe compares identities: `0.1.1` offered and `0.1.1+799e36a`
    reported match; `0.1.1` offered and `0.1.1-dev+799e36a` reported do not. The pre-release stays
    in the comparison because a `-dev` build is not the release it heads for, and the probe is the
    last gate that can say so before a fleet installs one. Two builds differing only by commit are
    the same release to the probe; the content hash is what distinguishes their bytes.

11. **An offered version with no parseable base fails the install**, naming the value. A value
    that is not a version cannot be compared to one.

12. **An operator names a release by its number.** `0.1.1` is the expected spelling wherever a
    version is typed; the full string is equivalent, since its identity is the same. Nothing has to
    be percent-encoded.

13. **The Server shows the identity and keeps the rest.** `AgentView.service_version` is the
    identity of what the Agent reported (the raw value when it is not a version), and
    `service_build` holds the complete string as reported. The bundled UI shows the former in its
    Version column and the latter on hover, and searches both.

14. **The full string is reported and recorded everywhere.** `service.version` on the wire carries
    all of it — provenance has to reach the Server for anyone to answer "which build is on that
    host". The version directory's `manifest.toml`, the self-update marker and `--version` output
    keep the full string too.

**Out of scope:** what a release builds and publishes (targets, artifacts, installers —
[ADR-0019](0019-the-client-supervisor-installed-service-releases-and-installers.md)); whether a Managed Process's
package version, free-form and an upstream project's own numbering, is parsed beyond what ordering
needs; release-candidate tags (`version/1.2.3-rc.1`), refused by the grammar until a
release-candidate flow is wanted.

## Alternatives considered

- **The tag as the only source of the version** — safe against drift, since nothing can disagree
  with it, but the number is then typed by hand into a ref nobody reviews, and `Cargo.toml` says
  something no binary reads.
- **`Cargo.toml` decides only what the pipeline releases, while `build.rs` derives the base from the
  nearest reachable tag** — with `Cargo.toml` at `0.1.0` and no tag yet, every binary would
  report `0.0.0-dev`. A version source no binary reads is not a version source, and a `-dev`
  that names the release a build descends from sorts misleadingly before it.
- **The pipeline writes `Cargo.toml` from a tag** — the same coupling in the other direction, and
  it needs the pipeline to commit to the branch during a release; a tag is immutable and
  inspectable, a commit changes the history a release was cut from.
- **Read `Cargo.toml` but leave tagging to a human** — keeps exactly the hand-typed tag that is the
  failure, and adds the file that can disagree with it.
- **Re-running a release by reusing a tag already on the commit** — harmless in the ordinary case,
  but a green run could overwrite artifacts already downloaded, and it is the same tolerance under
  which a forgotten bump releases nothing and says nothing.
- **Raw `git describe` output** (`1.2.3-4-ga1b2c3d`) — its suffix lands in the pre-release position
  with surprising ordering and duplicates what the `+` metadata carries.
- **Shelling out to `git` from `build.rs`** — needs no build-dependency, but every build then
  depends on a `git` executable on `PATH` and on parsing localised output.
- **`vergen`** — a framework for `build.rs` stamping that knows nothing of the `version/*` contract,
  which would still need custom code on top. **`gix`** — pure Rust but a large, fast-moving API;
  `git2`'s is small and stable, and libgit2 is vendored into the build script only, so this
  project's no-system-libraries posture is not touched.
- **A date in the build metadata** — the commit already pins the source state; a commit date
  lengthens every identifier and adds no identity, and a build date breaks reproducibility.
- **Reading the version at runtime** — the reported version would describe the deployment, and a
  copied binary would change identity.
- **A second `build.rs` in `crates/fleet-server`, or an `include!`d shared fragment** — duplicates the tag
  grammar and the failure modes where they can drift. **A crate holding only build support** — a
  further crate for one function, where a shared crate already sits between the two ends
  ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md)). **The
  resolution in the `opamp` crate** — a crate fetched from a registry is never inside a git
  checkout, so it would not build for anyone else (ADR-0010).
- **Keep comparing the full string and document `%2B`** — treats an unusable interface as a
  training problem.
- **Compare the base only, dropping the pre-release too** — would let an offer of `0.1.1` be
  satisfied by a `0.1.1-dev` build at the only gate that inspects a binary before a fleet runs it.
- **The Client reports only the base** — throws away the answer to "which build is on that host".
- **Leave `service_version` holding the full string and add a base field beside it** — leaves a
  field called `service_version` holding something nobody would call a version.
- **Name the variables for this project (`OPAMP_FLEET_VERSION`, `OPAMP_BUILD_VERSION`)** — a
  variant build (ADR-0019 clause 2) would set a variable that names a product it is not, and a
  *build* version beside a *fleet* version does not say which is the input and which the result.
  `OPAMP_PRODUCT_VERSION` and `OPAMP_PRODUCT_RELEASE` read as one pair.
- **No prefix (`PRODUCT_VERSION`)** — common in other toolchains, so an ambient value would set the
  version. `OPAMP_` is the prefix the build already uses for `OPAMP_BASELINE`
  ([ADR-0010](0010-five-crates-the-whole-opamp-communication-layer-in-the-opamp-crate-and-toml-configuration.md))
  and names the protocol, not the product, so it holds in every variant.

## Sources / Prior art

- [Semantic Versioning 2.0.0](https://semver.org/) — the `MAJOR.MINOR.PATCH` grammar, pre-release
  ordering (rule 11), and rule 10: build metadata MUST be ignored when determining precedence.
- [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html) —
  `cargo:rustc-env` sets a variable "for the compilation of the crate being built",
  `rerun-if-changed`, `rerun-if-env-changed`.
- [`cargo metadata`](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html) — reads the
  resolved package version, including `version.workspace = true`.
- [GitHub Actions: triggering a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
  — events triggered by `GITHUB_TOKEN` do not create a new workflow run.
- [`git2`](https://docs.rs/git2/) and [libgit2](https://libgit2.org/); the considered alternatives
  [gitoxide](https://github.com/GitoxideLabs/gitoxide) and [`vergen`](https://docs.rs/vergen/).
- [`git describe`](https://git-scm.com/docs/git-describe) — the exact-match semantics the tag
  lookup reproduces.
- [Reproducible builds: `SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/)
  — why nothing embedded in a binary depends on the build clock.
- [RFC 3986 §2.2](https://www.rfc-editor.org/rfc/rfc3986#section-2.2) and the
  `application/x-www-form-urlencoded` convention of `+` meaning a space in a query string.

## Consequences

- Positive: every binary is self-describing — number, `-dev` marker and commit — so a fleet
  report, a bug report or an install directory names the exact build, on both ends by the same
  rule. The same commit reproduces the same string. One number lives in the file a Rust developer
  already looks at, a release is "merge the bump, run the pipeline", and a mistyped tag cannot
  mint a release.
- Positive: a release is uploaded under the number it is called; the fleet table is scannable and
  still answers the provenance question on hover; `-dev` is enforced where a binary is accepted,
  not merely displayed.
- Negative / trade-offs: `git2` compiles vendored libgit2 for the build script, lengthening cold
  builds and requiring a C compiler on build hosts (which `ring` already requires); because the
  shared crate bakes the version, every commit rebuilds `fleet-core` and both binaries, and a
  Server-only build compiles libgit2 too. A build outside a git checkout fails.
- Negative / trade-offs: the drift between file and tag is caught rather than prevented; a
  forgotten bump is a failed run. A release cannot be re-run once its tag is pushed. The release
  run holds `contents: write`.
- Negative / trade-offs: the version string is long and contains `+`; any consumer that parses it
  must tolerate that (SemVer-conformant parsers do). Two builds of one release are the same release
  to the self-update probe; only the content hash tells their bytes apart.
- Follow-ups: whether CI should check that `Cargo.lock` carries the bumped version before a release
  is cut; whether the Server, published by no pipeline, is released under the same rule when it is.

## Enforcement

- `crates/fleet-core/src/version.rs` reads `OPAMP_PRODUCT_RELEASE` through `env!`, so a build
  script that emits another name fails the compilation, and the self-update end-to-end tests in
  `crates/fleet-agent/tests/self_update_e2e.rs` build their newer Client with
  `OPAMP_PRODUCT_VERSION` and fail when the override is not read, because that Client then reports
  no upgrade.
- `crates/fleet-core/build.rs` fails the build on a malformed `Cargo.toml` version or override, on a
  `version/*` tag on HEAD that names another version, and outside a git repository.
- `crates/fleet-core/src/version.rs` tests: `the_baked_version_has_the_prescribed_shape`,
  `takes_apart_the_shapes_this_project_produces`, `a_release_matches_the_build_that_carries_it`,
  `a_development_build_is_not_the_release_it_heads_for`, `different_releases_never_match`,
  `what_is_not_a_version_is_refused`, `a_version_that_would_escape_a_path_is_refused`,
  `leading_zeros_are_not_a_version`, `precedence_orders_versions_by_semver_rules`.
- `crates/fleet-server/tests/version_flag.rs` (`the_version_flag_prints_the_baked_version_and_nothing_of_its_own`,
  `the_baked_version_says_more_than_the_manifest_does`) and `crates/fleet-agent/src/cli.rs`
  `the_version_flag_reports_the_baked_in_version` hold both CLIs to `current()`.
- `crates/fleet-agent/src/update/installer.rs` probe tests: `the_probe_ignores_the_commit_a_build_came_from`,
  `the_probe_refuses_a_development_build_offered_as_a_release`,
  `the_probe_refuses_a_client_of_the_wrong_version`, `the_probe_refuses_an_offer_that_is_not_a_version`.
- `crates/fleet-server/src/fleet.rs` `the_displayed_version_drops_the_commit_and_keeps_the_pre_release`.
- The `version` job of [`.github/workflows/release.yml`](../../.github/workflows/release.yml): the
  steps *Read the version out of Cargo.toml*, *This version has not been released yet*, *Tag this
  commit* and *The binary agrees* implement clauses 6–8 and fail the run on violation.
