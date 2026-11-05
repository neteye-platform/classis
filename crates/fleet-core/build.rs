// The version this build reports (ADR-0012), baked in as
// `OPAMP_PRODUCT_RELEASE` and read back through `fleet_core::version::current`.
//
// It lives in the crate both binaries already depend on because ADR-0012 asks for a *single* helper
// that every surface reads, and `cargo:rustc-env` reaches only the crate whose script emitted it: a
// second copy in either binary would be a second implementation of the same rule, free to drift
// from this one.

use git2::Repository;

const TAG_PREFIX: &str = "version/";

fn main() {
    println!("cargo:rerun-if-env-changed=OPAMP_PRODUCT_VERSION");
    match resolve_version() {
        Ok(version) => println!("cargo:rustc-env=OPAMP_PRODUCT_RELEASE={version}"),
        Err(e) => {
            eprintln!("cannot resolve the build version: {e}");
            std::process::exit(1);
        }
    }
}

// The **base** is `[workspace.package] version` from `Cargo.toml`, which Cargo hands this script as
// `CARGO_PKG_VERSION`; `OPAMP_PRODUCT_VERSION` overrides it for builds that want to state a version
// explicitly. Git decides only what is *around* that number:
//
// - a `version/<base>` tag pointing at HEAD — a **release** build: the base as it stands;
// - no such tag — a **development** build: the base plus the `-dev` pre-release, so a build heading
//   for a release is unmistakably not it;
// - a `version/*` tag on HEAD naming a **different** version — a disagreement between the file and
//   the tag, which fails the build rather than picking one.
//
// The commit short-hash is appended as SemVer build metadata whenever a repository is present, so
// the same commit always reproduces the byte-identical version string. Nothing time-dependent goes
// into it. A malformed version fails the build (fail closed) rather than being guessed at.

fn resolve_version() -> Result<String, String> {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").map_err(|e| format!("CARGO_MANIFEST_DIR: {e}"))?;
    let repo = Repository::discover(&manifest_dir).ok();
    if let Some(repo) = &repo {
        // The version changes with the checked-out commit and with tag edits.
        println!(
            "cargo:rerun-if-changed={}",
            repo.path().join("HEAD").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repo.path().join("refs").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            repo.path().join("packed-refs").display()
        );
    }

    // The number itself, from the file that decides it (ADR-0012) or from the override.
    let (base, source) = match std::env::var("OPAMP_PRODUCT_VERSION") {
        Ok(raw) => (
            parse_components(&raw).ok_or_else(|| {
                format!("OPAMP_PRODUCT_VERSION {raw:?} is not a strict MAJOR.MINOR.PATCH version")
            })?,
            "OPAMP_PRODUCT_VERSION",
        ),
        Err(_) => {
            let raw = std::env::var("CARGO_PKG_VERSION")
                .map_err(|e| format!("CARGO_PKG_VERSION: {e}"))?;
            (
                parse_components(&raw).ok_or_else(|| {
                    format!(
                        "the version in Cargo.toml, {raw:?}, is not a strict MAJOR.MINOR.PATCH \
                         version (three integers, no pre-release, no metadata)"
                    )
                })?,
                "Cargo.toml",
            )
        }
    };

    // Outside a checkout there is no commit to cite and no way to tell a release from a development
    // build, which is a question the file cannot answer. Fail closed, naming the way out.
    let Some(repo) = repo else {
        return Err(format!(
            "not inside a git repository, so this build cannot tell whether {base} (from {source}) \
             is released; set OPAMP_PRODUCT_VERSION=MAJOR.MINOR.PATCH to state it"
        ));
    };
    let hash = short_hash(&repo)?;

    match release_tag_on_head(&repo)? {
        // The tag agrees with the file: this commit *is* the release it says it is.
        Some(tag) if parse_tag(&tag).as_deref() == Some(base.as_str()) => {
            Ok(format!("{base}+{hash}"))
        }
        // A tag on HEAD naming something else. One of the two is wrong and this build cannot know
        // which, so it says so instead of shipping a binary that disagrees with its own tag.
        Some(tag) => Err(format!(
            "HEAD carries the tag {tag:?} but {source} says {base} — a release tag and the version \
             it releases must be the same"
        )),
        // No release tag here: a build on the way to `base`, and unmistakably not it.
        None => Ok(format!("{base}-dev+{hash}")),
    }
}

/// The abbreviated commit id of HEAD: the first 7 hex characters of the full hash.
fn short_hash(repo: &Repository) -> Result<String, String> {
    let head = repo
        .head()
        .and_then(|r| r.peel_to_commit())
        .map_err(|e| format!("cannot resolve HEAD: {e}"))?;
    Ok(head.id().to_string()[..7].to_string())
}

/// A `version/*` tag pointing exactly at HEAD — the marker of a release build.
fn release_tag_on_head(repo: &Repository) -> Result<Option<String>, String> {
    let head = repo
        .head()
        .and_then(|r| r.peel_to_commit())
        .map_err(|e| format!("cannot resolve HEAD: {e}"))?
        .id();
    let refs = repo
        .references_glob(&format!("refs/tags/{TAG_PREFIX}*"))
        .map_err(|e| format!("cannot list version tags: {e}"))?;
    for reference in refs {
        let reference = reference.map_err(|e| format!("cannot read a version tag: {e}"))?;
        // Peeling covers both lightweight and annotated tags.
        if reference.peel_to_commit().map(|c| c.id()) == Ok(head) {
            if let Ok(name) = reference.name() {
                return Ok(Some(name.trim_start_matches("refs/tags/").to_string()));
            }
        }
    }
    Ok(None)
}

/// Strict parse of a `version/*` tag name into a normalised `MAJOR.MINOR.PATCH` string.
fn parse_tag(tag: &str) -> Option<String> {
    parse_components(tag.strip_prefix(TAG_PREFIX)?)
}

/// Strict SemVer core grammar (ADR-0012): exactly three non-negative integers without leading
/// zeros, separated by `.` or `/` (mixed permitted), normalised to dots. No pre-release, no
/// build metadata, no whitespace.
fn parse_components(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(['.', '/']).collect();
    if parts.len() != 3 {
        return None;
    }
    for part in &parts {
        let numeric = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        let no_leading_zero = *part == "0" || !part.starts_with('0');
        if !numeric || !no_leading_zero {
            return None;
        }
    }
    Some(parts.join("."))
}
