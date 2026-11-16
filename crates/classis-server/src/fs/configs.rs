//! Configurations on the filesystem (ADR-0025, ADR-0034): the default adapter behind
//! [`ConfigBackend`](crate::configs::ConfigBackend) — one JSON file per Configuration under
//! `<data_dir>/configurations/`, owner-only, written in one step (ADR-0037).

use std::path::PathBuf;

use crate::configs::{ConfigBackend, Configuration};

/// One JSON file per Configuration under `configurations/`, named after it.
pub struct FsConfigBackend {
    dir: PathBuf,
}

impl FsConfigBackend {
    /// Opens the store in the data directory `root`, creating `configurations/` owner-only.
    pub fn open(root: &std::path::Path) -> Result<Self, String> {
        let dir = root.join(super::CONFIGURATIONS);
        super::create_private_dir(&dir)?;
        Ok(FsConfigBackend { dir })
    }
}

/// Writes one Configuration into the `configurations/` directory `dir`, owner-only, in one step —
/// the write this store and a rollout's revisions (ADR-0037 clause 3) share.
pub(crate) fn write(dir: &std::path::Path, config: &Configuration) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(config).expect("a Configuration serializes");
    super::replace(&dir.join(format!("{}.json", config.name)), &json)
}

impl ConfigBackend for FsConfigBackend {
    /// A file that does not parse is a startup error that names it, and that includes a file in a
    /// shape this Server does not write: there is no legacy reader, so it is named rather than
    /// guessed at.
    fn load(&self) -> Result<Vec<Configuration>, String> {
        let mut configs = Vec::new();
        for (stem, path) in super::json_files(&self.dir)? {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            if names_a_selector(&value) {
                // The shape before ADR-0034: a Configuration aimed by itself. Read as content only,
                // it would silently reach nobody — or, put into a Deployment, other hosts than it
                // named — so it is refused and the operator decides where it belongs.
                return Err(format!(
                    "{} carries a selector, and a Configuration has none any more (ADR-0034): put \
                     it into a Deployment, whose Selector aims it, and remove the selector from \
                     the file; a data directory an older Server wrote is moved by `server migrate` \
                     (ADR-0037)",
                    path.display()
                ));
            }
            let config: Configuration = serde_json::from_value(value)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            if config.name != stem {
                return Err(super::misnamed(&path, "name"));
            }
            // A Configuration is written for one Agent type (ADR-0034 clause 1); one without it
            // would reach no Agent, so the operator saves it again with a type.
            crate::configs::check_type(&config.saved).map_err(|e| {
                format!(
                    "{}: {e} — save it again with the Agent type it is written for",
                    path.display()
                )
            })?;
            configs.push(config);
        }
        Ok(configs)
    }

    fn put(&self, config: &Configuration) -> Result<(), String> {
        write(&self.dir, config)
    }

    fn remove(&self, name: &str) -> Result<(), String> {
        super::remove_file(&self.dir.join(format!("{name}.json")))
    }
}

/// Whether a stored Configuration names a selector anywhere a revision could carry one: on the
/// record itself, on its saved revision, or on a retained one.
fn names_a_selector(value: &serde_json::Value) -> bool {
    let carries = |v: &serde_json::Value| v.get("selector").is_some();
    carries(value)
        || value.get("saved").is_some_and(carries)
        || value
            .get("retained")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|retained| retained.values().any(carries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::tests::{put_assigned, revision, with_role};
    use crate::configs::{ConfigStore, ROLE_SUPPLEMENTARY};

    fn open(dir: &std::path::Path) -> Result<ConfigStore, String> {
        ConfigStore::open(Box::new(FsConfigBackend::open(dir)?))
    }

    /// What one store wrote, a store opened on the same directory reads — assignments' pinned
    /// revisions included — and a deletion removes the file.
    #[test]
    fn the_store_round_trips_through_the_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open(dir.path()).expect("open");
        let assignments = put_assigned(&store, "base", revision("receivers: {}\n"));
        store
            .put_saved("other", revision("exporters: {}\n"))
            .expect("put");

        let reopened = open(dir.path()).expect("reopen");
        assert_eq!(reopened.list().len(), 2);
        assert_eq!(
            reopened.compose(&assignments).expect("pinned").entries[0].body,
            "receivers: {}\n"
        );
        assert!(reopened.delete("base").expect("delete"));
        assert!(!dir.path().join("configurations/base.json").exists());
        assert_eq!(open(dir.path()).expect("open").list().len(), 1);
    }

    /// No legacy reader: a file in a shape this Server does not write is a startup error that names
    /// the path, not a file quietly read as something else. The retired shapes are covered — a
    /// flat record, a two-revision one, and a saved or retained revision still carrying the
    /// selector a Configuration no longer has (ADR-0034).
    /// Verifies: ADR-0034
    #[test]
    fn a_file_in_a_retired_shape_refuses_to_open_and_names_it() {
        for (file, body) in [
            (
                "flat.json",
                r#"{"name":"flat","selector":{"os.type":"linux"},"body":"receivers: {}\n"}"#,
            ),
            (
                "staged.json",
                r#"{"name":"staged","draft":{"body":"v2\n"},"published":{"body":"v1\n"}}"#,
            ),
            (
                "aimed.json",
                r#"{"name":"aimed","saved":{"selector":{"os.type":"linux"},"body":"v1\n"}}"#,
            ),
            (
                "pinned.json",
                r#"{"name":"pinned","saved":{"body":"v2\n"},"retained":{"ab":{"selector":{},"body":"v1\n"}}}"#,
            ),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir_all(dir.path().join("configurations")).expect("dir");
            std::fs::write(dir.path().join("configurations").join(file), body)
                .expect("write the retired shape");

            let error = open(dir.path())
                .map(|_| ())
                .expect_err("a retired shape is refused, never guessed at");
            assert!(
                error.contains(file),
                "the error must name the file an operator has to deal with, got: {error}"
            );
            if file == "aimed.json" || file == "pinned.json" {
                assert!(
                    error.contains("selector") && error.contains("Deployment"),
                    "the refusal says where the aim went: {error}"
                );
            }
        }
    }

    /// A stored Configuration without an Agent type fails the start, naming its file
    /// (ADR-0034 clause 1).
    /// Verifies: ADR-0034
    #[test]
    fn a_stored_configuration_without_a_type_refuses_to_open_and_names_it() {
        for body in [
            r#"{"name":"untyped","saved":{"body":"receivers: {}\n"}}"#,
            r#"{"name":"untyped","saved":{"body":"receivers: {}\n","service_name":""}}"#,
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::create_dir_all(dir.path().join("configurations")).expect("dir");
            std::fs::write(dir.path().join("configurations/untyped.json"), body).expect("write");

            let error = open(dir.path())
                .map(|_| ())
                .expect_err("an untyped Configuration is refused");
            assert!(
                error.contains("untyped.json") && error.contains("service_name"),
                "the error names the file and the field: {error}"
            );
        }
    }

    #[test]
    fn a_role_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open(dir.path()).expect("open");
        put_assigned(
            &store,
            "certs",
            with_role(revision("PEM\n"), ROLE_SUPPLEMENTARY),
        );
        let reopened = open(dir.path()).expect("reopen");
        assert_eq!(
            reopened.get("certs").expect("certs").saved.role,
            ROLE_SUPPLEMENTARY
        );
    }
}
