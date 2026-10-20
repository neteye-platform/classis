//! Deployments on the filesystem (ADR-0026): the default adapter behind
//! [`DeploymentBackend`](crate::deployments::DeploymentBackend).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::configs::validate_name;
use crate::deployments::{check_selector, Deployment, DeploymentBackend};
use crate::packages::PackageId;

/// One JSON file per Deployment under `<data_dir>/deployments/`, owner-only (ADR-0037).
pub struct FsDeploymentBackend {
    dir: PathBuf,
}

impl FsDeploymentBackend {
    /// Opens the store in the data directory `root`, creating `deployments/` owner-only.
    pub fn open(root: &std::path::Path) -> Result<Self, String> {
        let dir = root.join(super::DEPLOYMENTS);
        super::create_private_dir(&dir)?;
        Ok(FsDeploymentBackend { dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }
}

impl DeploymentBackend for FsDeploymentBackend {
    fn load(&self) -> Result<Vec<Deployment>, String> {
        let mut deployments = Vec::new();
        for (stem, path) in super::json_files(&self.dir)? {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let meta: DeploymentMeta = serde_json::from_str(&text)
                .map_err(|e| format!("cannot parse {}: {e}", path.display()))?;
            let deployment = meta.into_deployment(&path)?;
            // The file name is derived from the name; a mismatch means a write would land
            // somewhere else, so it is refused rather than silently corrected.
            if stem != deployment.name {
                return Err(super::misnamed(&path, "name"));
            }
            deployments.push(deployment);
        }
        Ok(deployments)
    }

    fn put(&self, deployment: &Deployment) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&DeploymentMeta::of(deployment))
            .expect("deployment serializes");
        // Owner-only, like the directory: a Selector says which hosts an operator considers a
        // channel, which is not another local user's business.
        super::replace_owner_only(&self.path(&deployment.name), &bytes)
    }

    fn remove(&self, name: &str) -> Result<(), String> {
        super::remove_file(&self.path(name))
    }
}

/// A Deployment as persisted: `<data_dir>/deployments/<name>.json`. Unknown fields are refused, so a
/// file an older Server wrote — with `signatures` beside its Packages — is named rather than read
/// as something it is not: `server migrate` moves it (ADR-0037).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentMeta {
    name: String,
    selector: BTreeMap<String, String>,
    #[serde(default)]
    packages: Vec<PackageRefMeta>,
    /// The Configurations it holds, by name (ADR-0034). Absent in a file that holds none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    configurations: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct PackageRefMeta {
    agent_type: String,
    version: String,
}

impl DeploymentMeta {
    fn of(deployment: &Deployment) -> Self {
        DeploymentMeta {
            name: deployment.name.clone(),
            selector: deployment.selector.clone(),
            packages: deployment
                .packages
                .values()
                .map(|id| PackageRefMeta {
                    agent_type: id.agent_type.clone(),
                    version: id.version.clone(),
                })
                .collect(),
            configurations: deployment.configurations.iter().cloned().collect(),
        }
    }

    fn into_deployment(self, path: &std::path::Path) -> Result<Deployment, String> {
        let named = |e: String| format!("invalid deployment in {}: {e}", path.display());
        validate_name(&self.name).map_err(|e| named(format!("name {:?}: {e}", self.name)))?;
        check_selector(&self.selector).map_err(named)?;
        let mut packages = BTreeMap::new();
        for reference in self.packages {
            let id = PackageId::load(&reference.agent_type, &reference.version).map_err(named)?;
            packages.insert(id.agent_type.clone(), id);
        }
        let mut configurations = BTreeSet::new();
        for configuration in self.configurations {
            validate_name(&configuration)
                .map_err(|e| named(format!("configuration {configuration:?}: {e}")))?;
            configurations.insert(configuration);
        }
        Ok(Deployment {
            name: self.name,
            selector: self.selector,
            packages,
            configurations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployments::tests::{channel, id};
    use crate::deployments::DeploymentStore;

    fn open(dir: &std::path::Path) -> Result<DeploymentStore, String> {
        DeploymentStore::open(Box::new(FsDeploymentBackend::open(dir)?))
    }

    /// The whole store survives a reopen.
    /// Verifies: ADR-0026, ADR-0034
    #[test]
    fn a_deployment_survives_a_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let telegraf = id("telegraf", "1.30.0");
        {
            let store = open(dir.path()).expect("open");
            channel(&store, "canary", &[("channel", "canary"), ("env", "prod")]);
            store
                .put_package("canary", &telegraf, false)
                .expect("package");
            store
                .put_configuration("canary", "base")
                .expect("configuration");
        }

        let reopened = open(dir.path()).expect("reopen");
        let canary = reopened.get("canary").expect("canary");
        assert_eq!(canary.selector["channel"], "canary");
        assert_eq!(canary.selector["env"], "prod");
        assert_eq!(canary.package_for("telegraf"), Some(&telegraf));
        assert_eq!(
            canary.configurations.iter().collect::<Vec<_>>(),
            ["base"],
            "the Configurations it holds survive too (ADR-0034)"
        );

        assert!(reopened.delete("canary").expect("delete"));
        assert!(!reopened
            .delete("canary")
            .expect("deleting twice is not an error"));
        assert!(open(dir.path()).expect("reopen").is_empty());
    }

    /// A file this Server did not write fails the open, naming it. A channel that silently vanished
    /// would withdraw nothing and offer nothing, and say neither.
    /// Verifies: ADR-0026
    #[test]
    fn an_unreadable_file_fails_the_open_and_names_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("deployments")).expect("dir");
        std::fs::write(dir.path().join("deployments/broken.json"), "{").expect("write");
        let error = open(dir.path()).map(|_| ()).expect_err("refused");
        assert!(error.contains("broken.json"), "{error}");

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("deployments")).expect("dir");
        std::fs::write(
            dir.path().join("deployments/stable.json"),
            r#"{"name":"canary","selector":{"channel":"canary"}}"#,
        )
        .expect("write");
        let error = open(dir.path())
            .map(|_| ())
            .expect_err("a file whose name disagrees with its content is refused");
        assert!(error.contains("stable.json"), "{error}");
    }

    /// The store is owner-only, and so is every file in it: a Selector says which hosts a fleet
    /// operator considers a channel, which is not another local user's business.
    /// Verifies: ADR-0026
    #[cfg(unix)]
    #[test]
    fn the_store_and_its_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open(dir.path()).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        assert_eq!(
            std::fs::metadata(dir.path().join("deployments"))
                .expect("dir")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("deployments/stable.json"))
                .expect("file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
