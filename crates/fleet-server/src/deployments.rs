//! Deployments (ADR-0026, ADR-0034): what reaches a channel of hosts, and the only thing rolled out.
//!
//! A Package is what an Agent type runs at a version, with each artifact's signature on its entry
//! (ADR-0033), and a Configuration is content (ADR-0034) — neither has an aim or an act of its
//! own. A Deployment carries a **name**, a **Selector** over the channel it addresses, **one
//! Package per Agent type**, and **any number of Configurations**. The Selector matching lives
//! here, because a Deployment is the one thing a Selector aims.
//!
//! Two rules give the object its shape, and both are refusals:
//!
//! **An Agent belongs to at most one Deployment.** Where two match, that is a conflict and the
//! Agent is offered nothing new — not the most specific, not the newest, none. ADR-0026's
//! specificity ranking is withdrawn with no successor: it decided "which artifact does this host
//! get" by a computation across every stored object, which is an answer no operator could read off
//! anything. A refusal that names both Deployments is worse for nobody and legible to everyone.
//!
//! **A Selector is never empty.** An empty one is the channel that collides with every other, and a
//! forgotten field would quietly become the base for the whole fleet — the class of accident
//! ADR-0025 exists to prevent. Channels are therefore a *partition*: a Selector cannot express
//! "not", so disjoint channels come from membership, which is what ADR-0024's labels already are.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use opamp::attributes;
use opamp::proto::AgentDescription;

use crate::configs::validate_name;
use crate::packages::PackageId;

/// Does this Selector match this Agent (ADR-0034 clause 2)? Equality, AND, over every string
/// attribute of the effective description — identifying and non-identifying alike. An array-valued
/// attribute never matches, and an Agent that has not described itself yet matches only the empty
/// Selector, which no Deployment carries.
pub fn matches(
    selector: &BTreeMap<String, String>,
    description: Option<&AgentDescription>,
) -> bool {
    if selector.is_empty() {
        return true;
    }
    let Some(description) = description else {
        return false;
    };
    selector.iter().all(|(key, value)| {
        attributes::string_value(&description.identifying_attributes, key)
            .or_else(|| attributes::string_value(&description.non_identifying_attributes, key))
            .is_some_and(|reported| reported == *value)
    })
}

/// A named release of Packages and Configurations, aimed at a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// The operator's name for this channel. The one human-chosen label in the model, which is why
    /// it keeps the ADR-0019 grammar a Package gave up (ADR-0026).
    pub name: String,
    /// Equality pairs that must all match an attribute the Agent reported, labels included
    /// (ADR-0034 clause 2). **Never empty** — see the module note.
    pub selector: BTreeMap<String, String>,
    /// At most one Package per Agent type, keyed by that type. Two of one type would collide on
    /// the wire map key *and* fit the same Agent, so the second is refused at the moment it is
    /// written rather than puzzled over at resolution.
    pub packages: BTreeMap<String, PackageId>,
    /// The Configurations it holds, by name, in any number (ADR-0034 clause 4). A Configuration
    /// may sit in several Deployments, as a Package may; each fits the Agents of its type.
    pub configurations: BTreeSet<String>,
}

impl Deployment {
    /// The Package this Deployment holds for an Agent of `agent_type`, if any.
    pub fn package_for(&self, agent_type: &str) -> Option<&PackageId> {
        self.packages.get(agent_type)
    }

    /// Whether it holds nothing to release — no Package and no Configuration — which a rollout
    /// act refuses (ADR-0034 clause 6).
    pub fn holds_nothing(&self) -> bool {
        self.packages.is_empty() && self.configurations.is_empty()
    }
}

/// Why a write against a Deployment was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum DeploymentError {
    /// The name, the Selector, or an identity did not pass its grammar — a `400`.
    Invalid(String),
    /// No Deployment of that name, or it holds no such Package — a `404`.
    NotFound,
    /// Something the write names does not exist, or the Deployment does not hold it — also a
    /// `404`, saying which.
    Missing(String),
    /// The Deployment already holds a Package for that Agent type — a `409`.
    TypeTaken { agent_type: String, held: PackageId },
    /// The write collides with what this channel has already released — also a `409`.
    Conflict(String),
    /// The store could not be written.
    Storage(String),
}

impl std::fmt::Display for DeploymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeploymentError::Invalid(why)
            | DeploymentError::Missing(why)
            | DeploymentError::Conflict(why)
            | DeploymentError::Storage(why) => write!(f, "{why}"),
            DeploymentError::NotFound => write!(f, "no such deployment"),
            DeploymentError::TypeTaken { agent_type, held } => write!(
                f,
                "this deployment already holds {held} for Agent type {agent_type:?} — an Agent has \
                 one binary to replace, so remove that one first or use another deployment"
            ),
        }
    }
}

/// Whether a Selector may aim a Deployment: it must name at least one pair, and no pair may be
/// blank.
///
/// The emptiness rule is the load-bearing one. An empty Selector matches every Agent, so it would
/// collide with every other Deployment and make the one-Deployment-per-Agent rule unsatisfiable
/// the moment a second channel exists — and it is what a forgotten field looks like.
pub fn check_selector(selector: &BTreeMap<String, String>) -> Result<(), String> {
    if selector.is_empty() {
        return Err(
            "a deployment must name the channel it aims at: give its Selector at least one pair, \
             such as `channel = \"stable\"`, `region = \"eu-central\"` or `tenant = \"acme\"` \
             — the key is yours to invent, this Server prescribes none. There is no fleet-wide \
             default: two deployments matching one Agent is a conflict, and an empty Selector \
             matches everything"
                .to_string(),
        );
    }
    for (key, value) in selector {
        if key.trim().is_empty() || value.trim().is_empty() {
            return Err(format!(
                "the Selector pair {key:?} = {value:?} has an empty half — a Selector is equality \
                 over reported attributes, and neither side can be blank"
            ));
        }
    }
    Ok(())
}

/// The Deployment one Agent belongs to.
///
/// `Ok(None)` — no channel claims it; it waits, which after a fresh enrolment is the ordinary state.
/// `Err` — **two or more** claim it. That is the conflict, and the message names them all, because
/// a rollout that silently never starts is worse than one that explains itself.
pub fn deployment_for<'a>(
    deployments: &'a BTreeMap<String, Deployment>,
    description: Option<&AgentDescription>,
) -> Result<Option<&'a Deployment>, String> {
    let claiming: Vec<&Deployment> = deployments
        .values()
        .filter(|deployment| matches(&deployment.selector, description))
        .collect();
    match claiming.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        all => Err(format!(
            "deployments {} all match this Agent — an Agent belongs to at most one, so narrow \
             their Selectors until exactly one claims it",
            all.iter()
                .map(|d| format!("{:?}", d.name))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The Deployment store's port (ADR-0006): where Deployments persist. The filesystem adapter
/// ([`FsDeploymentBackend`](crate::fs::FsDeploymentBackend)) is what the composition root wires.
pub trait DeploymentBackend: Send + Sync {
    /// Every persisted Deployment, once, when the store opens. One that cannot be read fails the
    /// open and names where it is: a channel that silently vanished would withdraw nothing and
    /// offer nothing, and say neither (ADR-0010's principle).
    fn load(&self) -> Result<Vec<Deployment>, String>;

    /// Creates or replaces one Deployment, in one step.
    fn put(&self, deployment: &Deployment) -> Result<(), String>;

    /// Deletes one Deployment; removing what is already absent is not an error.
    fn remove(&self, name: &str) -> Result<(), String>;
}

/// The Deployments (ADR-0026), held in memory and persisted through a [`DeploymentBackend`].
pub struct DeploymentStore {
    backend: Box<dyn DeploymentBackend>,
    deployments: RwLock<BTreeMap<String, Deployment>>,
}

impl DeploymentStore {
    /// Opens the store on `backend`, loading every persisted Deployment.
    pub fn open(backend: Box<dyn DeploymentBackend>) -> Result<Self, String> {
        let deployments = backend
            .load()?
            .into_iter()
            .map(|deployment| (deployment.name.clone(), deployment))
            .collect();
        Ok(DeploymentStore {
            backend,
            deployments: RwLock::new(deployments),
        })
    }

    /// Every Deployment, in name order.
    pub fn list(&self) -> Vec<Deployment> {
        self.deployments
            .read()
            .expect("deployments lock")
            .values()
            .cloned()
            .collect()
    }

    /// One Deployment by name.
    pub fn get(&self, name: &str) -> Option<Deployment> {
        self.deployments
            .read()
            .expect("deployments lock")
            .get(name)
            .cloned()
    }

    /// A snapshot of the whole store, for one resolution pass.
    pub fn snapshot(&self) -> BTreeMap<String, Deployment> {
        self.deployments.read().expect("deployments lock").clone()
    }

    pub fn is_empty(&self) -> bool {
        self.deployments
            .read()
            .expect("deployments lock")
            .is_empty()
    }

    /// Creates a Deployment or replaces its Selector. Distributes nothing: a Deployment reaches an
    /// Agent only through a rollout act (ADR-0025), and this is the save.
    pub fn put(
        &self,
        name: &str,
        selector: BTreeMap<String, String>,
    ) -> Result<Deployment, DeploymentError> {
        validate_name(name)
            .map_err(|e| DeploymentError::Invalid(format!("invalid name {name:?}: {e}")))?;
        check_selector(&selector).map_err(DeploymentError::Invalid)?;
        let mut deployments = self.deployments.write().expect("deployments lock");
        let deployment = match deployments.get(name) {
            Some(existing) => Deployment {
                selector,
                ..existing.clone()
            },
            None => Deployment {
                name: name.to_string(),
                selector,
                packages: BTreeMap::new(),
                configurations: BTreeSet::new(),
            },
        };
        self.write(&deployment)?;
        deployments.insert(name.to_string(), deployment.clone());
        Ok(deployment)
    }

    /// Adds a Package to a Deployment, or replaces the one held for its Agent type when `replace`
    /// is set. Without `replace`, a type already held is refused by name (ADR-0026 point 23).
    pub fn put_package(
        &self,
        name: &str,
        id: &PackageId,
        replace: bool,
    ) -> Result<Deployment, DeploymentError> {
        self.amend(name, |deployment| {
            if !replace {
                if let Some(held) = deployment.packages.get(&id.agent_type) {
                    if held != id {
                        return Err(DeploymentError::TypeTaken {
                            agent_type: id.agent_type.clone(),
                            held: held.clone(),
                        });
                    }
                }
            }
            deployment
                .packages
                .insert(id.agent_type.clone(), id.clone());
            Ok(())
        })
    }

    /// Removes a Package from a Deployment.
    pub fn remove_package(
        &self,
        name: &str,
        id: &PackageId,
    ) -> Result<Deployment, DeploymentError> {
        self.amend(name, |deployment| {
            if deployment.packages.get(&id.agent_type) != Some(id) {
                return Err(DeploymentError::NotFound);
            }
            deployment.packages.remove(&id.agent_type);
            Ok(())
        })
    }

    /// Puts a Configuration into a Deployment; holding it already is the request arriving twice.
    /// Whether the Configuration exists is the caller's question — the fleet asks it.
    pub fn put_configuration(
        &self,
        name: &str,
        configuration: &str,
    ) -> Result<Deployment, DeploymentError> {
        self.amend(name, |deployment| {
            deployment.configurations.insert(configuration.to_string());
            Ok(())
        })
    }

    /// Takes a Configuration out of a Deployment; one it does not hold is `Missing`.
    pub fn remove_configuration(
        &self,
        name: &str,
        configuration: &str,
    ) -> Result<Deployment, DeploymentError> {
        self.amend(name, |deployment| {
            if !deployment.configurations.remove(configuration) {
                return Err(DeploymentError::Missing(format!(
                    "deployment {name:?} does not hold configuration {configuration:?}"
                )));
            }
            Ok(())
        })
    }

    /// Takes a deleted Configuration out of every Deployment that held it (ADR-0034 clause 8),
    /// and answers which those were.
    pub fn drop_configuration(&self, configuration: &str) -> Result<Vec<String>, DeploymentError> {
        self.drop_everywhere(|deployment| deployment.configurations.remove(configuration))
    }

    /// Takes a deleted Package out of every Deployment that held it (ADR-0034 clause 8), and
    /// answers which those were.
    pub fn drop_package(&self, id: &PackageId) -> Result<Vec<String>, DeploymentError> {
        self.drop_everywhere(|deployment| {
            if deployment.packages.get(&id.agent_type) == Some(id) {
                deployment.packages.remove(&id.agent_type);
                true
            } else {
                false
            }
        })
    }

    /// Applies `drop` to every Deployment and persists each one it changed.
    fn drop_everywhere(
        &self,
        mut drop: impl FnMut(&mut Deployment) -> bool,
    ) -> Result<Vec<String>, DeploymentError> {
        let mut deployments = self.deployments.write().expect("deployments lock");
        let mut changed = Vec::new();
        for deployment in deployments.values_mut() {
            let mut edited = deployment.clone();
            if drop(&mut edited) {
                self.write(&edited)?;
                *deployment = edited;
                changed.push(deployment.name.clone());
            }
        }
        Ok(changed)
    }

    /// Deletes a Deployment. Whether anything still names it is the fleet's business, not the
    /// store's — the fleet refuses the delete while an assignment does.
    pub fn delete(&self, name: &str) -> Result<bool, DeploymentError> {
        let mut deployments = self.deployments.write().expect("deployments lock");
        if deployments.remove(name).is_none() {
            return Ok(false);
        }
        self.backend
            .remove(name)
            .map_err(DeploymentError::Storage)?;
        Ok(true)
    }

    /// Reads one Deployment, lets `change` edit a copy, persists it, and swaps it in — the single
    /// path every amendment goes through, so a refused edit never reaches the file or the map.
    fn amend(
        &self,
        name: &str,
        change: impl FnOnce(&mut Deployment) -> Result<(), DeploymentError>,
    ) -> Result<Deployment, DeploymentError> {
        let mut deployments = self.deployments.write().expect("deployments lock");
        let mut deployment = deployments
            .get(name)
            .ok_or(DeploymentError::NotFound)?
            .clone();
        change(&mut deployment)?;
        self.write(&deployment)?;
        deployments.insert(name.to_string(), deployment.clone());
        Ok(deployment)
    }

    fn write(&self, deployment: &Deployment) -> Result<(), DeploymentError> {
        self.backend
            .put(deployment)
            .map_err(DeploymentError::Storage)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The backend as memory: what a second store opened on a clone of it reads is what the
    /// first one wrote.
    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<BTreeMap<String, Deployment>>>);

    impl DeploymentBackend for Memory {
        fn load(&self) -> Result<Vec<Deployment>, String> {
            Ok(self.0.lock().expect("memory").values().cloned().collect())
        }

        fn put(&self, deployment: &Deployment) -> Result<(), String> {
            self.0
                .lock()
                .expect("memory")
                .insert(deployment.name.clone(), deployment.clone());
            Ok(())
        }

        fn remove(&self, name: &str) -> Result<(), String> {
            self.0.lock().expect("memory").remove(name);
            Ok(())
        }
    }

    fn agent(pairs: &[(&str, &str)]) -> AgentDescription {
        AgentDescription {
            identifying_attributes: Vec::new(),
            non_identifying_attributes: pairs
                .iter()
                .map(|(key, value)| opamp::attributes::string_attr(key, value))
                .collect(),
        }
    }

    pub(crate) fn channel(
        store: &DeploymentStore,
        name: &str,
        pairs: &[(&str, &str)],
    ) -> Deployment {
        let selector = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        store.put(name, selector).expect("put")
    }

    pub(crate) fn id(agent_type: &str, version: &str) -> PackageId {
        PackageId::new(agent_type, version).expect("package id")
    }

    /// An Agent belongs to at most one Deployment. Two claiming it is the conflict, and the
    /// message names **both** — a rollout that silently never starts is worse than one that says
    /// why (ADR-0026 point 26).
    /// Verifies: ADR-0026
    #[test]
    fn two_deployments_matching_one_agent_are_a_conflict_that_names_them() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        channel(&store, "linux-hosts", &[("os.type", "linux")]);
        let all = store.snapshot();

        let both = agent(&[("channel", "stable"), ("os.type", "linux")]);
        let error = deployment_for(&all, Some(&both)).expect_err("two claim it");
        assert!(
            error.contains("stable") && error.contains("linux-hosts"),
            "the reason names every deployment in the way: {error}"
        );

        let one = agent(&[("channel", "stable"), ("os.type", "windows")]);
        assert_eq!(
            deployment_for(&all, Some(&one))
                .expect("exactly one claims it")
                .map(|d| d.name.as_str()),
            Some("stable")
        );
    }

    /// Specificity does not break the tie, and that is the decision — not an oversight: neither
    /// Selector wins by being narrower (ADR-0026 clause 26).
    /// Verifies: ADR-0026
    #[test]
    fn a_narrower_selector_does_not_win_over_a_wider_one() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        channel(
            &store,
            "canary",
            &[("channel", "stable"), ("host.name", "edge-01")],
        );

        deployment_for(
            &store.snapshot(),
            Some(&agent(&[("channel", "stable"), ("host.name", "edge-01")])),
        )
        .expect_err("the narrower one does not win — both match, so neither is chosen");
    }

    /// An Agent no channel claims waits, and that is not an error: after a fresh enrolment it is the
    /// ordinary state (ADR-0026 point 25).
    /// Verifies: ADR-0026
    #[test]
    fn an_agent_no_ring_claims_is_not_a_conflict() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        assert_eq!(
            deployment_for(&store.snapshot(), Some(&agent(&[("os.type", "linux")])))
                .expect("no claim is not a conflict"),
            None
        );
        assert_eq!(
            deployment_for(&store.snapshot(), None).expect("nor is reporting nothing"),
            None
        );
    }

    /// An empty Selector is refused, and the message says what to write instead. It is the channel
    /// that collides with every other, and it is what a forgotten field looks like.
    /// Verifies: ADR-0026
    #[test]
    fn a_deployment_must_name_the_ring_it_aims_at() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        let refused = store
            .put("everyone", BTreeMap::new())
            .expect_err("an empty Selector is refused");
        assert!(
            matches!(&refused, DeploymentError::Invalid(why)
                if why.contains("channel") && why.contains("prescribes none")),
            "the refusal tells the operator what to write: {refused}"
        );
        assert!(store.is_empty(), "and nothing was stored");

        assert!(matches!(
            store.put(
                "blank",
                BTreeMap::from([("channel".to_string(), "  ".to_string())])
            ),
            Err(DeploymentError::Invalid(_))
        ));
    }

    /// One Package per Agent type, refused at the write rather than puzzled over at resolution —
    /// and the refusal names what is already held.
    /// Verifies: ADR-0026
    #[test]
    fn a_deployment_holds_one_package_per_agent_type() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        store
            .put_package("stable", &id("telegraf", "1.30.0"), false)
            .expect("the first of its type");
        store
            .put_package("stable", &id("supervisor", "0.4.5"), false)
            .expect("another type is another package");

        let refused = store
            .put_package("stable", &id("telegraf", "1.31.0"), false)
            .expect_err("a second telegraf is refused");
        assert!(
            matches!(&refused, DeploymentError::TypeTaken { held, .. } if held.version == "1.30.0"),
            "the refusal names what is in the way: {refused}"
        );

        // Writing the same one again is not a collision — it is the request arriving twice.
        store
            .put_package("stable", &id("telegraf", "1.30.0"), false)
            .expect("idempotent");
        // And replacing is what the operator asks for explicitly.
        let replaced = store
            .put_package("stable", &id("telegraf", "1.31.0"), true)
            .expect("replace");
        assert_eq!(
            replaced.package_for("telegraf"),
            Some(&id("telegraf", "1.31.0"))
        );
    }

    /// Removing a Package takes it out of the channel, and only that: the Deployment holds no
    /// signature of its own to leave behind (ADR-0033). A Package it does not hold is `NotFound`.
    /// Verifies: ADR-0033
    #[test]
    fn removing_a_package_takes_it_out_of_the_channel() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        let telegraf = id("telegraf", "1.30.0");
        assert_eq!(
            store.remove_package("stable", &telegraf),
            Err(DeploymentError::NotFound),
            "a package this channel does not hold"
        );
        store
            .put_package("stable", &telegraf, false)
            .expect("package");
        let stripped = store
            .remove_package("stable", &telegraf)
            .expect("remove the package");
        assert!(stripped.packages.is_empty());
    }

    /// Editing the Selector is not editing the bytes: a Deployment's aim stays writable, and
    /// changing it keeps everything the channel holds.
    /// Verifies: ADR-0026
    #[test]
    fn the_selector_stays_editable_and_keeps_what_the_ring_holds() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        let telegraf = id("telegraf", "1.30.0");
        channel(&store, "canary", &[("channel", "canary")]);
        store
            .put_package("canary", &telegraf, false)
            .expect("package");

        let widened = channel(&store, "canary", &[("channel", "stable")]);
        assert_eq!(widened.selector["channel"], "stable");
        assert_eq!(widened.package_for("telegraf"), Some(&telegraf));
    }

    fn described(pairs: &[(&str, &str)]) -> AgentDescription {
        AgentDescription {
            identifying_attributes: pairs
                .iter()
                .map(|(k, v)| attributes::string_attr(k, v))
                .collect(),
            non_identifying_attributes: vec![],
        }
    }

    fn selector(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_empty_selector_matches_everything_even_an_undescribed_agent() {
        assert!(matches(&BTreeMap::new(), None));
        assert!(matches(&BTreeMap::new(), Some(&described(&[]))));
    }

    /// ADR-0034 clause 2: equality, AND, over the effective description.
    /// Verifies: ADR-0034
    #[test]
    fn every_selector_pair_must_equal_a_reported_attribute() {
        let desc = described(&[("service.name", "otelcol"), ("os.type", "linux")]);
        let one = selector(&[("os.type", "linux")]);
        let both = selector(&[("os.type", "linux"), ("service.name", "otelcol")]);
        let wrong = selector(&[("os.type", "windows")]);
        let extra = selector(&[("os.type", "linux"), ("env", "prod")]);
        assert!(matches(&one, Some(&desc)));
        assert!(matches(&both, Some(&desc)));
        assert!(!matches(&wrong, Some(&desc)));
        assert!(
            !matches(&extra, Some(&desc)),
            "an unreported key never matches"
        );
        assert!(
            !matches(&one, None),
            "no description matches only the empty Selector"
        );
    }

    #[test]
    fn non_identifying_attributes_match_too() {
        let desc = AgentDescription {
            identifying_attributes: vec![],
            non_identifying_attributes: described(&[("env", "prod")]).identifying_attributes,
        };
        assert!(matches(&selector(&[("env", "prod")]), Some(&desc)));
    }

    /// A Deployment holds Configurations by name beside its Packages, in any number, and one
    /// Configuration may sit in several Deployments (ADR-0034 clause 4). Taking out one it does not
    /// hold says so; a deleted Configuration or Package leaves every Deployment that held it
    /// (clause 8).
    /// Verifies: ADR-0034
    #[test]
    fn a_deployment_holds_configurations_beside_its_packages() {
        let memory = Memory::default();
        let store = DeploymentStore::open(Box::new(memory.clone())).expect("open");
        channel(&store, "stable", &[("channel", "stable")]);
        channel(&store, "canary", &[("channel", "canary")]);
        let telegraf = id("telegraf", "1.30.0");
        store
            .put_package("stable", &telegraf, false)
            .expect("package");
        assert!(!store.get("stable").expect("stable").holds_nothing());
        assert!(store.get("canary").expect("canary").holds_nothing());

        for name in ["stable", "canary"] {
            store.put_configuration(name, "base").expect("hold base");
        }
        store
            .put_configuration("stable", "base")
            .expect("holding it twice is the request arriving twice");
        store.put_configuration("stable", "extra").expect("extra");
        assert_eq!(
            store
                .get("stable")
                .expect("stable")
                .configurations
                .into_iter()
                .collect::<Vec<_>>(),
            ["base", "extra"]
        );
        assert!(matches!(
            store.put_configuration("missing", "base"),
            Err(DeploymentError::NotFound)
        ));
        assert!(matches!(
            store.remove_configuration("canary", "extra"),
            Err(DeploymentError::Missing(why)) if why.contains("extra")
        ));

        assert_eq!(
            store.drop_configuration("base").expect("drop"),
            ["canary", "stable"],
            "a deleted Configuration leaves every Deployment that held it"
        );
        assert_eq!(store.drop_package(&telegraf).expect("drop"), ["stable"]);
        let stable = store.get("stable").expect("stable");
        assert!(stable.packages.is_empty());
        assert_eq!(
            stable.configurations.into_iter().collect::<Vec<_>>(),
            ["extra"]
        );
        let reopened = DeploymentStore::open(Box::new(memory)).expect("reopen");
        assert!(reopened.get("canary").expect("canary").holds_nothing());
    }
}
