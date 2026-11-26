//! The port the socket server answers through.

use std::fmt;

/// Why the Server will not do what was asked, in words for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What `classis-cli` can ask of the Server's Spaces.
///
/// This trait is the CLI's own port. The enrolment store may implement it through an adapter, but
/// it is not the storage interface of the enrolment key and must not become it. The methods are
/// blocking: the server calls them off the async runtime.
pub trait Spaces: Send + Sync + 'static {
    /// Creates the Space `name` and returns its enrolment key.
    fn create(&self, name: &str) -> Result<String, Refusal>;

    /// The names of the Spaces.
    fn list(&self) -> Result<Vec<String>, Refusal>;

    /// Replaces the key of the Space `name` and returns the new one.
    fn rotate_key(&self, name: &str) -> Result<String, Refusal>;

    /// The current key of the Space `name`.
    fn key(&self, name: &str) -> Result<String, Refusal>;

    /// The public endpoint hosts reach the Server at.
    fn endpoint(&self) -> Result<String, Refusal>;
}
