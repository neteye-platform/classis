//! The wire: one JSON object each way per connection. The types only; the
//! encoding is done at the edges.

use serde::{Deserialize, Serialize};

/// The most bytes a request or an answer may hold. A reader stops one byte past it.
pub const MAX_MESSAGE_BYTES: u64 = 64 * 1024;

/// Where `classis-cli` looks for the Server's socket unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/classis/admin.sock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "kebab-case")]
pub enum Request {
    SpaceCreate { name: String },
    SpaceList,
    SpaceRotateKey { name: String },
    EnrolCommand { space: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "kebab-case")]
pub enum Response {
    Key { key: String },
    Names { names: Vec<String> },
    Enrol { endpoint: String, key: String },
    Refused { message: String },
}
