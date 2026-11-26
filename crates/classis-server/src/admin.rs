//! The Server's answer to `classis-cli`: the adapter that lets the socket server of
//! `classis-admin` reach the Spaces, and the binding of the socket itself.
//!
//! The adapter holds the running Server's [`Enrolment`] and asks it for its [`Spaces`] on every
//! request, so every rotation goes through the one instance whose lock orders it against the
//! registrations in flight. It never builds a `Spaces` of its own.
//!
//! [`Spaces`]: crate::spaces::Spaces

use std::io;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::Arc;

use classis_admin::spaces::{Refusal, Spaces};
use tokio::net::UnixListener;

use crate::enrolment::Enrolment;
use crate::spaces::SpaceError;

/// The operator's view of the Server's Spaces.
pub struct AdminSpaces {
    enrolment: Arc<Enrolment>,
}

impl AdminSpaces {
    /// The Spaces of `enrolment`, the one the running Server holds.
    #[must_use]
    pub fn new(enrolment: Arc<Enrolment>) -> Self {
        AdminSpaces { enrolment }
    }
}

fn refusal(error: SpaceError) -> Refusal {
    Refusal(error.to_string())
}

impl Spaces for AdminSpaces {
    fn create(&self, name: &str) -> Result<String, Refusal> {
        self.enrolment
            .spaces()
            .create(name)
            .map(|key| key.to_string())
            .map_err(refusal)
    }

    fn list(&self) -> Result<Vec<String>, Refusal> {
        self.enrolment.spaces().list().map_err(refusal)
    }

    fn rotate_key(&self, name: &str) -> Result<String, Refusal> {
        self.enrolment
            .spaces()
            .rotate(name)
            .map(|key| key.to_string())
            .map_err(refusal)
    }

    fn key(&self, name: &str) -> Result<String, Refusal> {
        self.enrolment
            .spaces()
            .key(name)
            .map(|key| key.to_string())
            .map_err(refusal)
    }

    fn endpoint(&self) -> Result<String, Refusal> {
        Err(Refusal(
            "the public endpoint hosts reach the Server at is not configured yet".into(),
        ))
    }
}

/// Binds the operator's socket at `path`.
///
/// A missing parent directory is created, with its missing ancestors, and the parent is made
/// owner-only; an existing directory is left as it is. A socket left by an earlier run is
/// replaced, but a live socket and anything else at the path are left untouched.
///
/// # Errors
/// Returns an error naming `path` when a live socket or a non-socket stands at it, and the
/// operating system's error when a directory or the socket cannot be created.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is already in use", path.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    classis_admin::server::bind(path)
}
