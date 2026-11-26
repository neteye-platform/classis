//! The Server's answer to `classis-cli`: the adapter that lets the socket server of
//! `classis-admin` reach the Spaces, and the binding of the socket itself.
//!
//! The adapter holds the running Server's [`Enrolment`] and asks it for its [`Spaces`] on every
//! request, so every rotation goes through the one instance whose lock orders it against the
//! registrations in flight. It never builds a `Spaces` of its own.
//!
//! [`Spaces`]: crate::spaces::Spaces

use std::io;
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use classis_admin::spaces::{Refusal, Spaces};

use crate::enrolment::Enrolment;
use crate::spaces::SpaceError;

/// The operator's view of the Server's Spaces.
pub struct AdminSpaces {
    enrolment: Arc<Enrolment>,
    public_url: Option<String>,
}

impl AdminSpaces {
    /// The Spaces of `enrolment`, the one the running Server holds, and the `public_url` its
    /// configuration was loaded with, which is what `enrol-command` prints its command against.
    #[must_use]
    pub fn new(enrolment: Arc<Enrolment>, public_url: Option<String>) -> Self {
        AdminSpaces {
            enrolment,
            public_url,
        }
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
        let Some(url) = self.public_url.clone() else {
            return Err(Refusal(
                "the public endpoint hosts reach the Server at is not configured yet".into(),
            ));
        };
        Ok(url)
    }
}

fn protected_directory(path: &Path, owner: u32, socket_parent: bool) -> io::Result<()> {
    let found = std::fs::symlink_metadata(path)?;
    let mode = found.mode();
    let trusted_owner = found.uid() == owner || found.uid() == 0;
    let protected = mode & 0o022 == 0 || (!socket_parent && mode & 0o1000 != 0);
    if !found.is_dir() || !trusted_owner || !protected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a protected socket directory", path.display()),
        ));
    }
    Ok(())
}

fn prepare_parent(parent: &Path, owner: u32) -> io::Result<PathBuf> {
    let mut existing = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    let mut missing = Vec::new();
    let canonical = loop {
        match std::fs::canonicalize(&existing) {
            Ok(path) => break path,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let name = existing.file_name().ok_or(e)?.to_os_string();
                missing.push(name);
                existing.pop();
            }
            Err(e) => return Err(e),
        }
    };
    for directory in canonical.ancestors().collect::<Vec<_>>().into_iter().rev() {
        protected_directory(
            directory,
            owner,
            missing.is_empty() && directory == canonical,
        )?;
    }
    let mut directory = canonical;
    for name in missing.into_iter().rev() {
        directory.push(name);
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        protected_directory(&directory, owner, true)?;
    }
    Ok(directory)
}

/// Binds the operator's socket at `path`.
///
/// A missing parent and its ancestors are created owner-only. Existing directories are left as
/// they are and must be protected from replacement by other accounts. A stale socket is replaced;
/// a live socket and anything else at the path are left untouched.
///
/// # Errors
/// Returns an error when the directory is unsafe or the socket cannot be bound.
pub fn bind(path: &Path) -> io::Result<classis_admin::server::Listener> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "the socket needs a file name")
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = prepare_parent(parent, classis_admin::server::effective_uid()?)?;
    let socket = parent.join(name);
    match std::fs::symlink_metadata(&socket) {
        Ok(found) if found.file_type().is_socket() => {
            match std::os::unix::net::UnixStream::connect(&socket) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is already in use", path.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(&socket)?;
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
    classis_admin::server::bind(&socket)
}
