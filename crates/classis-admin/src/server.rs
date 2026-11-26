//! The Server's side of the socket: binds a Unix domain socket and
//! answers one request per connection through `Spaces`. Nothing here logs a key.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::protocol::{Request, Response, MAX_MESSAGE_BYTES};
use crate::spaces::Spaces;

/// A bound socket and the uid of the account that owns it: every peer is admitted against that uid,
/// recorded at the bind, and never against the path.
#[derive(Debug)]
pub struct Listener {
    listener: UnixListener,
    owner: u32,
}

/// Returns the effective user ID of this process.
///
/// # Errors
/// Returns the operating system's error if peer credentials cannot be read.
pub fn effective_uid() -> io::Result<u32> {
    let (stream, _peer) = UnixStream::pair()?;
    Ok(stream.peer_cred()?.uid())
}

/// Binds the socket at `path` and restricts it to its owner.
pub fn bind(path: &Path) -> io::Result<Listener> {
    let owner = effective_uid()?;
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Listener { listener, owner })
}

/// Answers connections on the socket, one task per connection. A failed accept is logged and
/// retried: it must not leave the operator without a socket while both planes run on.
pub async fn serve(listener: Listener, spaces: Arc<dyn Spaces>) -> io::Result<()> {
    let Listener { listener, owner } = listener;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let spaces = Arc::clone(&spaces);
                tokio::spawn(async move {
                    // A connection that breaks has no one left to tell.
                    let _ = answer(stream, spaces, owner).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot accept a connection on the operator's socket");
                // Out of descriptors, typically: do not spin on it.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Whether a peer's account is served: the socket's owner, or root, whose `sudo classis-cli` is how
/// an operator who is not the Server's account reaches it.
///
/// # Errors
/// Returns why the peer is refused.
pub fn admit(peer_uid: u32, owner: u32) -> Result<(), String> {
    if peer_uid == owner || peer_uid == 0 {
        Ok(())
    } else {
        Err(format!(
            "uid {peer_uid} is neither the socket's owner nor root"
        ))
    }
}

async fn answer(mut stream: UnixStream, spaces: Arc<dyn Spaces>, owner: u32) -> io::Result<()> {
    // Security: the peer's account decides before a byte of its request is read.
    let admission = stream
        .peer_cred()
        .map_err(|e| format!("cannot read the peer's credentials: {e}"))
        .and_then(|cred| admit(cred.uid(), owner));
    let response = match admission {
        Err(reason) => {
            tracing::warn!(reason = %reason, "refused a connection to the operator's socket");
            refused("the operator's socket serves its owner and root only")
        }
        Ok(()) => {
            let mut bytes = Vec::new();
            (&mut stream)
                .take(MAX_MESSAGE_BYTES + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() as u64 > MAX_MESSAGE_BYTES {
                refused("the request is too large")
            } else {
                match serde_json::from_slice::<Request>(&bytes) {
                    Ok(request) => handle(request, spaces).await,
                    Err(_) => refused("the request is not understood"),
                }
            }
        }
    };
    let json = serde_json::to_vec(&response).map_err(io::Error::other)?;
    stream.write_all(&json).await?;
    stream.shutdown().await
}

async fn handle(request: Request, spaces: Arc<dyn Spaces>) -> Response {
    let outcome = tokio::task::spawn_blocking(move || match request {
        Request::SpaceCreate { name } => spaces.create(&name).map(|key| Response::Key { key }),
        Request::SpaceList => spaces.list().map(|names| Response::Names { names }),
        Request::SpaceRotateKey { name } => {
            spaces.rotate_key(&name).map(|key| Response::Key { key })
        }
        Request::EnrolCommand { space } => spaces.endpoint().and_then(|endpoint| {
            spaces
                .key(&space)
                .map(|key| Response::Enrol { endpoint, key })
        }),
    })
    .await;
    match outcome {
        Ok(Ok(response)) => response,
        Ok(Err(refusal)) => Response::Refused {
            message: refusal.to_string(),
        },
        Err(_) => refused("the Server failed to carry out the request"),
    }
}

fn refused(message: &str) -> Response {
    Response::Refused {
        message: message.to_owned(),
    }
}
