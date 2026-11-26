//! The Server's side of the socket: binds a Unix domain socket and
//! answers one request per connection through `Spaces`. Nothing here logs a key.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::protocol::{Request, Response, MAX_MESSAGE_BYTES};
use crate::spaces::Spaces;

/// Binds the socket at `path` and restricts it to its owner.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accepts connections until accepting fails, one task per connection.
pub async fn serve(listener: UnixListener, spaces: Arc<dyn Spaces>) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let spaces = Arc::clone(&spaces);
        tokio::spawn(async move {
            // A connection that breaks has no one left to tell.
            let _ = answer(stream, spaces).await;
        });
    }
}

async fn answer(mut stream: UnixStream, spaces: Arc<dyn Spaces>) -> io::Result<()> {
    let mut bytes = Vec::new();
    (&mut stream)
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    let response = if bytes.len() as u64 > MAX_MESSAGE_BYTES {
        refused("the request is too large")
    } else {
        match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) => handle(request, spaces).await,
            Err(_) => refused("the request is not understood"),
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
