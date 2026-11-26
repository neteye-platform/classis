//! The CLI's side of the socket: one request, one answer, on a blocking
//! stream.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::protocol::{Request, Response, MAX_MESSAGE_BYTES};

/// Sends `request` to the Server listening at `socket` and returns its answer.
pub fn request(socket: &Path, request: &Request) -> io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    let json = serde_json::to_vec(request).map_err(io::Error::other)?;
    stream.write_all(&json)?;
    stream.shutdown(Shutdown::Write)?;
    let mut bytes = Vec::new();
    (&mut stream)
        .take(MAX_MESSAGE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MESSAGE_BYTES {
        return Err(invalid("the answer is too large"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| invalid(&format!("the answer is not understood: {e}")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}
