//! OpAMP WebSocket message framing (ADR-0011, ADR-0013).
//!
//! The OpAMP specification defines every WebSocket message as a *header* — a varint-encoded
//! unsigned 64-bit integer, 1–10 bytes long — followed by the protobuf-encoded message. In this
//! protocol version the header is always `0`. A decoder that assumed a bare protobuf payload would
//! fail silently against a real peer.
//!
//! We reuse `prost`'s LEB128 varint codec rather than hand-rolling one: the framing header uses the
//! same encoding as the protobuf field tags `prost` already reads and writes, so there is no reason
//! to risk a second, independent implementation.

use std::fmt;

use prost::Message;

/// The default largest message either end accepts or sends, framing header included.
///
/// The Baseline requires both ends to enforce a receive limit and to keep what they send under one
/// — on both transports — and *recommends* 64 MiB as the default while asking that the limit be
/// configurable. This constant is that recommended default; `server.toml` and `supervisor.toml` each
/// carry a `max_message_size_bytes` key for deployments that want a tighter one.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 << 20; // 64 MiB

/// What a WebSocket peer is told when its message is past the limit, alongside the close status the
/// Baseline names for it — 1009, Message Too Big.
///
/// The status has a name in every WebSocket stack, so each caller uses its own; the sentence does
/// not, and it was written out at all three places that close a socket for this reason — the
/// Server's endpoint, the Client's upstream socket, and the Supervisor Endpoint. One string, so a
/// peer reading a log sees the same words whichever of the three hung up (ADR-0010).
pub const TOO_BIG_CLOSE_REASON: &str = "message exceeds the OpAMP message size limit";

/// The header value this protocol version mandates. A non-zero header is reserved for future
/// versions; receiving one means the peer speaks a protocol we do not.
const HEADER: u64 = 0;

/// Why a frame could not be turned into a message, or a message not into a frame.
#[derive(Debug)]
pub enum FrameError {
    /// The frame exceeds the limit in force — `TooLarge(size, limit)`.
    TooLarge(usize, usize),
    /// The header varint is cut off, or nothing follows it.
    Truncated,
    /// The header is not `0`; the peer speaks a protocol version we do not implement.
    UnexpectedHeader(u64),
    /// The protobuf payload did not decode into the expected message type.
    Decode(prost::DecodeError),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge(n, limit) => {
                write!(f, "message of {n} bytes exceeds the {limit}-byte limit")
            }
            FrameError::Truncated => write!(f, "frame ended before a complete header was read"),
            FrameError::UnexpectedHeader(h) => {
                write!(
                    f,
                    "unexpected framing header {h} (this protocol version requires {HEADER})"
                )
            }
            FrameError::Decode(e) => write!(f, "cannot decode protobuf payload: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Decodes one OpAMP WebSocket frame — `varint(header) || protobuf` — into a message.
///
/// `limit` is the receive limit the Baseline requires of both ends, applied to the whole frame
/// (header included). Exceeding it makes the message malformed; the caller answers as its transport
/// prescribes — closing the WebSocket with status 1009.
pub fn decode<M: Message + Default>(frame: &[u8], limit: usize) -> Result<M, FrameError> {
    if frame.len() > limit {
        return Err(FrameError::TooLarge(frame.len(), limit));
    }
    let mut cursor = frame;
    let header = prost::encoding::decode_varint(&mut cursor).map_err(|_| FrameError::Truncated)?;
    if header != HEADER {
        return Err(FrameError::UnexpectedHeader(header));
    }
    // `decode_varint` advanced `cursor` past the header; the remainder is the protobuf payload.
    M::decode(cursor).map_err(FrameError::Decode)
}

/// Encodes a message into one OpAMP WebSocket frame — `varint(0) || protobuf`.
///
/// The Baseline forbids *sending* a message past the limit as firmly as it forbids accepting one,
/// so the send limit is part of encoding rather than something each transport may remember to
/// check: a frame that would exceed `limit` is never produced, and the caller drops it with a log
/// line instead.
pub fn encode_within<M: Message>(msg: &M, limit: usize) -> Result<Vec<u8>, FrameError> {
    // The header for this protocol version is the single byte `0`.
    let framed = 1 + msg.encoded_len();
    if framed > limit {
        return Err(FrameError::TooLarge(framed, limit));
    }
    let mut out = Vec::with_capacity(framed);
    prost::encoding::encode_varint(HEADER, &mut out);
    // Encoding into a `Vec` cannot fail: it grows to fit, and `encoded_len` reserved enough.
    msg.encode(&mut out)
        .expect("encoding a protobuf message into a Vec is infallible");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{AgentToServer, ServerToAgent};

    /// The limit is not what these tests are about; they use the recommended default.
    const LIMIT: usize = DEFAULT_MAX_MESSAGE_SIZE;

    #[test]
    fn round_trips_a_message() {
        let msg = ServerToAgent {
            instance_uid: vec![1, 2, 3, 4],
            flags: 7,
            ..Default::default()
        };
        let frame = encode_within(&msg, LIMIT).expect("within the limit");
        // A zero header is a single 0x00 byte, so the frame is one byte longer than the payload.
        assert_eq!(frame[0], 0x00);
        assert_eq!(frame.len(), 1 + msg.encoded_len());

        let decoded: ServerToAgent = decode(&frame, LIMIT).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn decodes_an_empty_payload() {
        // A bare header with no payload is a valid, default-valued message.
        let decoded: AgentToServer = decode(&[0x00], LIMIT).expect("decode");
        assert_eq!(decoded, AgentToServer::default());
    }

    #[test]
    fn rejects_a_non_zero_header() {
        // Header varint 1 followed by an empty payload.
        let err = decode::<AgentToServer>(&[0x01], LIMIT).expect_err("must reject");
        assert!(matches!(err, FrameError::UnexpectedHeader(1)));
    }

    #[test]
    fn rejects_a_truncated_header() {
        // 0x80 has the varint continuation bit set but no following byte.
        let err = decode::<AgentToServer>(&[0x80], LIMIT).expect_err("must reject");
        assert!(matches!(err, FrameError::Truncated));
    }

    #[test]
    fn rejects_an_oversized_frame() {
        // The receive limit counts the whole frame, header included (Baseline v0.19.0).
        let frame = vec![0u8; 1025];
        let err = decode::<AgentToServer>(&frame, 1024).expect_err("must reject");
        assert!(matches!(err, FrameError::TooLarge(1025, 1024)));
    }

    #[test]
    fn refuses_to_encode_past_the_limit() {
        // A message whose frame would exceed the send limit is never produced: the Baseline's
        // "MUST NOT send" is enforced where the frame is built.
        let msg = ServerToAgent {
            instance_uid: vec![7; 64],
            ..Default::default()
        };
        let framed = 1 + msg.encoded_len();
        let err = encode_within(&msg, framed - 1).expect_err("must refuse");
        assert!(matches!(err, FrameError::TooLarge(n, l) if n == framed && l == framed - 1));
        // One byte more room and the same message encodes.
        assert_eq!(
            encode_within(&msg, framed).expect("fits exactly").len(),
            framed
        );
    }
}
