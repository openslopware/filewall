//! Shared IPC protocol between `filewalld` (root daemon) and `filewall-ui`
//! (unprivileged per-user helper).
//!
//! Framing: each message is a 4-byte big-endian length prefix followed by that
//! many bytes of JSON. The UI connects to the daemon's socket and holds the
//! connection; the daemon pushes a [`PromptRequest`] down it and reads back a
//! [`PromptResponse`].

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// A request from the daemon asking the user to decide on a file access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRequest {
    /// PID of the accessing process.
    pub pid: u32,
    /// Resolved executable path (`/proc/<pid>/exe`), or `<unresolved>`.
    pub exe: String,
    /// Full command line, NUL-joined args rendered with spaces.
    pub cmdline: String,
    /// Process working directory (`/proc/<pid>/cwd`); context for the human.
    pub cwd: String,
    /// The watched file path being accessed.
    pub path: String,
}

/// The user's decision for a single access. `*Once` are one-shot; `*Always`
/// also persist a learned rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    AllowOnce,
    DenyOnce,
    AllowAlways,
    DenyAlways,
}

impl Decision {
    /// Whether this decision permits the access (maps to FAN_ALLOW).
    pub fn allows(self) -> bool {
        matches!(self, Decision::AllowOnce | Decision::AllowAlways)
    }
}

/// The UI's reply to a [`PromptRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptResponse {
    pub decision: Decision,
}

/// Maximum accepted message size (guards against a hostile/garbled peer).
pub const MAX_MSG_LEN: u32 = 64 * 1024;

/// Serialize `msg` as JSON and write it with a 4-byte big-endian length prefix.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if len > MAX_MSG_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON message from `r`.
///
/// Returns `UnexpectedEof` if the stream closes between messages or mid-message.
pub fn read_msg<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_request() -> PromptRequest {
        PromptRequest {
            pid: 84321,
            exe: "/usr/bin/node".into(),
            cmdline: "node /home/user/evil.js".into(),
            cwd: "/home/user/projects/foo".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
        }
    }

    #[test]
    fn request_json_roundtrip() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let back: PromptRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn decision_serializes_kebab() {
        assert_eq!(serde_json::to_string(&Decision::AllowOnce).unwrap(), "\"allow-once\"");
        assert_eq!(serde_json::to_string(&Decision::DenyAlways).unwrap(), "\"deny-always\"");
    }

    #[test]
    fn decision_allows_predicate() {
        assert!(Decision::AllowOnce.allows());
        assert!(Decision::AllowAlways.allows());
        assert!(!Decision::DenyOnce.allows());
        assert!(!Decision::DenyAlways.allows());
    }

    #[test]
    fn framing_roundtrip_request() {
        let req = sample_request();
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        let back: PromptRequest = read_msg(&mut cur).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn framing_roundtrip_response() {
        let resp = PromptResponse { decision: Decision::DenyOnce };
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();
        let mut cur = Cursor::new(buf);
        let back: PromptResponse = read_msg(&mut cur).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn two_messages_back_to_back() {
        let a = sample_request();
        let b = PromptResponse { decision: Decision::AllowOnce };
        let mut buf = Vec::new();
        write_msg(&mut buf, &a).unwrap();
        write_msg(&mut buf, &b).unwrap();
        let mut cur = Cursor::new(buf);
        let ra: PromptRequest = read_msg(&mut cur).unwrap();
        let rb: PromptResponse = read_msg(&mut cur).unwrap();
        assert_eq!(a, ra);
        assert_eq!(b, rb);
    }

    #[test]
    fn truncated_stream_is_eof() {
        // Length prefix says 100 bytes, but body is short.
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"{}");
        let mut cur = Cursor::new(buf);
        let err = read_msg::<_, PromptResponse>(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MSG_LEN + 1).to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_msg::<_, PromptResponse>(&mut cur).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
