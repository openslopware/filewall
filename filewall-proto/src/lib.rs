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
    /// Path an "Always" rule would cover: the exact file, or a tree root.
    pub always_object: String,
    /// True when the rule covers every file under `always_object` (tree scope).
    pub always_tree: bool,
    /// True when the rule is pinned to the process's current cwd.
    pub always_cwd_pinned: bool,
    /// Milliseconds the UI has to answer before it must auto-deny, kept strictly
    /// below the daemon's `prompt_timeout` so a late click can never be mis-read
    /// as the answer to the *next* access (the protocol has no correlation id).
    /// `0` = unset (a UI falls back to its own built-in default). The yad helper
    /// ignores this field; `filewall-ui-iced` uses it to arm a self-timeout.
    #[serde(default)]
    pub ui_timeout_ms: u32,
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

/// Object kind reported in a [`WatchedObject`]: a single marked file inode, or a
/// directory marked with `FAN_EVENT_ON_CHILD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjKind {
    File,
    Dir,
}

/// One object the daemon is currently protecting. `fanotify` is the security
/// boundary (the open-permission mark); `live_marked` reports whether a
/// directory also has the inotify watch that live-marks new subdirectories
/// (`None` for files — not applicable). `fanotify == false` or
/// `live_marked == Some(false)` are coverage gaps (e.g. ENOSPC on the mark /
/// watch limit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedObject {
    pub path: String,
    pub kind: ObjKind,
    pub recursive: bool,
    /// Root of the config `[[watch]]` that covers this object.
    pub watch: String,
    pub fanotify: bool,
    pub live_marked: Option<bool>,
}

/// A request from `filewallctl` on the control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlRequest {
    /// Report every object the daemon is currently protecting.
    Dump,
}

/// The daemon's reply to [`ControlRequest::Dump`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DumpResponse {
    /// The daemon's PID (lets a caller correlate with `status`).
    pub pid: u32,
    /// Unix time the snapshot was taken.
    pub generated_unix: u64,
    pub objects: Vec<WatchedObject>,
}

/// Maximum accepted message size on the prompt channel (guards against a
/// hostile/garbled peer).
pub const MAX_MSG_LEN: u32 = 64 * 1024;

/// Maximum accepted message size on the control channel. A full `dump` of a
/// large recursive tree can be many thousands of objects, so the control
/// channel uses a far higher cap than the prompt channel.
pub const MAX_CONTROL_MSG_LEN: u32 = 8 * 1024 * 1024;

/// Serialize `msg` as JSON and write it with a 4-byte big-endian length prefix,
/// rejecting anything larger than `max` bytes.
pub fn write_msg_capped<W: Write, T: Serialize>(w: &mut W, msg: &T, max: u32) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too large"))?;
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one length-prefixed JSON message from `r`, rejecting a declared length
/// larger than `max` bytes.
///
/// Returns `UnexpectedEof` if the stream closes between messages or mid-message.
pub fn read_msg_capped<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R, max: u32) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Serialize `msg` as JSON and write it with a 4-byte big-endian length prefix
/// (prompt channel; capped at [`MAX_MSG_LEN`]).
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    write_msg_capped(w, msg, MAX_MSG_LEN)
}

/// Read one length-prefixed JSON message from `r` (prompt channel; capped at
/// [`MAX_MSG_LEN`]).
pub fn read_msg<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> io::Result<T> {
    read_msg_capped(r, MAX_MSG_LEN)
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
            always_object: "/home/user/.ssh".into(),
            always_tree: true,
            always_cwd_pinned: false,
            ui_timeout_ms: 25_000,
        }
    }

    #[test]
    fn request_roundtrip_preserves_scope_fields() {
        let req = sample_request();
        let back: PromptRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.always_object, "/home/user/.ssh");
        assert!(back.always_tree);
        assert!(!back.always_cwd_pinned);
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
    fn objkind_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&ObjKind::File).unwrap(), "\"file\"");
        assert_eq!(serde_json::to_string(&ObjKind::Dir).unwrap(), "\"dir\"");
    }

    fn sample_dump() -> DumpResponse {
        DumpResponse {
            pid: 4242,
            generated_unix: 1_700_000_000,
            objects: vec![
                WatchedObject {
                    path: "/home/u/.ssh".into(),
                    kind: ObjKind::Dir,
                    recursive: true,
                    watch: "/home/u/.ssh".into(),
                    fanotify: true,
                    live_marked: Some(true),
                },
                WatchedObject {
                    path: "/home/u/.vault-token".into(),
                    kind: ObjKind::File,
                    recursive: false,
                    watch: "/home/u/.vault-token".into(),
                    fanotify: true,
                    live_marked: None,
                },
            ],
        }
    }

    #[test]
    fn dump_response_json_roundtrip() {
        let d = sample_dump();
        let json = serde_json::to_string(&d).unwrap();
        let back: DumpResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn file_object_live_marked_is_null_in_json() {
        let d = sample_dump();
        let json = serde_json::to_string(&d).unwrap();
        // The file object must serialize live_marked as JSON null, never false.
        assert!(json.contains("\"live_marked\":null"));
    }

    #[test]
    fn control_request_roundtrip() {
        let req = ControlRequest::Dump;
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();
        let mut cur = Cursor::new(buf);
        let back: ControlRequest = read_msg(&mut cur).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn capped_framing_allows_payload_above_prompt_limit() {
        // A payload larger than MAX_MSG_LEN must go through the control-capped path.
        let big = DumpResponse {
            pid: 1,
            generated_unix: 0,
            objects: (0..2000)
                .map(|i| WatchedObject {
                    path: format!("/very/long/path/number/{i}/with/some/padding"),
                    kind: ObjKind::Dir,
                    recursive: true,
                    watch: "/very/long/path".into(),
                    fanotify: true,
                    live_marked: Some(true),
                })
                .collect(),
        };
        let mut buf = Vec::new();
        write_msg_capped(&mut buf, &big, MAX_CONTROL_MSG_LEN).unwrap();
        assert!(buf.len() as u32 > MAX_MSG_LEN, "test payload must exceed prompt cap");
        let mut cur = Cursor::new(buf);
        let back: DumpResponse = read_msg_capped(&mut cur, MAX_CONTROL_MSG_LEN).unwrap();
        assert_eq!(big, back);
    }

    #[test]
    fn capped_framing_rejects_payload_over_its_own_cap() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_CONTROL_MSG_LEN + 1).to_be_bytes());
        let mut cur = Cursor::new(buf);
        let err = read_msg_capped::<_, DumpResponse>(&mut cur, MAX_CONTROL_MSG_LEN).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
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
