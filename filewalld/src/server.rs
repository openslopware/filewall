//! Unix-socket link to the unprivileged `filewall-ui` helper.
//!
//! The daemon (root) binds and listens; the UI connects and holds the
//! connection. For each undecided access the daemon pushes a [`PromptRequest`]
//! and blocks for a [`PromptResponse`]. The socket read timeout doubles as the
//! watchdog: if the user doesn't answer within `prompt_timeout_seconds`, the
//! read fails and the caller denies.

use filewall_proto::{read_msg, write_msg, Decision, PromptRequest, PromptResponse};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct UiServer {
    listener: UnixListener,
    timeout: Duration,
    socket_path: PathBuf,
}

/// One connected UI client.
pub struct UiLink {
    stream: UnixStream,
}

impl UiServer {
    /// Bind the listening socket, replacing any stale socket file.
    pub fn bind(socket_path: &Path, timeout: Duration) -> io::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Remove a stale socket from a previous run.
        match fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(socket_path)?;
        // MVP: world-connectable. Multi-user hardening (per-user sockets /
        // SO_PEERCRED checks) is deferred per the plan.
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))?;
        Ok(Self {
            listener,
            timeout,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Block until the UI helper connects.
    pub fn accept(&self) -> io::Result<UiLink> {
        let (stream, _addr) = self.listener.accept()?;
        // The read timeout is the prompt watchdog.
        stream.set_read_timeout(Some(self.timeout))?;
        Ok(UiLink { stream })
    }

    /// Try to pick up a waiting UI without blocking. `Ok(None)` means none is
    /// waiting. Lets the event loop recover a dropped link without stalling.
    pub fn try_accept(&self) -> io::Result<Option<UiLink>> {
        self.listener.set_nonblocking(true)?;
        let res = self.listener.accept();
        // Restore blocking mode so the startup `accept()` path keeps working.
        let _ = self.listener.set_nonblocking(false);
        match res {
            Ok((stream, _addr)) => {
                // On Linux an accepted socket does not inherit the listener's
                // O_NONBLOCK, so the stream is blocking and the read timeout
                // (prompt watchdog) applies as usual.
                stream.set_read_timeout(Some(self.timeout))?;
                Ok(Some(UiLink { stream }))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Whether an error from [`UiLink::prompt`] means the connection is dead (and the
/// caller should reconnect) rather than a read timeout (deny once, keep the link).
/// A read timeout surfaces as `WouldBlock` on Unix, which is deliberately excluded.
pub fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
    )
}

impl Drop for UiServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

impl UiLink {
    /// Ask the user. Returns the decision, or an error on timeout / disconnect
    /// (which the caller maps to a deny).
    pub fn prompt(&mut self, req: &PromptRequest) -> io::Result<Decision> {
        write_msg(&mut self.stream, req)?;
        let resp: PromptResponse = read_msg(&mut self.stream)?;
        Ok(resp.decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_sock(tag: &str) -> PathBuf {
        // Collision-proof across parallel tests: secs + nanos + pid.
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        std::env::temp_dir().join(format!(
            "filewall-test-{tag}-{}-{}-{}.sock",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ))
    }

    fn sample_req() -> PromptRequest {
        PromptRequest {
            pid: 4321,
            exe: "/usr/bin/node".into(),
            cmdline: "node evil.js".into(),
            cwd: "/home/user/projects/foo".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
            always_object: "/home/user/.ssh".into(),
            always_tree: true,
            always_cwd_pinned: false,
        }
    }

    #[test]
    fn prompt_roundtrip_returns_user_decision() {
        let sock = temp_sock("allow");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();
        let sock2 = sock.clone();
        let client = thread::spawn(move || {
            let mut c = UnixStream::connect(&sock2).unwrap();
            let req: PromptRequest = read_msg(&mut c).unwrap();
            assert_eq!(req.exe, "/usr/bin/node");
            write_msg(&mut c, &PromptResponse { decision: Decision::AllowOnce }).unwrap();
        });

        let mut link = server.accept().unwrap();
        assert_eq!(link.prompt(&sample_req()).unwrap(), Decision::AllowOnce);
        client.join().unwrap();
    }

    #[test]
    fn prompt_times_out_when_ui_silent() {
        let sock = temp_sock("timeout");
        let server = UiServer::bind(&sock, Duration::from_millis(300)).unwrap();
        let sock2 = sock.clone();
        let client = thread::spawn(move || {
            // Connect but never answer; hold the connection open past the timeout
            // so the failure is a read timeout, not an EOF.
            let _c = UnixStream::connect(&sock2).unwrap();
            thread::sleep(Duration::from_millis(900));
        });

        let mut link = server.accept().unwrap();
        let res = link.prompt(&sample_req());
        assert!(res.is_err(), "expected timeout error, got {res:?}");
        client.join().unwrap();
    }

    #[test]
    fn prompt_errors_when_ui_disconnects() {
        let sock = temp_sock("disconnect");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();
        let sock2 = sock.clone();
        let client = thread::spawn(move || {
            let c = UnixStream::connect(&sock2).unwrap();
            drop(c); // disconnect immediately
        });

        let mut link = server.accept().unwrap();
        // Writing/reading against a closed peer must error (caller -> deny).
        let res = link.prompt(&sample_req());
        assert!(res.is_err(), "expected error on disconnect, got {res:?}");
        client.join().unwrap();
    }

    #[test]
    fn is_disconnect_classifies_kinds() {
        use io::ErrorKind::*;
        for kind in [BrokenPipe, UnexpectedEof, ConnectionReset, ConnectionAborted, NotConnected] {
            assert!(is_disconnect(&io::Error::from(kind)), "{kind:?} should be a disconnect");
        }
        // A read timeout (WouldBlock on Unix) is NOT a disconnect: keep the link.
        for kind in [WouldBlock, TimedOut] {
            assert!(!is_disconnect(&io::Error::from(kind)), "{kind:?} should not be a disconnect");
        }
    }

    #[test]
    fn try_accept_none_when_no_client() {
        let sock = temp_sock("tryacc-empty");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();
        assert!(server.try_accept().unwrap().is_none());
    }

    /// Retry `try_accept` for a short while, giving a just-spawned client time to
    /// land in the listen backlog.
    fn try_accept_with_retry(server: &UiServer) -> UiLink {
        for _ in 0..200 {
            if let Some(link) = server.try_accept().unwrap() {
                return link;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("try_accept never picked up the waiting client");
    }

    #[test]
    fn try_accept_picks_up_waiting_client() {
        let sock = temp_sock("tryacc-client");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();
        let sock2 = sock.clone();
        let client = thread::spawn(move || {
            let mut c = UnixStream::connect(&sock2).unwrap();
            let _req: PromptRequest = read_msg(&mut c).unwrap();
            write_msg(&mut c, &PromptResponse { decision: Decision::DenyOnce }).unwrap();
        });

        let mut link = try_accept_with_retry(&server);
        assert_eq!(link.prompt(&sample_req()).unwrap(), Decision::DenyOnce);
        client.join().unwrap();
    }

    #[test]
    fn reconnect_after_disconnect() {
        let sock = temp_sock("reconnect");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();

        // First client connects, then drops without answering.
        let sock2 = sock.clone();
        let client1 = thread::spawn(move || {
            let c = UnixStream::connect(&sock2).unwrap();
            drop(c);
        });
        let mut link1 = server.accept().unwrap();
        let err = link1.prompt(&sample_req()).unwrap_err();
        assert!(is_disconnect(&err), "dropped peer should classify as disconnect, got {err:?}");
        client1.join().unwrap();
        drop(link1); // caller drops the dead link

        // A fresh client connects; the listener must still serve it.
        let sock3 = sock.clone();
        let client2 = thread::spawn(move || {
            let mut c = UnixStream::connect(&sock3).unwrap();
            let _req: PromptRequest = read_msg(&mut c).unwrap();
            write_msg(&mut c, &PromptResponse { decision: Decision::AllowOnce }).unwrap();
        });
        let mut link2 = try_accept_with_retry(&server);
        assert_eq!(link2.prompt(&sample_req()).unwrap(), Decision::AllowOnce);
        client2.join().unwrap();
    }
}
