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

    /// Try to pick up a waiting UI without blocking. `Ok(None)` means none is
    /// waiting. The daemon never blocks on a UI: it marks files at startup and
    /// uses this in the event loop to accept the first UI (and recover a dropped
    /// link) without stalling.
    pub fn try_accept(&self) -> io::Result<Option<UiLink>> {
        self.listener.set_nonblocking(true)?;
        let res = self.listener.accept();
        // Restore blocking mode (the listener is otherwise only ever used here).
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

    /// Prompt the connected UI, recovering a *stale* link in place.
    ///
    /// A link held from an earlier prompt may have died while idle (e.g. the UI
    /// was restarted); the daemon only learns this when the write fails. So:
    /// ensure a link (accepting a waiting UI non-blockingly), try once, and on a
    /// **disconnect** drop it, pick up a freshly-connected UI if one is waiting,
    /// and retry **once**. This way the first access after a UI restart prompts
    /// instead of being denied. `*ui` is left `None` after an unrecoverable
    /// disconnect, so a later access re-accepts.
    ///
    /// Errors the caller denies on: a read timeout (watchdog) — the link is kept;
    /// `NotConnected` — no UI is available right now; or a still-dead link after
    /// the retry. The retry is bounded to one attempt, so this never blocks the
    /// event loop on a flapping peer.
    pub fn prompt_recovering(
        &self,
        ui: &mut Option<UiLink>,
        req: &PromptRequest,
    ) -> io::Result<Decision> {
        // Ensure we hold a link (cold start, or after a previous disconnect).
        if ui.is_none() {
            *ui = self.try_accept()?;
        }
        // First attempt. A disconnect means the held link was stale: drop it and
        // fall through to one reconnect+retry. A timeout/transient error keeps the
        // link (the watchdog) and is returned for the caller to deny.
        if let Some(link) = ui.as_mut() {
            match link.prompt(req) {
                Ok(d) => return Ok(d),
                Err(e) if is_disconnect(&e) => {
                    log::info!("held UI link was stale ({e}); reconnecting for this access");
                    *ui = None;
                }
                Err(e) => return Err(e),
            }
        }
        // Pick up a freshly-connected UI (the restarted process) and retry once.
        if ui.is_none() {
            *ui = self.try_accept()?;
        }
        match ui.as_mut() {
            Some(link) => {
                let r = link.prompt(req);
                if matches!(&r, Err(e) if is_disconnect(e)) {
                    *ui = None; // still dead after retry: re-accept next time
                }
                r
            }
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "no UI connected")),
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
            ui_timeout_ms: 25_000,
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

        let mut link = try_accept_with_retry(&server);
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

        let mut link = try_accept_with_retry(&server);
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

        let mut link = try_accept_with_retry(&server);
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
    fn prompt_recovering_picks_up_new_ui_after_stale_link() {
        // Reproduces the "first access after a UI restart" case: the daemon holds
        // a link to a UI that has since died; a replacement UI is connected. The
        // first prompt must recover onto the new UI rather than denying.
        let sock = temp_sock("recover-stale");
        let server = UiServer::bind(&sock, Duration::from_secs(5)).unwrap();

        // UI #1 connects and is accepted as the daemon's held link, then dies
        // (the pre-restart process).
        let sock2 = sock.clone();
        let c1 = thread::spawn(move || {
            let c = UnixStream::connect(&sock2).unwrap();
            drop(c);
        });
        let mut ui = Some(try_accept_with_retry(&server));
        c1.join().unwrap();

        // UI #2 (the restarted process) connects and will answer one prompt.
        let sock3 = sock.clone();
        let c2 = thread::spawn(move || {
            let mut c = UnixStream::connect(&sock3).unwrap();
            let _req: PromptRequest = read_msg(&mut c).unwrap();
            write_msg(&mut c, &PromptResponse { decision: Decision::AllowOnce }).unwrap();
        });

        // A single access: prompt_recovering drops the stale link, accepts #2, and
        // retries. The outer loop only covers the connect race (NotConnected until
        // #2 lands in the backlog); the recovery itself is one call.
        let decision = loop {
            match server.prompt_recovering(&mut ui, &sample_req()) {
                Ok(d) => break d,
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("unexpected error from prompt_recovering: {e:?}"),
            }
        };
        assert_eq!(decision, Decision::AllowOnce);
        assert!(ui.is_some(), "the recovered link should be retained");
        c2.join().unwrap();
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
        let mut link1 = try_accept_with_retry(&server);
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
