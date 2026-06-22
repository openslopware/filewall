//! Control socket: a second, request/response Unix socket dedicated to
//! `filewallctl` queries. Kept entirely separate from the prompt socket so the
//! security-critical, fail-closed prompt path is never touched. The event loop
//! polls this listener alongside the fanotify + inotify fds and answers one
//! request per accepted connection, then drops it.

use filewall_proto::{
    read_msg_capped, write_msg_capped, ControlRequest, DumpResponse, MAX_CONTROL_MSG_LEN,
};
use log::warn;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a control client has to send its request / receive its reply before
/// the daemon gives up — short, so a hung `filewallctl` can never stall the
/// security event loop.
const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ControlServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl ControlServer {
    /// Bind the control socket, replacing any stale socket file. World-connectable
    /// (`0o666`): the reported paths are no more sensitive than the world-readable
    /// `config.toml`.
    pub fn bind(socket_path: &Path) -> io::Result<Self> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(socket_path)?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o666))?;
        Ok(Self { listener, socket_path: socket_path.to_path_buf() })
    }

    /// The listener fd for the event loop's combined `poll`.
    pub fn raw_fd(&self) -> RawFd {
        self.listener.as_fd().as_raw_fd()
    }

    /// Accept one waiting connection (non-blocking) and answer its request using
    /// `build_dump` to produce the snapshot. `Ok(())` whether or not a client was
    /// waiting; per-connection I/O errors are logged and swallowed so a bad client
    /// never propagates into the event loop. Call only after `poll` reports
    /// `POLLIN` on [`raw_fd`](Self::raw_fd).
    pub fn handle_ready<F>(&self, build_dump: F)
    where
        F: FnOnce() -> DumpResponse,
    {
        self.listener.set_nonblocking(true).ok();
        let accepted = self.listener.accept();
        let _ = self.listener.set_nonblocking(false);
        let (mut stream, _addr) = match accepted {
            Ok(pair) => pair,
            // Nothing actually waiting (spurious wakeup): not an error.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) => {
                warn!("control: accept failed: {e}");
                return;
            }
        };
        if let Err(e) = Self::serve(&mut stream, build_dump) {
            warn!("control: serving request failed: {e}");
        }
    }

    fn serve<F>(stream: &mut UnixStream, build_dump: F) -> io::Result<()>
    where
        F: FnOnce() -> DumpResponse,
    {
        stream.set_read_timeout(Some(CONTROL_IO_TIMEOUT))?;
        stream.set_write_timeout(Some(CONTROL_IO_TIMEOUT))?;
        let req: ControlRequest = read_msg_capped(stream, MAX_CONTROL_MSG_LEN)?;
        match req {
            ControlRequest::Dump => {
                let resp = build_dump();
                write_msg_capped(stream, &resp, MAX_CONTROL_MSG_LEN)?;
            }
        }
        Ok(())
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}
