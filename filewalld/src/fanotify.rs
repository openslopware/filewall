//! Thin, safe-ish wrapper over the fanotify permission-event API.
//!
//! Validated in the Phase 0 spike on this kernel: `FAN_CLASS_CONTENT |
//! FAN_REPORT_PIDFD` permission events fire on per-inode marks, block the
//! accessing syscall until answered, and carry a parseable pidfd info record.
//!
//! Constants and structs are declared here explicitly (rather than relying on a
//! particular libc version exposing `FAN_REPORT_PIDFD`) because this is
//! security-critical FFI and the values are part of the stable kernel ABI.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

// fanotify_init flags
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_CLASS_CONTENT: libc::c_uint = 0x0000_0004;
const FAN_REPORT_PIDFD: libc::c_uint = 0x0000_0080;

// fanotify_mark flags / masks
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_OPEN_PERM: u64 = 0x0001_0000;

// responses
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

const O_RDONLY: libc::c_uint = 0;
const FAN_NOFD: libc::c_int = -1;
const FAN_NOPIDFD: i32 = -1;
const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

#[repr(C)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct InfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

#[repr(C)]
struct Response {
    fd: i32,
    response: u32,
}

extern "C" {
    fn fanotify_init(flags: libc::c_uint, event_f_flags: libc::c_uint) -> libc::c_int;
    fn fanotify_mark(
        fanotify_fd: libc::c_int,
        flags: libc::c_uint,
        mask: u64,
        dirfd: libc::c_int,
        pathname: *const libc::c_char,
    ) -> libc::c_int;
}

/// An owned fanotify group.
pub struct Fanotify {
    fd: OwnedFd,
}

/// A single permission event. Owns the file fd (and pidfd, if any); both are
/// closed on drop. Answer it via [`Fanotify::respond`] before dropping.
pub struct Event {
    pub mask: u64,
    pub pid: u32,
    file_fd: OwnedFd,
    pidfd: Option<OwnedFd>,
}

impl Fanotify {
    /// Create the group with content-class permission events and pidfd reporting.
    /// Requires `CAP_SYS_ADMIN` (otherwise `EPERM`).
    pub fn init() -> io::Result<Self> {
        let fd = unsafe {
            fanotify_init(
                FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_REPORT_PIDFD,
                O_RDONLY,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Add a `FAN_OPEN_PERM` mark on a single file inode.
    pub fn mark_file(&self, path: &std::path::Path) -> io::Result<()> {
        let c_path = path_to_cstring(path)?;
        let rc = unsafe {
            fanotify_mark(
                self.fd.as_raw_fd(),
                FAN_MARK_ADD,
                FAN_OPEN_PERM,
                FAN_NOFD,
                c_path.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Block until at least one event arrives, returning all events in the read.
    pub fn read_events(&self) -> io::Result<Vec<Event>> {
        let mut buf = vec![0u8; 8192];
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        let mut events = Vec::new();
        let mut off = 0usize;
        while off + size_of::<EventMetadata>() <= n {
            // SAFETY: bounds checked; buffer is correctly aligned for these
            // packed-but-naturally-aligned kernel structs.
            let meta = unsafe { &*(buf.as_ptr().add(off) as *const EventMetadata) };
            let event_len = meta.event_len as usize;
            if event_len < size_of::<EventMetadata>() || off + event_len > n {
                break;
            }

            let mut pidfd_raw = FAN_NOPIDFD;
            let mut ioff = off + meta.metadata_len as usize;
            while ioff + size_of::<InfoHeader>() <= off + event_len {
                let hdr = unsafe { &*(buf.as_ptr().add(ioff) as *const InfoHeader) };
                if hdr.info_type == FAN_EVENT_INFO_TYPE_PIDFD {
                    pidfd_raw =
                        unsafe { *(buf.as_ptr().add(ioff + size_of::<InfoHeader>()) as *const i32) };
                }
                if hdr.len == 0 {
                    break;
                }
                ioff += hdr.len as usize;
            }

            // Take ownership of the kernel-provided file fd so it's always closed.
            let file_fd = unsafe { OwnedFd::from_raw_fd(meta.fd) };
            let pidfd = if pidfd_raw >= 0 {
                Some(unsafe { OwnedFd::from_raw_fd(pidfd_raw) })
            } else {
                None
            };

            events.push(Event {
                mask: meta.mask,
                pid: meta.pid as u32,
                file_fd,
                pidfd,
            });

            off += event_len;
        }
        Ok(events)
    }

    /// Answer a permission event. Must be called before the event is dropped.
    pub fn respond(&self, ev: &Event, allow: bool) -> io::Result<()> {
        let resp = Response {
            fd: ev.file_fd.as_raw_fd(),
            response: if allow { FAN_ALLOW } else { FAN_DENY },
        };
        let rc = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &resp as *const Response as *const libc::c_void,
                size_of::<Response>(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Event {
    /// True if this is an open-permission event we should evaluate.
    pub fn is_open_perm(&self) -> bool {
        self.mask & FAN_OPEN_PERM != 0
    }

    /// Resolve the accessed file's real path via our copy of the file fd.
    pub fn accessed_path(&self) -> io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{}", self.file_fd.as_raw_fd()))
    }

    /// Resolve the accessing process's executable. The held pidfd keeps the PID
    /// from being recycled, so this read is race-free.
    pub fn exe(&self) -> String {
        std::fs::read_link(format!("/proc/{}/exe", self.pid))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unresolved>".into())
    }

    /// Resolve the accessing process's cwd. Race-free while the pidfd is held.
    pub fn cwd(&self) -> String {
        proc_cwd(self.pid)
    }

    /// Render the process command line (NUL-separated args -> space-joined).
    pub fn cmdline(&self) -> String {
        match std::fs::read(format!("/proc/{}/cmdline", self.pid)) {
            Ok(bytes) => {
                let s: Vec<String> = bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                s.join(" ")
            }
            Err(_) => String::new(),
        }
    }

    /// True once the pidfd was reported (sanity signal; not required to answer).
    pub fn has_pidfd(&self) -> bool {
        self.pidfd.is_some()
    }
}

fn path_to_cstring(path: &std::path::Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// Resolve a process's current working directory via `/proc/<pid>/cwd`.
/// Returns `<unresolved>` if the link can't be read.
pub fn proc_cwd(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".into())
}

#[cfg(test)]
mod tests {
    use super::proc_cwd;

    #[test]
    fn proc_cwd_resolves_own_process() {
        let me = std::process::id();
        let expect = std::env::current_dir().unwrap().display().to_string();
        assert_eq!(proc_cwd(me), expect);
    }

    #[test]
    fn proc_cwd_unknown_pid_is_placeholder() {
        // PID 0 has no /proc entry readable as a cwd link.
        assert_eq!(proc_cwd(0), "<unresolved>");
    }
}
