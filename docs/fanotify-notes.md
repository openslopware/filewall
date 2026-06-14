# Linux fanotify (permission events) — notes & gotchas

Learned while building filewall and validated on kernel `7.0.11-zen` (2026-06).

**A denied permission event returns EPERM, not EACCES.**
Answering `FAN_DENY` makes the blocked `open()` fail with `EPERM` ("Operation not
permitted"). Don't assert `EACCES` in tests or UX copy.

**Directory-inode marks do NOT fire for files inside the directory.**
`FAN_MARK_ADD` on a dir inode only catches opens of the dir itself. To intercept
opens of files *within*: mark each file inode individually, or use
`FAN_MARK_MOUNT` / `FAN_MARK_FILESYSTEM` and filter by path in userspace.

**Per-inode marks miss newly-created files.**
Files created after marking are unmarked. Re-scan on `IN_CREATE`/`IN_MOVED_TO`
(inotify) and add marks, or mark the whole filesystem. (This is filewall's next
planned iteration — see `../README.md` "Deferred".)

**Race-free PID resolution via `FAN_REPORT_PIDFD` (kernel 5.15+).**
Init with `FAN_CLASS_CONTENT | FAN_REPORT_PIDFD`. The event carries an info record
(`info_type == FAN_EVENT_INFO_TYPE_PIDFD == 4`) after the metadata. Hold the pidfd
open while reading `/proc/<pid>/exe` and `/cmdline` so the PID can't be recycled.
`metadata.metadata_len` is the base size; info records run from there to
`event_len`.

**Permission events need `CAP_SYS_ADMIN`.**
`fanotify_init` for permission classes returns `EPERM` without it.

See also: `sudo-in-claude-session.md`, `project-status.md`.
