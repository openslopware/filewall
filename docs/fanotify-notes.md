# Linux fanotify (permission events) — notes & gotchas

Learned while building filewall and validated on kernel `7.0.11-zen` (2026-06).

**A denied permission event returns EPERM, not EACCES.**
Answering `FAN_DENY` makes the blocked `open()` fail with `EPERM` ("Operation not
permitted"). Don't assert `EACCES` in tests or UX copy.

**A bare dir-inode mark does not fire for files inside — but `FAN_EVENT_ON_CHILD` does.**
`FAN_MARK_ADD` with just `FAN_OPEN_PERM` on a dir inode only catches opens of the dir
itself. Adding `FAN_EVENT_ON_CHILD` (`0x08000000`) makes it fire for opens of the
directory's **immediate children** — one mark per directory instead of one per file.
It is **not recursive**: subdirectories must be marked separately (filewall walks the
tree and live-marks new subdirs via inotify). Omit `FAN_ONDIR` (`0x40000000`) so
opening the subdirectories *themselves* produces no event (no spurious prompts on
traversal). Caveat: the mark now fires for **every** child, so any per-file exclusion
must be re-applied in userspace at event time (the kernel no longer suppresses it).

**`FAN_EVENT_ON_CHILD` covers newly-created files automatically.**
Because the mark lives on the parent directory, a file created in (or atomically
renamed into) a marked dir is covered with no re-marking. New **subdirectories** still
need their own mark — filewall watches each marked dir with inotify (`IN_CREATE |
IN_MOVED_TO | IN_ISDIR`) and marks new subdirs as they appear. Known gap: a file
opened in a brand-new subdir *before* its `IN_CREATE` is processed and the mark lands
is unprotected — a narrow window inotify can't close, closed on the next reload.

**Race-free PID resolution via `FAN_REPORT_PIDFD` (kernel 5.15+).**
Init with `FAN_CLASS_CONTENT | FAN_REPORT_PIDFD`. The event carries an info record
(`info_type == FAN_EVENT_INFO_TYPE_PIDFD == 4`) after the metadata. Hold the pidfd
open while reading `/proc/<pid>/exe` and `/cmdline` so the PID can't be recycled.
`metadata.metadata_len` is the base size; info records run from there to
`event_len`.

**Permission events need `CAP_SYS_ADMIN`.**
`fanotify_init` for permission classes returns `EPERM` without it.

See also: `sudo-in-claude-session.md`, `project-status.md`.
