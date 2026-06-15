# Rust + fanotify Rules

**`fanotify_mark` returning ENOSPC is the mark limit, NOT disk space**
"No space left on device" (os error 28) from `fanotify_mark` means the per-user
mark count exceeded `fs.fanotify.max_user_marks` (one mark per inode with
`FAN_MARK_ADD`). Nothing to do with disk. Files past the limit are left
**unmarked / unprotected**. Mitigate, in order of preference:
- prune noisy non-sensitive trees from what you mark (per-watch `exclude` globs),
- raise `fs.fanotify.max_user_marks` (sysctl), or
- `FAN_UNLIMITED_MARKS` in `fanotify_init` (needs CAP_SYS_ADMIN; unbounded kernel mem).

**Per-inode marks scope blocking; filesystem/mount marks do not**
Per-inode marks make only those inodes' opens block on the daemon's reply.
`FAN_MARK_FILESYSTEM` / `FAN_MARK_MOUNT` collapse thousands of marks into one, but
then **every** `open()` on the whole fs/mount blocks on the daemon — a system-wide
stall risk for a `FAN_CLASS_CONTENT` perm group guarding only a few dirs. Don't
switch to fs/mount marks to dodge the mark limit; use `exclude` instead.

**A blocking read() on the fanotify fd is not woken by an atomic flag**
Setting a `RELOAD` AtomicBool from another thread (the inotify watcher) does not
interrupt a thread parked in `read()` on the fanotify fd, so a reload stalls until
the next event. `poll()` the fd with a timeout (read on POLLIN, return empty on
timeout) so the loop re-checks the flag each cycle. Don't rely on SIGHUP+EINTR
alone: a process-directed signal may be delivered to the wrong thread (the
watcher's inotify read), never interrupting the main loop.

**Marks live on the inode — atomic replace orphans them**
A watched file rewritten via temp-file + `rename()` (vault/editors/kubectl) leaves
the mark on the old, now-unlinked inode; the new file is unprotected until re-marked.
(Marking the *parent directory* with `FAN_EVENT_ON_CHILD` sidesteps this — the mark
is on the dir, so an atomic replace of a file inside stays covered.)

**`FAN_EVENT_ON_CHILD` = scoped, non-recursive child coverage (one mark per dir)**
`FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` (`0x08000000`) on a directory fires perm events
for opens of its **immediate children**, so guarding a many-file dir costs one mark
instead of one-per-file (sidesteps `fs.fanotify.max_user_marks`). It is **not
recursive** — mark every directory in the tree, and mirror each with an inotify watch
(`IN_CREATE | IN_MOVED_TO | IN_ISDIR`) to live-mark new subdirs. Omit `FAN_ONDIR`
(`0x40000000`) so opening the subdirs themselves doesn't prompt. Two consequences:
- the mark fires for **every** child, so **file-level excludes must be re-checked in
  the event loop** (allow + skip) — the kernel no longer suppresses them as it did
  when you simply didn't mark the excluded file;
- `fs.inotify.max_user_watches` becomes the new parallel per-dir limit. Treat an
  `add_watch` `ENOSPC` like the fanotify mark-limit: warn loudly, keep going (new
  subdirs under the unwatched dir just won't be live-marked until the next reload).
- A brand-new subdir has a narrow unprotected window until its `IN_CREATE` is
  processed and `mark_dir` lands; inotify can't close it.
