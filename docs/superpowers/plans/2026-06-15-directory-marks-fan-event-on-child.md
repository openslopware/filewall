# Directory-Level Marking via `FAN_EVENT_ON_CHILD` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop marking one fanotify inode mark per *file* under a directory watch.
Instead mark each *directory* with `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD`, so the
kernel fires permission events for opens of that directory's immediate children with
no per-file marks — and live-mark new subdirectories with inotify so deep trees stay
covered.

**Why:** Pointing a watch at a folder with many small files (e.g. a browser profile)
exhausts `fs.fanotify.max_user_marks` → `fanotify_mark` returns ENOSPC and files past
the limit are left **unprotected** (see `.claude/rules/rust-fanotify.md`). Per-file
marks also miss newly-created files and orphan on atomic temp+rename (see
`docs/fanotify-notes.md`). Marking the parent directory with `FAN_EVENT_ON_CHILD`
fixes all three: mark count drops to one-per-dir, new files in a marked dir are
covered automatically, and an atomic rename inside a marked dir stays covered because
the mark lives on the parent.

**Key constraint:** `FAN_EVENT_ON_CHILD` (`0x08000000`) is **not recursive** — it
covers only immediate children. We deliberately omit `FAN_ONDIR` (`0x40000000`) so
opening subdirectories themselves produces no event (no extra prompts). To guard a
tree we mark every directory in it (pruned by the existing `exclude` globs), and
subdirectories created at runtime are live-marked via inotify (`IN_CREATE |
IN_MOVED_TO | IN_ISDIR`).

Because the mark now lives on the parent directory, the kernel fires an event for
**every** immediate child — so directory-level excludes prune at walk time (an
excluded dir is never marked), but **file-level excludes are now enforced in the event
loop, not by the kernel** (see Decisions + Task 4).

**Decisions (settled with user):**
- **Replace** per-file marking for directory watches. Single-file watches keep their
  direct per-inode `mark_file` (no `ON_CHILD`). No new config surface and `policy.rs`
  is unchanged — **but** observable exclude behavior is not unchanged: with per-file
  marks an excluded file was simply never marked (no event); with a directory
  `ON_CHILD` mark the kernel fires for every child, so the event loop must re-apply
  `is_excluded(path)` and auto-allow excluded paths to preserve the existing exclude
  contract (Task 4).
- **Live-mark** new subdirectories rather than waiting for the next reload.
- **inotify exhaustion:** an `add_watch` `ENOSPC` (the inotify analogue of the
  fanotify mark-limit, `fs.inotify.max_user_watches`) warns loudly per dir and keeps
  going; reload re-attempts.
- **New-subdir race (known limitation):** a file opened in a brand-new subdir before
  its `IN_CREATE` is processed and `mark_dir` lands is unprotected; inotify can't close
  this window. Documented + covered by an e2e case asserting the *second* (post-mark)
  open is caught.

**Architecture:** `fanotify.rs` gains `mark_dir` and splits its internal `poll()` out
of `read_events` so the event loop can poll the fanotify fd **and** a new tree-watch
inotify fd in one `poll()`. A new `filewalld/src/treewatch.rs` (main-thread-owned, no
cross-thread fanotify fd) holds an inotify instance watching every marked directory
and marks new subdirs as they appear. `main.rs` switches `mark_all` from files to
dirs and rebuilds the `TreeWatch` on reload. The existing config/rules reload watcher
thread (`watcher.rs`) is unchanged.

**Tech Stack:** Rust, raw fanotify FFI (existing `fanotify.rs`), `nix::sys::inotify`
(already a dep), `libc::poll`. Logging via `log` crate macros per
`.claude/rules/rust-logging.md` and the project logging convention (lifecycle=info,
allow=debug, deny=warn).

---

## File Map

| File | Change |
|---|---|
| `filewalld/src/fanotify.rs` | Add `FAN_EVENT_ON_CHILD`; add `mark_dir`; expose raw fd; split `read_events` poll → `read_ready` |
| `filewalld/src/treewatch.rs` | **New.** Inotify-backed live subdir marking |
| `filewalld/src/main.rs` | `mod treewatch;`; add `walk_dirs`; `scan_watch` Dir → dirs; `mark_all` marks dirs; event loop polls both fds; rebuild `TreeWatch` on reload |
| `docs/fanotify-notes.md` | Correct the "dir marks don't fire" + "miss newly-created files" notes |
| `.claude/rules/rust-fanotify.md` | Add `FAN_EVENT_ON_CHILD` rule |
| `README.md` | Move the per-inode iteration item out of "Deferred" |

---

## Task 1: Add `mark_dir` and split poll out of `read_events`

**Files:**
- Modify: `filewalld/src/fanotify.rs`

- [ ] **Step 1: Add the child-event constant**

After the existing mask constants (near `FAN_OPEN_PERM`, line ~23), add:
```rust
// Generate events for the immediate children of a marked directory (NOT
// recursive). FAN_ONDIR (0x40000000) is intentionally NOT set, so opening the
// subdirectories themselves produces no event — only opens of files within.
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
```

- [ ] **Step 2: Add `mark_dir`**

Beside `mark_file` (line ~106), add a twin that marks a directory inode for child
opens. Factor the shared body if desired; explicit is fine:
```rust
/// Add a `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` mark on a directory inode, so opens
/// of its immediate children (files) generate permission events without a
/// per-file mark. Not recursive — subdirectories must be marked separately.
pub fn mark_dir(&self, path: &std::path::Path) -> io::Result<()> {
    let c_path = path_to_cstring(path)?;
    let rc = unsafe {
        fanotify_mark(
            self.fd.as_raw_fd(),
            FAN_MARK_ADD,
            FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
            FAN_NOFD,
            c_path.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
```

- [ ] **Step 3: Expose the fanotify fd and split poll from read**

The event loop must `poll()` two fds together (fanotify + tree-watch inotify), so the
poll cannot stay buried in `read_events`. Add a raw-fd accessor and a poll-less read.
Note `fanotify.rs` **already** imports `std::os::fd::AsRawFd` and uses
`self.fd.as_raw_fd()` internally, so this only adds the public `impl` wrapper — no new
import:
```rust
impl std::os::fd::AsRawFd for Fanotify {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}
```
Rename the body of `read_events` after the `poll()` block into:
```rust
/// Read and parse all currently-ready events (no poll). Call only when poll has
/// reported POLLIN on this fd. Returns empty on a 0-byte read.
pub fn read_ready(&self) -> io::Result<Vec<Event>> { /* current post-poll body */ }
```
Keep `RELOAD_POLL_MS` but move the `poll()` itself to the event loop (Task 4). You may
keep a thin `read_events` that polls-then-reads for any caller that still wants it, or
delete it once Task 4 lands — your choice; the loop will own the combined poll.

- [ ] **Step 4: Verify compile + existing tests**
```bash
cargo build -p filewalld && cargo test -p filewalld fanotify
```
Expected: builds; existing `proc_cwd` tests still pass.

- [ ] **Step 5: Commit**
```bash
git add filewalld/src/fanotify.rs
git commit -m "feat(filewalld): add mark_dir (FAN_EVENT_ON_CHILD) and split read poll"
```

---

## Task 2: Switch directory watches from per-file to per-directory marking

**Files:**
- Modify: `filewalld/src/main.rs`

- [ ] **Step 1: Add `walk_dirs` (mirror of `walk_files`)**

Beside `walk_files` (line ~322), add a walker that returns `root` plus every
non-excluded **descendant directory** (an excluded directory prunes its whole
subtree, identical pruning semantics to `walk_files`):
```rust
/// Collect `root` and every non-excluded descendant directory. An excluded dir is
/// skipped and never descended (its subtree is pruned), which is what keeps noisy
/// trees from exhausting the fanotify mark limit. Symlinked dirs are not followed.
fn walk_dirs(root: &Path, is_excluded: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(e) => e, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_excluded(&path) { continue; }
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => { out.push(path.clone()); stack.push(path); }
                _ => {} // files/symlinks/special: covered by parent's ON_CHILD mark
            }
        }
    }
    out
}
```

- [ ] **Step 2: Point `WatchScan::Dir` at directories**

Change the `WatchScan::Dir` arm of `scan_watch` (line ~129) to call `walk_dirs`
instead of `walk_files`. Update the `WatchScan::Dir` doc comment to say it carries the
directories to mark. (Keep the `File` arm as-is.)

- [ ] **Step 3: Mark dirs in `mark_all`**

In `mark_all` (line ~139): for `WatchScan::File(p)` call `fan.mark_file(p)` (unchanged);
for `WatchScan::Dir(dirs)` call `fan.mark_dir(d)` for each. Update the empty/unresolved
warnings to talk about directories where appropriate, and change the success log to:
```rust
info!("watch {}: marked {n} dir(s) (children covered)", root.display());
```

- [ ] **Step 4: Update unit tests**

In `main.rs` tests: rename/retarget `walk_files_prunes_excluded_dirs_and_files` to a
`walk_dirs_*` test asserting the returned set contains `root` and `root/sub`, prunes
the excluded `Cache` subtree, and does **not** contain files. Update
`scan_watch_classifies_file_dir_and_missing` so the Dir case asserts directories are
returned (root + `tree`), not files.
```bash
cargo test -p filewalld
```
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add filewalld/src/main.rs
git commit -m "feat(filewalld): mark watched directories with ON_CHILD instead of each file"
```

---

## Task 3: Live-mark new subdirectories (`treewatch.rs`)

**Files:**
- Create: `filewalld/src/treewatch.rs`
- Modify: `filewalld/src/main.rs` (`mod treewatch;`)

- [ ] **Step 1: Register the module**

After the other `mod` lines in `main.rs` (line ~9): `mod treewatch;`

- [ ] **Step 2: Implement `TreeWatch`**

Main-thread-owned (no `Arc`/locks; matches the single-threaded-loop discipline in
`.claude/rules/rust-unix-socket.md`). Responsibilities:
- Hold a `nix::sys::inotify::Inotify` (`IN_CLOEXEC | IN_NONBLOCK`) and a
  `HashMap<WatchDescriptor, PathBuf>`.
- `fn build(policy: &Policy) -> TreeWatch`: for every directory marked by a **dir**
  watch (resolve via `scan_watch` → `WatchScan::Dir`), `add_watch(dir, IN_CREATE |
  IN_MOVED_TO | IN_ISDIR | IN_ONLYDIR)`. Single-file watches add nothing. Wrap every
  `add_watch` so an `ENOSPC` (or any error) **warns loudly and keeps going** rather
  than aborting the build:
  ```rust
  match inotify.add_watch(dir, MASK) {
      Ok(wd) => { wd_map.insert(wd, dir.to_path_buf()); }
      Err(e) => warn!(
          "treewatch: add_watch {} failed: {e}; new subdirs here won't be live-marked",
          dir.display()),
  }
  ```
- `fn raw_fd(&self) -> RawFd` for the combined poll.
- `fn on_ready(&mut self, fan: &Fanotify, policy: &Policy)`: drain
  `inotify.read_events()`; for each event whose mask has `IN_ISDIR`, build the new
  dir path (`self.wd_map[&ev.wd].join(ev.name)`), find the covering watch
  (`policy.watches().iter().find(|w| w.covers(&path))`), and if not
  `watch.is_excluded(&path)`: **recurse** via `walk_dirs(&path, |p|
  watch.is_excluded(p))` (a moved-in dir may already contain a populated subtree) and,
  for **every** dir the walk returns (not just the top-level moved-in dir),
  `fan.mark_dir(d)` **and** add an inotify `add_watch(d, ...)` — both, so future
  children deep in the moved-in tree are also caught. Use the same warn-loud-keep-going
  wrapper on each `add_watch`. Ignore non-dir events (parent's `ON_CHILD` already
  covers new files).
- On `IN_Q_OVERFLOW` (flood while the loop was blocked on a UI prompt), set
  `crate::RELOAD` to force a full re-mark + rebuild — simplest correct recovery.
- Log new marks at `info!` (lifecycle), failures at `warn!`.

- [ ] **Step 3: Tests**

`treewatch.rs` unit tests can't place real fanotify marks without CAP_SYS_ADMIN, so
test the path/recursion logic in isolation: a helper that, given a created
dir-tree + exclude set, returns the set of dirs `on_ready` *would* mark (factor the
"which dirs to mark for this new subdir" decision into a pure function and assert it
recurses and honors excludes). End-to-end marking is covered in Task 5.
```bash
cargo test -p filewalld treewatch
```

- [ ] **Step 4: Commit**
```bash
git add filewalld/src/treewatch.rs filewalld/src/main.rs
git commit -m "feat(filewalld): live-mark new subdirectories via inotify (treewatch)"
```

---

## Task 4: Poll both fds in the event loop; rebuild `TreeWatch` on reload

**Files:**
- Modify: `filewalld/src/main.rs`

- [ ] **Step 1: Build the `TreeWatch` after the initial `mark_all`**

In `run()` after `let marked = mark_all(...)` (line ~101): `let mut treewatch =
treewatch::TreeWatch::build(&policy);` and thread it into `event_loop`.

- [ ] **Step 2: Replace `fan.read_events()` with a combined poll**

In `event_loop`, replace the call to `fan.read_events()` with a `libc::poll` over a
two-entry `pollfd` array (`fan.as_raw_fd()`, `treewatch.raw_fd()`), timeout
`RELOAD_POLL_MS`. Handle EINTR/timeout as today (empty → fall through to RELOAD
check). Then:
- if the fanotify fd has `POLLIN`: `fan.read_ready()?` → process events exactly as the
  current loop body does.
- if the inotify fd has `POLLIN`: `treewatch.on_ready(&fan, policy)`.

- [ ] **Step 3: Honor file-level excludes at event time**

The parent-dir `ON_CHILD` mark fires for **every** child, so file-level exclude globs
(`**/*.tmp`, individual excluded files) are no longer suppressed by the kernel — the
event loop must enforce them. In the per-event body, after the existing `own_pid` /
`!is_open_perm` short-circuit and after resolving `path`, but **before** resolving
`exe`/`cwd` and calling `policy.evaluate` (so we don't pay glob cost on our own
accesses), add:
```rust
// Excluded paths: the parent-dir ON_CHILD mark fires for every child, so file-level
// excludes must be honored here (the kernel no longer suppresses them).
if let Some(w) = policy.watches().iter().find(|w| w.covers(&path)) {
    if w.is_excluded(&path) {
        let _ = fan.respond(ev, true);
        debug!("ALLOW (excluded) pid {} -> {}", ev.pid, path.display());
        continue;
    }
}
```
(Reuses the covering-watch lookup already used in the learned-rule path.)

- [ ] **Step 4: Rebuild `TreeWatch` on reload**

In the `RELOAD` branch, after a successful `mark_all(fan, policy)`, also
`*treewatch = treewatch::TreeWatch::build(policy);` so the inotify watch set matches
the new (re-marked) directory set.

- [ ] **Step 5: Verify full suite + clippy**
```bash
cargo test && cargo clippy -p filewalld -- -D warnings
```
Expected: all tests pass, no warnings.

- [ ] **Step 6: Commit**
```bash
git add filewalld/src/main.rs
git commit -m "feat(filewalld): poll fanotify + treewatch inotify together; rebuild on reload"
```

---

## Task 5: Docs, rules, and end-to-end verification

**Files:**
- Modify: `docs/fanotify-notes.md`, `.claude/rules/rust-fanotify.md`, `README.md`, `e2e.sh`

- [ ] **Step 1: Correct `docs/fanotify-notes.md`**

Update the *"Directory-inode marks do NOT fire for files inside the directory"* note
to state that `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` **does** fire for a directory's
immediate children (omit `FAN_ONDIR` to suppress dir-open events). Update the
*"Per-inode marks miss newly-created files"* note: files created in a marked dir are
now covered automatically; new subdirectories are live-marked via inotify. Add a
**known-gap** note: a file opened in a brand-new subdir *before* its `IN_CREATE` is
processed and `mark_dir` lands is unprotected (narrow window, inotify can't close it;
closed on the next reload). Also note file-level excludes are now enforced in the
event loop (kernel fires for every child), not by the kernel.

- [ ] **Step 2: Add a `.claude/rules/rust-fanotify.md` rule**

New rule: `FAN_EVENT_ON_CHILD` gives **scoped, non-recursive** child coverage — one
mark per directory, not per file; omit `FAN_ONDIR` to avoid dir-open noise; mirror
each directory mark with an inotify watch (`IN_CREATE | IN_MOVED_TO | IN_ISDIR`) for
live subdir coverage; `fs.inotify.max_user_watches` is now the parallel per-dir limit
(far below the old per-file fanotify mark pressure) — an `add_watch` `ENOSPC` warns
loudly and is non-fatal. Two consequences to call out: (a) the parent mark fires for
**every** child, so file-level excludes must be re-checked in the event loop; (b) a
brand-new subdir has a narrow unprotected window until its `IN_CREATE` is processed.

- [ ] **Step 3: Update `README.md`**

Move the per-inode "next iteration / Deferred" item to done (directory marking + new
file/subdir coverage shipped).

- [ ] **Step 4: Extend `e2e.sh` (run as normal user; needs root for the daemon)**

The watch on `$HOME/.filewall-e2e` is already a directory watch. Add cases proving the
new behavior, each expecting a prompt/deny for an unlisted binary (`cat`):
1. open a **pre-existing** file (regression — event fires).
2. create a **new file** in the watched dir, then `cat` it → event fires (old code
   missed this).
3. `mkdir` a **new subdir** + file inside, then `cat` the file → event fires (proves
   live subdir marking). Assert the **second** `cat` of a file in this just-created
   subdir fires (the post-mark open is reliably caught). Add a comment that the very
   first open in a just-created subdir may slip by design (the `IN_CREATE` race), so
   the assertion targets the post-mark open — give the daemon a moment after `mkdir`.
4. rewrite a watched file via temp + `mv` (atomic rename), then `cat` it → event fires
   (proves the mark didn't orphan).
5. **excluded file** — create a file matching an `exclude` glob (e.g. `*.tmp`) in the
   watched dir, then `cat` it → **no prompt/deny**, daemon logs `ALLOW (excluded)`
   (proves the event-loop exclude re-check honors file-level excludes the kernel no
   longer suppresses).
Assert the daemon log shows "marked N dir(s)" (N = directory count, not file count).
```bash
./e2e.sh   # or:  ! /home/pulsar/slowdata/development/priv/filewall/e2e.sh
```

- [ ] **Step 5: Commit**
```bash
git add docs/fanotify-notes.md .claude/rules/rust-fanotify.md README.md e2e.sh
git commit -m "docs(filewall): document directory marking via FAN_EVENT_ON_CHILD; extend e2e"
```

---

## Done when

- `cargo test` green; `cargo clippy -p filewalld -- -D warnings` clean.
- A watch on a many-file/few-dir tree reports `marked N` ≈ directory count with no
  ENOSPC warning where the old per-file path hit `max_user_marks`.
- `e2e.sh` cases 1–4 all fire prompts (pre-existing, new file, new subdir post-mark
  open, atomic rename); case 5 (excluded file) does **not** prompt and logs `ALLOW
  (excluded)`.
