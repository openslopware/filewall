# filewallctl `dump` + global output formats — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `filewallctl dump` command that live-queries the running daemon for the set of objects it is currently protecting, plus global `--json` / `--yaml` / `--table` output formatting (table default) across all subcommands.

**Architecture:** The daemon keeps an in-memory `MarkSet` of every fanotify mark it places (in `mark_all` and `treewatch`), and binds a second, control-only Unix socket. `filewallctl dump` connects to that socket, sends a `ControlRequest::Dump`, and the daemon replies with a `DumpResponse` assembled from the `MarkSet` (fanotify truth) cross-referenced against `TreeWatch` (inotify truth). The prompt socket and its fail-closed security path are left completely untouched.

**Tech Stack:** Rust, `nix` (signals/sockets), `libc` (fanotify/poll), `serde` + `serde_json` + `serde_norway` (YAML), hand-rolled length-prefixed-JSON framing in `filewall-proto`.

---

## File Structure

**`filewall-proto/src/lib.rs`** (modify) — add control-channel message types (`ControlRequest`, `DumpResponse`, `WatchedObject`, `ObjKind`), a larger `MAX_CONTROL_MSG_LEN`, and capped framing fns (`read_msg_capped` / `write_msg_capped`) that the existing `read_msg`/`write_msg` delegate to.

**`filewalld/src/config.rs`** (modify) — add `control_socket_path: PathBuf` to `Config` with a default.

**`filewalld/src/markset.rs`** (create) — `MarkSet` (the daemon's record of placed marks) + the pure `build_dump` assembler.

**`filewalld/src/treewatch.rs`** (modify) — add `TreeWatch::is_watching(&Path) -> bool`; thread `&mut MarkSet` through `on_ready` so live-marked subdirs are recorded.

**`filewalld/src/control.rs`** (create) — `ControlServer`: binds the control socket, exposes its fd for `poll`, and handles one request/response per connection.

**`filewalld/src/main.rs`** (modify) — own a `MarkSet`; have `mark_all` record into it; add the control listener to the event-loop `poll` set and answer `Dump`.

**`filewallctl/src/format.rs`** (create) — `Format` enum + `parse_format` (extracts `--json`/`--yaml`/`--table` from argv, last-wins, default `Table`).

**`filewallctl/src/render.rs`** (create) — generic `render_table(headers, rows)` and `emit<T: Serialize>(value, format)` helpers.

**`filewallctl/src/main.rs`** (modify) — wire format parsing, add the `dump` subcommand, and route every subcommand's output through the chosen format.

**`filewallctl/Cargo.toml`** (modify) — add `filewall-proto`, `serde`, `serde_json`, `serde_norway`.

---

## Task 1: Control-channel protocol types + capped framing

**Files:**
- Modify: `filewall-proto/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `filewall-proto/src/lib.rs`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p filewall-proto`
Expected: FAIL — `ObjKind`, `WatchedObject`, `DumpResponse`, `ControlRequest`, `write_msg_capped`, `read_msg_capped`, `MAX_CONTROL_MSG_LEN` are undefined.

- [ ] **Step 3: Add the types and capped framing**

In `filewall-proto/src/lib.rs`, after the `Decision` / `PromptResponse` definitions (before `MAX_MSG_LEN`), add:

```rust
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
```

Then change the framing section. Replace the existing `MAX_MSG_LEN` / `write_msg` / `read_msg` block with:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p filewall-proto`
Expected: PASS (all existing tests plus the new ones).

- [ ] **Step 5: Commit**

```bash
git add filewall-proto/src/lib.rs
git commit -m "feat(proto): control-channel dump types + capped framing"
```

---

## Task 2: `control_socket_path` config key

**Files:**
- Modify: `filewalld/src/config.rs`

- [ ] **Step 1: Write the failing test**

Find the `#[cfg(test)] mod tests` block in `filewalld/src/config.rs` and add:

```rust
    #[test]
    fn control_socket_path_defaults_when_absent() {
        // A minimal config with no control_socket_path must fall back to the default.
        let cfg: super::Config = toml::from_str("default_action = \"prompt\"\n").unwrap();
        assert_eq!(
            cfg.control_socket_path,
            std::path::PathBuf::from("/run/filewall/control.sock")
        );
    }

    #[test]
    fn control_socket_path_is_read_when_present() {
        let cfg: super::Config =
            toml::from_str("control_socket_path = \"/tmp/ctl.sock\"\n").unwrap();
        assert_eq!(cfg.control_socket_path, std::path::PathBuf::from("/tmp/ctl.sock"));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p filewalld --bin filewalld config:: 2>&1 | tail -20`
(If the test harness name differs, run `cargo test -p filewalld 2>&1 | tail -20`.)
Expected: FAIL — `Config` has no field `control_socket_path`.

- [ ] **Step 3: Add the field + default**

In `filewalld/src/config.rs`, add to `struct Config` (after `socket_path`):

```rust
    #[serde(default = "default_control_socket")]
    pub control_socket_path: PathBuf,
```

And add the default fn next to `default_socket` (search for `fn default_socket`):

```rust
fn default_control_socket() -> PathBuf {
    PathBuf::from("/run/filewall/control.sock")
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p filewalld 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewalld/src/config.rs
git commit -m "feat(filewalld): control_socket_path config key (default /run/filewall/control.sock)"
```

---

## Task 3: `MarkSet` + pure `build_dump` assembler

**Files:**
- Create: `filewalld/src/markset.rs`
- Modify: `filewalld/src/main.rs` (add `mod markset;`)

- [ ] **Step 1: Create the module with its tests**

Create `filewalld/src/markset.rs`:

```rust
//! The daemon's in-memory record of the fanotify marks it has placed, plus the
//! pure assembler that turns it (cross-referenced with the live inotify watch
//! set) into the `DumpResponse` answered on the control socket.
//!
//! Main-thread-owned: no `Arc`/locks. Populated by `mark_all` (cleared and
//! rebuilt on every (re)mark) and extended by `TreeWatch::on_ready` when new
//! subdirectories are live-marked.

use filewall_proto::{ObjKind, WatchedObject};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One placed (or attempted) fanotify mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkEntry {
    pub kind: ObjKind,
    /// Whether the covering watch recurses (drives `live_marked` semantics).
    pub recursive: bool,
    pub watch_root: PathBuf,
    /// Whether `fanotify_mark` succeeded. `false` is a coverage gap.
    pub ok: bool,
}

/// Set of placed marks, keyed by path. `BTreeMap` gives a stable, sorted dump.
#[derive(Debug, Default)]
pub struct MarkSet {
    entries: BTreeMap<PathBuf, MarkEntry>,
}

impl MarkSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop all entries (called at the start of every `mark_all`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Record (or overwrite) the mark for `path`.
    pub fn record(&mut self, path: &Path, entry: MarkEntry) {
        self.entries.insert(path.to_path_buf(), entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Build the dump object list. `is_watching(dir)` reports whether a directory
/// currently has an inotify watch (i.e. its new subdirs are live-marked); it is
/// only consulted for `Dir` entries — files report `live_marked = None`.
///
/// Pure (no I/O) so it is unit-testable without placing real marks or sockets.
pub fn build_dump(marks: &MarkSet, is_watching: impl Fn(&Path) -> bool) -> Vec<WatchedObject> {
    marks
        .entries
        .iter()
        .map(|(path, e)| WatchedObject {
            path: path.display().to_string(),
            kind: e.kind,
            recursive: e.recursive,
            watch: e.watch_root.display().to_string(),
            fanotify: e.ok,
            live_marked: match e.kind {
                ObjKind::Dir => Some(is_watching(path)),
                ObjKind::File => None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_entry(ok: bool) -> MarkEntry {
        MarkEntry {
            kind: ObjKind::Dir,
            recursive: true,
            watch_root: PathBuf::from("/w"),
            ok,
        }
    }

    #[test]
    fn file_entry_reports_live_marked_none() {
        let mut ms = MarkSet::new();
        ms.record(
            Path::new("/w/token"),
            MarkEntry { kind: ObjKind::File, recursive: false, watch_root: "/w".into(), ok: true },
        );
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].kind, ObjKind::File);
        assert_eq!(objs[0].live_marked, None);
        assert!(objs[0].fanotify);
    }

    #[test]
    fn healthy_dir_is_live_marked_true() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(true));
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs[0].live_marked, Some(true));
    }

    #[test]
    fn dir_without_inotify_watch_is_live_marked_false() {
        // fanotify mark ok, but inotify add_watch failed (ENOSPC) -> coverage gap.
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(true));
        let objs = build_dump(&ms, |_| false);
        assert_eq!(objs[0].live_marked, Some(false));
        assert!(objs[0].fanotify);
    }

    #[test]
    fn failed_mark_reports_fanotify_false() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(false));
        let objs = build_dump(&ms, |_| true);
        assert!(!objs[0].fanotify);
    }

    #[test]
    fn output_is_sorted_by_path() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/b"), dir_entry(true));
        ms.record(Path::new("/w/a"), dir_entry(true));
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs[0].path, "/w/a");
        assert_eq!(objs[1].path, "/w/b");
    }
}
```

- [ ] **Step 2: Register the module**

In `filewalld/src/main.rs`, add to the module list near the top (with the other `mod` lines):

```rust
mod markset;
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p filewalld markset 2>&1 | tail -20`
Expected: PASS (5 new tests).

- [ ] **Step 4: Commit**

```bash
git add filewalld/src/markset.rs filewalld/src/main.rs
git commit -m "feat(filewalld): MarkSet record + pure build_dump assembler"
```

---

## Task 4: Populate `MarkSet` from `mark_all` and `treewatch`

**Files:**
- Modify: `filewalld/src/main.rs` (`mark_all`, its two call sites, `event_loop` signature)
- Modify: `filewalld/src/treewatch.rs` (`is_watching`, `on_ready`)

- [ ] **Step 1: Write the failing test (TreeWatch::is_watching)**

Add to the `tests` module in `filewalld/src/treewatch.rs`:

```rust
    #[test]
    fn is_watching_false_for_unknown_and_when_inert() {
        // An inert TreeWatch (inotify unavailable) watches nothing.
        let tw = super::TreeWatch {
            inotify: None,
            wd_map: std::collections::HashMap::new(),
        };
        assert!(!tw.is_watching(std::path::Path::new("/anything")));
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p filewalld is_watching 2>&1 | tail -20`
Expected: FAIL — no method `is_watching`.

- [ ] **Step 3: Add `is_watching` to `TreeWatch`**

In `filewalld/src/treewatch.rs`, add this method to `impl TreeWatch` (e.g. after `raw_fd`):

```rust
    /// Whether `dir` currently has an inotify watch (its new subdirs get
    /// live-marked). Used to report a directory's `live_marked` status in a dump.
    pub fn is_watching(&self, dir: &Path) -> bool {
        self.wd_map.values().any(|p| p == dir)
    }
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p filewalld is_watching 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Thread `MarkSet` through `mark_all`**

In `filewalld/src/main.rs`, add the import near the top (with the other `use` lines):

```rust
use markset::{MarkEntry, MarkSet};
use filewall_proto::ObjKind;
```

(`filewall_proto` is already imported for `Decision, PromptRequest`; extend that `use` line to also bring in `ObjKind` instead of adding a second line if you prefer — either compiles.)

Change `mark_all`'s signature and body so it records into a `MarkSet`. Replace the whole `fn mark_all(...)` with:

```rust
/// Mark every guarded inode and record each attempt in `marks`. A watch root may
/// be a single regular file (mark that file inode directly) or a directory (mark
/// the directory and each non-excluded descendant directory with
/// `FAN_EVENT_ON_CHILD`). Idempotent (FAN_MARK_ADD on an already-marked inode is
/// a no-op). `marks` is cleared first, so this is also the reload rebuild path.
/// Logs a per-watch summary and warns loudly when a watch resolves to nothing
/// markable so a misconfigured guard is never silent.
fn mark_all(fan: &Fanotify, policy: &Policy, marks: &mut MarkSet) -> usize {
    marks.clear();
    let mut marked = 0usize;
    for watch in policy.watches() {
        let root = watch.root();
        let watch_root = root.to_path_buf();
        let recursive = watch.recursive();
        match scan_watch(watch) {
            WatchScan::File(p) => {
                let ok = match fan.mark_file(&p) {
                    Ok(()) => {
                        info!("watch {}: marked 1 file", root.display());
                        marked += 1;
                        true
                    }
                    Err(e) => {
                        warn!("could not mark {}: {e}", p.display());
                        false
                    }
                };
                marks.record(
                    &p,
                    MarkEntry { kind: ObjKind::File, recursive, watch_root: watch_root.clone(), ok },
                );
            }
            WatchScan::Dir(dirs) => {
                if dirs.is_empty() {
                    warn!("watch {}: no markable directories (empty)", root.display());
                    continue;
                }
                let mut n = 0usize;
                for dir in &dirs {
                    let ok = match fan.mark_dir(dir) {
                        Ok(()) => {
                            n += 1;
                            true
                        }
                        Err(e) => {
                            warn!("could not mark {}: {e}", dir.display());
                            false
                        }
                    };
                    marks.record(
                        dir,
                        MarkEntry { kind: ObjKind::Dir, recursive, watch_root: watch_root.clone(), ok },
                    );
                }
                info!("watch {}: marked {n} dir(s) (children covered)", root.display());
                marked += n;
            }
            WatchScan::Unresolved => {
                if root.exists() {
                    warn!("watch {}: not a regular file or directory; nothing marked", root.display());
                } else {
                    warn!("watch {}: path does not exist; nothing marked", root.display());
                }
            }
        }
    }
    marked
}
```

- [ ] **Step 6: Update `mark_all` call sites and own the `MarkSet`**

In `run()` (in `filewalld/src/main.rs`), where `mark_all` is first called, replace:

```rust
    // Mark every watched root (files directly; directories via ON_CHILD).
    let marked = mark_all(&fan, &policy);
```

with:

```rust
    // Mark every watched root (files directly; directories via ON_CHILD).
    let mut marks = MarkSet::new();
    let marked = mark_all(&fan, &policy, &mut marks);
```

Then update the `event_loop(...)` call at the end of `run()` to pass `&mut marks` (add it as the final argument; see Step 7 for the new signature). The call becomes:

```rust
    event_loop(
        &fan, &mut policy, &mut rules, &rules_path, &config_path, &server, &mut ui,
        &mut treewatch, own_pid, ui_timeout_ms, &mut marks,
    )
```

- [ ] **Step 7: Update `event_loop` signature and its internal `mark_all` (reload) + treewatch calls**

Change the `fn event_loop(...)` signature to add the parameter (keep `#[allow(clippy::too_many_arguments)]`):

```rust
    treewatch: &mut treewatch::TreeWatch,
    own_pid: u32,
    ui_timeout_ms: u32,
    marks: &mut MarkSet,
) -> Result<(), Box<dyn std::error::Error>> {
```

Inside the reload branch, replace `let n = mark_all(fan, policy);` with:

```rust
                        let n = mark_all(fan, policy, marks);
```

And update the `treewatch.on_ready(...)` call in the poll-drain section to pass `marks`:

```rust
            if fds[1].revents & libc::POLLIN != 0 {
                treewatch.on_ready(fan, policy, marks);
            }
```

- [ ] **Step 8: Record live-marked subdirs in `TreeWatch::on_ready`**

In `filewalld/src/treewatch.rs`, change `on_ready`'s signature to accept the mark set, and record each new dir it marks. Update the imports at the top:

```rust
use crate::markset::{MarkEntry, MarkSet};
use filewall_proto::ObjKind;
```

Change the signature:

```rust
    pub fn on_ready(&mut self, fan: &Fanotify, policy: &Policy, marks: &mut MarkSet) {
```

Inside the loop, in the `for dir in dirs_to_mark(...)` block, replace:

```rust
            for dir in dirs_to_mark(&new_dir, |p| watch.is_excluded(p)) {
                match fan.mark_dir(&dir) {
                    Ok(()) => info!("treewatch: marked new dir {} (children covered)", dir.display()),
                    Err(e) => warn!("treewatch: could not mark {}: {e}", dir.display()),
                }
                self.add(&dir);
            }
```

with:

```rust
            for dir in dirs_to_mark(&new_dir, |p| watch.is_excluded(p)) {
                let ok = match fan.mark_dir(&dir) {
                    Ok(()) => {
                        info!("treewatch: marked new dir {} (children covered)", dir.display());
                        true
                    }
                    Err(e) => {
                        warn!("treewatch: could not mark {}: {e}", dir.display());
                        false
                    }
                };
                marks.record(
                    &dir,
                    MarkEntry {
                        kind: ObjKind::Dir,
                        recursive: watch.recursive(),
                        watch_root: watch.root().to_path_buf(),
                        ok,
                    },
                );
                self.add(&dir);
            }
```

- [ ] **Step 9: Build and run the full daemon test suite**

Run: `cargo test -p filewalld 2>&1 | tail -25`
Expected: PASS (existing tests + `is_watching`). Compilation must succeed with the new signatures.

- [ ] **Step 10: Commit**

```bash
git add filewalld/src/main.rs filewalld/src/treewatch.rs
git commit -m "feat(filewalld): populate MarkSet from mark_all and treewatch"
```

---

## Task 5: Control socket server + event-loop integration

**Files:**
- Create: `filewalld/src/control.rs`
- Modify: `filewalld/src/main.rs` (`mod control;`, bind, poll, handle)

- [ ] **Step 1: Create the control server**

Create `filewalld/src/control.rs`:

```rust
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
```

- [ ] **Step 2: Register the module and bind the socket**

In `filewalld/src/main.rs`, add to the module list:

```rust
mod control;
```

Add the import:

```rust
use control::ControlServer;
use std::time::SystemTime;
```

In `run()`, after the prompt `server` is bound and logged (right after `info!("listening on {}", cfg.socket_path.display());`), add:

```rust
    // Second socket for filewallctl queries (dump). Separate from the prompt
    // socket so the fail-closed prompt path is untouched. A bind failure here is
    // non-fatal: protection still works, only `filewallctl dump` is unavailable.
    let control = match ControlServer::bind(&cfg.control_socket_path) {
        Ok(c) => {
            info!("control socket on {}", cfg.control_socket_path.display());
            Some(c)
        }
        Err(e) => {
            warn!("could not bind control socket {}: {e}", cfg.control_socket_path.display());
            None
        }
    };
```

Pass `control.as_ref()` to `event_loop` (add as the final argument):

```rust
    event_loop(
        &fan, &mut policy, &mut rules, &rules_path, &config_path, &server, &mut ui,
        &mut treewatch, own_pid, ui_timeout_ms, &mut marks, control.as_ref(),
    )
```

- [ ] **Step 3: Poll + answer in `event_loop`**

Update `event_loop`'s signature (final param):

```rust
    marks: &mut MarkSet,
    control: Option<&ControlServer>,
) -> Result<(), Box<dyn std::error::Error>> {
```

Replace the `poll` fd array construction with one that includes the control fd (use `-1` when there is no control socket — `poll` ignores a negative fd):

```rust
        let control_fd = control.map(|c| c.raw_fd()).unwrap_or(-1);
        let mut fds = [
            libc::pollfd { fd: fan.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: treewatch.raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: control_fd, events: libc::POLLIN, revents: 0 },
        ];
```

In the `else` arm (where `rc > 0`), after the `treewatch.on_ready(...)` call and before/after the fanotify drain, add the control handling. Place it right after the treewatch block:

```rust
            if fds[2].revents & libc::POLLIN != 0 {
                if let Some(ctl) = control {
                    let own = own_pid;
                    ctl.handle_ready(|| filewall_proto::DumpResponse {
                        pid: own,
                        generated_unix: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        objects: markset::build_dump(marks, |p| treewatch.is_watching(p)),
                    });
                }
            }
```

> Note: `marks` and `treewatch` are both borrowed immutably inside the closure here, which is fine — the `treewatch.on_ready` call above (which borrows `treewatch` mutably) has already returned by this point.

- [ ] **Step 4: Build the daemon**

Run: `cargo build -p filewalld 2>&1 | tail -25`
Expected: clean build (no borrow-checker errors).

- [ ] **Step 5: Run the daemon test suite**

Run: `cargo test -p filewalld 2>&1 | tail -25`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add filewalld/src/control.rs filewalld/src/main.rs
git commit -m "feat(filewalld): control socket serving DumpResponse"
```

---

## Task 6: filewallctl output-format flag parsing

**Files:**
- Modify: `filewallctl/Cargo.toml`
- Create: `filewallctl/src/format.rs`
- Modify: `filewallctl/src/main.rs` (add `mod format;`)

- [ ] **Step 1: Add dependencies**

Run:

```bash
cargo add filewall-proto -p filewallctl
cargo add serde -p filewallctl --features derive
cargo add serde_json -p filewallctl
cargo add serde_norway -p filewallctl
```

Expected: `filewallctl/Cargo.toml` `[dependencies]` now lists `filewall-proto`, `serde`, `serde_json`, `serde_norway`.

- [ ] **Step 2: Create `format.rs` with tests**

Create `filewallctl/src/format.rs`:

```rust
//! Output-format selection. A global, position-independent flag (`--json`,
//! `--yaml`, or `--table`) is extracted from argv before subcommand dispatch.
//! Default is `Table` everywhere (no TTY auto-switching); if more than one flag
//! is given, the last one wins.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
    Yaml,
}

/// Split `args` into the chosen [`Format`] and the remaining (non-format) args.
/// Order of the remaining args is preserved.
pub fn parse_format(args: &[String]) -> (Format, Vec<String>) {
    let mut fmt = Format::Table;
    let mut rest = Vec::with_capacity(args.len());
    for a in args {
        match a.as_str() {
            "--json" => fmt = Format::Json,
            "--yaml" => fmt = Format::Yaml,
            "--table" => fmt = Format::Table,
            _ => rest.push(a.clone()),
        }
    }
    (fmt, rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_is_table() {
        let (fmt, rest) = parse_format(&v(&["dump"]));
        assert_eq!(fmt, Format::Table);
        assert_eq!(rest, v(&["dump"]));
    }

    #[test]
    fn json_flag_anywhere_is_extracted() {
        let (fmt, rest) = parse_format(&v(&["list", "--json", "/path"]));
        assert_eq!(fmt, Format::Json);
        assert_eq!(rest, v(&["list", "/path"]));
    }

    #[test]
    fn last_flag_wins() {
        let (fmt, _) = parse_format(&v(&["--json", "dump", "--yaml"]));
        assert_eq!(fmt, Format::Yaml);
    }

    #[test]
    fn yaml_flag() {
        let (fmt, rest) = parse_format(&v(&["status", "--yaml"]));
        assert_eq!(fmt, Format::Yaml);
        assert_eq!(rest, v(&["status"]));
    }
}
```

- [ ] **Step 3: Register the module**

In `filewallctl/src/main.rs`, add near the top (above `fn main`):

```rust
mod format;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p filewallctl format 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add filewallctl/Cargo.toml filewallctl/src/format.rs filewallctl/src/main.rs Cargo.lock
git commit -m "feat(filewallctl): global --json/--yaml/--table flag parsing"
```

---

## Task 7: Render helpers (table + json/yaml emit)

**Files:**
- Create: `filewallctl/src/render.rs`
- Modify: `filewallctl/src/main.rs` (add `mod render;`)

- [ ] **Step 1: Create `render.rs` with tests**

Create `filewallctl/src/render.rs`:

```rust
//! Output rendering. `emit` serializes any `Serialize` value as JSON or YAML;
//! `render_table` lays out aligned columns for the human-default table view.

use crate::format::Format;
use serde::Serialize;

/// Serialize `value` as JSON or YAML. Not used for `Format::Table` (callers
/// render their own table layout). Returns the serialized string.
pub fn emit<T: Serialize>(value: &T, format: Format) -> Result<String, String> {
    match format {
        Format::Json => serde_json::to_string_pretty(value).map_err(|e| e.to_string()),
        Format::Yaml => serde_norway::to_string(value).map_err(|e| e.to_string()),
        Format::Table => Err("emit() called with Format::Table".to_string()),
    }
}

/// Render rows as a left-aligned, space-padded table with a header row. Column
/// widths are the max cell width in each column. `headers.len()` defines the
/// column count; each row must have the same length.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .take(cols)
            .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = String::new();
    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    out.push_str(&fmt_row(&header_cells));
    out.push('\n');
    for row in rows {
        out.push_str(&fmt_row(row));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns_and_has_header() {
        let rows = vec![
            vec!["/a".to_string(), "dir".to_string()],
            vec!["/longer/path".to_string(), "file".to_string()],
        ];
        let out = render_table(&["PATH", "KIND"], &rows);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "PATH          KIND");
        assert_eq!(lines[1], "/a            dir");
        assert_eq!(lines[2], "/longer/path  file");
    }

    #[test]
    fn emit_json_is_pretty_and_parseable() {
        #[derive(serde::Serialize)]
        struct S {
            a: u32,
        }
        let s = emit(&S { a: 1 }, Format::Json).unwrap();
        assert!(s.contains("\"a\": 1"));
    }

    #[test]
    fn emit_yaml_renders_key() {
        #[derive(serde::Serialize)]
        struct S {
            a: u32,
        }
        let s = emit(&S { a: 1 }, Format::Yaml).unwrap();
        assert!(s.contains("a: 1"));
    }
}
```

- [ ] **Step 2: Register the module**

In `filewallctl/src/main.rs`, add near the top:

```rust
mod render;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p filewallctl render 2>&1 | tail -20`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add filewallctl/src/render.rs filewallctl/src/main.rs
git commit -m "feat(filewallctl): table + json/yaml render helpers"
```

---

## Task 8: `dump` subcommand (control-socket client)

**Files:**
- Modify: `filewallctl/src/main.rs`

- [ ] **Step 1: Write the failing test (table rendering of a DumpResponse)**

Add a `dump` rendering helper and test it. First add the test to the `tests` module in `filewallctl/src/main.rs`:

```rust
    #[test]
    fn dump_table_renders_objects_with_health() {
        use filewall_proto::{DumpResponse, ObjKind, WatchedObject};
        let resp = DumpResponse {
            pid: 7,
            generated_unix: 0,
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
        };
        let out = super::dump_table(&resp);
        assert!(out.contains("PATH"));
        assert!(out.contains("/home/u/.ssh"));
        assert!(out.contains("dir"));
        // File live_marked None renders as "-", healthy dir as "yes".
        assert!(out.contains("yes"));
        assert!(out.contains('-'));
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p filewallctl dump_table 2>&1 | tail -20`
Expected: FAIL — `dump_table` is undefined.

- [ ] **Step 3: Implement `dump_table`, the socket client, and `cmd_dump`**

In `filewallctl/src/main.rs`, add imports near the existing `use` lines:

```rust
use filewall_proto::{
    read_msg_capped, write_msg_capped, ControlRequest, DumpResponse, MAX_CONTROL_MSG_LEN,
};
use format::Format;
use std::io;
use std::os::unix::net::UnixStream;
use std::time::Duration;
```

Add the default control socket constant near `DEFAULT_PIDFILE`:

```rust
const DEFAULT_CONTROL_SOCKET: &str = "/run/filewall/control.sock";
```

Add the rendering helper and the command:

```rust
/// Render a dump as an aligned table. `live` column: "yes"/"no" for dirs,
/// "-" for files (not applicable). `fanotify` column flags coverage gaps.
fn dump_table(resp: &DumpResponse) -> String {
    let rows: Vec<Vec<String>> = resp
        .objects
        .iter()
        .map(|o| {
            let kind = match o.kind {
                filewall_proto::ObjKind::File => "file",
                filewall_proto::ObjKind::Dir => "dir",
            };
            let live = match o.live_marked {
                Some(true) => "yes",
                Some(false) => "no",
                None => "-",
            };
            vec![
                o.path.clone(),
                kind.to_string(),
                if o.recursive { "yes" } else { "no" }.to_string(),
                if o.fanotify { "yes" } else { "no" }.to_string(),
                live.to_string(),
                o.watch.clone(),
            ]
        })
        .collect();
    let mut out = render::render_table(
        &["PATH", "KIND", "RECURSIVE", "FANOTIFY", "LIVE", "WATCH"],
        &rows,
    );
    out.push_str(&format!("\n{} object(s) (pid {})\n", resp.objects.len(), resp.pid));
    out
}

/// Connect to the control socket, request a dump, and return the response.
fn fetch_dump(socket: &Path) -> io::Result<DumpResponse> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_msg_capped(&mut stream, &ControlRequest::Dump, MAX_CONTROL_MSG_LEN)?;
    read_msg_capped(&mut stream, MAX_CONTROL_MSG_LEN)
}

fn cmd_dump(socket: &Path, format: Format) -> ExitCode {
    match fetch_dump(socket) {
        Ok(resp) => match format {
            Format::Table => {
                print!("{}", dump_table(&resp));
                ExitCode::SUCCESS
            }
            _ => match render::emit(&resp, format) {
                Ok(s) => {
                    println!("{s}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("filewallctl: render failed: {e}");
                    ExitCode::FAILURE
                }
            },
        },
        Err(e) => {
            emit_error(
                format,
                &format!(
                    "could not query daemon on {} ({e}); is filewalld running?",
                    socket.display()
                ),
            );
            ExitCode::FAILURE
        }
    }
}
```

Add a shared error emitter (used by `dump` and later by other commands):

```rust
/// Print an error in the chosen format: a plain stderr line for tables, a
/// `{ "error": ... }` object for json/yaml (so automation can detect failure).
fn emit_error(format: Format, msg: &str) {
    match format {
        Format::Table => eprintln!("filewallctl: {msg}"),
        _ => {
            #[derive(serde::Serialize)]
            struct ErrorReport<'a> {
                error: &'a str,
            }
            match render::emit(&ErrorReport { error: msg }, format) {
                Ok(s) => eprintln!("{s}"),
                Err(_) => eprintln!("filewallctl: {msg}"),
            }
        }
    }
}
```

- [ ] **Step 4: Wire `main` to parse the format and dispatch `dump`**

Replace the body of `fn main()` so it first extracts the format, then dispatches on the remaining args. Replace:

```rust
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
```

with:

```rust
fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let (format, args) = format::parse_format(&raw);
    match args.first().map(String::as_str) {
        Some("dump") => {
            let socket = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
            cmd_dump(&socket, format)
        }
```

(Leave the existing `list` / `remove` / `reload` / `status` / `_ => usage()` arms in place for now; Task 9 routes their output through `format`.)

Update `usage()` to mention `dump` and the format flags — replace the `eprintln!` block in `usage()` with:

```rust
    eprintln!(
        "usage:\n  \
         filewallctl [--json|--yaml|--table] <command>\n\n\
         commands:\n  \
         list   [rules_path]      Print learned rules\n  \
         dump   [control_socket]  Print objects the daemon is protecting\n  \
         remove <index> [path]    Remove a rule by index, then SIGHUP the daemon\n  \
         reload [pidfile]         Send SIGHUP to the running daemon\n  \
         status [pidfile]         Report whether the daemon is running"
    );
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p filewallctl 2>&1 | tail -25`
Expected: PASS (incl. `dump_table`). Build must succeed.

- [ ] **Step 6: Commit**

```bash
git add filewallctl/src/main.rs
git commit -m "feat(filewallctl): dump subcommand querying the control socket"
```

---

## Task 9: Route list / status / reload / remove through `format`

**Files:**
- Modify: `filewallctl/src/main.rs`

- [ ] **Step 1: Write the failing tests (report structs serialize)**

Add to the `tests` module in `filewallctl/src/main.rs`:

```rust
    #[test]
    fn status_report_serializes() {
        let r = super::StatusReport { running: true, pid: Some(42), state: "running" };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"state\":\"running\""));
    }

    #[test]
    fn ack_report_serializes() {
        let r = super::Ack { ok: true, pid: Some(7), detail: "reloaded".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"detail\":\"reloaded\""));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p filewallctl _report 2>&1 | tail -20`
Expected: FAIL — `StatusReport` / `Ack` undefined.

- [ ] **Step 3: Add report structs and format-aware command bodies**

In `filewallctl/src/main.rs`, add the structs (near the top, after the consts):

```rust
#[derive(serde::Serialize)]
struct StatusReport {
    running: bool,
    pid: Option<i32>,
    state: &'static str,
}

#[derive(serde::Serialize)]
struct Ack {
    ok: bool,
    pid: Option<i32>,
    detail: String,
}
```

Thread `format` into the four commands. Update each call in `main`'s match arms to pass `format`, and update the function signatures/bodies as follows.

`cmd_list` — add `format`, and branch:

```rust
fn cmd_list(path: &Path, format: Format) -> ExitCode {
    let rules = Rules::load(path);
    match format {
        Format::Table => {
            if rules.rules.is_empty() {
                println!("No learned rules ({})", path.display());
                return ExitCode::SUCCESS;
            }
            println!("Learned rules ({}):", path.display());
            for (i, r) in rules.rules.iter().enumerate() {
                let cwd = r.cwd.as_deref().unwrap_or("-");
                println!(
                    "  [{i}] {:?} exe={} object={} kind={:?} cwd={} created_unix={}",
                    r.action,
                    r.exe,
                    r.object.display(),
                    r.object_kind,
                    cwd,
                    r.created_unix
                );
            }
            ExitCode::SUCCESS
        }
        _ => match render::emit(&rules.rules, format) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("filewallctl: render failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
```

`cmd_status` — add `format`. Reuse the existing `classify_liveness`. Replace the final `match classify_liveness(...)` block so it builds a `StatusReport` and renders per format:

```rust
fn cmd_status(pidfile: &Path, format: Format) -> ExitCode {
    let report = status_report(pidfile);
    let code = if report.running { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    match format {
        Format::Table => {
            match report.state {
                "running" => println!("filewalld: running (pid {})", report.pid.unwrap_or(0)),
                "stale" => println!("filewalld: not running (stale pid {})", report.pid.unwrap_or(0)),
                "no-pidfile" => println!("filewalld: not running (no pidfile)"),
                "bad-pidfile" => println!("filewalld: unknown (bad pidfile)"),
                other => println!("filewalld: {other}"),
            }
            code
        }
        _ => match render::emit(&report, format) {
            Ok(s) => {
                println!("{s}");
                code
            }
            Err(e) => {
                eprintln!("filewallctl: render failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Classify the daemon's status from its pidfile into a serializable report.
fn status_report(pidfile: &Path) -> StatusReport {
    let text = match std::fs::read_to_string(pidfile) {
        Ok(t) => t,
        Err(_) => return StatusReport { running: false, pid: None, state: "no-pidfile" },
    };
    let pid = match parse_pidfile(&text) {
        Some(p) => p,
        None => return StatusReport { running: false, pid: None, state: "bad-pidfile" },
    };
    match classify_liveness(kill(Pid::from_raw(pid), None)) {
        Liveness::Running => StatusReport { running: true, pid: Some(pid), state: "running" },
        Liveness::Stale => StatusReport { running: false, pid: Some(pid), state: "stale" },
        Liveness::Unknown(_) => StatusReport { running: false, pid: Some(pid), state: "unknown" },
    }
}
```

`cmd_reload` — add `format`, emit an `Ack` for json/yaml:

```rust
fn cmd_reload(pidfile: &Path, format: Format) -> ExitCode {
    match send_sighup(pidfile) {
        Ok(pid) => {
            let ack = Ack { ok: true, pid: Some(pid), detail: "sent SIGHUP".into() };
            match format {
                Format::Table => println!("Sent SIGHUP to filewalld (pid {pid})"),
                _ => print_ack(&ack, format),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            match format {
                Format::Table => eprintln!("filewallctl: reload failed: {e}"),
                _ => print_ack(&Ack { ok: false, pid: None, detail: format!("reload failed: {e}") }, format),
            }
            ExitCode::FAILURE
        }
    }
}

/// Render an Ack to stdout in json/yaml (table callers print their own line).
fn print_ack(ack: &Ack, format: Format) {
    match render::emit(ack, format) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("filewallctl: render failed: {e}"),
    }
}
```

`cmd_remove` — add `format`. Replace the two terminal branches' output:

```rust
fn cmd_remove(index: usize, rules_path: &Path, pidfile: &Path, format: Format) -> ExitCode {
    let mut rules = Rules::load(rules_path);
    match remove_at(&mut rules, index) {
        Some(removed) => {
            if let Err(e) = rules.save_atomic(rules_path) {
                let ack = Ack { ok: false, pid: None, detail: format!("could not write {}: {e}", rules_path.display()) };
                match format {
                    Format::Table => eprintln!("filewallctl: {}", ack.detail),
                    _ => print_ack(&ack, format),
                }
                return ExitCode::FAILURE;
            }
            let pid = send_sighup(pidfile).ok();
            let detail = format!("removed [{index}] {} -> {}", removed.exe, removed.object.display());
            match format {
                Format::Table => println!("Removed [{index}] {} -> {}", removed.exe, removed.object.display()),
                _ => print_ack(&Ack { ok: true, pid, detail }, format),
            }
            ExitCode::SUCCESS
        }
        None => {
            let ack = Ack { ok: false, pid: None, detail: format!("no rule at index {index}") };
            match format {
                Format::Table => eprintln!("filewallctl: {}", ack.detail),
                _ => print_ack(&ack, format),
            }
            ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 4: Update the `main` match arms to pass `format`**

In `fn main`, update the existing arms:

```rust
        Some("list") => {
            let path = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_list(&path, format)
        }
        Some("remove") => {
            let Some(index) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!("filewallctl: remove needs a numeric <index>");
                return usage();
            };
            let rules_path = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_remove(index, &rules_path, Path::new(DEFAULT_PIDFILE), format)
        }
        Some("reload") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_reload(&pidfile, format)
        }
        Some("status") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_status(&pidfile, format)
        }
```

- [ ] **Step 5: Run the full filewallctl suite**

Run: `cargo test -p filewallctl 2>&1 | tail -25`
Expected: PASS (all prior tests + `status_report` + `ack_report`).

- [ ] **Step 6: Commit**

```bash
git add filewallctl/src/main.rs
git commit -m "feat(filewallctl): apply --json/--yaml to list/status/reload/remove"
```

---

## Task 10: Workspace build, docs, and live smoke test

**Files:**
- Modify: `example_config.toml` (document the new key)
- Modify: `README.md` (document `dump` + formats)
- Modify: `e2e.sh` (optional dump smoke check)

- [ ] **Step 1: Full workspace build + test**

Run: `cargo test 2>&1 | tail -30`
Expected: every crate's tests PASS.

Run: `cargo clippy --workspace 2>&1 | tail -30`
Expected: no new warnings (the existing `#[allow(clippy::too_many_arguments)]` on `event_loop` stays).

- [ ] **Step 2: Document the config key**

In `example_config.toml`, add under the other top-level keys:

```toml
# Control socket for `filewallctl` queries (e.g. `dump`). Separate from the
# prompt socket. Default: /run/filewall/control.sock
control_socket_path = "/run/filewall/control.sock"
```

- [ ] **Step 3: Document the command in the README**

In `README.md`, in the `filewallctl` section, add:

```markdown
### Output formats

All `filewallctl` commands accept a global `--json`, `--yaml`, or `--table`
flag (anywhere on the command line). `--table` is the default.

### `filewallctl dump`

Live-queries the running daemon (over its control socket) for every object it
is currently protecting:

```
filewallctl dump            # human table
filewallctl dump --json     # machine-readable, for config management
```

Columns: `PATH`, `KIND` (file/dir), `RECURSIVE`, `FANOTIFY` (the security
mark — `no` means a coverage gap, e.g. ENOSPC), `LIVE` (inotify watch present
so new subdirs are live-marked; `-` for files), `WATCH` (the covering config
watch root).
```

- [ ] **Step 4: (Optional) add a dump smoke check to e2e.sh**

If `e2e.sh` starts a daemon and runs `filewallctl` against it, add after the daemon is up:

```bash
echo "== dump (json) =="
filewallctl dump --json | tee /tmp/filewall-dump.json
# Expect valid JSON with an "objects" array.
python3 -c 'import json,sys; d=json.load(open("/tmp/filewall-dump.json")); assert "objects" in d; print(len(d["objects"]), "objects")'
```

- [ ] **Step 5: Live verification against the running daemon**

> Requires rebuilding and restarting the root daemon so it binds the new control socket. Provide the user a script to run with sudo (per project convention — privileged ops go in a script, not an inline one-liner):

Create `phase0/verify-dump.sh` (or hand the commands to the user):

```bash
#!/usr/bin/env bash
set -euo pipefail
cargo build --release
sudo systemctl stop filewalld 2>/dev/null || true
sudo install -m755 target/release/filewalld /usr/bin/filewalld
sudo systemctl start filewalld   # or: sudo /usr/bin/filewalld /etc/filewall/config.toml &
sleep 1
ls -l /run/filewall/control.sock
./target/release/filewallctl dump
./target/release/filewallctl dump --json | head -40
```

Expected: `control.sock` exists; the table lists the configured watches (e.g. `~/.ssh`, `~/.vault-token`) with `FANOTIFY=yes`, recursive dirs `LIVE=yes`, the single-file watch `LIVE=-`.

- [ ] **Step 6: Commit**

```bash
git add example_config.toml README.md e2e.sh phase0/verify-dump.sh
git commit -m "docs: document filewallctl dump + output formats; add dump smoke check"
```

---

## Self-Review Notes

- **Spec coverage:** live IPC query (Tasks 1,5,8); object-centric model + `live_marked` health field (Tasks 1,3); separate control socket (Tasks 2,5); global `--json/--yaml/--table`, table default (Tasks 6,7,9); JSON across all commands (Tasks 8,9). ✔
- **Type consistency:** `WatchedObject`/`ObjKind`/`DumpResponse`/`ControlRequest` defined once in Task 1 and reused verbatim in filewalld (`build_dump`) and filewallctl (`dump_table`, `fetch_dump`). `MarkEntry`/`MarkSet` defined in Task 3, consumed in Task 4. `Format` defined in Task 6, consumed in Tasks 7–9. `render_table`/`emit` defined in Task 7, consumed in Tasks 8–9. ✔
- **Capped framing:** the >64 KiB dump path is covered by `MAX_CONTROL_MSG_LEN` + `*_capped` fns (Task 1), used on both ends (Tasks 5, 8). ✔
- **Borrow safety note:** the control closure in Task 5 borrows `marks` + `treewatch` immutably *after* `treewatch.on_ready` (mutable borrow) has returned in the same poll cycle — ordering matters; documented inline.
