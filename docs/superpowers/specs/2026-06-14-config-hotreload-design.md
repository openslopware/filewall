# Design: Config & Rules Hot-Reload via inotify

**Date:** 2026-06-14  
**Status:** Approved

## Problem

`filewalld` currently reloads `config.toml` and `rules.toml` only on `SIGHUP`. Edits to either file take no effect until the operator manually signals the daemon. `rules.toml` is particularly affected because it will be written atomically by external tools (`filewallctl remove`), making silent reload especially desirable.

## Goal

Automatically detect changes to both watched files and trigger the existing reload path, with no changes to the event loop and SIGHUP remaining fully functional.

## Non-Goals

- Changes to the fanotify event loop.
- Watching files listed in `[[watch]]` entries for config changes (only the daemon's own config and rules files are watched).
- Per-user or multi-daemon support.
- Debouncing (the AtomicBool is idempotent; the event loop coalesces reloads naturally).

## Approach

A dedicated watcher thread uses Linux `inotify` (via the `nix` crate's `inotify` feature) to watch the **parent directories** of `config.toml` and `rules.toml`. On a matching filename event the thread sets the same `RELOAD` `AtomicBool` that `SIGHUP` already sets. The event loop is unchanged.

Watching parent directories (rather than file inodes) is necessary to catch atomic rename-into-place writes such as `rules::save_atomic`, which replaces the inode via `rename()` and would not fire on a direct inode watch.

## Dependency Change

Add the `inotify` feature to the existing `nix` workspace dependency in `Cargo.toml`:

```toml
nix = { version = "0.29", features = ["fs", "signal", "inotify"] }
```

No new crates are introduced.

## Required Code Change in `main.rs`

The existing `RELOAD` declaration is private to the `main` module:

```rust
static RELOAD: AtomicBool = AtomicBool::new(false);
```

It must be made crate-visible so `watcher.rs` can reference `crate::RELOAD`:

```rust
pub(crate) static RELOAD: AtomicBool = AtomicBool::new(false);
```

## New Module: `filewalld/src/watcher.rs`

Single public function:

```rust
pub fn spawn_watcher(config_path: &Path, rules_path: &Path)
```

### Setup

1. Compute the parent directory and filename (`OsStr`) for each path.
2. Deduplicate: if both paths share the same parent directory, place a single `add_watch` on that directory.
3. Watch mask: `IN_CLOSE_WRITE | IN_MOVED_TO`.
   - `IN_CLOSE_WRITE`: direct editor saves (file fully closed after write). Also fires after unlink+recreate patterns once the new file is closed — no partial-read risk.
   - `IN_MOVED_TO`: atomic rename-into-place (`rules.toml`'s `save_atomic`).
   - `IN_CREATE` is intentionally excluded: it fires before data is written and would trigger a reload on an empty or partial file.
4. On any failure (inotify init, `add_watch`): log a warning and return. The daemon continues without file watching; SIGHUP still works.

### Thread

Detached thread (`JoinHandle` dropped). Runs for daemon lifetime; killed with the process. No graceful shutdown channel is needed.

```
loop:
  events = inotify.read_events()   // blocking
  for each event:
    if event.name (OsStr) matches config_filename OR rules_filename:
      RELOAD.store(true, SeqCst)
  on read error:
    log warning, break             // file watching silently degrades
```

**Filename matching** uses `OsStr` comparison, not `&str`, to correctly handle non-UTF-8 paths:

```rust
if ev.name.as_deref() == Some(config_name) || ev.name.as_deref() == Some(rules_name) {
    crate::RELOAD.store(true, Ordering::SeqCst);
}
```

### Self-triggered reload on "Always" decisions

When the daemon persists an "Always" decision it calls `rules.save_atomic`, which renames a temp file to `rules.toml`. This fires `IN_MOVED_TO` on the watcher, which sets `RELOAD`. On the next event-loop iteration the daemon reloads `rules.toml` — the same file it just wrote. The reload is a no-op in practice (the file is consistent) and the `Config::load` / `Rules::load` error paths keep the current state on any failure. This redundant reload on every "Always" decision is accepted as a minor cost of the simple design; debouncing is not worth the complexity.

## Integration in `main.rs`

`spawn_watcher` is called in `run()` immediately after `rules_path` is cloned (line 53 in the current source), before `UiServer::bind`. This is the earliest useful point (both paths are known) and ensures the watcher is live during the potentially-long blocking `server.accept()` that waits for the UI helper to connect, and before any fanotify marks are placed.

```rust
let rules_path = cfg.rules_path.clone();
watcher::spawn_watcher(Path::new(&config_path), &rules_path);  // ← new, before UiServer::bind
// ... rest of existing run() unchanged ...
let server = UiServer::bind(&cfg.socket_path, timeout)?;
```

Placing it after `server.accept()` (which blocks indefinitely) would create a window during UI connection where a config change could be missed; that placement is explicitly wrong.

## Error Handling

| Failure | Behaviour |
|---|---|
| `inotify::init` fails | Log warning, return; daemon runs without file watching |
| `add_watch` fails | Log warning, return; daemon runs without file watching |
| Thread read error | Log warning, thread exits; SIGHUP still available |
| Invalid config on reload | Existing behaviour: log error, keep current config |

## Testing

All tests in `filewalld/src/watcher.rs`, runnable under `cargo test` (no root required).

**Shared-static isolation:** All tests touch the same `crate::RELOAD` static. Because `cargo test` runs tests in parallel by default, concurrent tests would race on this flag. Tests serialize via a module-level mutex:

```rust
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
```

Each test acquires `let _guard = TEST_LOCK.lock().unwrap();` as its first line, then calls `RELOAD.store(false, SeqCst)` to clear state left by previous tests before entering the timed assertion window. No new dev-dependencies are required.

| Test | What it validates |
|---|---|
| `config_close_write_triggers_reload` | Writing and closing the config file sets `RELOAD` via `IN_CLOSE_WRITE` |
| `rules_moved_to_triggers_reload` | Atomic rename into rules filename sets `RELOAD` via `IN_MOVED_TO` |
| `unrelated_file_does_not_trigger_reload` | Writing a different filename in the same dir does not set `RELOAD` |
| `shared_parent_both_files_trigger_reload` | When both paths share a parent dir, a single watch covers both filenames |

Tests write real files in `std::env::temp_dir()`, spin up `spawn_watcher`, and assert `RELOAD` within a short timeout (500 ms).

## Sequence Diagram

```
editor / filewallctl           watcher thread           event loop (main thread)
        |                            |                            |
        |-- write rules.toml ------->|                            |
        |   (atomic rename)          |-- inotify IN_MOVED_TO      |
        |                            |-- RELOAD.store(true) ----->|
        |                            |                            |-- reload config+rules
        |                            |                            |-- re-mark files
```
