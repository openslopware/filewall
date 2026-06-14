# Config/Rules Hot-Reload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically reload `config.toml` and `rules.toml` when they change on disk, without operator intervention, by watching their parent directories with inotify from a dedicated background thread.

**Architecture:** A new `filewalld/src/watcher.rs` module exposes a single `spawn_watcher(config_path, rules_path)` function that sets up inotify watches on the parent directories of both files and detaches a thread that sets the existing `RELOAD` `AtomicBool` on matching events. The fanotify event loop is unchanged; SIGHUP reload is unchanged and remains functional.

**Tech Stack:** Rust, `nix` crate v0.29 inotify bindings (new feature flag on existing dep), `std::thread::spawn`.

---

## File Map

| File | Change |
|---|---|
| `Cargo.toml` | Add `"inotify"` to nix features |
| `filewalld/src/main.rs` | Add `pub(crate)` to `RELOAD`; add `mod watcher;`; call `watcher::spawn_watcher(...)` in `run()` |
| `filewalld/src/watcher.rs` | **New.** `spawn_watcher` implementation + all 4 tests |

---

## Task 1: Enable `nix` inotify feature and expose `RELOAD`

**Files:**
- Modify: `Cargo.toml` (workspace root, line 18)
- Modify: `filewalld/src/main.rs` (line 23)

- [ ] **Step 1: Add `inotify` feature to the nix workspace dependency**

In `Cargo.toml`, change:
```toml
nix = { version = "0.29", features = ["fs", "signal"] }
```
to:
```toml
nix = { version = "0.29", features = ["fs", "signal", "inotify"] }
```

- [ ] **Step 2: Make `RELOAD` crate-visible**

In `filewalld/src/main.rs` line 23, change:
```rust
static RELOAD: AtomicBool = AtomicBool::new(false);
```
to:
```rust
pub(crate) static RELOAD: AtomicBool = AtomicBool::new(false);
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build -p filewalld
```
Expected: no errors. The `nix::sys::inotify` module is now available.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml filewalld/src/main.rs
git commit -m "feat: enable nix inotify feature and expose RELOAD as pub(crate)"
```

---

## Task 2: Create `watcher.rs` with first test and full implementation

The entire `spawn_watcher` implementation is written here alongside the first test. The remaining three tests (Task 3) build on the same function without changing it.

**Files:**
- Create: `filewalld/src/watcher.rs`
- Modify: `filewalld/src/main.rs` (add `mod watcher;`)

- [ ] **Step 1: Register the module in `main.rs`**

At the top of `filewalld/src/main.rs`, after the existing `mod` declarations (after `mod server;`, around line 6), add:
```rust
mod watcher;
```

- [ ] **Step 2: Create `filewalld/src/watcher.rs` with a stub and the first failing test**

Create the file with a no-op stub so the module compiles, plus the first test which must fail because the stub does nothing. The `OsString` import is intentionally omitted from the stub — it's added with the real implementation in Step 4:

```rust
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use std::path::Path;
use std::sync::atomic::Ordering;

pub fn spawn_watcher(_config_path: &Path, _rules_path: &Path) {
    // stub — not yet implemented
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RELOAD;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "filewall-watcher-{}-{}-{}-{}",
            tag,
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn wait_for_reload(timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if RELOAD.load(Ordering::SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn config_close_write_triggers_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmp_dir("cfg");
        let config_path = dir.join("config.toml");
        let rules_path = dir.join("rules.toml");
        std::fs::write(&config_path, b"").unwrap();
        std::fs::write(&rules_path, b"").unwrap();

        spawn_watcher(&config_path, &rules_path);
        std::thread::sleep(Duration::from_millis(50)); // let watcher thread settle

        RELOAD.store(false, Ordering::SeqCst);
        std::fs::write(&config_path, b"default_action = \"prompt\"").unwrap();

        assert!(wait_for_reload(Duration::from_millis(500)), "RELOAD not set after config write");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 3: Run the first test to confirm it fails**

```bash
cargo test -p filewalld watcher::tests::config_close_write_triggers_reload -- --nocapture
```
Expected: FAIL — the stub does nothing so RELOAD is never set and `wait_for_reload` returns `false`.

- [ ] **Step 4: Replace the stub with the full `spawn_watcher` implementation**

Replace the stub function body in `filewalld/src/watcher.rs`. Also add `use std::ffi::OsString;` to the imports at the top of the file (it was intentionally omitted from the stub to avoid an unused-import warning):

```rust
pub fn spawn_watcher(config_path: &Path, rules_path: &Path) {
    let config_dir = match config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => {
            eprintln!("[filewalld] watcher: no parent dir for config, file watching disabled");
            return;
        }
    };
    let config_name: OsString = match config_path.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            eprintln!("[filewalld] watcher: no filename for config, file watching disabled");
            return;
        }
    };
    let rules_dir = match rules_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => {
            eprintln!("[filewalld] watcher: no parent dir for rules, file watching disabled");
            return;
        }
    };
    let rules_name: OsString = match rules_path.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            eprintln!("[filewalld] watcher: no filename for rules, file watching disabled");
            return;
        }
    };

    let inotify = match Inotify::init(InitFlags::IN_CLOEXEC) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("[filewalld] watcher: inotify init failed ({e}), file watching disabled");
            return;
        }
    };

    let mask = AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;
    if let Err(e) = inotify.add_watch(&config_dir, mask) {
        eprintln!(
            "[filewalld] watcher: cannot watch {}: {e}, file watching disabled",
            config_dir.display()
        );
        return;
    }
    if rules_dir != config_dir {
        if let Err(e) = inotify.add_watch(&rules_dir, mask) {
            eprintln!(
                "[filewalld] watcher: cannot watch {}: {e}, file watching disabled",
                rules_dir.display()
            );
            return;
        }
    }
    eprintln!("[filewalld] watcher: watching for config/rules changes");

    std::thread::spawn(move || loop {
        let events = match inotify.read_events() {
            Ok(evs) => evs,
            Err(e) => {
                eprintln!("[filewalld] watcher: read error ({e}), file watching disabled");
                break;
            }
        };
        for ev in &events {
            if ev.name.as_deref() == Some(&*config_name)
                || ev.name.as_deref() == Some(&*rules_name)
            {
                crate::RELOAD.store(true, Ordering::SeqCst);
            }
        }
    });
}
```

- [ ] **Step 5: Run the first test to confirm it passes**

```bash
cargo test -p filewalld watcher::tests::config_close_write_triggers_reload -- --nocapture
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add filewalld/src/watcher.rs filewalld/src/main.rs
git commit -m "feat: add inotify watcher module with config close-write test"
```

---

## Task 3: Add remaining three tests

No implementation changes — all three tests exercise the same `spawn_watcher` function.

**Files:**
- Modify: `filewalld/src/watcher.rs` (append to `tests` module)

- [ ] **Step 1: Add the three remaining tests to the `tests` module**

Append inside the `#[cfg(test)] mod tests` block, after `config_close_write_triggers_reload`:

```rust
    #[test]
    fn rules_moved_to_triggers_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmp_dir("mv");
        let config_path = dir.join("config.toml");
        let rules_path = dir.join("rules.toml");
        std::fs::write(&config_path, b"").unwrap();
        std::fs::write(&rules_path, b"").unwrap();

        spawn_watcher(&config_path, &rules_path);
        std::thread::sleep(Duration::from_millis(50));

        RELOAD.store(false, Ordering::SeqCst);
        // Simulate save_atomic: write to a temp file, then rename into place.
        let tmp = dir.join(".rules.tmp");
        std::fs::write(&tmp, b"[[rule]]").unwrap();
        std::fs::rename(&tmp, &rules_path).unwrap();

        assert!(wait_for_reload(Duration::from_millis(500)), "RELOAD not set after atomic rename of rules");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrelated_file_does_not_trigger_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tmp_dir("unrel");
        let config_path = dir.join("config.toml");
        let rules_path = dir.join("rules.toml");
        std::fs::write(&config_path, b"").unwrap();
        std::fs::write(&rules_path, b"").unwrap();

        spawn_watcher(&config_path, &rules_path);
        std::thread::sleep(Duration::from_millis(50));

        RELOAD.store(false, Ordering::SeqCst);
        // Write a file with a different name in the same watched directory.
        std::fs::write(dir.join("unrelated.txt"), b"noise").unwrap();

        std::thread::sleep(Duration::from_millis(300));
        assert!(!RELOAD.load(Ordering::SeqCst), "RELOAD was set by an unrelated file write");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_parent_both_files_trigger_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Both files in the same directory — only one add_watch call should be made.
        let dir = tmp_dir("shared");
        let config_path = dir.join("config.toml");
        let rules_path = dir.join("rules.toml");
        std::fs::write(&config_path, b"").unwrap();
        std::fs::write(&rules_path, b"").unwrap();

        spawn_watcher(&config_path, &rules_path);
        std::thread::sleep(Duration::from_millis(50));

        // Config triggers reload.
        RELOAD.store(false, Ordering::SeqCst);
        std::fs::write(&config_path, b"changed").unwrap();
        assert!(wait_for_reload(Duration::from_millis(500)), "RELOAD not set for config in shared dir");

        // Rules triggers reload.
        RELOAD.store(false, Ordering::SeqCst);
        std::fs::write(&rules_path, b"changed").unwrap();
        assert!(wait_for_reload(Duration::from_millis(500)), "RELOAD not set for rules in shared dir");

        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 2: Run all watcher tests**

```bash
cargo test -p filewalld watcher::tests -- --nocapture
```
Expected: all 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add filewalld/src/watcher.rs
git commit -m "test: add remaining inotify watcher tests (moved_to, unrelated, shared parent)"
```

---

## Task 4: Wire `spawn_watcher` into `run()` and verify full suite

**Files:**
- Modify: `filewalld/src/main.rs` (around line 53)

- [ ] **Step 1: Call `spawn_watcher` in `run()` immediately after `rules_path` is cloned**

In `filewalld/src/main.rs`, the current lines around 53–54 read:

```rust
    let rules_path = cfg.rules_path.clone();
    let mut rules = Rules::load(&rules_path);
```

Insert the `spawn_watcher` call between them:

```rust
    let rules_path = cfg.rules_path.clone();
    watcher::spawn_watcher(Path::new(&config_path), &rules_path);
    let mut rules = Rules::load(&rules_path);
```

This placement is before `UiServer::bind` (line 83) and before `mark_all` (line 94), ensuring the watcher is live during the blocking `server.accept()` and before any fanotify marks are placed.

- [ ] **Step 2: Run the full test suite**

```bash
cargo test
```
Expected: all 27 existing tests + 4 new watcher tests pass (31 total). Zero warnings on the new code.

- [ ] **Step 3: Commit**

```bash
git add filewalld/src/main.rs
git commit -m "feat: wire inotify watcher into filewalld run() for automatic config/rules reload"
```
