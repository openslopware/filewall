# Learned-Rules Persistence + `filewallctl` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make filewall a daily driver — persist "Always allow/deny" decisions so the user stops re-answering the same prompts, and add a `filewallctl` CLI to inspect and revoke learned rules.

**Architecture:** A new `filewall-rules` library crate holds the learned-rule schema, an atomic-write `rules.toml` store, and a deny-wins matcher. `filewalld` consults it alongside the existing compiled config `Policy` (config + learned, deny-wins), captures process `cwd` as an opt-in match dimension, persists rules on `*Always` decisions, and reloads config+rules on `SIGHUP`. `filewall-ui` grows from a 2-button to a 4-button zenity prompt. A new `filewallctl` binary lists/removes rules and pokes the daemon via a pidfile + SIGHUP.

**Tech Stack:** Rust (workspace), `fanotify` FFI (existing), `globset`, `toml`/`serde`, `nix` (signal), zenity.

---

## Design references

- Spec: `docs/superpowers/specs/2026-06-13-learned-rules-persistence-filewallctl-design.md`
- Security framing: globbable exe path is the trust anchor; `cwd`/argv are opt-in narrowing + always-shown context, never the sole basis for trust; no auto-glob generalization of learned rules.

## Deviations from spec (intentional, minor)

- `created` is stored as **`created_unix: u64`** (epoch seconds) rather than an ISO-8601 string, to avoid pulling in a date crate. `filewallctl list` renders it human-readably.
- Malformed `rules.toml` → **log loudly and start with an empty learned set** (rather than per-entry skip, which `toml` derive can't do without manual `Value` walking). Net safety property is preserved: a corrupt learned file never bricks the daemon, and config enforcement is unaffected.

## File structure

| File | Responsibility |
|---|---|
| `filewall-rules/Cargo.toml` | New lib crate manifest. |
| `filewall-rules/src/lib.rs` | `RuleAction`, `ObjectKind`, `LearnedRule`, `Rules` (load/save_atomic/push/evaluate), `now_unix`. Shared by daemon + ctl. |
| `filewall-proto/src/lib.rs` | `Decision` → 4 variants + `allows()`; `PromptRequest` gains `cwd`. |
| `filewalld/src/fanotify.rs` | `Event::cwd()` + testable `proc_cwd(pid)`. |
| `filewalld/src/policy.rs` | `combine(cfg, learned)` deny-wins; `WatchPolicy` gains learn settings + `learned_rule(...)`. |
| `filewalld/src/config.rs` | `rules_path`; per-watch `learn_object`/`learn_match`. |
| `filewalld/src/main.rs` | Consult rules, persist on `*Always`, SIGHUP reload, pidfile. |
| `filewall-ui/src/main.rs` | 4-button zenity + `classify()`; show `cwd`. |
| `filewallctl/Cargo.toml` | New bin crate manifest. |
| `filewallctl/src/main.rs` | `list`/`remove`/`reload`/`status`; `parse_pidfile`, `remove_at`. |
| `Cargo.toml` | Add members + `filewall-rules` dep; add `nix` `signal` feature. |
| `config.toml`, `e2e.sh`, `README.md`, `docs/project-status.md` | Examples, E2E, docs. |

---

## Task 1: Capture process `cwd` in fanotify events

**Files:**
- Modify: `filewalld/src/fanotify.rs`

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)]` module at the bottom of `filewalld/src/fanotify.rs` (create the module if absent):

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p filewalld proc_cwd`
Expected: FAIL — `cannot find function proc_cwd`.

- [ ] **Step 3: Add the helper and the `Event::cwd()` method**

In `filewalld/src/fanotify.rs`, add a free function near `path_to_cstring`:

```rust
/// Resolve a process's current working directory via `/proc/<pid>/cwd`.
/// Returns `<unresolved>` if the link can't be read.
pub fn proc_cwd(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unresolved>".into())
}
```

Add a method inside `impl Event { ... }` (next to `exe()`):

```rust
    /// Resolve the accessing process's cwd. Race-free while the pidfd is held.
    pub fn cwd(&self) -> String {
        proc_cwd(self.pid)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p filewalld proc_cwd`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add filewalld/src/fanotify.rs
git commit -m "feat(filewalld): capture process cwd from fanotify events"
```

---

## Task 2: Widen the IPC `Decision` to 4 variants + add `cwd` to `PromptRequest`

This is a protocol change. To keep the workspace compiling, downstream call sites are updated in the same task with behavior unchanged (always-variants are wired to persistence in Task 7; the 4-button UI lands in Task 3).

**Files:**
- Modify: `filewall-proto/src/lib.rs`
- Modify: `filewalld/src/main.rs`
- Modify: `filewalld/src/server.rs` (test fixture only)
- Modify: `filewall-ui/src/main.rs`

- [ ] **Step 1: Update proto tests to the new shape**

In `filewall-proto/src/lib.rs`, replace the `decision_serializes_lowercase` test and update `sample_request`:

```rust
    fn sample_request() -> PromptRequest {
        PromptRequest {
            pid: 84321,
            exe: "/usr/bin/node".into(),
            cmdline: "node /home/user/evil.js".into(),
            cwd: "/home/user/projects/foo".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
        }
    }

    #[test]
    fn decision_serializes_kebab() {
        assert_eq!(serde_json::to_string(&Decision::AllowOnce).unwrap(), "\"allow-once\"");
        assert_eq!(serde_json::to_string(&Decision::DenyAlways).unwrap(), "\"deny-always\"");
    }

    #[test]
    fn decision_allows_predicate() {
        assert!(Decision::AllowOnce.allows());
        assert!(Decision::AllowAlways.allows());
        assert!(!Decision::DenyOnce.allows());
        assert!(!Decision::DenyAlways.allows());
    }
```

Also update the two response-construction sites in proto tests (`framing_roundtrip_response`, `two_messages_back_to_back`) to use `Decision::DenyOnce` / `Decision::AllowOnce` instead of `Decision::Deny` / `Decision::Allow`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p filewall-proto`
Expected: FAIL to compile — `Decision::AllowOnce` not found, `PromptRequest` has no field `cwd`.

- [ ] **Step 3: Change the enum and struct**

In `filewall-proto/src/lib.rs`, replace the `Decision` enum and add `cwd` to `PromptRequest`:

```rust
/// A request from the daemon asking the user to decide on a file access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRequest {
    /// PID of the accessing process.
    pub pid: u32,
    /// Resolved executable path (`/proc/<pid>/exe`), or `<unresolved>`.
    pub exe: String,
    /// Full command line, NUL-joined args rendered with spaces.
    pub cmdline: String,
    /// Process working directory (`/proc/<pid>/cwd`); context for the human.
    pub cwd: String,
    /// The watched file path being accessed.
    pub path: String,
}

/// The user's decision for a single access. `*Once` are one-shot; `*Always`
/// also persist a learned rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    AllowOnce,
    DenyOnce,
    AllowAlways,
    DenyAlways,
}

impl Decision {
    /// Whether this decision permits the access (maps to FAN_ALLOW).
    pub fn allows(self) -> bool {
        matches!(self, Decision::AllowOnce | Decision::AllowAlways)
    }
}
```

- [ ] **Step 4: Fix `filewalld/src/main.rs` to compile (behavior unchanged)**

In the `Outcome::Prompt` arm of `event_loop`, build the request with `cwd` and collapse the decision via `allows()`:

```rust
                Outcome::Prompt => {
                    let req = PromptRequest {
                        pid: ev.pid,
                        exe: exe.clone(),
                        cmdline: ev.cmdline(),
                        cwd: ev.cwd(),
                        path: path.display().to_string(),
                    };
                    match ui.prompt(&req) {
                        Ok(decision) => decision.allows(),
                        // Timeout or UI disconnect -> deny (watchdog / fail-closed).
                        Err(e) => {
                            log(&format!(
                                "prompt failed ({e}); denying {} for {}",
                                path.display(),
                                exe
                            ));
                            false
                        }
                    }
                }
```

- [ ] **Step 5: Fix `filewalld/src/server.rs` test fixture**

In the `sample_req()` test helper, add the `cwd` field and switch the two `Decision::Allow` usages to `Decision::AllowOnce`:

```rust
    fn sample_req() -> PromptRequest {
        PromptRequest {
            pid: 4321,
            exe: "/usr/bin/node".into(),
            cmdline: "node evil.js".into(),
            cwd: "/home/user/projects/foo".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
        }
    }
```

In `prompt_roundtrip_returns_user_decision`, change both `Decision::Allow` to `Decision::AllowOnce`.

- [ ] **Step 6: Fix `filewall-ui/src/main.rs` to compile (still 2-button for now)**

In `ask()`, map the existing zenity result to the new variants:

```rust
    match status {
        // zenity exits 0 when the OK/--ok-label button is pressed.
        Ok(s) if s.code() == Some(0) => Decision::AllowOnce,
        Ok(_) => Decision::DenyOnce,
        Err(e) => {
            eprintln!("filewall-ui: failed to run zenity: {e}");
            Decision::DenyOnce
        }
    }
```

- [ ] **Step 7: Run the whole workspace test suite**

Run: `cargo test`
Expected: PASS — all existing tests green with the widened protocol.

- [ ] **Step 8: Commit**

```bash
git add filewall-proto/src/lib.rs filewalld/src/main.rs filewalld/src/server.rs filewall-ui/src/main.rs
git commit -m "feat(proto): 4-way Decision and cwd field; wire call sites"
```

---

## Task 3: 4-button zenity prompt in `filewall-ui`

**Files:**
- Modify: `filewall-ui/src/main.rs`

- [ ] **Step 1: Write the failing test for `classify`**

Add to a `#[cfg(test)]` module at the bottom of `filewall-ui/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::classify;
    use filewall_proto::Decision;

    #[test]
    fn ok_button_is_allow_once() {
        assert_eq!(classify(Some(0), ""), Decision::AllowOnce);
    }

    #[test]
    fn extra_buttons_map_to_always() {
        assert_eq!(classify(Some(1), "Always allow\n"), Decision::AllowAlways);
        assert_eq!(classify(Some(1), "Always deny\n"), Decision::DenyAlways);
    }

    #[test]
    fn cancel_close_and_error_fail_closed() {
        assert_eq!(classify(Some(1), ""), Decision::DenyOnce);   // cancel/close
        assert_eq!(classify(None, ""), Decision::DenyOnce);      // killed/no code
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p filewall-ui classify`
Expected: FAIL — `cannot find function classify`.

- [ ] **Step 3: Implement `classify` and the 4-button dialog**

In `filewall-ui/src/main.rs`, add the pure classifier:

```rust
/// Map a zenity exit code + stdout to a Decision. Fail-closed: anything that
/// isn't an explicit allow/always choice becomes DenyOnce.
fn classify(code: Option<i32>, stdout: &str) -> Decision {
    match (code, stdout.trim()) {
        (Some(0), _) => Decision::AllowOnce,
        (_, "Always allow") => Decision::AllowAlways,
        (_, "Always deny") => Decision::DenyAlways,
        _ => Decision::DenyOnce,
    }
}
```

Replace the body of `ask()` after the `text` is built. Add the `cwd` line to the dialog body and switch to `output()`:

```rust
    let text = format!(
        "\u{26A0}  filewall — sensitive file access\n\n\
         Process:     {proc_name}  (PID {pid})\n\
         Executable:  {exe}\n\
         Command:     {cmd}\n\
         Working dir: {cwd}\n\
         File:        {path}\n\n\
         Allow this access?",
        pid = req.pid,
        exe = req.exe,
        cmd = if req.cmdline.is_empty() { "<unavailable>" } else { &req.cmdline },
        cwd = if req.cwd.is_empty() { "<unavailable>" } else { &req.cwd },
        path = req.path,
    );

    let output = Command::new("zenity")
        .args([
            "--question",
            "--no-markup",
            "--title=filewall security prompt",
            "--width=480",
            "--ok-label=Allow once",
            "--cancel-label=Deny once",
            "--extra-button=Always allow",
            "--extra-button=Always deny",
            // Default focus on Deny: an accidental Enter fails closed.
            "--default-cancel",
            "--text",
            &text,
        ])
        .output();

    match output {
        Ok(out) => classify(out.status.code(), &String::from_utf8_lossy(&out.stdout)),
        Err(e) => {
            eprintln!("filewall-ui: failed to run zenity: {e}");
            Decision::DenyOnce
        }
    }
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p filewall-ui`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewall-ui/src/main.rs
git commit -m "feat(ui): 4-button always/once zenity prompt with cwd context"
```

---

## Task 4: New `filewall-rules` crate — schema + store

**Files:**
- Create: `filewall-rules/Cargo.toml`
- Create: `filewall-rules/src/lib.rs`
- Modify: `Cargo.toml` (workspace members + dependency)

- [ ] **Step 1: Add the crate to the workspace**

In the root `Cargo.toml`, add `filewall-rules` to `members` and to `[workspace.dependencies]`:

```toml
members = ["filewall-proto", "filewall-rules", "filewalld", "filewall-ui", "filewallctl"]
```

```toml
filewall-rules = { path = "filewall-rules" }
```

(`filewallctl` is created in Task 9; declaring it now is harmless only once its dir exists, so add `filewallctl` to `members` in Task 9 instead. For THIS task add only `filewall-rules`.)

Set `members = ["filewall-proto", "filewall-rules", "filewalld", "filewall-ui"]` for now.

- [ ] **Step 2: Create the crate manifest**

Create `filewall-rules/Cargo.toml`:

```toml
[package]
name = "filewall-rules"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
toml.workspace = true
```

- [ ] **Step 3: Write failing tests**

Create `filewall-rules/src/lib.rs` with ONLY the tests first (the types come next):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn tree_allow(exe: &str, root: &str) -> LearnedRule {
        LearnedRule {
            created_unix: 0,
            action: RuleAction::Allow,
            exe: exe.into(),
            object: PathBuf::from(root),
            object_kind: ObjectKind::Tree,
            cwd: None,
        }
    }

    #[test]
    fn tree_rule_matches_subpath_same_exe() {
        let r = tree_allow("/usr/bin/git", "/home/u/.ssh");
        assert!(r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.aws/creds"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/node", None));
    }

    #[test]
    fn file_rule_requires_exact_path() {
        let r = LearnedRule {
            created_unix: 0, action: RuleAction::Allow, exe: "/usr/bin/git".into(),
            object: PathBuf::from("/home/u/.ssh/id_ed25519"), object_kind: ObjectKind::File, cwd: None,
        };
        assert!(r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.ssh/other"), "/usr/bin/git", None));
    }

    #[test]
    fn cwd_constraint_must_match_when_present() {
        let mut r = tree_allow("/usr/bin/node", "/home/u/.ssh");
        r.cwd = Some("/home/u/projects/foo".into());
        assert!(r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", Some("/home/u/projects/foo")));
        assert!(!r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", Some("/elsewhere")));
        assert!(!r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", None));
    }

    #[test]
    fn evaluate_is_deny_wins() {
        let mut rs = Rules::default();
        rs.push(tree_allow("/usr/bin/node", "/home/u/.ssh"));
        let mut deny = tree_allow("/usr/bin/node", "/home/u/.ssh");
        deny.action = RuleAction::Deny;
        rs.push(deny);
        assert_eq!(
            rs.evaluate(Path::new("/home/u/.ssh/k"), "/usr/bin/node", None),
            Some(RuleAction::Deny)
        );
    }

    #[test]
    fn evaluate_returns_none_when_nothing_matches() {
        let rs = Rules::default();
        assert_eq!(rs.evaluate(Path::new("/x"), "/usr/bin/node", None), None);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let mut rs = Rules::default();
        rs.push(tree_allow("/usr/bin/git", "/home/u/.ssh"));
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-rules-test-{}-{}-{}.toml",
            std::process::id(), ts.as_secs(), ts.subsec_nanos()
        ));
        rs.save_atomic(&path).unwrap();
        let back = Rules::load(&path);
        assert_eq!(back.rules.len(), 1);
        assert_eq!(back.rules[0].exe, "/usr/bin/git");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let rs = Rules::load(Path::new("/nonexistent/filewall/rules.toml"));
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn load_corrupt_file_is_empty() {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-rules-corrupt-{}-{}.toml", std::process::id(), ts.subsec_nanos()
        ));
        std::fs::write(&path, b"this is not valid toml {{{").unwrap();
        let rs = Rules::load(&path);
        assert!(rs.rules.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
```

- [ ] **Step 4: Run to verify failure**

Run: `cargo test -p filewall-rules`
Expected: FAIL to compile — types not defined.

- [ ] **Step 5: Implement the types and store**

Prepend to `filewall-rules/src/lib.rs` (above the test module):

```rust
//! Learned-rule schema and store, shared by `filewalld` and `filewallctl`.
//!
//! A learned rule pins a *literal* executable path (the trust anchor) to an
//! object (a file or a watched tree), optionally constrained by the process
//! cwd. Matching never globs — generalization is an explicit act elsewhere.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// What a learned rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Whether a rule's object is a single file or a watched tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    File,
    Tree,
}

/// One persisted decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedRule {
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: u64,
    pub action: RuleAction,
    /// Literal executable path as observed (`/proc/<pid>/exe`).
    pub exe: String,
    /// File path (kind=file) or tree root (kind=tree) the rule covers.
    pub object: PathBuf,
    pub object_kind: ObjectKind,
    /// Optional cwd constraint; recorded only when the watch opts in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

impl LearnedRule {
    /// Does this rule apply to an access of `path` by `exe` from `cwd`?
    pub fn matches(&self, path: &Path, exe: &str, cwd: Option<&str>) -> bool {
        if self.exe != exe {
            return false;
        }
        let object_ok = match self.object_kind {
            ObjectKind::File => path == self.object,
            ObjectKind::Tree => path.starts_with(&self.object),
        };
        if !object_ok {
            return false;
        }
        match &self.cwd {
            None => true,
            Some(rule_cwd) => cwd == Some(rule_cwd.as_str()),
        }
    }
}

/// The full learned-rule set, mirrored to `rules.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Rules {
    #[serde(default, rename = "rule")]
    pub rules: Vec<LearnedRule>,
}

impl Rules {
    /// Load from disk. A missing or unparseable file yields an empty set (with a
    /// stderr warning on parse error) — a corrupt learned file must never brick
    /// the daemon.
    pub fn load(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return Rules::default(),
        };
        match toml::from_str(&text) {
            Ok(rs) => rs,
            Err(e) => {
                eprintln!("[filewall] warning: ignoring corrupt rules file {}: {e}", path.display());
                Rules::default()
            }
        }
    }

    /// Persist atomically: write a temp file in the same dir, then rename.
    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        let body = toml::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let tmp = dir.join(format!(
            ".rules.{}.{}.{}.tmp",
            std::process::id(), ts.as_secs(), ts.subsec_nanos()
        ));
        std::fs::write(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, path)
    }

    pub fn push(&mut self, rule: LearnedRule) {
        self.rules.push(rule);
    }

    /// Deny-wins evaluation across all learned rules.
    pub fn evaluate(&self, path: &Path, exe: &str, cwd: Option<&str>) -> Option<RuleAction> {
        let mut allow = false;
        for r in &self.rules {
            if r.matches(path, exe, cwd) {
                match r.action {
                    RuleAction::Deny => return Some(RuleAction::Deny),
                    RuleAction::Allow => allow = true,
                }
            }
        }
        if allow { Some(RuleAction::Allow) } else { None }
    }
}

/// Seconds since the Unix epoch (for `LearnedRule::created_unix`).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
```

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p filewall-rules`
Expected: PASS (8 tests).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml filewall-rules/
git commit -m "feat(rules): learned-rule schema, atomic store, deny-wins matcher"
```

---

## Task 5: Config + `WatchPolicy` learn settings

**Files:**
- Modify: `filewalld/Cargo.toml` (add `filewall-rules` dep)
- Modify: `filewalld/src/policy.rs`
- Modify: `filewalld/src/config.rs`

- [ ] **Step 1: Add the dependency**

In `filewalld/Cargo.toml` `[dependencies]`, add:

```toml
filewall-rules.workspace = true
```

- [ ] **Step 2: Write failing tests for `WatchPolicy::learned_rule`**

Add to the `tests` module in `filewalld/src/policy.rs`:

```rust
    use filewall_rules::{ObjectKind, RuleAction};

    #[test]
    fn learned_rule_tree_uses_watch_root() {
        let p = WatchPolicy::new(
            "/home/u/.ssh", &[], Action::Prompt, ObjectKind::Tree, false,
        ).unwrap();
        let r = p.learned_rule(RuleAction::Allow, "/usr/bin/node",
            std::path::Path::new("/home/u/.ssh/id_ed25519"), Some("/home/u/p"));
        assert_eq!(r.object_kind, ObjectKind::Tree);
        assert_eq!(r.object, std::path::PathBuf::from("/home/u/.ssh"));
        assert_eq!(r.exe, "/usr/bin/node");
        assert_eq!(r.cwd, None); // learn_cwd = false
    }

    #[test]
    fn learned_rule_file_uses_exact_path_and_cwd() {
        let p = WatchPolicy::new(
            "/home/u/.ssh", &[], Action::Prompt, ObjectKind::File, true,
        ).unwrap();
        let r = p.learned_rule(RuleAction::Deny, "/usr/bin/node",
            std::path::Path::new("/home/u/.ssh/id_ed25519"), Some("/home/u/p"));
        assert_eq!(r.object_kind, ObjectKind::File);
        assert_eq!(r.object, std::path::PathBuf::from("/home/u/.ssh/id_ed25519"));
        assert_eq!(r.action, RuleAction::Deny);
        assert_eq!(r.cwd.as_deref(), Some("/home/u/p"));
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p filewalld learned_rule`
Expected: FAIL to compile — `WatchPolicy::new` arity wrong, no `learned_rule`.

- [ ] **Step 4: Extend `WatchPolicy`**

In `filewalld/src/policy.rs`, add an import at the top:

```rust
use filewall_rules::{LearnedRule, ObjectKind, RuleAction, now_unix};
```

Add two fields to the `WatchPolicy` struct:

```rust
    /// Object granularity a learned "Always" rule records.
    learn_object: ObjectKind,
    /// Whether learned rules from this watch pin the process cwd.
    learn_cwd: bool,
```

Update `WatchPolicy::new` signature and body:

```rust
    pub fn new(
        root: impl Into<PathBuf>,
        allow_patterns: &[String],
        default_action: Action,
        learn_object: ObjectKind,
        learn_cwd: bool,
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for pat in allow_patterns {
            let glob: Glob = GlobBuilder::new(pat).literal_separator(true).build()?;
            builder.add(glob);
        }
        Ok(Self {
            root: root.into(),
            allow: builder.build()?,
            default_action,
            learn_object,
            learn_cwd,
        })
    }
```

Add the rule-builder method inside `impl WatchPolicy`:

```rust
    /// Build a learned rule for an access this watch covered, honoring the
    /// watch's `learn_object`/`learn_cwd` policy.
    pub fn learned_rule(
        &self,
        action: RuleAction,
        exe: &str,
        path: &Path,
        cwd: Option<&str>,
    ) -> LearnedRule {
        let (object, object_kind) = match self.learn_object {
            ObjectKind::Tree => (self.root.clone(), ObjectKind::Tree),
            ObjectKind::File => (path.to_path_buf(), ObjectKind::File),
        };
        LearnedRule {
            created_unix: now_unix(),
            action,
            exe: exe.to_string(),
            object,
            object_kind,
            cwd: if self.learn_cwd { cwd.map(|s| s.to_string()) } else { None },
        }
    }
```

Update the existing `ssh_policy()` test helper and every other `WatchPolicy::new(...)` call in the policy tests to pass the two new args. For `ssh_policy` and the other allow/deny-list tests use `ObjectKind::File, false`:

```rust
    fn ssh_policy() -> WatchPolicy {
        WatchPolicy::new(
            "/home/user/.ssh",
            &[
                "/usr/bin/ssh".to_string(),
                "/usr/bin/ssh-*".to_string(),
                "/usr/lib/openssh/*".to_string(),
            ],
            Action::Prompt,
            ObjectKind::File,
            false,
        )
        .unwrap()
    }
```

Apply the same two-arg addition (`ObjectKind::File, false`) to the `WatchPolicy::new` calls in `double_star_crosses_slash`, `default_action_deny_is_honored`, and `policy_routes_to_covering_watch`.

- [ ] **Step 5: Run policy tests**

Run: `cargo test -p filewalld --lib policy`
Expected: FAIL — `config.rs` no longer compiles (its `build_policy` calls the old `WatchPolicy::new`). That's fixed next; if you want policy green in isolation, proceed to Step 6 then run the full suite.

- [ ] **Step 6: Add config fields and update `build_policy`**

In `filewalld/src/config.rs`, add an import:

```rust
use filewall_rules::ObjectKind;
```

Extend `WatchConfig`:

```rust
#[derive(Debug, Deserialize)]
pub struct WatchConfig {
    pub path: String,
    #[serde(default)]
    pub allow: Vec<String>,
    /// "file" | "tree" — what an "Always" decision records. Default: file.
    #[serde(default = "default_learn_object")]
    pub learn_object: ObjectKind,
    /// Subset of ["exe","cwd"]; "cwd" opts the watch into cwd-pinned rules.
    #[serde(default)]
    pub learn_match: Vec<String>,
}
```

Add `rules_path` to `Config` and the default fns:

```rust
    #[serde(default = "default_rules_path")]
    pub rules_path: PathBuf,
```

```rust
fn default_learn_object() -> ObjectKind {
    ObjectKind::File
}
fn default_rules_path() -> PathBuf {
    PathBuf::from("/var/lib/filewall/rules.toml")
}
```

Update `build_policy` to pass the learn settings:

```rust
    pub fn build_policy(&self) -> Result<Policy, ConfigError> {
        let mut watches = Vec::new();
        for w in &self.watch {
            let root = expand_home(&w.path);
            let learn_cwd = w.learn_match.iter().any(|m| m == "cwd");
            let wp = WatchPolicy::new(root, &w.allow, self.default_action, w.learn_object, learn_cwd)
                .map_err(|e| ConfigError::Glob(w.path.clone(), e))?;
            watches.push(wp);
        }
        Ok(Policy::new(watches))
    }
```

- [ ] **Step 7: Add a config test for the new fields**

Add to the `tests` module in `filewalld/src/config.rs`:

```rust
    #[test]
    fn learn_settings_default_and_parse() {
        let cfg = Config::from_str(
            r#"
            rules_path = "/var/lib/filewall/rules.toml"
            [[watch]]
            path = "/home/u/.ssh"
            [[watch]]
            path = "/home/u/.aws"
            learn_object = "tree"
            learn_match = ["exe", "cwd"]
            "#,
        ).unwrap();
        assert_eq!(cfg.rules_path, PathBuf::from("/var/lib/filewall/rules.toml"));
        // defaults
        assert_eq!(cfg.watch[0].learn_object, filewall_rules::ObjectKind::File);
        assert!(cfg.watch[0].learn_match.is_empty());
        // explicit
        assert_eq!(cfg.watch[1].learn_object, filewall_rules::ObjectKind::Tree);
        assert!(cfg.watch[1].learn_match.iter().any(|m| m == "cwd"));
    }
```

- [ ] **Step 8: Run the full daemon suite**

Run: `cargo test -p filewalld`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add filewalld/Cargo.toml filewalld/src/policy.rs filewalld/src/config.rs
git commit -m "feat(filewalld): per-watch learn_object/learn_match config + rule builder"
```

---

## Task 6: Deny-wins combiner in `policy.rs`

**Files:**
- Modify: `filewalld/src/policy.rs`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `filewalld/src/policy.rs`:

```rust
    #[test]
    fn combine_deny_wins() {
        use filewall_rules::RuleAction::{Allow as LA, Deny as LD};
        // learned deny beats config allow
        assert_eq!(combine(Outcome::Allow, Some(LD)), Outcome::Deny);
        // config deny beats learned allow
        assert_eq!(combine(Outcome::Deny, Some(LA)), Outcome::Deny);
        // learned allow upgrades a prompt
        assert_eq!(combine(Outcome::Prompt, Some(LA)), Outcome::Allow);
        // config allow with no learned rule
        assert_eq!(combine(Outcome::Allow, None), Outcome::Allow);
        // nothing matches -> prompt
        assert_eq!(combine(Outcome::Prompt, None), Outcome::Prompt);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p filewalld combine_deny_wins`
Expected: FAIL — `cannot find function combine`.

- [ ] **Step 3: Implement `combine`**

Add to `filewalld/src/policy.rs` (top-level, after the `Outcome` impl):

```rust
/// Combine the config outcome with any learned-rule verdict, deny-wins.
pub fn combine(cfg: Outcome, learned: Option<RuleAction>) -> Outcome {
    match (cfg, learned) {
        (_, Some(RuleAction::Deny)) => Outcome::Deny,
        (Outcome::Deny, _) => Outcome::Deny,
        (_, Some(RuleAction::Allow)) => Outcome::Allow,
        (Outcome::Allow, _) => Outcome::Allow,
        (Outcome::Prompt, None) => Outcome::Prompt,
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p filewalld combine_deny_wins`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewalld/src/policy.rs
git commit -m "feat(filewalld): deny-wins combiner for config + learned outcomes"
```

---

## Task 7: Wire rules into the daemon event loop + persist on "Always"

**Files:**
- Modify: `filewalld/src/main.rs`

- [ ] **Step 1: Load rules at startup and thread them through**

In `filewalld/src/main.rs`, add imports:

```rust
use filewall_rules::{Rules, RuleAction};
use policy::combine;
use std::path::PathBuf;
```

(Keep the existing `use policy::{Outcome, Policy};`.)

In `run()`, after `let policy = cfg.build_policy()?;`, load the rules and capture the path:

```rust
    let rules_path = cfg.rules_path.clone();
    let mut rules = Rules::load(&rules_path);
    log(&format!("loaded {} learned rule(s) from {}", rules.rules.len(), rules_path.display()));
```

Change the `event_loop(...)` call to pass the rules and path:

```rust
    event_loop(&fan, &policy, &mut rules, &rules_path, &mut ui, own_pid)
```

- [ ] **Step 2: Update `event_loop` to consult rules and persist**

Replace the `event_loop` signature and the decision logic:

```rust
fn event_loop(
    fan: &Fanotify,
    policy: &Policy,
    rules: &mut Rules,
    rules_path: &Path,
    ui: &mut UiLink,
    own_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let events = fan.read_events()?;
        for ev in &events {
            if !ev.is_open_perm() || ev.pid == own_pid {
                let _ = fan.respond(ev, true);
                continue;
            }

            let path = ev.accessed_path().unwrap_or_else(|_| PathBuf::from("<unknown>"));
            if !ev.has_pidfd() {
                log(&format!("warning: no pidfd for pid {}; exe may be racy", ev.pid));
            }
            let exe = ev.exe();
            let cwd = ev.cwd();

            let cfg_outcome = policy.evaluate(&path, &exe);
            let learned = rules.evaluate(&path, &exe, Some(cwd.as_str()));
            let allow = match combine(cfg_outcome, learned) {
                Outcome::Allow => true,
                Outcome::Deny => false,
                Outcome::Prompt => {
                    let req = PromptRequest {
                        pid: ev.pid,
                        exe: exe.clone(),
                        cmdline: ev.cmdline(),
                        cwd: cwd.clone(),
                        path: path.display().to_string(),
                    };
                    match ui.prompt(&req) {
                        Ok(decision) => {
                            // Persist "Always" decisions: add in-memory now, mirror to disk.
                            if let Some(action) = always_action(decision) {
                                if let Some(watch) = policy.watches().iter().find(|w| w.covers(&path)) {
                                    let rule = watch.learned_rule(action, &exe, &path, Some(cwd.as_str()));
                                    rules.push(rule);
                                    if let Err(e) = rules.save_atomic(rules_path) {
                                        log(&format!("warning: could not persist rule: {e}"));
                                    } else {
                                        log(&format!("learned {:?} {} -> {}", action, exe, path.display()));
                                    }
                                }
                            }
                            decision.allows()
                        }
                        Err(e) => {
                            log(&format!(
                                "prompt failed ({e}); denying {} for {}",
                                path.display(), exe
                            ));
                            false
                        }
                    }
                }
            };

            if let Err(e) = fan.respond(ev, allow) {
                log(&format!("warning: failed to answer event: {e}"));
            }
            log(&format!(
                "{} {} -> {}",
                if allow { "ALLOW" } else { "DENY " },
                exe,
                path.display()
            ));
        }
    }
}
```

Add the mapping helper at the bottom of `main.rs`:

```rust
/// Map an "Always" decision to the rule action to persist; `None` for one-shots.
fn always_action(d: Decision) -> Option<RuleAction> {
    match d {
        Decision::AllowAlways => Some(RuleAction::Allow),
        Decision::DenyAlways => Some(RuleAction::Deny),
        Decision::AllowOnce | Decision::DenyOnce => None,
    }
}
```

Note: `WatchPolicy::covers` is already `pub`. `policy.watches()` is already `pub`.

- [ ] **Step 3: Build and run the full suite**

Run: `cargo test`
Expected: PASS — workspace compiles; existing tests green. (No new unit test here; the persistence path is exercised by the E2E in Task 10. The pure pieces it composes — `combine`, `learned_rule`, `Rules` — are already unit-tested.)

- [ ] **Step 4: Commit**

```bash
git add filewalld/src/main.rs
git commit -m "feat(filewalld): consult learned rules and persist Always decisions"
```

---

## Task 8: SIGHUP reload + pidfile

**Files:**
- Modify: `filewalld/Cargo.toml` (none — `nix` signal feature added in root)
- Modify: `Cargo.toml` (add `signal` to nix features)
- Modify: `filewalld/src/main.rs`

- [ ] **Step 1: Enable the `nix` signal feature**

In the root `Cargo.toml`, update the `nix` dependency:

```toml
nix = { version = "0.29", features = ["fs", "signal"] }
```

- [ ] **Step 2: Write a failing test for the pidfile helpers**

Add a `#[cfg(test)]` module to `filewalld/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::{write_pidfile, read_pidfile};

    #[test]
    fn pidfile_write_then_read() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-pid-{}-{}.pid", std::process::id(), ts.subsec_nanos()
        ));
        write_pidfile(&path, 4242).unwrap();
        assert_eq!(read_pidfile(&path).unwrap(), 4242);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_pidfile_missing_is_err() {
        assert!(read_pidfile(std::path::Path::new("/nonexistent/x.pid")).is_err());
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p filewalld pidfile`
Expected: FAIL — helpers not defined.

- [ ] **Step 4: Implement pidfile helpers + SIGHUP handler + reload**

In `filewalld/src/main.rs`, add near the top (after the `use` block):

```rust
use std::sync::atomic::{AtomicBool, Ordering};

const PIDFILE: &str = "/run/filewall/filewalld.pid";

static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sighup(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// Write our PID so `filewallctl reload`/`status` can find us.
fn write_pidfile(path: &std::path::Path, pid: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{pid}\n"))
}

/// Read a PID from a pidfile.
fn read_pidfile(path: &std::path::Path) -> std::io::Result<i32> {
    let s = std::fs::read_to_string(path)?;
    s.trim().parse::<i32>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
```

In `run()`, after `Fanotify::init()` succeeds and before the event loop, install the handler and write the pidfile:

```rust
    // SAFETY: installing a trivial signal handler that only sets an atomic flag.
    unsafe {
        libc::signal(libc::SIGHUP, on_sighup as libc::sighandler_t);
    }
    let pidfile = PathBuf::from(PIDFILE);
    if let Err(e) = write_pidfile(&pidfile, own_pid) {
        log(&format!("warning: could not write pidfile {}: {e}", pidfile.display()));
    }
```

Make `policy` and the marking re-usable for reload. Refactor the marking into a helper and call it both initially and on reload:

```rust
/// Mark every existing regular file under each watched root. Idempotent
/// (FAN_MARK_ADD on an already-marked inode is a no-op).
fn mark_all(fan: &Fanotify, policy: &Policy) -> usize {
    let mut marked = 0usize;
    for watch in policy.watches() {
        for file in walk_files(watch.root()) {
            match fan.mark_file(&file) {
                Ok(()) => marked += 1,
                Err(e) => log(&format!("warning: could not mark {}: {e}", file.display())),
            }
        }
    }
    marked
}
```

Replace the inline marking block in `run()` with `let _ = mark_all(&fan, &policy);` and a log line.

Now make `run()` own `policy` mutably and pass `config_path` into the loop so reload can rebuild. Change the `event_loop` call and add reload handling. Update the loop's read step:

```rust
        let events = match fan.read_events() {
            Ok(evs) => evs,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => {
                // Likely our SIGHUP. Fall through to the reload check.
                Vec::new()
            }
            Err(e) => return Err(e.into()),
        };

        if RELOAD.swap(false, Ordering::SeqCst) {
            match Config::load(Path::new(config_path)) {
                Ok(new_cfg) => match new_cfg.build_policy() {
                    Ok(new_policy) => {
                        *policy = new_policy;
                        *rules = Rules::load(rules_path);
                        let n = mark_all(fan, policy);
                        log(&format!("reloaded config + {} rule(s); re-marked {n} file(s)", rules.rules.len()));
                    }
                    Err(e) => log(&format!("reload failed (policy): {e}; keeping current config")),
                },
                Err(e) => log(&format!("reload failed (config): {e}; keeping current config")),
            }
        }
```

This requires `event_loop` to take `policy: &mut Policy` and `config_path: &str`. Update its signature:

```rust
fn event_loop(
    fan: &Fanotify,
    policy: &mut Policy,
    rules: &mut Rules,
    rules_path: &Path,
    config_path: &str,
    ui: &mut UiLink,
    own_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
```

And the `run()` locals: change `let policy = ...` to `let mut policy = ...`, and the call to:

```rust
    event_loop(&fan, &mut policy, &mut rules, &rules_path, &config_path, &mut ui, own_pid)
```

The `for ev in &events` body is unchanged; on an EINTR with no events the `for` simply iterates zero times.

- [ ] **Step 5: Run tests**

Run: `cargo test -p filewalld`
Expected: PASS — pidfile tests green, workspace compiles.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml filewalld/src/main.rs
git commit -m "feat(filewalld): SIGHUP reload of config+rules and pidfile"
```

---

## Task 9: `filewallctl` CLI

**Files:**
- Create: `filewallctl/Cargo.toml`
- Create: `filewallctl/src/main.rs`
- Modify: `Cargo.toml` (add member)

- [ ] **Step 1: Register the crate**

In the root `Cargo.toml`, set:

```toml
members = ["filewall-proto", "filewall-rules", "filewalld", "filewall-ui", "filewallctl"]
```

- [ ] **Step 2: Create the manifest**

Create `filewallctl/Cargo.toml`:

```toml
[package]
name = "filewallctl"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "filewallctl"
path = "src/main.rs"

[dependencies]
filewall-rules.workspace = true
nix = { workspace = true }
```

- [ ] **Step 3: Write failing tests**

Create `filewallctl/src/main.rs` with the tests first plus stub `fn main() {}`:

```rust
fn main() {}

#[cfg(test)]
mod tests {
    use super::{parse_pidfile, remove_at};
    use filewall_rules::{LearnedRule, ObjectKind, RuleAction, Rules};
    use std::path::PathBuf;

    fn rule(exe: &str) -> LearnedRule {
        LearnedRule {
            created_unix: 0, action: RuleAction::Allow, exe: exe.into(),
            object: PathBuf::from("/home/u/.ssh"), object_kind: ObjectKind::Tree, cwd: None,
        }
    }

    #[test]
    fn parse_pidfile_trims_and_parses() {
        assert_eq!(parse_pidfile("4242\n").unwrap(), 4242);
        assert!(parse_pidfile("not-a-pid").is_none());
    }

    #[test]
    fn remove_at_removes_in_range() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a"));
        rs.push(rule("/usr/bin/b"));
        let removed = remove_at(&mut rs, 0).unwrap();
        assert_eq!(removed.exe, "/usr/bin/a");
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].exe, "/usr/bin/b");
    }

    #[test]
    fn remove_at_out_of_range_is_none() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a"));
        assert!(remove_at(&mut rs, 5).is_none());
        assert_eq!(rs.rules.len(), 1);
    }
}
```

- [ ] **Step 4: Run to verify failure**

Run: `cargo test -p filewallctl`
Expected: FAIL — `parse_pidfile` / `remove_at` not defined.

- [ ] **Step 5: Implement the CLI**

Replace the stub `fn main()` and add the helpers in `filewallctl/src/main.rs` (keep the test module):

```rust
//! filewallctl — inspect and manage filewall's learned rules.
//!
//! Subcommands:
//!   list   [rules_path]      Print learned rules.
//!   remove <index> [path]    Remove a rule by index, then SIGHUP the daemon.
//!   reload [pidfile]         Send SIGHUP to the running daemon.
//!   status [pidfile]         Report whether the daemon is running.

use filewall_rules::Rules;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_RULES: &str = "/var/lib/filewall/rules.toml";
const DEFAULT_PIDFILE: &str = "/run/filewall/filewalld.pid";

fn parse_pidfile(s: &str) -> Option<i32> {
    s.trim().parse::<i32>().ok()
}

/// Remove the rule at `index`, returning it, or `None` if out of range.
fn remove_at(rules: &mut Rules, index: usize) -> Option<filewall_rules::LearnedRule> {
    if index < rules.rules.len() {
        Some(rules.rules.remove(index))
    } else {
        None
    }
}

fn cmd_list(path: &Path) -> ExitCode {
    let rules = Rules::load(path);
    if rules.rules.is_empty() {
        println!("No learned rules ({})", path.display());
        return ExitCode::SUCCESS;
    }
    println!("Learned rules ({}):", path.display());
    for (i, r) in rules.rules.iter().enumerate() {
        let cwd = r.cwd.as_deref().unwrap_or("-");
        println!(
            "  [{i}] {:?} exe={} object={} kind={:?} cwd={} created_unix={}",
            r.action, r.exe, r.object.display(), r.object_kind, cwd, r.created_unix
        );
    }
    ExitCode::SUCCESS
}

fn cmd_remove(index: usize, rules_path: &Path, pidfile: &Path) -> ExitCode {
    let mut rules = Rules::load(rules_path);
    match remove_at(&mut rules, index) {
        Some(removed) => {
            if let Err(e) = rules.save_atomic(rules_path) {
                eprintln!("filewallctl: could not write {}: {e}", rules_path.display());
                return ExitCode::FAILURE;
            }
            println!("Removed [{index}] {} -> {}", removed.exe, removed.object.display());
            // Best-effort: tell the daemon to reload.
            let _ = send_sighup(pidfile);
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("filewallctl: no rule at index {index}");
            ExitCode::FAILURE
        }
    }
}

fn send_sighup(pidfile: &Path) -> Result<i32, String> {
    let text = std::fs::read_to_string(pidfile)
        .map_err(|e| format!("reading {}: {e}", pidfile.display()))?;
    let pid = parse_pidfile(&text).ok_or_else(|| format!("invalid pidfile {}", pidfile.display()))?;
    kill(Pid::from_raw(pid), Signal::SIGHUP).map_err(|e| format!("kill {pid}: {e}"))?;
    Ok(pid)
}

fn cmd_reload(pidfile: &Path) -> ExitCode {
    match send_sighup(pidfile) {
        Ok(pid) => { println!("Sent SIGHUP to filewalld (pid {pid})"); ExitCode::SUCCESS }
        Err(e) => { eprintln!("filewallctl: reload failed: {e}"); ExitCode::FAILURE }
    }
}

fn cmd_status(pidfile: &Path) -> ExitCode {
    let text = match std::fs::read_to_string(pidfile) {
        Ok(t) => t,
        Err(_) => { println!("filewalld: not running (no pidfile)"); return ExitCode::FAILURE; }
    };
    let pid = match parse_pidfile(&text) {
        Some(p) => p,
        None => { println!("filewalld: unknown (bad pidfile)"); return ExitCode::FAILURE; }
    };
    // Signal 0 probes liveness without delivering a signal.
    match kill(Pid::from_raw(pid), None) {
        Ok(()) => { println!("filewalld: running (pid {pid})"); ExitCode::SUCCESS }
        Err(_) => { println!("filewalld: not running (stale pid {pid})"); ExitCode::FAILURE }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         filewallctl list [rules_path]\n  \
         filewallctl remove <index> [rules_path]\n  \
         filewallctl reload [pidfile]\n  \
         filewallctl status [pidfile]"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => {
            let path = args.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_list(&path)
        }
        Some("remove") => {
            let Some(index) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!("filewallctl: remove needs a numeric <index>");
                return usage();
            };
            let rules_path = args.get(2).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_remove(index, &rules_path, Path::new(DEFAULT_PIDFILE))
        }
        Some("reload") => {
            let pidfile = args.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_reload(&pidfile)
        }
        Some("status") => {
            let pidfile = args.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_status(&pidfile)
        }
        _ => usage(),
    }
}
```

Remove the temporary `fn main() {}` stub.

- [ ] **Step 6: Run to verify pass**

Run: `cargo test -p filewallctl`
Expected: PASS (3 tests).

- [ ] **Step 7: Build the binary**

Run: `cargo build -p filewallctl`
Expected: builds `target/debug/filewallctl`.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml filewallctl/
git commit -m "feat(filewallctl): list/remove/reload/status for learned rules"
```

---

## Task 10: Example config, E2E, and docs

**Files:**
- Modify: `config.toml`
- Modify: `e2e.sh`
- Modify: `README.md`
- Modify: `docs/project-status.md`

- [ ] **Step 1: Extend `config.toml` with the new knobs**

Read `config.toml` first. Add `rules_path` near the top and `learn_object`/`learn_match` to one watch as a documented example:

```toml
# Where the daemon persists "Always" decisions (managed by filewalld; inspect
# or revoke with `filewallctl`).
rules_path = "/var/lib/filewall/rules.toml"
```

For an example watch:

```toml
[[watch]]
path = "/home/you/.ssh"
allow = ["/usr/bin/ssh", "/usr/bin/ssh-*", "/usr/bin/git"]
# What an "Always allow/deny" click records:
#   learn_object = "file"  -> just the file that triggered the prompt (default)
#   learn_object = "tree"  -> any file under this watch
learn_object = "file"
# Extra dimensions a learned rule pins. "cwd" makes a rule apply only when the
# process runs from the same working directory. cwd is attacker-controllable,
# so treat it as a convenience, not a security boundary.
learn_match = ["exe"]
```

- [ ] **Step 2: Extend `e2e.sh` to prove the persistence loop**

Read `e2e.sh` first to match its style and variable names. After the existing "unlisted binary triggers the prompt" step, add a phase that:

1. Points the daemon at a writable `rules_path` (e.g. `$E2E_DIR/rules.toml`) — add `rules_path = "$E2E_DIR/rules.toml"` to the generated config, and `learn_object = "file"` on the watch.
2. Documents (in an echo block) the manual verification, since the prompt is interactive:
   - First unlisted access → prompt → click **Always allow**.
   - `filewallctl list "$E2E_DIR/rules.toml"` shows one rule.
   - Second access by the same binary → **no prompt** (rule fires).
   - `filewallctl remove 0 "$E2E_DIR/rules.toml"` (auto-SIGHUPs the daemon) → next access prompts again.

Add concrete `echo` lines invoking `target/release/filewallctl list "$E2E_DIR/rules.toml"` so the operator can copy-paste. Keep the existing allow/deny phases intact.

- [ ] **Step 3: Build release to confirm e2e references resolve**

Run: `cargo build --release`
Expected: builds `filewalld`, `filewall-ui`, `filewallctl`.

- [ ] **Step 4: Update `README.md`**

- Update the components table to add a `filewallctl` row.
- Update "How a decision is made" to mention learned rules consulted alongside the allowlist (deny-wins) and the 4 prompt choices.
- In "Configuration", document `rules_path`, `learn_object`, and `learn_match`.
- In "Deferred (post-MVP)", strike `filewallctl` and learned-rules persistence (now done); keep new-file marking, mount/fs marking, multi-user, systemd/PKGBUILD, notify-send, privilege drop.

- [ ] **Step 5: Update `docs/project-status.md`**

Bump the status line and "What exists" to reflect: learned-rules persistence, 4-button prompt, cwd matching, `filewallctl`, SIGHUP reload, pidfile. Update test count (`cargo test 2>&1 | tail` to get the new total). Set "Next agreed iteration" to inotify-driven new-file marking.

- [ ] **Step 6: Run the full suite one last time**

Run: `cargo test`
Expected: PASS across all crates.

- [ ] **Step 7: Commit**

```bash
git add config.toml e2e.sh README.md docs/project-status.md
git commit -m "docs: document learned rules + filewallctl; extend e2e"
```

---

## Self-review (completed during planning)

**Spec coverage:**
- 4-way prompt → Task 2 (proto) + Task 3 (UI). ✓
- Persistence loop (in-memory + rules.toml) → Task 4 (store) + Task 7 (wiring). ✓
- Opt-in cwd matching → Task 1 (capture) + Task 5 (config/builder) + Task 4 (matcher). ✓
- Deny-wins precedence → Task 4 (within learned) + Task 6 (config+learned). ✓
- filewallctl list/remove/reload/status → Task 9. ✓
- SIGHUP reload + pidfile → Task 8. ✓
- No auto-glob generalization → learned rules store literal exe (Task 4/5). ✓
- Config: learn_object/learn_match/rules_path → Task 5. ✓
- Fail-closed preserved in UI → Task 3 `classify` default arm. ✓
- Testing matrix (file/tree × cwd, deny-wins, config parse, filewallctl, e2e) → Tasks 4,5,6,9,10. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. E2E step 2 is necessarily descriptive (interactive prompt) but specifies exact commands.

**Type consistency:** `Decision` (kebab serde, `allows()`), `RuleAction`/`ObjectKind`/`LearnedRule`/`Rules` (filewall-rules), `WatchPolicy::new(root, allow, default_action, learn_object, learn_cwd)`, `learned_rule(action, exe, path, cwd)`, `combine(Outcome, Option<RuleAction>)`, `always_action(Decision) -> Option<RuleAction>`, `parse_pidfile`/`remove_at`/`write_pidfile`/`read_pidfile` — names consistent across tasks.
