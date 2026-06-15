# Prompt Scope Transparency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the access prompt show exactly what an "Always allow/deny" choice will persist — this file vs. an entire tree, the exe it's tied to, and any cwd pin — so the user makes an informed decision.

**Architecture:** The scope is config-driven (`learn_object`), already decided in `filewalld`. We (1) add three *descriptive* fields to the IPC `PromptRequest`, (2) source them from one `WatchPolicy::always_target` method that the persisted rule also uses (so display can't drift from reality), and (3) rewrite the UI helper to render them with `yad` (Pango markup: bold + a red warning for tree grants), classifying the result by per-button exit code.

**Tech Stack:** Rust workspace (`filewall-proto`, `filewall-rules`, `filewalld`, `filewall-ui`), serde/serde_json IPC, `yad` GTK dialog (replaces `zenity`).

**Spec:** `docs/superpowers/specs/2026-06-15-prompt-scope-transparency-design.md`

---

## File Structure

- `filewall-proto/src/lib.rs` — **modify.** `PromptRequest` gains `always_object: String`, `always_tree: bool`, `always_cwd_pinned: bool`. Update test fixtures + roundtrip assertions.
- `filewalld/src/policy.rs` — **modify.** Add `WatchPolicy::always_target(&self, &Path) -> (PathBuf, ObjectKind)` and `learn_cwd(&self) -> bool`; rewrite `learned_rule` to call `always_target`. Add consistency test.
- `filewalld/src/main.rs` — **modify.** Populate the three new `PromptRequest` fields in the `Outcome::Prompt` arm from the covering watch.
- `filewall-ui/src/main.rs` — **modify.** Add `pango_escape` and `abbrev` helpers; change `classify` to exit-code based; rewrite `ask` to spawn `yad` with markup + scope-aware buttons.
- `README.md`, `e2e.sh` — **modify.** Document/require `yad` instead of `zenity` for the UI helper.

Tasks are ordered so each compiles and its tests pass before the next. Tasks 1–3 are the daemon/protocol half; 4–7 the UI half; 8 docs.

---

## Task 1: Protocol — descriptive scope fields on `PromptRequest`

**Files:**
- Modify: `filewall-proto/src/lib.rs` (struct at lines 13-25; `sample_request` at 89-97; tests)

- [ ] **Step 1: Update the test fixture and add field assertions (failing test)**

In `filewall-proto/src/lib.rs`, update `sample_request` (currently lines 89-97) to include the new fields:

```rust
    fn sample_request() -> PromptRequest {
        PromptRequest {
            pid: 84321,
            exe: "/usr/bin/node".into(),
            cmdline: "node /home/user/evil.js".into(),
            cwd: "/home/user/projects/foo".into(),
            path: "/home/user/.ssh/id_ed25519".into(),
            always_object: "/home/user/.ssh".into(),
            always_tree: true,
            always_cwd_pinned: false,
        }
    }
```

Add a dedicated roundtrip test asserting the new fields survive:

```rust
    #[test]
    fn request_roundtrip_preserves_scope_fields() {
        let req = sample_request();
        let back: PromptRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back.always_object, "/home/user/.ssh");
        assert!(back.always_tree);
        assert!(!back.always_cwd_pinned);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p filewall-proto`
Expected: FAIL — compile error, `PromptRequest` has no field `always_object`.

- [ ] **Step 3: Add the fields to the struct**

In the `PromptRequest` struct (lines 13-25), after `pub path: String,` add:

```rust
    /// Path an "Always" rule would cover: the exact file, or a tree root.
    pub always_object: String,
    /// True when the rule covers every file under `always_object` (tree scope).
    pub always_tree: bool,
    /// True when the rule is pinned to the process's current cwd.
    pub always_cwd_pinned: bool,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p filewall-proto`
Expected: PASS (all existing tests + `request_roundtrip_preserves_scope_fields`).

- [ ] **Step 5: Commit**

```bash
git add filewall-proto/src/lib.rs
git commit -m "feat(proto): add always-scope descriptor fields to PromptRequest"
```

---

## Task 2: Daemon policy — single source of truth for scope

**Files:**
- Modify: `filewalld/src/policy.rs` (`learned_rule` at lines 100-123; tests below)

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `filewalld/src/policy.rs`:

```rust
    #[test]
    fn always_target_tree_is_root_file_is_path() {
        let tree = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::Tree, false, &[]).unwrap();
        let (obj, kind) = tree.always_target(Path::new("/home/u/.ssh/id_ed25519"));
        assert_eq!(kind, ObjectKind::Tree);
        assert_eq!(obj, PathBuf::from("/home/u/.ssh"));

        let file = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::File, false, &[]).unwrap();
        let (obj, kind) = file.always_target(Path::new("/home/u/.ssh/id_ed25519"));
        assert_eq!(kind, ObjectKind::File);
        assert_eq!(obj, PathBuf::from("/home/u/.ssh/id_ed25519"));
    }

    #[test]
    fn always_target_agrees_with_learned_rule() {
        // The scope we would *display* must equal the scope we would *persist*.
        for kind in [ObjectKind::Tree, ObjectKind::File] {
            for learn_cwd in [false, true] {
                let p = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, kind, learn_cwd, &[]).unwrap();
                let path = Path::new("/home/u/.ssh/id_ed25519");
                let (obj, obj_kind) = p.always_target(path);
                let rule = p.learned_rule(RuleAction::Allow, "/usr/bin/node", path, Some("/home/u/p"));
                assert_eq!(rule.object, obj);
                assert_eq!(rule.object_kind, obj_kind);
                assert_eq!(rule.cwd.is_some(), p.learn_cwd());
            }
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p filewalld --lib policy`
Expected: FAIL — `no method named always_target` / `learn_cwd` found for `WatchPolicy`.

- [ ] **Step 3: Add the accessors and route `learned_rule` through `always_target`**

In `impl WatchPolicy`, add (e.g. just before `learned_rule` at line 100):

```rust
    /// The object an "Always" rule would target for an access of `path`, per
    /// this watch's `learn_object`. Single source of truth shared by the prompt
    /// (what we display) and `learned_rule` (what we persist) so they can't drift.
    pub fn always_target(&self, path: &Path) -> (PathBuf, ObjectKind) {
        match self.learn_object {
            ObjectKind::Tree => (self.root.clone(), ObjectKind::Tree),
            ObjectKind::File => (path.to_path_buf(), ObjectKind::File),
        }
    }

    /// Whether learned rules from this watch pin the process cwd.
    pub fn learn_cwd(&self) -> bool {
        self.learn_cwd
    }
```

Rewrite the body of `learned_rule` (lines 100-123) so the object comes from `always_target`:

```rust
    pub fn learned_rule(
        &self,
        action: RuleAction,
        exe: &str,
        path: &Path,
        cwd: Option<&str>,
    ) -> LearnedRule {
        let (object, object_kind) = self.always_target(path);
        LearnedRule {
            created_unix: now_unix(),
            action,
            exe: exe.to_string(),
            object,
            object_kind,
            cwd: if self.learn_cwd {
                cwd.map(|s| s.to_string())
            } else {
                None
            },
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p filewalld --lib policy`
Expected: PASS (new tests + the existing `learned_rule_*` tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add filewalld/src/policy.rs
git commit -m "refactor(filewalld): extract always_target as single source of scope truth"
```

---

## Task 3: Daemon main — populate scope fields in the prompt request

**Files:**
- Modify: `filewalld/src/main.rs` (`Outcome::Prompt` arm, `PromptRequest` literal at lines 297-303)

Note: `main.rs`'s `event_loop` is not unit-testable in isolation (it owns fanotify/socket state); correctness of the *scope values* is locked by Task 2's `always_target_agrees_with_learned_rule`. This task is wiring, verified by a compile + the full suite.

- [ ] **Step 1: Compute scope from the covering watch and fill the request**

Replace the `PromptRequest` literal (lines 297-303) with a version that looks up the covering watch first. The lookup mirrors the existing one at line 275:

```rust
                Outcome::Prompt => {
                    // Describe what an "Always" choice would persist, from the
                    // covering watch's config — same source `learned_rule` uses.
                    // Fail narrow: if no watch covers it, scope is the literal file.
                    let (always_object, always_tree, always_cwd_pinned) =
                        match policy.watches().iter().find(|w| w.covers(&path)) {
                            Some(w) => {
                                let (obj, kind) = w.always_target(&path);
                                (
                                    obj.display().to_string(),
                                    matches!(kind, filewall_rules::ObjectKind::Tree),
                                    w.learn_cwd(),
                                )
                            }
                            None => (path.display().to_string(), false, false),
                        };
                    let req = PromptRequest {
                        pid: ev.pid,
                        exe: exe.clone(),
                        cmdline: ev.cmdline(),
                        cwd: cwd.clone(),
                        path: path.display().to_string(),
                        always_object,
                        always_tree,
                        always_cwd_pinned,
                    };
```

If `filewall_rules::ObjectKind` is not already in scope at the top of `main.rs`, use the full path as shown (no new `use` needed).

- [ ] **Step 2: Build and run the whole suite**

Run: `cargo build -p filewalld && cargo test -p filewalld`
Expected: PASS — compiles, all tests green. (No new test here; scope values are covered by Task 2.)

- [ ] **Step 3: Commit**

```bash
git add filewalld/src/main.rs
git commit -m "feat(filewalld): send always-scope descriptor in prompt requests"
```

---

## Task 4: UI — `pango_escape` (anti-spoof for markup mode)

**Files:**
- Modify: `filewall-ui/src/main.rs` (add helper + tests)

Markup is now enabled (we want bold/color), so every dynamic value must be escaped or a hostile cmdline could inject Pango tags to spoof the dialog. This is the security-critical replacement for zenity's `--no-markup`.

- [ ] **Step 1: Write the failing test**

Add to a `tests` module in `filewall-ui/src/main.rs` (next to the existing `classify` tests):

```rust
    #[test]
    fn pango_escape_handles_markup_metachars() {
        use super::pango_escape;
        // Ampersand must be escaped first to avoid double-escaping.
        assert_eq!(pango_escape("a & b"), "a &amp; b");
        assert_eq!(pango_escape("<b>x</b>"), "&lt;b&gt;x&lt;/b&gt;");
        assert_eq!(
            pango_escape("evil & <span foreground=\"red\">"),
            "evil &amp; &lt;span foreground=\"red\"&gt;"
        );
        assert_eq!(pango_escape("plain text"), "plain text");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p filewall-ui pango_escape`
Expected: FAIL — `cannot find function pango_escape`.

- [ ] **Step 3: Implement the helper**

Add near the top of `filewall-ui/src/main.rs` (after the imports):

```rust
/// Escape Pango markup metacharacters so attacker-controlled strings (cmdline,
/// paths) cannot inject tags to spoof the dialog. `&` first to avoid double-
/// escaping the entities we introduce.
fn pango_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p filewall-ui pango_escape`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewall-ui/src/main.rs
git commit -m "feat(ui): add pango_escape for markup-mode anti-spoofing"
```

---

## Task 5: UI — `abbrev` home-path helper

**Files:**
- Modify: `filewall-ui/src/main.rs` (add helper + tests)

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn abbrev_replaces_home_prefix_only() {
        use super::abbrev;
        assert_eq!(abbrev("/home/alice/.ssh/id", "/home/alice"), "~/.ssh/id");
        // Exact home dir.
        assert_eq!(abbrev("/home/alice", "/home/alice"), "~");
        // Not under home: unchanged.
        assert_eq!(abbrev("/etc/hosts", "/home/alice"), "/etc/hosts");
        // A path that merely starts with the same characters but is a different
        // dir must NOT be abbreviated.
        assert_eq!(abbrev("/home/alice2/x", "/home/alice"), "/home/alice2/x");
        // Empty home (HOME unset) disables abbreviation.
        assert_eq!(abbrev("/home/alice/.ssh", ""), "/home/alice/.ssh");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p filewall-ui abbrev`
Expected: FAIL — `cannot find function abbrev`.

- [ ] **Step 3: Implement the helper**

```rust
/// Abbreviate a leading `$HOME` to `~` for readability. Only matches whole path
/// components (so `/home/alice` does not shorten `/home/alice2/...`). An empty
/// `home` disables abbreviation.
fn abbrev(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    if path == home {
        return "~".to_string();
    }
    if let Some(rest) = path.strip_prefix(home) {
        if rest.starts_with('/') {
            return format!("~{rest}");
        }
    }
    path.to_string()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p filewall-ui abbrev`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewall-ui/src/main.rs
git commit -m "feat(ui): add abbrev helper to shorten $HOME to ~"
```

---

## Task 6: UI — exit-code based `classify`

**Files:**
- Modify: `filewall-ui/src/main.rs` (`classify` at lines 130-137; its tests at 144-159)

Switch from stdout-label matching (brittle: breaks when button wording changes) to yad's per-button exit codes. Button codes: AllowOnce=10, DenyOnce=11, AllowAlways=12, DenyAlways=13.

- [ ] **Step 1: Replace the classify tests (failing)**

Replace the three existing `classify` tests (currently `ok_button_is_allow_once`, `extra_buttons_map_to_always`, `cancel_close_and_error_fail_closed`) with:

```rust
    #[test]
    fn classify_maps_button_codes() {
        assert_eq!(classify(Some(10)), Decision::AllowOnce);
        assert_eq!(classify(Some(12)), Decision::AllowAlways);
        assert_eq!(classify(Some(13)), Decision::DenyAlways);
    }

    #[test]
    fn classify_fails_closed_on_everything_else() {
        assert_eq!(classify(Some(11)), Decision::DenyOnce); // explicit deny-once
        assert_eq!(classify(Some(252)), Decision::DenyOnce); // yad ESC/close
        assert_eq!(classify(None), Decision::DenyOnce); // killed / no code
        assert_eq!(classify(Some(1)), Decision::DenyOnce); // unknown
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p filewall-ui classify`
Expected: FAIL — compile error (`classify` still takes two args / old tests gone).

- [ ] **Step 3: Rewrite `classify`**

Replace `classify` (lines 130-137) with:

```rust
/// Map a yad exit code to a Decision. Fail-closed: only the three explicit
/// allow/always codes pass; everything else (deny-once button, ESC=252, error,
/// unknown) becomes DenyOnce.
fn classify(code: Option<i32>) -> Decision {
    match code {
        Some(10) => Decision::AllowOnce,
        Some(12) => Decision::AllowAlways,
        Some(13) => Decision::DenyAlways,
        _ => Decision::DenyOnce,
    }
}
```

Also update the call site in `ask` (line 120): `classify(out.status.code(), &String::from_utf8_lossy(&out.stdout))` becomes `classify(out.status.code())`. (Task 7 rewrites `ask` fully; if doing this task alone, make that one-line change so it compiles.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p filewall-ui classify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add filewall-ui/src/main.rs
git commit -m "feat(ui): classify decisions by yad exit code, not stdout label"
```

---

## Task 7: UI — render the yad dialog

**Files:**
- Modify: `filewall-ui/src/main.rs` (`ask` at lines 78-126)

This is wiring around the now-tested helpers; verified by build + manual smoke (yad renders, not unit-testable). Uses `pango_escape` on every dynamic value, `abbrev` for readability, scope-aware body + buttons.

- [ ] **Step 1: Rewrite `ask`**

Replace `ask` (lines 78-126) with:

```rust
/// Render the prompt with yad. Returns Deny on any failure (fail-closed).
fn ask(req: &PromptRequest) -> Decision {
    let home = std::env::var("HOME").unwrap_or_default();

    // Escape every attacker-influenced value; abbreviate paths for readability.
    let proc_name = pango_escape(
        &Path::new(&req.exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| req.exe.clone()),
    );
    let exe = pango_escape(&req.exe);
    let path = pango_escape(&abbrev(&req.path, &home));
    let object = pango_escape(&abbrev(&req.always_object, &home));
    let cwd = pango_escape(&abbrev(&req.cwd, &home));
    let cmdline = pango_escape(if req.cmdline.is_empty() {
        "<unavailable>"
    } else {
        &req.cmdline
    });

    // Scope block: loud red warning for a tree grant, neutral line for a file.
    let scope = if req.always_tree {
        format!(
            "<span foreground=\"#cc0000\"><b>\u{300C}Always allow\u{300D} GRANTS ACCESS TO ALL FILES</b></span>\n\
             <span foreground=\"#cc0000\">    under {object} \u{2014} every subfolder, not just the file above.</span>"
        )
    } else {
        format!("\u{300C}Always allow\u{300D} remembers only this one file:\n    {object}")
    };
    let cwd_line = if req.always_cwd_pinned {
        format!("\n\u{2026}and only while it runs from {cwd}")
    } else {
        String::new()
    };

    let text = format!(
        "<b>\u{26A0}  filewall \u{2014} sensitive file access</b>\n\n\
         <b>{proc_name}</b> wants to open:\n    {path}\n\n\
         {scope}\n\n\
         Rule is tied to this program:\n    {exe}{cwd_line}\n\n\
         <small>PID {pid} \u{00B7} cmd: {cmdline}</small>",
        pid = req.pid,
    );

    // Scope-aware "Always" labels: ALL (tree) vs file. button=LABEL:CODE.
    let (allow_always, deny_always) = if req.always_tree {
        ("Always allow ALL:12", "Always deny ALL:13")
    } else {
        ("Always allow file:12", "Always deny file:13")
    };

    let output = Command::new("yad")
        .args([
            "--title=filewall security prompt",
            "--width=520",
            "--image=dialog-warning",
            "--text",
            &text,
            // Order: safe Deny once first (default focus); broad Allow-ALL last.
            "--button=Deny once:11",
            "--button=Allow once:10",
            &format!("--button={deny_always}"),
            &format!("--button={allow_always}"),
        ])
        .output();

    match output {
        Ok(out) => classify(out.status.code()),
        Err(e) => {
            eprintln!("filewall-ui: failed to run yad: {e}");
            Decision::DenyOnce
        }
    }
}
```

- [ ] **Step 2: Build and run all UI tests**

Run: `cargo build -p filewall-ui && cargo test -p filewall-ui`
Expected: PASS — compiles, helper + classify tests green.

- [ ] **Step 3: Manual smoke test (requires `yad` installed)**

Run (renders a real dialog; needs a display):

```bash
yad --title=test --width=520 --text='<b>bold</b> <span foreground="#cc0000">red</span>' \
    --button=Deny:11 --button=Allow:10 ; echo "exit=$?"
```

Expected: a dialog with bold + red text; clicking Deny prints `exit=11`, Allow prints `exit=10`, closing the window prints `exit=252`. Confirms markup renders and button codes map as `classify` expects.

- [ ] **Step 4: Commit**

```bash
git add filewall-ui/src/main.rs
git commit -m "feat(ui): render scope-aware prompt with yad (bold + tree warning)"
```

---

## Task 8: Docs & deploy — require `yad`

**Files:**
- Modify: `README.md` (zenity references)
- Modify: `e2e.sh` (line 56-57 comment/context; the UI now needs yad, not zenity)

`yad` is a new runtime dependency of `filewall-ui` and is NOT installed on every host (the dev host has zenity only). Note: `e2e.sh`'s *askpass* sudo helper (lines 9-10) still uses zenity for the password prompt — that is a separate use and stays. Only the UI dialog moves to yad.

- [ ] **Step 1: Update README dependency mention**

In `README.md`, find the `zenity` reference and change the UI helper's dependency to `yad`. Add a one-line prerequisite, e.g.:

```markdown
`filewall-ui` requires **`yad`** (GTK dialog tool) on the user's session —
e.g. `sudo pacman -S yad` / `sudo apt install yad`. It renders the access
prompt with markup so a broad (whole-tree) grant is visually distinct.
```

- [ ] **Step 2: Update e2e.sh note**

In `e2e.sh`, update the header comment near line 9-10 so it states the UI helper needs `yad` (the askpass zenity use is unchanged). If e2e asserts on UI behavior, ensure `yad` is mentioned as a prerequisite; otherwise a comment suffices:

```bash
# Prereqs: yad (filewall-ui dialog) and zenity (sudo askpass helper).
```

- [ ] **Step 3: Verify the whole workspace builds and tests pass**

Run: `cargo test`
Expected: PASS across `filewall-proto`, `filewall-rules`, `filewalld`, `filewall-ui`.

- [ ] **Step 4: Commit**

```bash
git add README.md e2e.sh
git commit -m "docs: require yad for filewall-ui dialog (replaces zenity)"
```

---

## Self-Review

**Spec coverage:**
- Goal 1 (state the scope) → Tasks 1, 3, 7. ✓
- Goal 2 (tree grant unmistakable) → Task 7 red warning + `ALL` buttons. ✓
- Goal 3 (display == persisted, locked by test) → Task 2 `always_target_agrees_with_learned_rule`. ✓
- Protocol fields → Task 1. ✓
- `always_target` single source of truth → Task 2. ✓
- Daemon populates request → Task 3. ✓
- yad renderer + markup + buttons + ordering + safe default → Task 7. ✓
- `pango_escape` anti-spoof → Task 4. ✓
- exit-code classify → Task 6. ✓
- `~` abbreviation → Task 5 + used in Task 7. ✓
- Deny-narrow fallback when no watch covers → Task 3. ✓
- yad dependency docs / e2e / rollout → Task 8. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output.

**Type consistency:** `always_object: String`, `always_tree: bool`, `always_cwd_pinned: bool` identical across Tasks 1/3/7. `always_target(&Path) -> (PathBuf, ObjectKind)` and `learn_cwd() -> bool` consistent across Tasks 2/3. Button codes 10/11/12/13 consistent across Tasks 6 (`classify`) and 7 (`--button`). `pango_escape(&str) -> String` and `abbrev(&str, &str) -> String` signatures match between definition (Tasks 4/5) and use (Task 7).
