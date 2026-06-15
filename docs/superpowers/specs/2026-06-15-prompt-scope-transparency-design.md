# Design: surface the "always" rule scope in the prompt

**Date:** 2026-06-15
**Status:** Approved (design); pending implementation plan
**Component:** `filewall-ui`, `filewall-proto`, `filewalld`

## Problem

When the daemon prompts the user to allow/deny a file access, the dialog offers
four outcomes: **Allow once**, **Deny once**, **Always allow**, **Always deny**
(`filewall-ui/src/main.rs` `ask`). The two "Always" choices persist a learned
rule — but **the scope of that rule is invisible to the user**.

The scope is decided entirely by the covering watch's config:
`WatchPolicy::learned_rule` (`filewalld/src/policy.rs`) reads `learn_object`
(`file` | `tree`) and `learn_cwd` to choose what object the rule covers:

- `tree` → the rule covers **every file under the watch root**
  (`LearnedRule::matches` uses `path.starts_with(object)`, recursively).
- `file` → the rule covers **only the exact path** shown.
- `learn_cwd` → the rule is additionally pinned to the process's current cwd.

`PromptRequest` (`filewall-proto/src/lib.rs`) carries `pid / exe / cmdline /
cwd / path` — but **not** the scope an "Always" decision would create. So the
UI cannot show it, and the user clicking **"Always allow"** on
`~/.config/google-chrome/Default/Login Data` may silently grant access to
*all* of `~/.config/google-chrome` — a far broader grant than the single file
shown. The exe trust-anchor and the optional cwd pin are likewise invisible.

## Goals

1. The prompt states, in plain language, exactly what an "Always" choice will
   persist: the object (this file vs. every file under a tree root), the exe
   the rule is tied to, and whether it is pinned to the current cwd.
2. The broad (tree) grant is **visually unmistakable** — not a buried line.
3. The displayed scope is **provably identical** to the rule actually written:
   one source of truth, locked by a test.

## Non-goals

- **Letting the user choose the granularity** at decision time. Scope stays
  config-driven via `learn_object`; the UI reports it, it does not override it.
  (Decided in brainstorming.)
- Changing allow/deny/persist behavior, the deny-wins evaluation, or the
  learned-rule schema.
- Multi-user socket hardening (tracked separately).

## Decisions (from brainstorming)

- **Source of truth: config `learn_object`.** No user-facing scope picker — the
  option set was getting out of hand. The UI's job is transparency only.
- **Renderer: switch zenity → `yad`.** zenity `--no-markup` gives a flat text
  blob with no emphasis (`--no-markup` is kept for anti-spoofing, which kills
  the one styling lever zenity has). `yad` supports Pango markup (bold + color)
  and per-button exit codes while keeping the UI a thin dialog-spawner (no
  `gtk-rs` embedding). Chosen over staying on zenity.
- **Tree grants get an explicit warning line** (caps + red), naming the
  breadth. File grants get a neutral description, no alarm styling.

## Approach

### 1. Protocol — `filewall-proto`

Extend `PromptRequest` with three **descriptive** fields. They report the
daemon's already-made (config-driven) decision; they do not change it:

```rust
/// Path an "Always" rule would cover: the exact file, or a tree root.
pub always_object: String,
/// True when the rule covers every file under `always_object` (tree scope).
pub always_tree: bool,
/// True when the rule is pinned to the process's current cwd.
pub always_cwd_pinned: bool,
```

A plain `bool` rather than sharing `ObjectKind` from `filewall-rules` keeps
`filewall-proto` dependency-free (it currently depends only on `serde`).

### 2. Daemon — `filewalld` (policy.rs + main.rs)

**Single source of truth.** Extract the object-targeting currently inside
`learned_rule` into one method:

```rust
// policy.rs
pub fn always_target(&self, path: &Path) -> (PathBuf, ObjectKind) {
    match self.learn_object {
        ObjectKind::Tree => (self.root.clone(), ObjectKind::Tree),
        ObjectKind::File => (path.to_path_buf(), ObjectKind::File),
    }
}
pub fn learn_cwd(&self) -> bool { self.learn_cwd }
```

`learned_rule` is rewritten to call `always_target`, so the persisted object
and the displayed object come from the same code path and cannot diverge.

**Populate the request.** When building `PromptRequest` (`main.rs`, currently
the `Outcome::Prompt` arm), find the covering watch (the lookup already happens
post-decision to build the learned rule — do it up front and reuse it) and fill
the three fields from `always_target(path)` + `learn_cwd()`. No change to the
allow/deny/persist logic.

Edge case: if no watch covers the path (shouldn't happen — we only mark watched
files), fall back to file scope on the literal path, cwd-unpinned.

### 3. UI — `filewall-ui`

Replace the zenity invocation with `yad`. Dialog is **consequence-first**:

```
⚠  filewall — sensitive file access            (bold)

chrome wants to open:                           (bold process name)
    ~/.config/google-chrome/Default/Login Data

「Always allow」 GRANTS ACCESS TO ALL FILES      (red + bold — tree only)
    under ~/.config/google-chrome — every subfolder,
    not just the file shown above.

Rule is tied to this program:
    /opt/google/chrome/chrome
…and only while it runs from ~/work             (only if always_cwd_pinned)

PID 8421 · cmd: /opt/google/chrome/chrome …     (small / dim — evidence)
```

- **File scope** swaps the red block for a neutral line:
  `「Always allow」 remembers only this one file:` followed by the path.
- **Buttons** are breadth-explicit. `--button=LABEL:CODE`:
  - `Deny once` → 11
  - `Allow once` → 10
  - tree: `Always deny ALL` → 13 · `Always allow ALL` → 12
  - file: `Always deny file` → 13 · `Always allow file` → 12
- **Ordering & safe default:** `Deny once` is leftmost / default focus; the
  broad **`Always allow ALL`** sits farthest from it (anti-misclick). ESC /
  window-close / any unmapped code → `DenyOnce` (fail-closed).
- **Path abbreviation:** `/home/<user>` → `~` in `path`, `always_object`,
  `cwd` (and the headline file), via a small `abbrev` helper using `$HOME`.

**Anti-spoofing (critical — replaces what `--no-markup` gave for free).**
Markup is now *on*, so every interpolated value (`exe`, `cmdline`, `cwd`,
`path`, `always_object`) is passed through `pango_escape`:
`&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;` (ampersand first). The static template owns
all markup tags; dynamic data is always escaped. A hostile cmdline therefore
cannot inject Pango tags to spoof the dialog.

**Classification** moves from stdout-label matching to exit code:

```rust
fn classify(code: Option<i32>) -> Decision {
    match code {
        Some(10) => Decision::AllowOnce,
        Some(12) => Decision::AllowAlways,
        Some(13) => Decision::DenyAlways,
        _        => Decision::DenyOnce, // 11, ESC (252), error, unknown
    }
}
```

This removes the brittle string-matching on button labels — label wording can
change freely without touching `classify`.

## Error handling

- yad missing / spawn failure → `DenyOnce` (fail-closed), logged to stderr, as
  today for a zenity failure.
- Unmapped/!0 exit code, ESC, window-close → `DenyOnce`.
- Daemon: covering-watch lookup miss → file scope on the literal path
  (fail-narrow: never advertise a broader grant than the literal file).

## Testing

- **proto:** `PromptRequest` JSON + framing roundtrip including the three new
  fields.
- **UI `pango_escape`:** `&`, `<`, `>`, and combinations escape correctly;
  ampersand-first ordering verified (no double-escaping).
- **UI `classify`:** table over 10/11/12/13, `None`, 252, and an unmapped code
  → expected decisions, all fail-closed except the three explicit allow/always
  codes.
- **policy consistency:** for both `learn_object` values, assert the scope a
  `PromptRequest` would advertise (`always_target` + `learn_cwd`) equals the
  object/kind/cwd that `learned_rule` actually persists. Locks the invariant.

## Deployment / rollout notes

- **New runtime dependency: `yad`.** It is *not* a drop-in package everywhere
  (this dev host has zenity but not yad). Must be:
  - documented in `README.md` as a required dependency of `filewall-ui`;
  - reflected in `e2e.sh` and any packaging/systemd unit that assumed zenity.
- No daemon restart contract changes; `filewall-ui` is independently
  deployable (it reconnects to the daemon socket).

## Open questions

None blocking. Possible future polish (out of scope): directory-aware noun in
the warning ("folder" vs "file") via `stat` of the object; per-watch override
of the warning copy.
