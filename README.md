# filewall

Synchronous, object-centric prompting for sensitive file access on Linux.

When an unknown binary tries to `open()` a watched file (e.g. `~/.ssh/id_ed25519`),
the kernel **blocks the syscall** and a desktop prompt asks you to allow or deny it
in real time. This mitigates supply-chain attacks (malicious npm/pip/cargo
postinstall scripts, compromised dev tools) that try to read developer secrets — the
policy is attached to the *file*, with an allowlist of binaries permitted to read it,
rather than to each binary.

Built on Linux `fanotify` permission events (`FAN_OPEN_PERM`), which are the only
primitive that synchronously blocks a syscall pending a userspace decision. 

> **Status: beyond MVP.** The full chain works end-to-end and "Always allow/deny"
> decisions now persist as learned rules. Some spec features remain deferred — see
> *Deferred* below.

## Components

| Crate / binary | Privilege | Role |
|----------------|-----------|------|
| `filewalld`      | root (`CAP_SYS_ADMIN`) | Marks watched paths (single files directly; directories via `FAN_EVENT_ON_CHILD`, so new files and atomically-renamed files are covered automatically and new subdirs are live-marked via inotify), evaluates accesses against the allowlist **and learned rules**, asks the UI on a miss, persists "Always" decisions, answers the kernel. |
| `filewall-ui`    | user session | Renders the scope-aware **yad** prompt — showing whether an "Always" rule will cover one file or a whole tree — and returns the decision. |
| `filewallctl`    | user (root for live paths) | Lists/removes learned rules; reloads (`SIGHUP`) and reports daemon status. |
| `filewall-proto` | library | Shared length-prefixed-JSON IPC types. |
| `filewall-rules` | library | Learned-rule schema, atomic `rules.toml` store, deny-wins matcher (shared by daemon + ctl). |

The two processes talk over a Unix socket (`/run/filewall/prompt.sock`). Keeping the
privileged daemon minimal and rendering the GUI as the unprivileged user is the whole
point of the split — root can't (and shouldn't) pop a dialog into your session.

## How a decision is made

1. Kernel fires a `FAN_OPEN_PERM` event on a guarded file — via the file's own mark,
   or its parent directory's `FAN_EVENT_ON_CHILD` mark — and blocks the opener. A path
   matching the watch's `exclude` globs is allowed immediately, without a prompt.
2. Daemon resolves the accessing process **race-free** via the event's pidfd
   (`/proc/<pid>/exe`, `/proc/<pid>/cmdline`, `/proc/<pid>/cwd`).
3. The config `allow` globs and the persisted **learned rules** are evaluated
   together, **deny-wins**:
   - any matching deny → `FAN_DENY`
   - else any matching allow (config glob or learned rule) → `FAN_ALLOW`
   - else → prompt the user, who picks **Allow once / Deny once / Always allow /
     Always deny**. The dialog states exactly what an "Always" choice will
     persist — just the file shown, or the whole watched tree (per `learn_object`),
     and the program the rule is tied to — with a prominent warning when the grant
     would cover an entire tree. The choice is persisted to `rules.toml` (and
     applied immediately). The default keyboard action (Enter/Escape) is the
     fail-closed **Deny once**.
   - no answer within `prompt_timeout_seconds` → **deny** (fail-closed)
4. A denied open returns **`EPERM`** ("Operation not permitted") to the caller.

A learned rule pins the **literal** executable path (the trust anchor) to either
the triggering file or the whole watched tree (`learn_object`), optionally
constrained by the process working directory (`learn_match = ["exe","cwd"]`). `cwd`
is attacker-controllable, so it narrows prompts but is never a security boundary;
learned rules are never auto-generalized into globs.

## Prerequisites

- **Rust** (stable) with `cargo` — to build the workspace.
- **Linux with fanotify permission events.** `filewalld` runs as root
  (`CAP_SYS_ADMIN`); `FAN_OPEN_PERM` is a Linux-only primitive.
- **[`yad`](https://github.com/v1cont/yad)** — the GTK dialog tool that
  `filewall-ui` shells out to for the access prompt. Install it before running
  the UI: `sudo pacman -S yad` (Arch) · `sudo apt install yad` (Debian/Ubuntu).
  If `yad` is missing the UI cannot render a prompt, so **every prompt fails
  closed (denied)**.

## Build & test

```sh
cargo build --release
cargo test    # unit/integration tests: policy, config, directory marking, treewatch, rules, proto, UI link
```

## Configuration

A watch on a directory marks the directory itself (with `FAN_EVENT_ON_CHILD`), so
its files are covered with one kernel mark per directory rather than one per file —
**newly-created files and atomically-renamed files are covered automatically**, and
new sub-directories are live-marked as they appear. A watch on a single file marks
that file directly.

`config.toml` (see [`example_config.toml`](example_config.toml) for every option,
fully commented):

```toml
default_action = "prompt"          # prompt | allow | deny (global; no per-watch default)
prompt_timeout_seconds = 30
socket_path = "/run/filewall/prompt.sock"
rules_path  = "/var/lib/filewall/rules.toml"   # where "Always" decisions persist

[[watch]]
path = "/home/you/.ssh"            # ~ expands to $HOME; symlinked roots are canonicalized
allow = ["/usr/bin/ssh", "/usr/bin/ssh-*", "/usr/bin/git"]
exclude = ["**/Cache"]             # prune noisy subtrees; file globs auto-allow at access time
learn_object = "file"              # "file" | "tree" — scope of an "Always" rule
learn_match  = ["exe"]             # add "cwd" to pin the working directory too
```

Glob semantics: `*` does not cross `/`; `**` does.

Run the daemon: `sudo ./target/release/filewalld /path/to/config.toml`
Run the UI:     `./target/release/filewall-ui`

> Needs **`yad`** in the session (see [Prerequisites](#prerequisites)); the
> prompt is rendered with markup so a broad (whole-tree) "Always allow" grant is
> visually distinct from a single-file one.

## Managing learned rules

```sh
filewallctl list                 # show persisted "Always" decisions
filewallctl remove <index>       # revoke one, then auto-reloads the daemon
filewallctl reload               # SIGHUP the daemon to re-read config + rules
filewallctl status               # is filewalld running?
```

The daemon also re-reads its config and `rules.toml` on `SIGHUP`.

## Deferred (post-MVP)

- mount/filesystem-wide marking; multi-user / per-user sockets and `SO_PEERCRED`.
- systemd units; PKGBUILD; `notify-send` UI variant.
- Privilege drop after init.
