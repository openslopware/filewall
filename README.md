# filewall

Synchronous, object-centric prompting for sensitive file access on Linux.

When an unknown binary tries to `open()` a watched file (e.g. `~/.ssh/id_ed25519`),
the kernel **blocks the syscall** and a desktop prompt asks you to allow or deny it
in real time. This mitigates supply-chain attacks (malicious npm/pip/cargo
postinstall scripts, compromised dev tools) that try to read developer secrets — the
policy is attached to the *file*, with an allowlist of binaries permitted to read it,
rather than to each binary.

Built on Linux `fanotify` permission events (`FAN_OPEN_PERM`), which are the only
primitive that synchronously blocks a syscall pending a userspace decision. See
`spec.md` for the full background and design rationale.

> **Status: beyond MVP.** The full chain works end-to-end and "Always allow/deny"
> decisions now persist as learned rules. Some spec features remain deferred — see
> *Deferred* below.

## Components

| Crate / binary | Privilege | Role |
|----------------|-----------|------|
| `filewalld`      | root (`CAP_SYS_ADMIN`) | Marks watched files, evaluates accesses against the allowlist **and learned rules**, asks the UI on a miss, persists "Always" decisions, answers the kernel. |
| `filewall-ui`    | user session | Renders the 4-button zenity prompt and returns the decision. |
| `filewallctl`    | user (root for live paths) | Lists/removes learned rules; reloads (`SIGHUP`) and reports daemon status. |
| `filewall-proto` | library | Shared length-prefixed-JSON IPC types. |
| `filewall-rules` | library | Learned-rule schema, atomic `rules.toml` store, deny-wins matcher (shared by daemon + ctl). |

The two processes talk over a Unix socket (`/run/filewall/prompt.sock`). Keeping the
privileged daemon minimal and rendering the GUI as the unprivileged user is the whole
point of the split — root can't (and shouldn't) pop a dialog into your session.

## How a decision is made

1. Kernel fires a `FAN_OPEN_PERM` event on a marked file and blocks the opener.
2. Daemon resolves the accessing process **race-free** via the event's pidfd
   (`/proc/<pid>/exe`, `/proc/<pid>/cmdline`, `/proc/<pid>/cwd`).
3. The config `allow` globs and the persisted **learned rules** are evaluated
   together, **deny-wins**:
   - any matching deny → `FAN_DENY`
   - else any matching allow (config glob or learned rule) → `FAN_ALLOW`
   - else → prompt the user, who picks **Allow once / Deny once / Always allow /
     Always deny**. An "Always" choice is persisted to `rules.toml` (and applied
     immediately).
   - no answer within `prompt_timeout_seconds` → **deny** (fail-closed)
4. A denied open returns **`EPERM`** ("Operation not permitted") to the caller.

A learned rule pins the **literal** executable path (the trust anchor) to either
the triggering file or the whole watched tree (`learn_object`), optionally
constrained by the process working directory (`learn_match = ["exe","cwd"]`). `cwd`
is attacker-controllable, so it narrows prompts but is never a security boundary;
learned rules are never auto-generalized into globs.

## Build & test

```sh
cargo build --release
cargo test            # 23 unit/integration tests (policy, config, proto, UI link)
```

## Try it (end-to-end)

```sh
./e2e.sh
```

Runs `filewall-ui` as you and `filewalld` as root against a throwaway
`~/.filewall-e2e/secret.key`, then shows an allowlisted binary reading with no prompt
and an unlisted binary triggering the prompt.

## Configuration

`config.toml` (see the file for a documented example):

```toml
default_action = "prompt"          # prompt | allow | deny
prompt_timeout_seconds = 30
socket_path = "/run/filewall/prompt.sock"
rules_path  = "/var/lib/filewall/rules.toml"   # where "Always" decisions persist

[[watch]]
path = "/home/you/.ssh"            # use ABSOLUTE paths (daemon runs as root)
allow = ["/usr/bin/ssh", "/usr/bin/ssh-*", "/usr/bin/git"]
learn_object = "file"              # "file" | "tree" — scope of an "Always" rule
learn_match  = ["exe"]             # add "cwd" to pin the working directory too
```

Glob semantics: `*` does not cross `/`; `**` does.

Run the daemon: `sudo ./target/release/filewalld /path/to/config.toml`
Run the UI:     `./target/release/filewall-ui`

## Managing learned rules

```sh
filewallctl list                 # show persisted "Always" decisions
filewallctl remove <index>       # revoke one, then auto-reloads the daemon
filewallctl reload               # SIGHUP the daemon to re-read config + rules
filewallctl status               # is filewalld running?
```

The daemon also re-reads its config and `rules.toml` on `SIGHUP`.

## Deferred (post-MVP)

- inotify-driven marking of **newly-created** files (marks only files present at
  startup). Per-inode marks don't catch new files.
- mount/filesystem-wide marking; multi-user / per-user sockets and `SO_PEERCRED`.
- systemd units; PKGBUILD; `notify-send` UI variant.
- Privilege drop after init.

## Phase 0 spike

`phase0/spike.rs` is the throwaway program used to validate that fanotify permission
events + pidfd reporting behave as required on this kernel. Kept for reference.
