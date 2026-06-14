# Design: Learned-rules persistence + `filewallctl`

**Date:** 2026-06-13
**Status:** Approved (pending spec review)
**Goal:** Daily-driver usability — stop re-answering the same prompts. Add the
learned-rules persistence loop ("Always allow/deny") and a `filewallctl` CLI to
inspect and manage rules.

## Background

The MVP proves the full fanotify chain end-to-end (kernel blocks → pidfd-resolved
process → glob allowlist → zenity prompt → allow/deny). It is otherwise a one-shot
tool: every access by an unlisted binary re-prompts. This iteration makes it livable
by persisting "Always" decisions and giving the user a way to review and revoke them.

## Scope

**In:**
- 4-way prompt (`Allow once` / `Deny once` / `Always allow` / `Always deny`).
- Learned-rule persistence loop: in-memory policy update + mirror to `rules.toml`.
- Opt-in `cwd` matching as a disambiguator/narrowing dimension (per watch).
- `filewallctl` with `list` / `remove` / `reload` / `status`.
- SIGHUP-driven config + rules reload; daemon pidfile.

**Explicitly out (deferred to later iterations):**
- Auto-glob generalization of learned rules (footgun — generalization is an explicit
  act via config or `filewallctl`, never inferred from one observation).
- Control socket / IPC protocol for `filewallctl` (using file + SIGHUP instead).
- Multi-user / per-user sockets / `SO_PEERCRED` (single-user assumption holds).
- New-file marking (inotify-driven) — separate iteration.
- `filewallctl add` (hand-edit config globs for the deliberate-allowlist case).

## Security framing (drives the matching model)

Process-side signals fall into two tiers, and conflating them would silently weaken
the tool:

- **Tamper-resistant:** a binary at a root-owned, non-user-writable path
  (`/usr/bin/ssh`, `/usr/lib/...`). Malware running as the user cannot replace it.
  This is the trust anchor.
- **Attacker-controllable:** `cwd`, `argv`, `env`, and **any binary under `$HOME`**
  (nvm/pyenv versions, `node_modules/.bin/*`, pnpm store). Malware running as the user
  can `chdir()` anywhere, forge any argv, and overwrite binaries in `$HOME`.

Therefore: the **globbable executable path is the trust anchor**. `cwd` (and argv) are
**prompt-fatigue reducers and disambiguators**, not security upgrades. They may
*narrow* an allow (require exe AND cwd) but must never be the sole basis for trust, and
the UI must not imply they harden anything. They are always *shown* as context the
human uses to decide; *recording* them in a rule is opt-in per watch.

The multi-version dev-environment problem (many `node`/`python` under `$HOME`) is
solved by **deliberate globs in config** (`~/.nvm/versions/node/*/bin/node`,
`**/node_modules/.bin/*`), authored by the user — not by auto-widening a learned rule.

## Architecture

Running policy = config globs **+** learned rules, both held in memory. Learned rules
are mirrored to `rules.toml` (daemon is the writer). `filewallctl` edits that file
atomically and pokes the daemon via SIGHUP to re-sync.

```
filewall-ui ──prompt/response──► filewalld ──FAN_ALLOW/DENY──► kernel
                                    │  in-memory Policy = config + learned
                                    │  on *Always: add in-memory + append file
                                    ▼
                              /var/lib/filewall/rules.toml
                                    ▲
                  list (read) │     │ remove (atomic edit) + SIGHUP
                              └── filewallctl ──SIGHUP──► filewalld (pidfile)
```

## Component changes

### `filewall-proto`
- `Decision` enum → 4 variants: `AllowOnce`, `DenyOnce`, `AllowAlways`, `DenyAlways`.
  The daemon maps each to a kernel verdict (`FAN_ALLOW`/`FAN_DENY`) plus a
  `persist: bool`.
- `PromptRequest` gains `cwd: String`. Optionally `parent: String` (display-only,
  may be deferred if it complicates pidfd capture).

### `filewalld`

**`config.rs`** — per `[[watch]]`:
```toml
learn_object = "file"      # "file" | "tree"  — what an "Always" rule covers; default "file"
learn_match  = ["exe"]     # subset of ["exe","cwd"]; default ["exe"]
```
Top-level: `rules_path = "/var/lib/filewall/rules.toml"` (default). Pidfile implicit at
`/run/filewall/filewalld.pid`.

**`rules.rs`** (new) — `LearnedRule` struct, load/save, atomic append.
`rules.toml` schema:
```toml
[[rule]]
created     = "2026-06-13T10:30:00Z"
action      = "allow"          # allow | deny
exe         = "/usr/bin/git-credential-libsecret"   # literal, as observed
object      = "/home/you/.ssh"  # tree root, or exact file path
object_kind = "tree"           # tree | file
cwd         = "/home/you/projects/foo"   # present only if learn_match includes cwd
```
- Load: skip malformed entries, log loudly, continue (a corrupt learned file must not
  brick the daemon).
- Save/append: atomic temp + rename in the same dir as `rules_path`.

**`policy.rs`** — decision path consults config globs AND learned rules with
**deny-wins** precedence:
> any matching deny (config or learned) → DENY · else any matching allow → ALLOW ·
> else `default_action`.

Learned-rule match predicate:
`exe` exact-equals event exe **AND** object matches (`file`: path equality; `tree`:
event path under root) **AND** (`cwd` absent OR equals event cwd).

**`fanotify.rs`** — capture `cwd` via the event's pidfd
(`readlink /proc/<pidfd>/cwd`), alongside the existing exe/cmdline capture.

**`main.rs`** — on an `*Always` response: add the rule to in-memory policy
immediately (covers the next access this session) and append to `rules.toml`. Install a
SIGHUP handler setting an `AtomicBool`; the blocking `read()` on the fanotify fd returns
`EINTR`, the loop checks the flag and rebuilds `Policy` from config + rules, then swaps
it. Write the pidfile at startup. Malformed `config.toml` → refuse to start (admin
file).

### `filewall-ui`
4-button `zenity --question`:
- `--ok-label="Allow once"` → exit 0 → `AllowOnce`
- `--cancel-label="Deny once"` → exit 1, empty stdout → `DenyOnce`
- `--extra-button="Always allow"` → exit 1, stdout `Always allow` → `AllowAlways`
- `--extra-button="Always deny"` → exit 1, stdout `Always deny` → `DenyAlways`

Disambiguate by stdout. **Window-close / timeout / empty stdout → `DenyOnce`**
(fail-closed preserved). Add a `cwd` line to the dialog body; keep `--no-markup`.

### `filewallctl` (new binary crate)
- `list` — read & pretty-print `rules.toml` (read-only, daemon not required).
- `remove <n>` — atomic edit removing the indexed rule, then auto-SIGHUP.
- `reload` — read pidfile, `kill(pid, SIGHUP)`.
- `status` — pidfile + `/proc/<pid>` liveness + socket presence.

## Error handling

- `rules.toml` write failure → still honor the current decision (no hang); in-memory
  add still applies; log that persistence failed.
- `filewallctl remove` racing the daemon's append → both use atomic rename,
  last-writer-wins; `reload` re-syncs the daemon to the file on disk.
- Malformed `config.toml` → refuse to start. Malformed `rules.toml` → skip bad entries,
  continue.

## Testing

- **proto:** 4-way `Decision` serde roundtrip.
- **rules:** load/save roundtrip; atomic write; skip-bad-entry; matching matrix
  (file/tree × cwd present/absent); deny-wins precedence.
- **config:** `learn_object` / `learn_match` parse + defaults.
- **policy:** learned-rule integration with config globs; deny-wins.
- **filewallctl:** list/remove against a fixture `rules.toml`; reload signal logic via a
  dummy pid.
- **E2E (`e2e.sh`):** click "Always allow" → second access by same binary triggers no
  prompt → `filewallctl list` shows the rule → `remove` + reload → access re-prompts.
