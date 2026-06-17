# filewall — project status

**Beyond MVP: learned-rules persistence + `filewallctl` (2026-06-13); packaged as
systemd services + Arch PKGBUILD (2026-06-17).**

fanotify-based synchronous file-access prompting daemon (Rust). When an unlisted
binary opens a watched file, the kernel blocks the syscall and the user is prompted
in real time to allow/deny — and "Always" decisions now persist as learned rules.

## What exists
- `filewall-proto` — shared length-prefixed-JSON IPC types; 4-way `Decision`
  (allow/deny × once/always) + `cwd` field.
- `filewall-rules` — learned-rule schema, atomic `rules.toml` store, deny-wins
  matcher. Shared by daemon + ctl.
- `filewalld` (root) — config, policy/glob matching, fanotify FFI, UI socket
  server, event loop. Consults config globs **and** learned rules (deny-wins),
  persists "Always" decisions, captures process `cwd`, reloads config+rules on
  `SIGHUP`, writes a pidfile.
- `filewall-ui` (user session) — 4-button yad prompt (Allow/Deny once,
  Always allow/deny), scope-aware (file vs whole-tree), shows cwd, fail-closed.
- `filewallctl` — list / remove / reload (SIGHUP) / status for learned rules.
- Per-inode marking; watchdog timeout → deny; pidfd-based race-free resolution.
- **Marks placed at startup, before any UI connects** — guarded files are protected
  from the moment the daemon runs; accesses needing a prompt fail closed (deny)
  until a UI connects.
- UI link auto-recovers: a dropped/absent UI connection is accepted non-blockingly in
  the event loop (deny while disconnected, fail-closed), so the daemon survives a
  UI restart instead of breaking until a daemon restart.
- Packaging (`packaging/`): system unit `filewalld.service` (root, fanotify-safe
  hardening, `RuntimeDirectory`/`StateDirectory`), per-user unit
  `filewall-ui.service` (`graphical-session.target`), commented `/etc/filewall/
  config.toml` template (pacman `backup`), local working-tree `PKGBUILD` +
  `.install` scriptlet, and an MIT `LICENSE`.
- 69 tests pass; Phase 0 spike (`phase0/`) validated fanotify on this kernel.

## Verified
- Phase 0 spike: per-inode perm events fire, block, gate the open; deny → EPERM.
- E2E (`./e2e.sh`): allowlisted `head` reads with no prompt; unlisted `cat`
  triggers the yad prompt; "Always allow" persists a rule so the second access
  is silent; `filewallctl list`/`remove`+reload revokes it. Also confirms the
  fail-closed path: with **no UI connected**, an access to a guarded file is denied.
- Packaging: `makepkg` builds the package clean (build → test → fakeroot package);
  binaries, units, config, docs and license land at the expected paths;
  `systemd-analyze verify` accepts both units.

## Design + plan
- Spec: `docs/superpowers/specs/2026-06-13-learned-rules-persistence-filewallctl-design.md`
- Plan: `docs/superpowers/plans/2026-06-13-learned-rules-persistence-filewallctl.md`

## Next agreed iteration
Packaging follow-ups surfaced this session: tighten the daemon unit's sandbox
(test `ProtectSystem=strict` against fanotify), add a reproducible/tagged PKGBUILD
variant, commit `Cargo.lock`, and ship man pages. See `../README.md` "Deferred" for
the full backlog (also: mount/fs-wide marking, multi-user / per-user sockets,
notify-send UI, privilege drop).

See also: `fanotify-notes.md`, `sudo-in-claude-session.md`.
