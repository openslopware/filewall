# Design: watch individual files

**Date:** 2026-06-14
**Status:** Approved (design); pending implementation plan
**Component:** `filewalld`

## Problem

A `[[watch]]` block can only guard a **directory tree**. The marking path
(`mark_all` → `walk_files`) seeds its stack with the configured root and
immediately calls `std::fs::read_dir(root)`. When `path` points at a regular
file, `read_dir` returns `ENOTDIR`, the error arm does `continue`, and the walk
yields zero files — so **nothing is marked and no fanotify event ever fires for
that file**. `Policy::covers()` (`path.starts_with(root)`) *would* match the
exact file, but no event reaches policy.

The failure is **silent**: `example_config.toml` ships `~/.vault-token` as a
file watch that today protects nothing, with no warning. Single files (tokens,
keys, single dotfiles) are exactly the high-value targets this daemon exists to
guard.

The fanotify layer is not the limitation — `Fanotify::mark_file` marks any
inode, file or directory. The gap is purely in `walk_files`/`mark_all`.

## Goals

1. A `[[watch]]` whose `path` is a regular file marks and guards that file.
2. A watch that resolves to nothing markable (missing path, empty directory) is
   **visible in the logs**, not silent.

## Non-goals

- Handling inode replacement (atomic `rename()` over the target). See
  *Follow-up* below. Deferred deliberately (Q3 decision).
- Any new configuration surface. File-vs-directory is auto-detected.

## Decisions (from brainstorming)

- **Detection: auto-detect from the filesystem** at mark time (`stat` the root).
  No new `kind` field. Existing file watches like `~/.vault-token` start working
  with no config edits.
- **Observability: warn per missing/empty watch + per-watch marked-count info.**
- **Inode replacement: out of scope now, tracked as a follow-up.**
- **Code structure: a dedicated scan step** (`WatchScan`) rather than smuggling
  resolution status into `walk_files`'s return value.

## Architecture

All changes are confined to `filewalld/src/main.rs`, in the marking path.
`config.rs`, `policy.rs`, and `fanotify.rs` are unchanged.

### `covers()` already handles file roots

`Path::starts_with` is component-wise, so a watch on `/home/u/.vault-token`
covers exactly `/home/u/.vault-token` and **not** `/home/u/.vault-token-backup`.
No policy change is required.

### New type: `WatchScan`

Captures what a watch root resolved to on disk:

```rust
enum WatchScan {
    Unresolved,        // path missing, or not a regular file/dir (symlink/special)
    File(PathBuf),     // a single regular file -> mark this one inode
    Dir(Vec<PathBuf>), // a directory tree (may be empty) -> mark each file
}
```

### New function: `scan_watch`

```rust
fn scan_watch(watch: &WatchPolicy) -> WatchScan
```

`symlink_metadata` the watch root (already canonicalized by
`config::canonicalize_root`) **once**:

- `Err`, or a type that is neither file nor dir → `Unresolved`
- `is_file()` → `File(root)`
- `is_dir()` → `Dir(walk_files(root, |p| watch.is_excluded(p)))`

`walk_files` is **untouched** — it stays a pure directory recursor that already
takes an `is_excluded` predicate.

### `mark_all` rewritten

Consume one `WatchScan` per watch; mark the inodes; emit per-watch logging:

| Scan result        | Marks                  | Log                                                            |
|--------------------|------------------------|---------------------------------------------------------------|
| `File(p)`          | `mark_file(p)`         | `info!  watch {root}: marked 1 file`                           |
| `Dir(files)` n>0   | `mark_file` each       | `info!  watch {root}: marked {n} file(s)`                      |
| `Dir(files)` n==0  | none                   | `warn!  watch {root}: no markable files (empty)`              |
| `Unresolved`       | none                   | `warn!  watch {root}: path does not exist; nothing marked` *  |

\* Wording tailored at log time: if the path exists but is the wrong type, say
"not a regular file or directory" instead of "does not exist".

The existing global `info!("marked {marked} file(s); ...")` total is preserved
on top of the per-watch lines. Individual `mark_file` failures keep their
current per-file `warn!` (e.g. the `ENOSPC` mark-limit case).

### Reload behavior

`mark_all` is called from both startup and the hot-reload path, so a file
created after launch is picked up on the next reload (SIGHUP or config edit) —
consistent with how directory watches already behave.

## Minor semantics (recorded, not enforced)

- **`exclude` on a `File` watch is ignored** — there is no subtree to prune.
  Documented behavior; a file listing itself in `exclude` is user error and is
  not special-cased.
- **`learn_object = "tree"` on a file watch** degenerates to file granularity
  naturally: the learned rule's tree root would be the file path, and
  `starts_with(file)` matches only that file. No special handling needed.

## Testing

Temp-directory tests (matching the existing suites), targeting `scan_watch`
because its returned status drives every log branch:

- missing path → `Unresolved`
- regular-file root → `File(path)`
- directory with files → `Dir` with the expected set; excluded entries pruned
- empty directory → `Dir(vec![])`
- the existing `walk_files` prune test remains valid unchanged

`mark_all`'s logging is a side effect; it is covered indirectly because the
branch decisions live entirely in the `WatchScan` value that `scan_watch`
produces.

## Follow-up (out of scope, tracked here)

**Inode-replacement gap.** fanotify marks an inode. Tools that write a secret by
creating a temp file and `rename()`-ing it over the target (`vault login`,
editors, `kubectl config`, password managers) leave the mark on the old, now
unlinked inode; the new file is unprotected until the next reload/re-mark. This
affects directory-watched files too, but is sharper for a single-file watch
(one rewrite silently lapses the guard).

Proposed future fix: extend the existing inotify watcher (`watcher.rs`) to also
watch each file-watch's parent directory for that basename
(`IN_CREATE`/`IN_MOVED_TO`) and trigger a targeted re-mark of the new inode,
rather than only flipping the global `RELOAD` flag.

## Affected files

- `filewalld/src/main.rs` — `WatchScan`, `scan_watch`, `mark_all` rewrite, tests.
- (verify) `example_config.toml` — `~/.vault-token` file watch becomes genuinely
  functional; confirm the comment is accurate, no change expected.
