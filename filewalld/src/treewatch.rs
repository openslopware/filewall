//! Live-marking of new subdirectories under a directory watch.
//!
//! A directory watch marks each directory with `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD`,
//! which covers that directory's *immediate* children but is not recursive. To keep a
//! tree covered as it grows, [`TreeWatch`] holds an inotify instance watching every
//! marked directory and, when a new subdirectory appears (`IN_CREATE` / `IN_MOVED_TO`
//! with `IN_ISDIR`), marks it (and any already-populated descendant dirs, for a
//! moved-in subtree) and adds an inotify watch on it.
//!
//! Main-thread-owned: no `Arc`/locks. The event loop polls this inotify fd alongside
//! the fanotify fd (see `main.rs`) and calls [`TreeWatch::on_ready`] when it signals.

use crate::fanotify::Fanotify;
use crate::policy::Policy;
use crate::{scan_watch, walk_dirs, WatchScan};
use log::{info, warn};
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

/// Mask for the per-directory inotify watch: new immediate children that are
/// directories (created or moved in). `IN_ONLYDIR` makes `add_watch` fail fast if the
/// path is not a directory; `IN_ISDIR` is reported in event masks to flag dir entries.
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO | AddWatchFlags::IN_ONLYDIR
}

/// Inotify-backed live marking of new subdirectories.
pub struct TreeWatch {
    /// `None` if inotify init failed — then this is an inert no-op (raw fd -1, which
    /// `poll` ignores), and new subdirs are simply not live-marked until the next
    /// reload re-walks the trees.
    inotify: Option<Inotify>,
    /// Maps each watched directory's descriptor back to its path, so an event's
    /// `name` can be joined onto the right parent.
    wd_map: HashMap<WatchDescriptor, PathBuf>,
}

impl TreeWatch {
    /// Build a watch set covering every directory a **dir** watch marks. Single-file
    /// watches contribute nothing. An `add_watch` failure (e.g. `ENOSPC` from
    /// `fs.inotify.max_user_watches`) warns loudly and is skipped — the rest of the
    /// tree is still watched.
    pub fn build(policy: &Policy) -> TreeWatch {
        let inotify = match Inotify::init(InitFlags::IN_CLOEXEC | InitFlags::IN_NONBLOCK) {
            Ok(i) => i,
            Err(e) => {
                warn!("treewatch: inotify init failed ({e}); new subdirs won't be live-marked");
                return TreeWatch {
                    inotify: None,
                    wd_map: HashMap::new(),
                };
            }
        };
        let mut tw = TreeWatch {
            inotify: Some(inotify),
            wd_map: HashMap::new(),
        };
        for watch in policy.watches() {
            // A non-recursive watch (scoped by shallow `patterns`) marks only its root
            // and must never live-mark new subdirs — that would silently make it
            // recursive. Skip it so its subtree stays unwatched by design.
            if !watch.recursive() {
                continue;
            }
            if let WatchScan::Dir(dirs) = scan_watch(watch) {
                for dir in &dirs {
                    tw.add(dir);
                }
            }
        }
        info!(
            "treewatch: watching {} dir(s) for new subdirectories",
            tw.wd_map.len()
        );
        tw
    }

    /// The inotify fd for the event loop's combined `poll`. Returns `-1` when inotify
    /// is unavailable; `poll` treats a negative fd as "ignore" (revents 0).
    pub fn raw_fd(&self) -> RawFd {
        self.inotify
            .as_ref()
            .map(|i| i.as_fd().as_raw_fd())
            .unwrap_or(-1)
    }

    /// Drain ready inotify events and live-mark any new subdirectories. Call only when
    /// `poll` reported `POLLIN` on [`raw_fd`](Self::raw_fd).
    pub fn on_ready(&mut self, fan: &Fanotify, policy: &Policy) {
        let events = match self.inotify.as_ref() {
            Some(i) => match i.read_events() {
                Ok(evs) => evs,
                // Non-blocking inotify: nothing left to read.
                Err(nix::Error::EAGAIN) | Err(nix::Error::EINTR) => return,
                Err(e) => {
                    warn!("treewatch: inotify read error ({e})");
                    return;
                }
            },
            None => return,
        };

        for ev in events {
            // A queue overflow means we missed events while the loop was blocked (e.g.
            // on a UI prompt). Force a full re-mark + rebuild — simplest correct
            // recovery.
            if ev.mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                warn!("treewatch: inotify queue overflow; forcing full re-mark via reload");
                crate::RELOAD.store(true, Ordering::SeqCst);
                continue;
            }
            // Only new directories matter; new files are already covered by the
            // parent dir's ON_CHILD mark.
            if !ev.mask.contains(AddWatchFlags::IN_ISDIR) {
                continue;
            }
            let (Some(name), Some(parent)) = (ev.name.as_ref(), self.wd_map.get(&ev.wd)) else {
                continue;
            };
            let new_dir = parent.join(name);
            let Some(watch) = policy.watches().iter().find(|w| w.covers(&new_dir)) else {
                continue;
            };
            // A moved-in directory may already contain a populated subtree, so mark +
            // watch the new dir and every non-excluded descendant dir, not just the top.
            for dir in dirs_to_mark(&new_dir, |p| watch.is_excluded(p)) {
                match fan.mark_dir(&dir) {
                    Ok(()) => info!("treewatch: marked new dir {} (children covered)", dir.display()),
                    Err(e) => warn!("treewatch: could not mark {}: {e}", dir.display()),
                }
                self.add(&dir);
            }
        }
    }

    /// Add an inotify watch on `dir`, recording its descriptor. Warns and continues on
    /// failure (the fanotify mark may still have succeeded; only live coverage of
    /// *future* children under `dir` is lost).
    fn add(&mut self, dir: &Path) {
        let Some(inotify) = self.inotify.as_ref() else {
            return;
        };
        match inotify.add_watch(dir, watch_mask()) {
            Ok(wd) => {
                self.wd_map.insert(wd, dir.to_path_buf());
            }
            Err(e) => warn!(
                "treewatch: add_watch {} failed: {e}; new subdirs here won't be live-marked",
                dir.display()
            ),
        }
    }
}

/// Pure decision: which directories to mark + watch when a new subdir appears at
/// `new_dir`, given the covering watch's exclude predicate. Empty if `new_dir` is
/// itself excluded; otherwise `new_dir` plus every already-present non-excluded
/// descendant directory (a moved-in dir may arrive populated). Factored out so the
/// recursion/exclude logic is unit-testable without placing real fanotify marks.
fn dirs_to_mark(new_dir: &Path, is_excluded: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    if is_excluded(new_dir) {
        return Vec::new();
    }
    walk_dirs(new_dir, is_excluded)
}

#[cfg(test)]
mod tests {
    use super::dirs_to_mark;
    use std::path::PathBuf;

    fn tmp_tree(tag: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        std::env::temp_dir().join(format!(
            "filewall-treewatch-{}-{}-{}-{}",
            tag,
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ))
    }

    #[test]
    fn dirs_to_mark_recurses_into_populated_subtree() {
        // A moved-in dir that already contains nested subdirs: all of them must be
        // returned for marking (the parent's ON_CHILD doesn't reach grandchildren).
        let root = tmp_tree("recurse");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/file.txt"), b"x").unwrap();

        let dirs: std::collections::HashSet<PathBuf> =
            dirs_to_mark(&root, |_| false).into_iter().collect();

        assert!(dirs.contains(&root));
        assert!(dirs.contains(&root.join("a")));
        assert!(dirs.contains(&root.join("a/b")));
        // Files are never marked directly.
        assert!(!dirs.contains(&root.join("a/file.txt")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dirs_to_mark_honors_excludes() {
        let root = tmp_tree("exclude");
        std::fs::create_dir_all(root.join("keep")).unwrap();
        std::fs::create_dir_all(root.join("Cache/inner")).unwrap();

        let dirs: std::collections::HashSet<PathBuf> =
            dirs_to_mark(&root, |p| p.to_string_lossy().ends_with("/Cache"))
                .into_iter()
                .collect();

        assert!(dirs.contains(&root));
        assert!(dirs.contains(&root.join("keep")));
        // The excluded dir and its whole subtree are pruned.
        assert!(!dirs.contains(&root.join("Cache")));
        assert!(!dirs.contains(&root.join("Cache/inner")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dirs_to_mark_empty_when_new_dir_itself_excluded() {
        let root = tmp_tree("self-excluded");
        std::fs::create_dir_all(root.join("child")).unwrap();

        // The new dir itself matches an exclude -> nothing to mark.
        let dirs = dirs_to_mark(&root, |_| true);
        assert!(dirs.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }
}
