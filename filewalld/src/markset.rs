//! The daemon's in-memory record of the fanotify marks it has placed, plus the
//! pure assembler that turns it (cross-referenced with the live inotify watch
//! set) into the `DumpResponse` answered on the control socket.
//!
//! Main-thread-owned: no `Arc`/locks. Populated by `mark_all` (cleared and
//! rebuilt on every (re)mark) and extended by `TreeWatch::on_ready` when new
//! subdirectories are live-marked.

use filewall_proto::{ObjKind, WatchedObject};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One placed (or attempted) fanotify mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkEntry {
    pub kind: ObjKind,
    /// Whether the covering watch recurses (drives `live_marked` semantics).
    pub recursive: bool,
    pub watch_root: PathBuf,
    /// Whether `fanotify_mark` succeeded. `false` is a coverage gap.
    pub ok: bool,
}

/// Set of placed marks, keyed by path. `BTreeMap` gives a stable, sorted dump.
#[derive(Debug, Default)]
pub struct MarkSet {
    entries: BTreeMap<PathBuf, MarkEntry>,
}

impl MarkSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop all entries (called at the start of every `mark_all`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Record (or overwrite) the mark for `path`.
    pub fn record(&mut self, path: &Path, entry: MarkEntry) {
        self.entries.insert(path.to_path_buf(), entry);
    }
}

/// Build the dump object list. `is_watching(dir)` reports whether a directory
/// currently has an inotify watch (i.e. its new subdirs are live-marked); it is
/// only consulted for `Dir` entries — files report `live_marked = None`.
///
/// Pure (no I/O) so it is unit-testable without placing real marks or sockets.
pub fn build_dump(marks: &MarkSet, is_watching: impl Fn(&Path) -> bool) -> Vec<WatchedObject> {
    marks
        .entries
        .iter()
        .map(|(path, e)| WatchedObject {
            path: path.display().to_string(),
            kind: e.kind,
            recursive: e.recursive,
            watch: e.watch_root.display().to_string(),
            fanotify: e.ok,
            live_marked: match e.kind {
                ObjKind::Dir => Some(is_watching(path)),
                ObjKind::File => None,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_entry(ok: bool) -> MarkEntry {
        MarkEntry {
            kind: ObjKind::Dir,
            recursive: true,
            watch_root: PathBuf::from("/w"),
            ok,
        }
    }

    #[test]
    fn file_entry_reports_live_marked_none() {
        let mut ms = MarkSet::new();
        ms.record(
            Path::new("/w/token"),
            MarkEntry { kind: ObjKind::File, recursive: false, watch_root: "/w".into(), ok: true },
        );
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].kind, ObjKind::File);
        assert_eq!(objs[0].live_marked, None);
        assert!(objs[0].fanotify);
    }

    #[test]
    fn healthy_dir_is_live_marked_true() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(true));
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs[0].live_marked, Some(true));
    }

    #[test]
    fn dir_without_inotify_watch_is_live_marked_false() {
        // fanotify mark ok, but inotify add_watch failed (ENOSPC) -> coverage gap.
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(true));
        let objs = build_dump(&ms, |_| false);
        assert_eq!(objs[0].live_marked, Some(false));
        assert!(objs[0].fanotify);
    }

    #[test]
    fn failed_mark_reports_fanotify_false() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/sub"), dir_entry(false));
        let objs = build_dump(&ms, |_| true);
        assert!(!objs[0].fanotify);
    }

    #[test]
    fn output_is_sorted_by_path() {
        let mut ms = MarkSet::new();
        ms.record(Path::new("/w/b"), dir_entry(true));
        ms.record(Path::new("/w/a"), dir_entry(true));
        let objs = build_dump(&ms, |_| true);
        assert_eq!(objs[0].path, "/w/a");
        assert_eq!(objs[1].path, "/w/b");
    }
}
