//! filewall daemon (root). Marks watched files with fanotify open-permission
//! events and, for any process not on a path's allowlist, asks the user via the
//! `filewall-ui` helper whether to allow the access.

mod config;
mod fanotify;
mod policy;
mod server;
mod treewatch;
mod watcher;

use config::Config;
use fanotify::Fanotify;
use filewall_proto::{Decision, PromptRequest};
use filewall_rules::{RuleAction, Rules};
use log::{debug, info, warn};
use policy::{combine, Outcome, Policy, WatchPolicy};
use server::{is_disconnect, UiLink, UiServer};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DEFAULT_CONFIG: &str = "/etc/filewall/config.toml";
const PIDFILE: &str = "/run/filewall/filewalld.pid";

/// How long the event loop blocks in `poll` per cycle before falling through to the
/// `RELOAD` check. A config/rules change only flips the `RELOAD` atomic, which cannot
/// interrupt a blocking `read()`, so this bounds worst-case hot-reload latency.
const RELOAD_POLL_MS: libc::c_int = 500;

pub(crate) static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sighup(_sig: libc::c_int) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// Write our PID so `filewallctl reload`/`status` can find us.
fn write_pidfile(path: &Path, pid: u32) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{pid}\n"))
}

fn main() {
    // Default to `info`; `RUST_LOG=debug` surfaces per-access allow decisions.
    // Logs go to stderr, which journald captures under the unit.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    if let Err(e) = run() {
        eprintln!("filewalld: fatal: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    let cfg = Config::load(Path::new(&config_path))?;
    let mut policy = cfg.build_policy()?;
    let timeout = Duration::from_secs(cfg.prompt_timeout_seconds);
    let own_pid = std::process::id();

    let rules_path = cfg.rules_path.clone();
    watcher::spawn_watcher(Path::new(&config_path), &rules_path);
    let mut rules = Rules::load(&rules_path);

    info!("loaded config from {config_path}");
    info!(
        "loaded {} learned rule(s) from {}",
        rules.rules.len(),
        rules_path.display()
    );

    // Init the fanotify group first (fails fast with EPERM if not root).
    let fan = Fanotify::init().map_err(|e| {
        format!("fanotify_init failed ({e}). Run as root (needs CAP_SYS_ADMIN).")
    })?;

    // SAFETY: installing a trivial signal handler that only sets an atomic flag.
    unsafe {
        let handler = on_sighup as extern "C" fn(libc::c_int);
        libc::signal(libc::SIGHUP, handler as libc::sighandler_t);
    }
    let pidfile = PathBuf::from(PIDFILE);
    if let Err(e) = write_pidfile(&pidfile, own_pid) {
        warn!("could not write pidfile {}: {e}", pidfile.display());
    }

    // Bind and wait for the UI helper BEFORE marking files, so there is never a
    // window where marks exist but no one can answer prompts.
    let server = UiServer::bind(&cfg.socket_path, timeout)?;
    info!(
        "listening on {}; waiting for filewall-ui to connect...",
        cfg.socket_path.display()
    );
    // Block for the first UI at startup; thereafter the link is recovered
    // non-blockingly in the event loop, so it is held as an Option.
    let mut ui = Some(server.accept()?);
    info!("UI helper connected");

    // Now mark every watched root (files directly; directories via ON_CHILD).
    let marked = mark_all(&fan, &policy);
    info!("marked {marked} inode(s); entering event loop");

    // Live-mark new subdirectories as they appear under directory watches.
    let mut treewatch = treewatch::TreeWatch::build(&policy);

    event_loop(
        &fan, &mut policy, &mut rules, &rules_path, &config_path, &server, &mut ui,
        &mut treewatch, own_pid,
    )
}

/// What a watch root resolved to on disk at mark time. Drives both what gets
/// marked and the per-watch log line.
#[derive(Debug)]
enum WatchScan {
    /// Path missing, or neither a regular file nor a directory.
    Unresolved,
    /// A single regular file: mark just this one inode.
    File(PathBuf),
    /// A directory tree: the directories to mark (root plus non-excluded descendant
    /// dirs). Each is marked with `FAN_EVENT_ON_CHILD`, so its immediate files are
    /// covered without a per-file mark. May be just `[root]` for an empty tree.
    Dir(Vec<PathBuf>),
}

/// Resolve a watch root once and classify it for marking + reporting. The root
/// is already canonicalized by the config loader, so `symlink_metadata` reflects
/// the real target type. `exclude` does not apply to a single-file watch (there
/// is no subtree to prune), only to directory recursion.
fn scan_watch(watch: &WatchPolicy) -> WatchScan {
    let root = watch.root();
    match std::fs::symlink_metadata(root) {
        Ok(m) if m.is_file() => WatchScan::File(root.to_path_buf()),
        Ok(m) if m.is_dir() => WatchScan::Dir(walk_dirs(root, |p| watch.is_excluded(p))),
        _ => WatchScan::Unresolved,
    }
}

/// Mark every guarded inode. A watch root may be a single regular file (mark that
/// file inode directly) or a directory (mark the directory and each non-excluded
/// descendant directory with `FAN_EVENT_ON_CHILD`, so their immediate children are
/// covered without a per-file mark). Idempotent (FAN_MARK_ADD on an already-marked
/// inode is a no-op). Logs a per-watch summary, and warns loudly when a watch
/// resolves to nothing markable so a misconfigured guard is never silent.
fn mark_all(fan: &Fanotify, policy: &Policy) -> usize {
    let mut marked = 0usize;
    for watch in policy.watches() {
        let root = watch.root();
        match scan_watch(watch) {
            // Single-file watch: mark just that inode.
            WatchScan::File(p) => match fan.mark_file(&p) {
                Ok(()) => {
                    info!("watch {}: marked 1 file", root.display());
                    marked += 1;
                }
                Err(e) => warn!("could not mark {}: {e}", p.display()),
            },
            // Directory watch: mark each directory with FAN_EVENT_ON_CHILD so its
            // immediate children are covered without a per-file mark.
            WatchScan::Dir(dirs) => {
                if dirs.is_empty() {
                    warn!("watch {}: no markable directories (empty)", root.display());
                    continue;
                }
                let mut n = 0usize;
                for dir in &dirs {
                    match fan.mark_dir(dir) {
                        Ok(()) => n += 1,
                        Err(e) => warn!("could not mark {}: {e}", dir.display()),
                    }
                }
                info!("watch {}: marked {n} dir(s) (children covered)", root.display());
                marked += n;
            }
            WatchScan::Unresolved => {
                if root.exists() {
                    warn!("watch {}: not a regular file or directory; nothing marked", root.display());
                } else {
                    warn!("watch {}: path does not exist; nothing marked", root.display());
                }
            }
        }
    }
    marked
}

#[allow(clippy::too_many_arguments)] // distinct collaborators an event loop needs
fn event_loop(
    fan: &Fanotify,
    policy: &mut Policy,
    rules: &mut Rules,
    rules_path: &Path,
    config_path: &str,
    server: &UiServer,
    ui: &mut Option<UiLink>,
    treewatch: &mut treewatch::TreeWatch,
    own_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Poll the fanotify fd and the treewatch inotify fd together. A bounded
        // timeout lets a pending RELOAD (set by the config/rules watcher thread or a
        // SIGHUP, neither of which can interrupt a blocking read) be acted on
        // promptly.
        let mut fds = [
            libc::pollfd { fd: fan.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: treewatch.raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, RELOAD_POLL_MS) };
        let events = if rc < 0 {
            let e = std::io::Error::last_os_error();
            // EINTR (e.g. a SIGHUP that landed here) is not an error: fall through to
            // the RELOAD check with no events.
            if e.raw_os_error() == Some(libc::EINTR) {
                Vec::new()
            } else {
                return Err(e.into());
            }
        } else if rc == 0 {
            Vec::new() // timeout: no events, just check RELOAD
        } else {
            // Drain new-subdirectory marks first, so files in a just-appeared subdir
            // are likelier covered before we process the fanotify backlog.
            if fds[1].revents & libc::POLLIN != 0 {
                treewatch.on_ready(fan, policy);
            }
            if fds[0].revents & libc::POLLIN != 0 {
                fan.read_ready()?
            } else {
                Vec::new()
            }
        };

        if RELOAD.swap(false, Ordering::SeqCst) {
            info!("reload requested; reloading config from {config_path}");
            match Config::load(Path::new(config_path)) {
                Ok(new_cfg) => match new_cfg.build_policy() {
                    Ok(new_policy) => {
                        *policy = new_policy;
                        *rules = Rules::load(rules_path);
                        let n = mark_all(fan, policy);
                        // Rebuild the inotify watch set to match the re-marked dirs.
                        *treewatch = treewatch::TreeWatch::build(policy);
                        info!(
                            "reloaded config + {} rule(s); re-marked {n} inode(s)",
                            rules.rules.len()
                        );
                    }
                    Err(e) => warn!("reload failed (policy): {e}; keeping current config"),
                },
                Err(e) => warn!("reload failed (config): {e}; keeping current config"),
            }
        }

        for ev in &events {
            // Anything that isn't an open-perm event, or our own access, is allowed.
            if !ev.is_open_perm() || ev.pid == own_pid {
                let _ = fan.respond(ev, true);
                continue;
            }

            let path = ev.accessed_path().unwrap_or_else(|_| PathBuf::from("<unknown>"));

            // File-level excludes: a directory's ON_CHILD mark fires for *every* child,
            // so per-file exclude globs are no longer suppressed by the kernel — honor
            // them here. (Done before exe/cwd resolution so we don't pay that cost on
            // an access we're going to allow anyway.)
            if let Some(w) = policy.watches().iter().find(|w| w.covers(&path)) {
                if w.is_excluded(&path) {
                    let _ = fan.respond(ev, true);
                    debug!("ALLOW (excluded) pid {} -> {}", ev.pid, path.display());
                    continue;
                }
            }

            // The held pidfd is what makes exe()/cmdline() race-free; warn if the
            // kernel didn't deliver one (then resolution is best-effort).
            if !ev.has_pidfd() {
                warn!("no pidfd for pid {}; exe may be racy", ev.pid);
            }
            let exe = ev.exe();
            let cwd = ev.cwd();

            let cfg_outcome = policy.evaluate(&path, &exe);
            let learned = rules.evaluate(&path, &exe, Some(cwd.as_str()));
            let allow = match combine(cfg_outcome, learned) {
                Outcome::Allow => true,
                Outcome::Deny => false,
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
                    // Recover a dropped link without blocking the event loop.
                    if ui.is_none() {
                        match server.try_accept() {
                            Ok(Some(link)) => {
                                *ui = Some(link);
                                info!("UI reconnected");
                            }
                            Ok(None) => {}
                            Err(e) => warn!("try_accept failed: {e}"),
                        }
                    }
                    // Borrow ends with the result; lets us reassign `ui` below.
                    let result = ui.as_mut().map(|link| link.prompt(&req));
                    match result {
                        Some(Ok(decision)) => {
                            // Persist "Always": add in-memory now, mirror to disk.
                            if let Some(action) = always_action(decision) {
                                if let Some(watch) =
                                    policy.watches().iter().find(|w| w.covers(&path))
                                {
                                    let rule =
                                        watch.learned_rule(action, &exe, &path, Some(cwd.as_str()));
                                    rules.push(rule);
                                    if let Err(e) = rules.save_atomic(rules_path) {
                                        warn!("could not persist rule: {e}");
                                    } else {
                                        info!("learned {:?} {} -> {}", action, exe, path.display());
                                    }
                                }
                            }
                            decision.allows()
                        }
                        // Dead connection -> deny this access and drop the link so a
                        // restarted UI is picked up on the next prompt.
                        Some(Err(e)) if is_disconnect(&e) => {
                            warn!(
                                "UI disconnected ({e}); denying {} and awaiting reconnect",
                                path.display()
                            );
                            *ui = None;
                            false
                        }
                        // Timeout / transient -> deny (watchdog), keep the link.
                        Some(Err(e)) => {
                            warn!("prompt failed ({e}); denying {} for {}", path.display(), exe);
                            false
                        }
                        // No UI connected right now -> deny (fail-closed).
                        None => {
                            warn!("no UI connected; denying {} for {}", path.display(), exe);
                            false
                        }
                    }
                }
            };

            if let Err(e) = fan.respond(ev, allow) {
                warn!("failed to answer event: {e}");
            }
            // Per-access outcome: allows are routine (debug); denies are the
            // security-relevant signal (warn).
            if allow {
                debug!("ALLOW {} -> {}", exe, path.display());
            } else {
                warn!("DENY {} -> {}", exe, path.display());
            }
        }
    }
}

/// Map an "Always" decision to the rule action to persist; `None` for one-shots.
fn always_action(d: Decision) -> Option<RuleAction> {
    match d {
        Decision::AllowAlways => Some(RuleAction::Allow),
        Decision::DenyAlways => Some(RuleAction::Deny),
        Decision::AllowOnce | Decision::DenyOnce => None,
    }
}

/// Collect `root` and every non-excluded descendant directory. An excluded dir is
/// skipped and never descended (its subtree is pruned), which is what keeps noisy
/// trees from exhausting the fanotify mark limit. Symlinked dirs are not followed.
/// The returned dirs are marked with `FAN_EVENT_ON_CHILD`, so each one's immediate
/// files are covered without a per-file mark.
fn walk_dirs(root: &Path, is_excluded: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_excluded(&path) {
                continue; // pruned: excluded dir subtree
            }
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {
                    out.push(path.clone());
                    stack.push(path);
                }
                _ => {} // files/symlinks/special: covered by parent's ON_CHILD mark
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{scan_watch, walk_dirs, write_pidfile, WatchScan};
    use crate::policy::{Action, WatchPolicy};
    use filewall_rules::ObjectKind;
    use std::path::{Path, PathBuf};

    fn unique_tmp(tag: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        std::env::temp_dir().join(format!(
            "filewall-{tag}-{}-{}-{}",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ))
    }

    fn watch_for(root: &Path, exclude: &[String]) -> WatchPolicy {
        WatchPolicy::new(root, &[], Action::Prompt, ObjectKind::File, false, exclude).unwrap()
    }

    #[test]
    fn scan_watch_classifies_file_dir_and_missing() {
        let base = unique_tmp("scan");
        std::fs::create_dir_all(&base).unwrap();

        // Missing path -> Unresolved.
        let missing = base.join("nope");
        assert!(matches!(
            scan_watch(&watch_for(&missing, &[])),
            WatchScan::Unresolved
        ));

        // Single regular file -> File(that path).
        let file = base.join("token");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            scan_watch(&watch_for(&file, &[])),
            WatchScan::File(p) if p == file
        ));

        // Directory with a subdir, with an excluded subtree pruned -> Dir(dirs).
        // The scan returns directories to mark (root + non-excluded subdirs), not
        // files — files are covered by their parent dir's ON_CHILD mark.
        let dir = base.join("tree");
        std::fs::create_dir_all(dir.join("Cache")).unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        std::fs::write(dir.join("Cache/junk"), b"x").unwrap();
        match scan_watch(&watch_for(&dir, &["**/Cache".to_string()])) {
            WatchScan::Dir(dirs) => {
                assert!(dirs.contains(&dir)); // the root itself is marked
                assert!(dirs.contains(&dir.join("sub")));
                // The excluded Cache subtree is pruned.
                assert!(!dirs.iter().any(|d| d.starts_with(dir.join("Cache"))));
                // Files are never returned — only directories get marked.
                assert!(!dirs.contains(&dir.join("a.txt")));
            }
            other => panic!("expected Dir, got {other:?}"),
        }

        // Empty directory -> Dir([root]) (the root is always markable).
        let empty = base.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(matches!(
            scan_watch(&watch_for(&empty, &[])),
            WatchScan::Dir(ref d) if d == &vec![empty.clone()]
        ));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn walk_dirs_returns_root_and_subdirs_pruning_excluded() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "filewall-walk-{}-{}-{}",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        // root/keep.txt, root/Cache/junk, root/sub/keep2.txt, root/sub/deep/
        std::fs::create_dir_all(root.join("Cache")).unwrap();
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::fs::write(root.join("keep.txt"), b"x").unwrap();
        std::fs::write(root.join("Cache/junk"), b"x").unwrap();
        std::fs::write(root.join("sub/keep2.txt"), b"x").unwrap();

        // Exclude the Cache subtree.
        let dirs = walk_dirs(&root, |p| p.to_string_lossy().ends_with("/Cache"));

        let names: std::collections::HashSet<PathBuf> = dirs.into_iter().collect();
        // The root and every non-excluded descendant dir are returned.
        assert!(names.contains(&root));
        assert!(names.contains(&root.join("sub")));
        assert!(names.contains(&root.join("sub/deep")));
        // Pruned: the excluded dir and never-descended subtree.
        assert!(!names.contains(&root.join("Cache")));
        // Files are never returned — only directories get marked.
        assert!(!names.contains(&root.join("keep.txt")));
        assert!(!names.contains(&root.join("sub/keep2.txt")));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pidfile_write_has_trailing_newline() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-pid-{}-{}.pid",
            std::process::id(),
            ts.subsec_nanos()
        ));
        write_pidfile(&path, 4242).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, "4242\n");
        // filewallctl parses this with a trim()+parse, which must succeed.
        assert_eq!(written.trim().parse::<i32>().unwrap(), 4242);
        let _ = std::fs::remove_file(&path);
    }
}
