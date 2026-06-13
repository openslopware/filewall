//! filewall daemon (root). Marks watched files with fanotify open-permission
//! events and, for any process not on a path's allowlist, asks the user via the
//! `filewall-ui` helper whether to allow the access.

mod config;
mod fanotify;
mod policy;
mod server;

use config::Config;
use fanotify::Fanotify;
use filewall_proto::{Decision, PromptRequest};
use filewall_rules::{RuleAction, Rules};
use policy::{combine, Outcome, Policy};
use server::{is_disconnect, UiLink, UiServer};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const DEFAULT_CONFIG: &str = "/etc/filewall/config.toml";
const PIDFILE: &str = "/run/filewall/filewalld.pid";

static RELOAD: AtomicBool = AtomicBool::new(false);

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
    let mut rules = Rules::load(&rules_path);

    log(&format!("loaded config from {config_path}"));
    log(&format!(
        "loaded {} learned rule(s) from {}",
        rules.rules.len(),
        rules_path.display()
    ));

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
        log(&format!(
            "warning: could not write pidfile {}: {e}",
            pidfile.display()
        ));
    }

    // Bind and wait for the UI helper BEFORE marking files, so there is never a
    // window where marks exist but no one can answer prompts.
    let server = UiServer::bind(&cfg.socket_path, timeout)?;
    log(&format!(
        "listening on {}; waiting for filewall-ui to connect...",
        cfg.socket_path.display()
    ));
    // Block for the first UI at startup; thereafter the link is recovered
    // non-blockingly in the event loop, so it is held as an Option.
    let mut ui = Some(server.accept()?);
    log("UI helper connected");

    // Now mark every existing file under each watched root.
    let marked = mark_all(&fan, &policy);
    log(&format!("marked {marked} file(s); entering event loop"));

    event_loop(
        &fan, &mut policy, &mut rules, &rules_path, &config_path, &server, &mut ui, own_pid,
    )
}

/// Mark every existing regular file under each watched root. Idempotent
/// (FAN_MARK_ADD on an already-marked inode is a no-op).
fn mark_all(fan: &Fanotify, policy: &Policy) -> usize {
    let mut marked = 0usize;
    for watch in policy.watches() {
        for file in walk_files(watch.root()) {
            match fan.mark_file(&file) {
                Ok(()) => marked += 1,
                Err(e) => log(&format!("warning: could not mark {}: {e}", file.display())),
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
    own_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let events = match fan.read_events() {
            Ok(evs) => evs,
            // A SIGHUP interrupts the blocking read; fall through to reload.
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        if RELOAD.swap(false, Ordering::SeqCst) {
            match Config::load(Path::new(config_path)) {
                Ok(new_cfg) => match new_cfg.build_policy() {
                    Ok(new_policy) => {
                        *policy = new_policy;
                        *rules = Rules::load(rules_path);
                        let n = mark_all(fan, policy);
                        log(&format!(
                            "reloaded config + {} rule(s); re-marked {n} file(s)",
                            rules.rules.len()
                        ));
                    }
                    Err(e) => log(&format!("reload failed (policy): {e}; keeping current config")),
                },
                Err(e) => log(&format!("reload failed (config): {e}; keeping current config")),
            }
        }

        for ev in &events {
            // Anything that isn't an open-perm event, or our own access, is allowed.
            if !ev.is_open_perm() || ev.pid == own_pid {
                let _ = fan.respond(ev, true);
                continue;
            }

            let path = ev.accessed_path().unwrap_or_else(|_| PathBuf::from("<unknown>"));
            // The held pidfd is what makes exe()/cmdline() race-free; warn if the
            // kernel didn't deliver one (then resolution is best-effort).
            if !ev.has_pidfd() {
                log(&format!("warning: no pidfd for pid {}; exe may be racy", ev.pid));
            }
            let exe = ev.exe();
            let cwd = ev.cwd();

            let cfg_outcome = policy.evaluate(&path, &exe);
            let learned = rules.evaluate(&path, &exe, Some(cwd.as_str()));
            let allow = match combine(cfg_outcome, learned) {
                Outcome::Allow => true,
                Outcome::Deny => false,
                Outcome::Prompt => {
                    let req = PromptRequest {
                        pid: ev.pid,
                        exe: exe.clone(),
                        cmdline: ev.cmdline(),
                        cwd: cwd.clone(),
                        path: path.display().to_string(),
                    };
                    // Recover a dropped link without blocking the event loop.
                    if ui.is_none() {
                        match server.try_accept() {
                            Ok(Some(link)) => {
                                *ui = Some(link);
                                log("UI reconnected");
                            }
                            Ok(None) => {}
                            Err(e) => log(&format!("warning: try_accept failed: {e}")),
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
                                        log(&format!("warning: could not persist rule: {e}"));
                                    } else {
                                        log(&format!(
                                            "learned {:?} {} -> {}",
                                            action,
                                            exe,
                                            path.display()
                                        ));
                                    }
                                }
                            }
                            decision.allows()
                        }
                        // Dead connection -> deny this access and drop the link so a
                        // restarted UI is picked up on the next prompt.
                        Some(Err(e)) if is_disconnect(&e) => {
                            log(&format!(
                                "UI disconnected ({e}); denying {} and awaiting reconnect",
                                path.display()
                            ));
                            *ui = None;
                            false
                        }
                        // Timeout / transient -> deny (watchdog), keep the link.
                        Some(Err(e)) => {
                            log(&format!(
                                "prompt failed ({e}); denying {} for {}",
                                path.display(),
                                exe
                            ));
                            false
                        }
                        // No UI connected right now -> deny (fail-closed).
                        None => {
                            log(&format!(
                                "no UI connected; denying {} for {}",
                                path.display(),
                                exe
                            ));
                            false
                        }
                    }
                }
            };

            if let Err(e) = fan.respond(ev, allow) {
                log(&format!("warning: failed to answer event: {e}"));
            }
            log(&format!(
                "{} {} -> {}",
                if allow { "ALLOW" } else { "DENY " },
                exe,
                path.display()
            ));
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

/// Recursively collect regular files under `root` (skipping symlinks).
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.push(path);
            }
            // symlinks and special files are skipped
        }
    }
    out
}

fn log(msg: &str) {
    eprintln!("[filewalld] {msg}");
}

#[cfg(test)]
mod tests {
    use super::write_pidfile;

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
