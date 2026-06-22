//! filewallctl — inspect and manage filewall's learned rules.
//!
//! Subcommands:
//!   list   [rules_path]      Print learned rules.
//!   remove <index> [path]    Remove a rule by index, then SIGHUP the daemon.
//!   reload [pidfile]         Send SIGHUP to the running daemon.
//!   status [pidfile]         Report whether the daemon is running.

mod format;

use filewall_rules::Rules;
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_RULES: &str = "/var/lib/filewall/rules.toml";
const DEFAULT_PIDFILE: &str = "/run/filewall/filewalld.pid";

fn parse_pidfile(s: &str) -> Option<i32> {
    s.trim().parse::<i32>().ok()
}

/// Remove the rule at `index`, returning it, or `None` if out of range.
fn remove_at(rules: &mut Rules, index: usize) -> Option<filewall_rules::LearnedRule> {
    if index < rules.rules.len() {
        Some(rules.rules.remove(index))
    } else {
        None
    }
}

fn cmd_list(path: &Path) -> ExitCode {
    let rules = Rules::load(path);
    if rules.rules.is_empty() {
        println!("No learned rules ({})", path.display());
        return ExitCode::SUCCESS;
    }
    println!("Learned rules ({}):", path.display());
    for (i, r) in rules.rules.iter().enumerate() {
        let cwd = r.cwd.as_deref().unwrap_or("-");
        println!(
            "  [{i}] {:?} exe={} object={} kind={:?} cwd={} created_unix={}",
            r.action,
            r.exe,
            r.object.display(),
            r.object_kind,
            cwd,
            r.created_unix
        );
    }
    ExitCode::SUCCESS
}

fn cmd_remove(index: usize, rules_path: &Path, pidfile: &Path) -> ExitCode {
    let mut rules = Rules::load(rules_path);
    match remove_at(&mut rules, index) {
        Some(removed) => {
            if let Err(e) = rules.save_atomic(rules_path) {
                eprintln!("filewallctl: could not write {}: {e}", rules_path.display());
                return ExitCode::FAILURE;
            }
            println!("Removed [{index}] {} -> {}", removed.exe, removed.object.display());
            // Best-effort: tell the daemon to reload.
            let _ = send_sighup(pidfile);
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("filewallctl: no rule at index {index}");
            ExitCode::FAILURE
        }
    }
}

fn send_sighup(pidfile: &Path) -> Result<i32, String> {
    let text = std::fs::read_to_string(pidfile)
        .map_err(|e| format!("reading {}: {e}", pidfile.display()))?;
    let pid =
        parse_pidfile(&text).ok_or_else(|| format!("invalid pidfile {}", pidfile.display()))?;
    kill(Pid::from_raw(pid), Signal::SIGHUP).map_err(|e| format!("kill {pid}: {e}"))?;
    Ok(pid)
}

fn cmd_reload(pidfile: &Path) -> ExitCode {
    match send_sighup(pidfile) {
        Ok(pid) => {
            println!("Sent SIGHUP to filewalld (pid {pid})");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("filewallctl: reload failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Daemon liveness derived from a signal-0 probe.
#[derive(Debug, PartialEq, Eq)]
enum Liveness {
    Running,
    Stale,
    Unknown(Errno),
}

/// Classify a `kill(pid, 0)` result into daemon liveness.
///
/// `EPERM` means the process exists but we lack permission to signal it — the
/// daemon runs as root while filewallctl runs unprivileged, so this is a live
/// process, not a stale pid. Only `ESRCH` (no such process) is genuinely stale.
fn classify_liveness(probe: Result<(), Errno>) -> Liveness {
    match probe {
        Ok(()) => Liveness::Running,
        Err(Errno::EPERM) => Liveness::Running,
        Err(Errno::ESRCH) => Liveness::Stale,
        Err(e) => Liveness::Unknown(e),
    }
}

fn cmd_status(pidfile: &Path) -> ExitCode {
    let text = match std::fs::read_to_string(pidfile) {
        Ok(t) => t,
        Err(_) => {
            println!("filewalld: not running (no pidfile)");
            return ExitCode::FAILURE;
        }
    };
    let pid = match parse_pidfile(&text) {
        Some(p) => p,
        None => {
            println!("filewalld: unknown (bad pidfile)");
            return ExitCode::FAILURE;
        }
    };
    // Signal 0 probes liveness without delivering a signal.
    match classify_liveness(kill(Pid::from_raw(pid), None)) {
        Liveness::Running => {
            println!("filewalld: running (pid {pid})");
            ExitCode::SUCCESS
        }
        Liveness::Stale => {
            println!("filewalld: not running (stale pid {pid})");
            ExitCode::FAILURE
        }
        Liveness::Unknown(e) => {
            println!("filewalld: unknown (pid {pid}: {e})");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         filewallctl list [rules_path]\n  \
         filewallctl remove <index> [rules_path]\n  \
         filewallctl reload [pidfile]\n  \
         filewallctl status [pidfile]"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => {
            let path = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_list(&path)
        }
        Some("remove") => {
            let Some(index) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!("filewallctl: remove needs a numeric <index>");
                return usage();
            };
            let rules_path = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_remove(index, &rules_path, Path::new(DEFAULT_PIDFILE))
        }
        Some("reload") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_reload(&pidfile)
        }
        Some("status") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_status(&pidfile)
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_liveness, parse_pidfile, remove_at, Liveness};
    use filewall_rules::{LearnedRule, ObjectKind, RuleAction, Rules};
    use nix::errno::Errno;
    use std::path::PathBuf;

    fn rule(exe: &str) -> LearnedRule {
        LearnedRule {
            created_unix: 0,
            action: RuleAction::Allow,
            exe: exe.into(),
            object: PathBuf::from("/home/u/.ssh"),
            object_kind: ObjectKind::Tree,
            cwd: None,
        }
    }

    #[test]
    fn parse_pidfile_trims_and_parses() {
        assert_eq!(parse_pidfile("4242\n").unwrap(), 4242);
        assert!(parse_pidfile("not-a-pid").is_none());
    }

    #[test]
    fn remove_at_removes_in_range() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a"));
        rs.push(rule("/usr/bin/b"));
        let removed = remove_at(&mut rs, 0).unwrap();
        assert_eq!(removed.exe, "/usr/bin/a");
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].exe, "/usr/bin/b");
    }

    #[test]
    fn eperm_means_running_not_stale() {
        // Daemon owned by another user (root) — exists but unsignalable.
        assert_eq!(classify_liveness(Err(Errno::EPERM)), Liveness::Running);
    }

    #[test]
    fn esrch_means_stale() {
        assert_eq!(classify_liveness(Err(Errno::ESRCH)), Liveness::Stale);
    }

    #[test]
    fn ok_means_running() {
        assert_eq!(classify_liveness(Ok(())), Liveness::Running);
    }

    #[test]
    fn other_errno_is_unknown() {
        assert_eq!(
            classify_liveness(Err(Errno::EINVAL)),
            Liveness::Unknown(Errno::EINVAL)
        );
    }

    #[test]
    fn remove_at_out_of_range_is_none() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a"));
        assert!(remove_at(&mut rs, 5).is_none());
        assert_eq!(rs.rules.len(), 1);
    }
}
