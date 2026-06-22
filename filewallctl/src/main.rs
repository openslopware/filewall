//! filewallctl — inspect and manage filewall's learned rules.
//!
//! Subcommands:
//!   list   [rules_path]      Print learned rules.
//!   remove <index> [path]    Remove a rule by index, then SIGHUP the daemon.
//!   reload [pidfile]         Send SIGHUP to the running daemon.
//!   status [pidfile]         Report whether the daemon is running.

mod format;
mod render;

use filewall_proto::{
    read_msg_capped, write_msg_capped, ControlRequest, DumpResponse, MAX_CONTROL_MSG_LEN,
};
use filewall_rules::Rules;
use format::Format;
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_RULES: &str = "/var/lib/filewall/rules.toml";
const DEFAULT_PIDFILE: &str = "/run/filewall/filewalld.pid";
const DEFAULT_CONTROL_SOCKET: &str = "/run/filewall/control.sock";

#[derive(serde::Serialize)]
struct StatusReport {
    running: bool,
    pid: Option<i32>,
    state: &'static str,
}

#[derive(serde::Serialize)]
struct Ack {
    ok: bool,
    pid: Option<i32>,
    detail: String,
}

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

fn cmd_list(path: &Path, format: Format) -> ExitCode {
    let rules = Rules::load(path);
    match format {
        Format::Table => {
            if rules.rules.is_empty() {
                println!("No learned rules ({})", path.display());
                return ExitCode::SUCCESS;
            }
            print!("{}", list_table(&rules.rules, path));
            ExitCode::SUCCESS
        }
        _ => match render::emit(&rules.rules, format) {
            Ok(s) => {
                println!("{s}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("filewallctl: render failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn cmd_remove(index: usize, rules_path: &Path, pidfile: &Path, format: Format) -> ExitCode {
    let mut rules = Rules::load(rules_path);
    match remove_at(&mut rules, index) {
        Some(removed) => {
            if let Err(e) = rules.save_atomic(rules_path) {
                let ack = Ack {
                    ok: false,
                    pid: None,
                    detail: format!("could not write {}: {e}", rules_path.display()),
                };
                match format {
                    Format::Table => eprintln!("filewallctl: {}", ack.detail),
                    _ => print_ack(&ack, format),
                }
                return ExitCode::FAILURE;
            }
            // Best-effort: tell the daemon to reload.
            let pid = send_sighup(pidfile).ok();
            let detail = format!("removed [{index}] {} -> {}", removed.exe, removed.object.display());
            match format {
                Format::Table => println!("Removed [{index}] {} -> {}", removed.exe, removed.object.display()),
                _ => print_ack(&Ack { ok: true, pid, detail }, format),
            }
            ExitCode::SUCCESS
        }
        None => {
            let ack = Ack { ok: false, pid: None, detail: format!("no rule at index {index}") };
            match format {
                Format::Table => eprintln!("filewallctl: {}", ack.detail),
                _ => print_ack(&ack, format),
            }
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

fn cmd_reload(pidfile: &Path, format: Format) -> ExitCode {
    match send_sighup(pidfile) {
        Ok(pid) => {
            let ack = Ack { ok: true, pid: Some(pid), detail: "sent SIGHUP".into() };
            match format {
                Format::Table => println!("Sent SIGHUP to filewalld (pid {pid})"),
                _ => print_ack(&ack, format),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            match format {
                Format::Table => eprintln!("filewallctl: reload failed: {e}"),
                _ => print_ack(&Ack { ok: false, pid: None, detail: format!("reload failed: {e}") }, format),
            }
            ExitCode::FAILURE
        }
    }
}

/// Render an Ack to stdout in json/yaml (table callers print their own line).
fn print_ack(ack: &Ack, format: Format) {
    match render::emit(ack, format) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("filewallctl: render failed: {e}"),
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

fn cmd_status(pidfile: &Path, format: Format) -> ExitCode {
    let report = status_report(pidfile);
    let code = if report.running { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    match format {
        Format::Table => {
            match report.state {
                "running" => println!("filewalld: running (pid {})", report.pid.unwrap_or(0)),
                "stale" => println!("filewalld: not running (stale pid {})", report.pid.unwrap_or(0)),
                "no-pidfile" => println!("filewalld: not running (no pidfile)"),
                "bad-pidfile" => println!("filewalld: unknown (bad pidfile)"),
                other => println!("filewalld: {other} (pid {})", report.pid.unwrap_or(0)),
            }
            code
        }
        _ => match render::emit(&report, format) {
            Ok(s) => {
                println!("{s}");
                code
            }
            Err(e) => {
                eprintln!("filewallctl: render failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Classify the daemon's status from its pidfile into a serializable report.
fn status_report(pidfile: &Path) -> StatusReport {
    let text = match std::fs::read_to_string(pidfile) {
        Ok(t) => t,
        Err(_) => return StatusReport { running: false, pid: None, state: "no-pidfile" },
    };
    let pid = match parse_pidfile(&text) {
        Some(p) => p,
        None => return StatusReport { running: false, pid: None, state: "bad-pidfile" },
    };
    // Signal 0 probes liveness without delivering a signal.
    match classify_liveness(kill(Pid::from_raw(pid), None)) {
        Liveness::Running => StatusReport { running: true, pid: Some(pid), state: "running" },
        Liveness::Stale => StatusReport { running: false, pid: Some(pid), state: "stale" },
        Liveness::Unknown(_) => StatusReport { running: false, pid: Some(pid), state: "unknown" },
    }
}

/// Render a dump as an aligned table. `live` column: "yes"/"no" for dirs,
/// "-" for files (not applicable). `fanotify` column flags coverage gaps.
fn dump_table(resp: &DumpResponse) -> String {
    let rows: Vec<Vec<String>> = resp
        .objects
        .iter()
        .map(|o| {
            let kind = match o.kind {
                filewall_proto::ObjKind::File => "file",
                filewall_proto::ObjKind::Dir => "dir",
            };
            let live = match o.live_marked {
                Some(true) => "yes",
                Some(false) => "no",
                None => "-",
            };
            vec![
                o.path.clone(),
                kind.to_string(),
                if o.recursive { "yes" } else { "no" }.to_string(),
                if o.fanotify { "yes" } else { "no" }.to_string(),
                live.to_string(),
                o.watch.clone(),
            ]
        })
        .collect();
    let mut out = render::render_table(
        &["PATH", "KIND", "RECURSIVE", "FANOTIFY", "LIVE", "WATCH"],
        &rows,
    );
    out.push_str(&format!("\n{} object(s) (pid {})\n", resp.objects.len(), resp.pid));
    out
}

/// Render learned rules as an aligned table, mirroring `dump_table`'s layout.
fn list_table(rules: &[filewall_rules::LearnedRule], path: &Path) -> String {
    let rows: Vec<Vec<String>> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            vec![
                i.to_string(),
                format!("{:?}", r.action).to_lowercase(),
                r.exe.clone(),
                r.object.display().to_string(),
                format!("{:?}", r.object_kind).to_lowercase(),
                r.cwd.as_deref().unwrap_or("-").to_string(),
                r.created_unix.to_string(),
            ]
        })
        .collect();
    let mut out = render::render_table(
        &["IDX", "ACTION", "EXE", "OBJECT", "KIND", "CWD", "CREATED"],
        &rows,
    );
    out.push_str(&format!("\n{} rule(s) ({})\n", rules.len(), path.display()));
    out
}

/// Connect to the control socket, request a dump, and return the response.
fn fetch_dump(socket: &Path) -> io::Result<DumpResponse> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_msg_capped(&mut stream, &ControlRequest::Dump, MAX_CONTROL_MSG_LEN)?;
    read_msg_capped(&mut stream, MAX_CONTROL_MSG_LEN)
}

fn cmd_dump(socket: &Path, format: Format) -> ExitCode {
    match fetch_dump(socket) {
        Ok(resp) => match format {
            Format::Table => {
                print!("{}", dump_table(&resp));
                ExitCode::SUCCESS
            }
            _ => match render::emit(&resp, format) {
                Ok(s) => {
                    println!("{s}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("filewallctl: render failed: {e}");
                    ExitCode::FAILURE
                }
            },
        },
        Err(e) => {
            emit_error(
                format,
                &format!(
                    "could not query daemon on {} ({e}); is filewalld running?",
                    socket.display()
                ),
            );
            ExitCode::FAILURE
        }
    }
}

/// Print an error in the chosen format: a plain stderr line for tables, a
/// `{ "error": ... }` object for json/yaml (so automation can detect failure).
fn emit_error(format: Format, msg: &str) {
    match format {
        Format::Table => eprintln!("filewallctl: {msg}"),
        _ => {
            #[derive(serde::Serialize)]
            struct ErrorReport<'a> {
                error: &'a str,
            }
            match render::emit(&ErrorReport { error: msg }, format) {
                Ok(s) => eprintln!("{s}"),
                Err(_) => eprintln!("filewallctl: {msg}"),
            }
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  \
         filewallctl [--json|--yaml|--table] <command>\n\n\
         commands:\n  \
         list   [rules_path]      Print learned rules\n  \
         dump   [control_socket]  Print objects the daemon is protecting\n  \
         remove <index> [path]    Remove a rule by index, then SIGHUP the daemon\n  \
         reload [pidfile]         Send SIGHUP to the running daemon\n  \
         status [pidfile]         Report whether the daemon is running"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let (format, args) = format::parse_format(&raw);
    match args.first().map(String::as_str) {
        Some("dump") => {
            let socket = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));
            cmd_dump(&socket, format)
        }
        Some("list") => {
            let path = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES));
            cmd_list(&path, format)
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
            cmd_remove(index, &rules_path, Path::new(DEFAULT_PIDFILE), format)
        }
        Some("reload") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_reload(&pidfile, format)
        }
        Some("status") => {
            let pidfile = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PIDFILE));
            cmd_status(&pidfile, format)
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
    fn status_report_serializes() {
        let r = super::StatusReport { running: true, pid: Some(42), state: "running" };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"pid\":42"));
        assert!(json.contains("\"state\":\"running\""));
    }

    #[test]
    fn ack_report_serializes() {
        let r = super::Ack { ok: true, pid: Some(7), detail: "reloaded".into() };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"detail\":\"reloaded\""));
    }

    #[test]
    fn list_table_renders_aligned_columns() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/ssh"));
        let out = super::list_table(&rs.rules, std::path::Path::new("/var/lib/filewall/rules.toml"));
        let lines: Vec<&str> = out.lines().collect();
        // Header row with the expected columns.
        assert!(lines[0].starts_with("IDX  ACTION"));
        assert!(lines[0].contains("OBJECT"));
        // Data row: index 0, lowercased action/kind, the exe and object.
        assert!(lines[1].starts_with("0    allow"));
        assert!(lines[1].contains("/usr/bin/ssh"));
        assert!(lines[1].contains("/home/u/.ssh"));
        assert!(lines[1].contains("tree"));
        // Trailing summary line.
        assert!(out.contains("1 rule(s) (/var/lib/filewall/rules.toml)"));
    }

    #[test]
    fn dump_table_renders_objects_with_health() {
        use filewall_proto::{DumpResponse, ObjKind, WatchedObject};
        let resp = DumpResponse {
            pid: 7,
            generated_unix: 0,
            objects: vec![
                WatchedObject {
                    path: "/home/u/.ssh".into(),
                    kind: ObjKind::Dir,
                    recursive: true,
                    watch: "/home/u/.ssh".into(),
                    fanotify: true,
                    live_marked: Some(true),
                },
                WatchedObject {
                    path: "/home/u/.vault-token".into(),
                    kind: ObjKind::File,
                    recursive: false,
                    watch: "/home/u/.vault-token".into(),
                    fanotify: true,
                    live_marked: None,
                },
            ],
        };
        let out = super::dump_table(&resp);
        assert!(out.contains("PATH"));
        assert!(out.contains("/home/u/.ssh"));
        assert!(out.contains("dir"));
        // File live_marked None renders as "-", healthy dir as "yes".
        assert!(out.contains("yes"));
        assert!(out.contains('-'));
    }

    #[test]
    fn remove_at_out_of_range_is_none() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a"));
        assert!(remove_at(&mut rs, 5).is_none());
        assert_eq!(rs.rules.len(), 1);
    }
}
