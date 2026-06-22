//! filewallctl — inspect and manage filewall's learned rules.
//!
//! Subcommands:
//!   list   [rules_path]      Print learned rules.
//!   remove <id> [id...]      Remove rules by stable id, then SIGHUP the daemon.
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
    /// Stable ids actually removed (empty for non-remove acks).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    removed: Vec<u64>,
    /// Requested ids that matched no rule (empty when all matched).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    missing: Vec<u64>,
}

fn parse_pidfile(s: &str) -> Option<i32> {
    s.trim().parse::<i32>().ok()
}

/// Remove every rule whose stable id is in `ids`. Returns the removed rules (in
/// their original file order) and any requested ids that matched no rule.
fn remove_ids(rules: &mut Rules, ids: &[u64]) -> (Vec<filewall_rules::LearnedRule>, Vec<u64>) {
    let mut removed = Vec::new();
    rules.rules.retain(|r| {
        if ids.contains(&r.id) {
            removed.push(r.clone());
            false
        } else {
            true
        }
    });
    let missing: Vec<u64> = ids
        .iter()
        .copied()
        .filter(|id| !removed.iter().any(|r| r.id == *id))
        .collect();
    (removed, missing)
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

fn cmd_remove(ids: &[u64], rules_path: &Path, pidfile: &Path, format: Format) -> ExitCode {
    let mut rules = Rules::load(rules_path);
    let (removed, missing) = remove_ids(&mut rules, ids);

    // Persist and signal the daemon only if something actually changed.
    let mut pid = None;
    if !removed.is_empty() {
        if let Err(e) = rules.save_atomic(rules_path) {
            let ack = Ack {
                ok: false,
                pid: None,
                detail: format!("could not write {}: {e}", rules_path.display()),
                removed: vec![],
                missing: vec![],
            };
            match format {
                Format::Table => eprintln!("filewallctl: {}", ack.detail),
                _ => print_ack(&ack, format),
            }
            return ExitCode::FAILURE;
        }
        // Best-effort: tell the daemon to reload.
        pid = send_sighup(pidfile).ok();
    }

    let removed_ids: Vec<u64> = removed.iter().map(|r| r.id).collect();
    let ok = missing.is_empty();
    let detail = format!("removed {} rule(s), {} missing", removed.len(), missing.len());
    match format {
        Format::Table => {
            for r in &removed {
                println!("Removed [{}] {} -> {}", r.id, r.exe, r.object.display());
            }
            if !missing.is_empty() {
                let list = missing
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                eprintln!("filewallctl: no rule with id {list}");
            }
        }
        _ => print_ack(
            &Ack { ok, pid, detail, removed: removed_ids, missing: missing.clone() },
            format,
        ),
    }
    // Strict: any unmatched id is a failure, even though matched ids were removed.
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
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
            let ack = Ack {
                ok: true,
                pid: Some(pid),
                detail: "sent SIGHUP".into(),
                removed: vec![],
                missing: vec![],
            };
            match format {
                Format::Table => println!("Sent SIGHUP to filewalld (pid {pid})"),
                _ => print_ack(&ack, format),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            let ack = Ack {
                ok: false,
                pid: None,
                detail: format!("reload failed: {e}"),
                removed: vec![],
                missing: vec![],
            };
            match format {
                Format::Table => eprintln!("filewallctl: reload failed: {e}"),
                _ => print_ack(&ack, format),
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
        .map(|r| {
            vec![
                r.id.to_string(),
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
        &["ID", "ACTION", "EXE", "OBJECT", "KIND", "CWD", "CREATED"],
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
         remove <id> [id...]      Remove rules by stable id, then SIGHUP the daemon\n  \
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
            let parsed: Result<Vec<u64>, _> =
                args[1..].iter().map(|s| s.parse::<u64>()).collect();
            match parsed {
                Ok(ids) if !ids.is_empty() => cmd_remove(
                    &ids,
                    Path::new(DEFAULT_RULES),
                    Path::new(DEFAULT_PIDFILE),
                    format,
                ),
                _ => {
                    eprintln!("filewallctl: remove needs one or more numeric <id>");
                    usage()
                }
            }
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
    use super::{classify_liveness, parse_pidfile, Liveness};
    use filewall_rules::{LearnedRule, ObjectKind, RuleAction, Rules};
    use nix::errno::Errno;
    use std::path::PathBuf;

    fn rule(exe: &str) -> LearnedRule {
        LearnedRule {
            id: 0,
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
    fn remove_ids_removes_matched_reports_missing() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a")); // id 1
        rs.push(rule("/usr/bin/b")); // id 2
        rs.push(rule("/usr/bin/c")); // id 3
        let (removed, missing) = super::remove_ids(&mut rs, &[1, 3, 99]);
        let removed_exes: Vec<&str> = removed.iter().map(|r| r.exe.as_str()).collect();
        assert_eq!(removed_exes, vec!["/usr/bin/a", "/usr/bin/c"]);
        assert_eq!(missing, vec![99]);
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
        let r = super::Ack {
            ok: true,
            pid: Some(7),
            detail: "reloaded".into(),
            removed: vec![],
            missing: vec![],
        };
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
        assert!(lines[0].starts_with("ID  ACTION"));
        assert!(lines[0].contains("OBJECT"));
        // Data row: stable id 1, lowercased action/kind, the exe and object.
        assert!(lines[1].starts_with("1   allow"));
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
    fn remove_ids_all_missing_removes_nothing() {
        let mut rs = Rules::default();
        rs.push(rule("/usr/bin/a")); // id 1
        let (removed, missing) = super::remove_ids(&mut rs, &[7, 8]);
        assert!(removed.is_empty());
        assert_eq!(missing, vec![7, 8]);
        assert_eq!(rs.rules.len(), 1);
    }
}
