//! filewall UI helper (unprivileged, runs in the user's session).
//!
//! Connects to the daemon's socket, then for each [`PromptRequest`] pops a
//! yad dialog and returns the user's [`Decision`]. Fails closed: any yad
//! error, timeout, or window-close is treated as Deny.

use filewall_proto::{read_msg, write_msg, Decision, PromptRequest, PromptResponse};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/filewall/prompt.sock";

/// Escape Pango markup metacharacters so attacker-controlled strings (cmdline,
/// paths) cannot inject tags to spoof the dialog. `&` first to avoid double-
/// escaping the entities we introduce.
fn pango_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn main() {
    let socket = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    // Stay alive across daemon restarts: wait for the socket, serve until the
    // connection drops, then reconnect — forever.
    loop {
        let mut stream = connect_forever(Path::new(&socket));
        eprintln!("filewall-ui: connected to {socket}");
        serve(&mut stream);
        eprintln!("filewall-ui: disconnected from {socket}, reconnecting...");
    }
}

/// Serve prompt requests on `stream` until the connection drops. Returns (rather
/// than exits) on EOF or any read/write error so the caller can reconnect.
fn serve(stream: &mut UnixStream) {
    loop {
        let req: PromptRequest = match read_msg(stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                eprintln!("filewall-ui: daemon closed connection");
                return;
            }
            Err(e) => {
                eprintln!("filewall-ui: read error: {e}");
                return;
            }
        };

        let decision = ask(&req);
        if let Err(e) = write_msg(stream, &PromptResponse { decision }) {
            eprintln!("filewall-ui: write error: {e}");
            return;
        }
    }
}

/// Connect to the daemon socket, retrying once per second until it succeeds.
/// Logs once per disconnected spell to avoid spamming on every retry.
fn connect_forever(path: &Path) -> UnixStream {
    let mut logged = false;
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return s,
            Err(e) => {
                if !logged {
                    eprintln!(
                        "filewall-ui: waiting for {}: {e} (retrying every 1s)",
                        path.display()
                    );
                    logged = true;
                }
                sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Abbreviate a leading `$HOME` to `~` for readability. Only matches whole path
/// components (so `/home/alice` does not shorten `/home/alice2/...`). An empty
/// `home` disables abbreviation.
fn abbrev(path: &str, home: &str) -> String {
    if home.is_empty() {
        return path.to_string();
    }
    if path == home {
        return "~".to_string();
    }
    if let Some(rest) = path.strip_prefix(home) {
        if rest.starts_with('/') {
            return format!("~{rest}");
        }
    }
    path.to_string()
}

/// Build the Pango-markup dialog text for a prompt. Pure given `home`, so the
/// rendering — especially the tree-scope warning and the cwd-pin line — is
/// unit-testable without spawning yad. Every attacker-influenced field is
/// escaped here.
fn build_dialog_text(req: &PromptRequest, home: &str) -> String {
    // Abbreviate $HOME -> ~ then escape markup metachars, in one place.
    let esc = |s: &str| pango_escape(&abbrev(s, home));

    // Process base-name for the headline; fall back to full exe if no filename.
    let proc_name = pango_escape(
        &Path::new(&req.exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| req.exe.clone()),
    );
    let exe = esc(&req.exe);
    let path = esc(&req.path);
    let object = esc(&req.always_object);
    let cwd = esc(&req.cwd);
    // "<unavailable>" is a program-controlled literal (pango_escape leaves it
    // markup-safe); req.cmdline is attacker-controlled and must be escaped.
    let cmdline = pango_escape(if req.cmdline.is_empty() {
        "<unavailable>"
    } else {
        &req.cmdline
    });

    // Scope block: loud red warning for a tree grant, neutral line for a file.
    let scope = if req.always_tree {
        format!(
            "<span foreground=\"#cc0000\"><b>\u{300C}Always allow\u{300D} GRANTS ACCESS TO ALL FILES</b></span>\n\
             <span foreground=\"#cc0000\">    under {object} \u{2014} every subfolder, not just the file above.</span>"
        )
    } else {
        format!("\u{300C}Always allow\u{300D} remembers only this one file:\n    {object}")
    };
    let cwd_line = if req.always_cwd_pinned {
        format!("\n\u{2026}and only while it runs from {cwd}")
    } else {
        String::new()
    };

    format!(
        "<b>\u{26A0}  filewall \u{2014} sensitive file access</b>\n\n\
         <b>{proc_name}</b> wants to open:\n    {path}\n\n\
         {scope}\n\n\
         Rule is tied to this program:\n    {exe}{cwd_line}\n\n\
         <small>PID {pid} \u{00B7} cmd: {cmdline}</small>",
        pid = req.pid,
    )
}

/// Render the prompt with yad. Returns Deny on any failure (fail-closed).
fn ask(req: &PromptRequest) -> Decision {
    let home = std::env::var("HOME").unwrap_or_default();
    let text = build_dialog_text(req, &home);

    // Scope-aware "Always" labels: ALL (tree) vs file. button=LABEL:CODE.
    let (allow_always, deny_always) = if req.always_tree {
        ("Always allow ALL:12", "Always deny ALL:13")
    } else {
        ("Always allow file:12", "Always deny file:13")
    };

    let output = Command::new("yad")
        .args([
            "--title=filewall security prompt",
            "--width=520",
            "--image=dialog-warning",
            "--text",
            &text,
            // Order: safe Deny once first (default focus); broad Allow-ALL last.
            "--button=Deny once:11",
            "--button=Allow once:10",
            &format!("--button={deny_always}"),
            &format!("--button={allow_always}"),
        ])
        .output();

    match output {
        Ok(out) => classify(out.status.code()),
        Err(e) => {
            eprintln!("filewall-ui: failed to run yad: {e}");
            Decision::DenyOnce
        }
    }
}

/// Map a yad exit code to a Decision. Fail-closed: only the three explicit
/// allow/always codes pass; everything else (deny-once button, ESC=252, error,
/// unknown) becomes DenyOnce.
fn classify(code: Option<i32>) -> Decision {
    match code {
        Some(10) => Decision::AllowOnce,
        Some(12) => Decision::AllowAlways,
        Some(13) => Decision::DenyAlways,
        _ => Decision::DenyOnce,
    }
}

#[cfg(test)]
mod tests {
    use super::classify;
    use filewall_proto::{Decision, PromptRequest};

    #[test]
    fn pango_escape_handles_markup_metachars() {
        use super::pango_escape;
        // Ampersand must be escaped first to avoid double-escaping.
        assert_eq!(pango_escape("a & b"), "a &amp; b");
        assert_eq!(pango_escape("<b>x</b>"), "&lt;b&gt;x&lt;/b&gt;");
        assert_eq!(
            pango_escape("evil & <span foreground=\"red\">"),
            "evil &amp; &lt;span foreground=\"red\"&gt;"
        );
        assert_eq!(pango_escape("plain text"), "plain text");
    }

    #[test]
    fn classify_maps_button_codes() {
        assert_eq!(classify(Some(10)), Decision::AllowOnce);
        assert_eq!(classify(Some(12)), Decision::AllowAlways);
        assert_eq!(classify(Some(13)), Decision::DenyAlways);
    }

    #[test]
    fn classify_fails_closed_on_everything_else() {
        assert_eq!(classify(Some(11)), Decision::DenyOnce); // explicit deny-once
        assert_eq!(classify(Some(252)), Decision::DenyOnce); // yad ESC/close
        assert_eq!(classify(None), Decision::DenyOnce); // killed / no code
        assert_eq!(classify(Some(1)), Decision::DenyOnce); // unknown
    }

    #[test]
    fn abbrev_replaces_home_prefix_only() {
        use super::abbrev;
        assert_eq!(abbrev("/home/alice/.ssh/id", "/home/alice"), "~/.ssh/id");
        // Exact home dir.
        assert_eq!(abbrev("/home/alice", "/home/alice"), "~");
        // Not under home: unchanged.
        assert_eq!(abbrev("/etc/hosts", "/home/alice"), "/etc/hosts");
        // A path that merely starts with the same characters but is a different
        // dir must NOT be abbreviated.
        assert_eq!(abbrev("/home/alice2/x", "/home/alice"), "/home/alice2/x");
        // Empty home (HOME unset) disables abbreviation.
        assert_eq!(abbrev("/home/alice/.ssh", ""), "/home/alice/.ssh");
    }

    fn req_fixture() -> PromptRequest {
        PromptRequest {
            pid: 7,
            exe: "/usr/bin/node".into(),
            cmdline: "node app.js".into(),
            cwd: "/home/u/work".into(),
            path: "/home/u/.ssh/id_ed25519".into(),
            always_object: "/home/u/.ssh".into(),
            always_tree: true,
            always_cwd_pinned: false,
        }
    }

    #[test]
    fn dialog_text_tree_grant_shows_red_all_files_warning() {
        use super::build_dialog_text;
        let t = build_dialog_text(&req_fixture(), "/home/u");
        assert!(t.contains("GRANTS ACCESS TO ALL FILES"));
        assert!(t.contains("#cc0000"));
        assert!(t.contains("~/.ssh")); // object abbreviated
        assert!(!t.contains("remembers only this one file"));
    }

    #[test]
    fn dialog_text_file_grant_is_neutral_no_warning() {
        use super::build_dialog_text;
        let mut req = req_fixture();
        req.always_tree = false;
        req.always_object = "/home/u/.ssh/id_ed25519".into();
        let t = build_dialog_text(&req, "/home/u");
        assert!(t.contains("remembers only this one file"));
        assert!(!t.contains("ALL FILES"));
        assert!(!t.contains("#cc0000"));
    }

    #[test]
    fn dialog_text_cwd_pin_line_present_only_when_pinned() {
        use super::build_dialog_text;
        let mut req = req_fixture();
        req.always_cwd_pinned = true;
        let t = build_dialog_text(&req, "/home/u");
        assert!(t.contains("and only while it runs from"));
        assert!(t.contains("~/work")); // cwd abbreviated
        req.always_cwd_pinned = false;
        let t2 = build_dialog_text(&req, "/home/u");
        assert!(!t2.contains("and only while it runs from"));
    }

    #[test]
    fn dialog_text_escapes_malicious_cmdline() {
        use super::build_dialog_text;
        let mut req = req_fixture();
        req.cmdline = "node </span><b>SPOOF".into();
        let t = build_dialog_text(&req, "/home/u");
        // The raw injection must NOT survive; the escaped form must be present.
        assert!(!t.contains("</span><b>SPOOF"));
        assert!(t.contains("&lt;/span&gt;&lt;b&gt;SPOOF"));
    }
}
