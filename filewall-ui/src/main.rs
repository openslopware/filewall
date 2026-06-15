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

/// Render the prompt with yad. Returns Deny on any failure (fail-closed).
fn ask(req: &PromptRequest) -> Decision {
    let home = std::env::var("HOME").unwrap_or_default();

    // Escape every attacker-influenced value; abbreviate paths for readability.
    let proc_name = pango_escape(
        &Path::new(&req.exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| req.exe.clone()),
    );
    let exe = pango_escape(&req.exe);
    let path = pango_escape(&abbrev(&req.path, &home));
    let object = pango_escape(&abbrev(&req.always_object, &home));
    let cwd = pango_escape(&abbrev(&req.cwd, &home));
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

    let text = format!(
        "<b>\u{26A0}  filewall \u{2014} sensitive file access</b>\n\n\
         <b>{proc_name}</b> wants to open:\n    {path}\n\n\
         {scope}\n\n\
         Rule is tied to this program:\n    {exe}{cwd_line}\n\n\
         <small>PID {pid} \u{00B7} cmd: {cmdline}</small>",
        pid = req.pid,
    );

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
    use filewall_proto::Decision;

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
}
