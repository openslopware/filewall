//! filewall UI helper (unprivileged, runs in the user's session).
//!
//! Connects to the daemon's socket, then for each [`PromptRequest`] pops a
//! zenity dialog and returns the user's [`Decision`]. Fails closed: any zenity
//! error, timeout, or window-close is treated as Deny.

use filewall_proto::{read_msg, write_msg, Decision, PromptRequest, PromptResponse};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/filewall/prompt.sock";

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

/// Render the prompt. Returns Deny on any failure (fail-closed).
fn ask(req: &PromptRequest) -> Decision {
    // Plain process name from the executable path for the headline.
    let proc_name = Path::new(&req.exe)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| req.exe.clone());

    // --no-markup makes all of this literal, so attacker-controlled cmdline
    // cannot inject Pango markup to spoof the dialog.
    let text = format!(
        "\u{26A0}  filewall — sensitive file access\n\n\
         Process:     {proc_name}  (PID {pid})\n\
         Executable:  {exe}\n\
         Command:     {cmd}\n\
         Working dir: {cwd}\n\
         File:        {path}\n\n\
         Allow this access?",
        pid = req.pid,
        exe = req.exe,
        cmd = if req.cmdline.is_empty() { "<unavailable>" } else { &req.cmdline },
        cwd = if req.cwd.is_empty() { "<unavailable>" } else { &req.cwd },
        path = req.path,
    );

    let output = Command::new("zenity")
        .args([
            "--question",
            "--no-markup",
            "--title=filewall security prompt",
            "--width=480",
            "--ok-label=Allow once",
            "--cancel-label=Deny once",
            "--extra-button=Always allow",
            "--extra-button=Always deny",
            // Default focus on Deny: an accidental Enter fails closed.
            "--default-cancel",
            "--text",
            &text,
        ])
        .output();

    match output {
        Ok(out) => classify(out.status.code(), &String::from_utf8_lossy(&out.stdout)),
        Err(e) => {
            eprintln!("filewall-ui: failed to run zenity: {e}");
            Decision::DenyOnce
        }
    }
}

/// Map a zenity exit code + stdout to a Decision. Fail-closed: anything that
/// isn't an explicit allow/always choice becomes DenyOnce.
fn classify(code: Option<i32>, stdout: &str) -> Decision {
    match (code, stdout.trim()) {
        (Some(0), _) => Decision::AllowOnce,
        (_, "Always allow") => Decision::AllowAlways,
        (_, "Always deny") => Decision::DenyAlways,
        _ => Decision::DenyOnce,
    }
}

#[cfg(test)]
mod tests {
    use super::classify;
    use filewall_proto::Decision;

    #[test]
    fn ok_button_is_allow_once() {
        assert_eq!(classify(Some(0), ""), Decision::AllowOnce);
    }

    #[test]
    fn extra_buttons_map_to_always() {
        assert_eq!(classify(Some(1), "Always allow\n"), Decision::AllowAlways);
        assert_eq!(classify(Some(1), "Always deny\n"), Decision::DenyAlways);
    }

    #[test]
    fn cancel_close_and_error_fail_closed() {
        assert_eq!(classify(Some(1), ""), Decision::DenyOnce); // cancel/close
        assert_eq!(classify(None, ""), Decision::DenyOnce); // killed/no code
    }
}
