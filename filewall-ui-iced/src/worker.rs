//! The socket worker: a blocking OS thread that owns the Unix-socket link to the
//! daemon, mirroring the yad helper's `connect_forever` + `serve` loop. Instead
//! of spawning a dialog it hands each [`PromptRequest`] to the iced GUI and
//! blocks for the answer.
//!
//! Fail-closed: if the GUI does not answer within the request's `ui_timeout_ms`
//! (plus a small grace), or the GUI is gone entirely, the access is denied. This
//! is a *backstop* — the GUI arms its own (shorter) timer as the primary guard.

use filewall_proto::{read_msg, write_msg, Decision, PromptRequest, PromptResponse};
use iced::futures::channel::mpsc::UnboundedSender;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::thread::sleep;
use std::time::Duration;

/// Extra time the worker waits beyond the UI deadline, so the GUI's own timer
/// fires (sending DenyOnce) *before* this backstop does. Only used if the GUI is
/// wedged or never picks up the request (e.g. no `$DISPLAY`).
const BACKSTOP_GRACE_MS: u64 = 2_000;

/// Serve prompts from the daemon socket forever: connect, serve until the link
/// drops, reconnect. `req_tx` pushes a request to the GUI; `dec_rx` receives the
/// GUI's decision. `fallback_ms` is used when a request carries `ui_timeout_ms == 0`.
pub fn run_socket(
    socket: &Path,
    req_tx: UnboundedSender<PromptRequest>,
    dec_rx: Receiver<Decision>,
    fallback_ms: u32,
) {
    loop {
        let mut stream = connect_forever(socket);
        eprintln!("filewall-ui-iced: connected to {}", socket.display());
        if serve(&mut stream, &req_tx, &dec_rx, fallback_ms).is_break() {
            // GUI channel closed: the app is shutting down, stop the worker.
            return;
        }
        eprintln!(
            "filewall-ui-iced: disconnected from {}, reconnecting...",
            socket.display()
        );
    }
}

/// `Continue` = link dropped, caller should reconnect. `Break` = GUI gone, stop.
enum Flow {
    Continue,
    Break,
}
impl Flow {
    fn is_break(&self) -> bool {
        matches!(self, Flow::Break)
    }
}

fn serve(
    stream: &mut UnixStream,
    req_tx: &UnboundedSender<PromptRequest>,
    dec_rx: &Receiver<Decision>,
    fallback_ms: u32,
) -> Flow {
    loop {
        let req: PromptRequest = match read_msg(stream) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("filewall-ui-iced: read error: {e}");
                return Flow::Continue;
            }
        };

        let decision = resolve(req, req_tx, dec_rx, fallback_ms);
        let decision = match decision {
            Some(d) => d,
            None => return Flow::Break, // GUI channel dead
        };

        if let Err(e) = write_msg(stream, &PromptResponse { decision }) {
            eprintln!("filewall-ui-iced: write error: {e}");
            return Flow::Continue;
        }
    }
}

/// Hand `req` to the GUI and block for its decision. Returns `None` only if the
/// GUI request channel is closed (app shutting down). A timeout (wedged/headless
/// GUI) yields `Some(DenyOnce)` — fail closed.
fn resolve(
    req: PromptRequest,
    req_tx: &UnboundedSender<PromptRequest>,
    dec_rx: &Receiver<Decision>,
    fallback_ms: u32,
) -> Option<Decision> {
    let effective_ms = if req.ui_timeout_ms > 0 {
        req.ui_timeout_ms
    } else {
        fallback_ms
    };

    // Defensively drain any stale decision so it can't be mis-read as the answer
    // to this request (the GUI's resolve-once guard should prevent strays, but a
    // straggler here would desync request/response — exactly what we must avoid).
    while dec_rx.try_recv().is_ok() {}

    if req_tx.unbounded_send(req).is_err() {
        return None; // GUI gone
    }

    let wait = Duration::from_millis(effective_ms as u64 + BACKSTOP_GRACE_MS);
    match dec_rx.recv_timeout(wait) {
        Ok(d) => Some(d),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!("filewall-ui-iced: GUI did not answer in time; denying");
            Some(Decision::DenyOnce)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
    }
}

/// Connect to the daemon socket, retrying once per second until it succeeds.
fn connect_forever(path: &Path) -> UnixStream {
    let mut logged = false;
    loop {
        match UnixStream::connect(path) {
            Ok(s) => return s,
            Err(e) => {
                if !logged {
                    eprintln!(
                        "filewall-ui-iced: waiting for {}: {e} (retrying every 1s)",
                        path.display()
                    );
                    logged = true;
                }
                sleep(Duration::from_secs(1));
            }
        }
    }
}

/// Demo driver (`--demo`): no socket. Sends a tree-scope then a file-scope fake
/// request, printing each decision, so the window can be inspected without a daemon.
pub fn run_demo(req_tx: UnboundedSender<PromptRequest>, dec_rx: Receiver<Decision>) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/demo".into());
    let samples = [
        PromptRequest {
            pid: 84321,
            exe: "/usr/bin/node".into(),
            cmdline: "node /home/demo/evil.js --steal --exfil".into(),
            cwd: format!("{home}/projects/foo"),
            path: format!("{home}/.ssh/id_ed25519"),
            always_object: format!("{home}/.ssh"),
            always_tree: true,
            always_cwd_pinned: false,
            ui_timeout_ms: 30_000,
        },
        PromptRequest {
            pid: 90210,
            exe: "/usr/bin/cat".into(),
            cmdline: "cat /home/demo/.config/secret.toml".into(),
            cwd: format!("{home}/work"),
            path: format!("{home}/.config/secret.toml"),
            always_object: format!("{home}/.config/secret.toml"),
            always_tree: false,
            always_cwd_pinned: true,
            ui_timeout_ms: 30_000,
        },
    ];

    for req in samples {
        if req_tx.unbounded_send(req).is_err() {
            return;
        }
        match dec_rx.recv() {
            Ok(d) => println!("filewall-ui-iced[demo]: decision = {d:?}"),
            Err(_) => return,
        }
    }
    eprintln!("filewall-ui-iced[demo]: done; close the app to exit.");
}
