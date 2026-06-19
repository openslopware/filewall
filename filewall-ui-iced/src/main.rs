//! filewall UI helper, native (iced) variant. Experimental alternative to the
//! yad-based `filewall-ui`. A background worker thread owns the daemon socket;
//! iced runs in **daemon mode** (no window until a prompt arrives) on the main
//! thread. They talk over channels: requests in, one decision out.
//!
//! Fail-closed by construction: Escape, Enter, the window close button, and the
//! self-timeout all resolve to `DenyOnce`; if iced cannot initialize (no
//! display) the process exits and the daemon — seeing the dropped link — denies.

mod model;
mod theme;
mod worker;

use filewall_proto::{Decision, PromptRequest};
use iced::futures::{SinkExt, Stream, StreamExt};
use iced::widget::{button, column, container, row, text, Space};
use iced::{
    event, keyboard, stream, time, window, Color, Element, Font, Length, Subscription, Task,
};
use model::{PromptView, Scope};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const DEFAULT_SOCKET: &str = "/run/filewall/prompt.sock";
/// Used when a request carries `ui_timeout_ms == 0` (e.g. an older daemon).
const DEFAULT_FALLBACK_MS: u32 = 90_000;

/// Worker configuration, set once in `main` before iced runs so the worker
/// subscription builder can be a plain `fn` (stable subscription identity).
struct WorkerConfig {
    socket: PathBuf,
    fallback_ms: u32,
    demo: bool,
}
static CONFIG: OnceLock<WorkerConfig> = OnceLock::new();

fn main() -> iced::Result {
    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut demo = false;
    let mut fallback_ms = DEFAULT_FALLBACK_MS;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--demo" => demo = true,
            "--fallback-timeout" => {
                if let Some(v) = args.next().and_then(|s| s.parse::<u32>().ok()) {
                    fallback_ms = v.saturating_mul(1000);
                }
            }
            other if !other.starts_with('-') => socket = PathBuf::from(other),
            other => eprintln!("filewall-ui-iced: ignoring unknown arg {other}"),
        }
    }

    CONFIG
        .set(WorkerConfig {
            socket,
            fallback_ms,
            demo,
        })
        .ok()
        .expect("CONFIG set once");

    iced::daemon(App::title, App::update, App::view)
        .subscription(App::subscription)
        .theme(App::theme)
        .run_with(App::new)
}

/// One in-flight prompt and its deadline.
struct Pending {
    view: PromptView,
    deadline: Instant,
    remaining_s: u64,
}

struct App {
    decision_tx: Option<Sender<Decision>>,
    pending: Option<Pending>,
    window: Option<window::Id>,
    /// Current light/dark theme, derived from the desktop's color-scheme.
    theme: iced::Theme,
    /// Reused session-bus connection for re-reading the color-scheme per prompt.
    portal: Option<zbus::blocking::Connection>,
}

#[derive(Debug, Clone)]
enum Message {
    /// Worker handed us the channel to send decisions back on.
    WorkerReady(Sender<Decision>),
    /// A new access prompt to display.
    Prompt(PromptRequest),
    /// The prompt window finished opening.
    WindowOpened(window::Id),
    /// A button was clicked.
    Decide(Decision),
    /// Escape / Enter / window close → fail closed.
    Deny,
    /// Countdown tick.
    Tick,
}

fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_default()
}

fn window_settings() -> window::Settings {
    window::Settings {
        size: iced::Size::new(580.0, 400.0),
        position: window::Position::Centered,
        resizable: false,
        level: window::Level::AlwaysOnTop,
        // We intercept the close button ourselves to fail closed; don't let the
        // window vanish without sending a decision.
        exit_on_close_request: false,
        ..Default::default()
    }
}

impl App {
    fn new() -> (Self, Task<Message>) {
        // Detect the desktop's light/dark preference once up front; re-checked on
        // each prompt so a mid-session theme switch is picked up.
        let portal = theme::connect();
        let theme = portal
            .as_ref()
            .and_then(theme::detect)
            .unwrap_or(theme::FALLBACK);
        let app = App {
            decision_tx: None,
            pending: None,
            window: None,
            theme,
            portal,
        };
        (app, Task::none())
    }

    fn title(&self, _id: window::Id) -> String {
        "filewall security prompt".to_string()
    }

    fn theme(&self, _id: window::Id) -> iced::Theme {
        self.theme.clone()
    }

    /// Send a single decision back to the worker and close the window. Guarded so
    /// it fires at most **once** per prompt: a second event (e.g. a click then a
    /// close) is ignored, so we never write a stray decision that the worker
    /// would mis-read as the answer to the next request.
    fn resolve(&mut self, decision: Decision) -> Task<Message> {
        if self.pending.take().is_none() {
            return Task::none();
        }
        if let Some(tx) = &self.decision_tx {
            let _ = tx.send(decision);
        }
        match self.window.take() {
            Some(id) => window::close(id),
            None => Task::none(),
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::WorkerReady(tx) => {
                self.decision_tx = Some(tx);
                Task::none()
            }
            Message::Prompt(req) => {
                // Defensive: if somehow a prompt is already showing, deny it first.
                let _ = self.resolve(Decision::DenyOnce);

                // Follow the desktop's current light/dark preference for this prompt.
                if let Some(t) = self.portal.as_ref().and_then(theme::detect) {
                    self.theme = t;
                }

                let effective_ms = if req.ui_timeout_ms > 0 {
                    req.ui_timeout_ms
                } else {
                    CONFIG
                        .get()
                        .map(|c| c.fallback_ms)
                        .unwrap_or(DEFAULT_FALLBACK_MS)
                };
                let deadline = Instant::now() + Duration::from_millis(effective_ms as u64);
                self.pending = Some(Pending {
                    view: PromptView::build(&req, &home_dir()),
                    deadline,
                    remaining_s: (effective_ms as u64).div_ceil(1000),
                });

                let (id, open) = window::open(window_settings());
                self.window = Some(id);
                open.map(Message::WindowOpened)
            }
            Message::WindowOpened(_id) => Task::none(),
            Message::Decide(d) => self.resolve(d),
            Message::Deny => self.resolve(Decision::DenyOnce),
            Message::Tick => {
                let expired = match &mut self.pending {
                    Some(p) => {
                        let now = Instant::now();
                        if now >= p.deadline {
                            true
                        } else {
                            p.remaining_s = p.deadline.saturating_duration_since(now).as_secs() + 1;
                            false
                        }
                    }
                    None => false,
                };
                if expired {
                    self.resolve(Decision::DenyOnce)
                } else {
                    Task::none()
                }
            }
        }
    }

    fn view(&self, _id: window::Id) -> Element<'_, Message> {
        let Some(p) = &self.pending else {
            return text("").into();
        };
        let v = &p.view;
        let bold = Font {
            weight: iced::font::Weight::Bold,
            ..Font::DEFAULT
        };
        let danger = Color::from_rgb(0.90, 0.50, 0.50);
        let muted = Color::from_rgb(0.45, 0.45, 0.45);

        // Portable glyphs only: the bundled Fira Sans lacks ⚠/「」, which would
        // render as tofu boxes on a security prompt. Emphasis comes from bold +
        // size + the red scope warning, not exotic symbols.
        let header = text("filewall \u{2014} sensitive file access")
            .font(bold)
            .size(18)
            .color(danger);

        let wants = column![
            text(format!("{} wants to open:", v.proc_name)).font(bold),
            text(v.path.clone()).size(15),
        ]
        .spacing(2);

        // Scope block: loud red warning for a tree grant, neutral line for a file.
        let scope: Element<Message> = match v.scope {
            Scope::Tree => column![
                text("\"Always allow\" GRANTS ACCESS TO ALL FILES")
                    .font(bold)
                    .color(danger),
                text(format!(
                    "    under {} \u{2014} every subfolder, not just the file above.",
                    v.object
                ))
                .color(danger),
            ]
            .spacing(2)
            .into(),
            Scope::File => column![
                text("\"Always allow\" remembers only this one file:"),
                text(format!("    {}", v.object)),
            ]
            .spacing(2)
            .into(),
        };

        let mut tied = column![
            text("Rule is tied to this program:"),
            text(format!("    {}", v.exe)),
        ]
        .spacing(2);
        if v.cwd_pinned {
            tied = tied
                .push(text(format!("\u{2026}and only while it runs from {}", v.cwd)).color(muted));
        }

        let meta = text(format!("PID {} \u{00B7} cmd: {}", v.pid, v.cmdline))
            .size(12)
            .color(muted);

        let countdown = text(format!("auto-deny in {}s", p.remaining_s))
            .size(12)
            .color(muted);

        // Button order mirrors the yad rule: safe "Deny once" first; the broad
        // "Always allow ALL" last (hardest to hit by accident). Enter/Escape also
        // map to Deny (handled in the events subscription).
        let buttons = row![
            button(text("Deny once"))
                .on_press(Message::Deny)
                .style(button::primary),
            button(text("Allow once"))
                .on_press(Message::Decide(Decision::AllowOnce))
                .style(button::secondary),
            Space::with_width(Length::Fill),
            button(text(v.deny_always_label()))
                .on_press(Message::Decide(Decision::DenyAlways))
                .style(button::secondary),
            button(text(v.allow_always_label()))
                .on_press(Message::Decide(Decision::AllowAlways))
                .style(button::danger),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);

        let content = column![
            header,
            wants,
            scope,
            tied,
            meta,
            Space::with_height(4),
            countdown,
            buttons,
        ]
        .spacing(14)
        .padding(20);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        let mut subs = vec![
            Subscription::run(worker_stream),
            event::listen_with(|ev, _status, _id| match ev {
                event::Event::Window(window::Event::CloseRequested) => Some(Message::Deny),
                event::Event::Keyboard(keyboard::Event::KeyPressed {
                    key:
                        keyboard::Key::Named(keyboard::key::Named::Escape | keyboard::key::Named::Enter),
                    ..
                }) => Some(Message::Deny),
                _ => None,
            }),
        ];
        if self.pending.is_some() {
            subs.push(time::every(Duration::from_millis(250)).map(|_| Message::Tick));
        }
        Subscription::batch(subs)
    }
}

/// The worker subscription: spawns the socket (or demo) thread once and forwards
/// each [`PromptRequest`] into the app as a [`Message::Prompt`]. A plain `fn` so
/// the subscription has a stable identity across updates.
fn worker_stream() -> impl Stream<Item = Message> {
    stream::channel(16, |mut output| async move {
        let cfg = CONFIG.get().expect("CONFIG set before run");

        // GUI -> worker decisions (sync mpsc); worker -> GUI requests (async mpsc).
        let (dec_tx, dec_rx): (Sender<Decision>, Receiver<Decision>) = std::sync::mpsc::channel();
        let (req_tx, mut req_rx) = iced::futures::channel::mpsc::unbounded::<PromptRequest>();

        let demo = cfg.demo;
        std::thread::Builder::new()
            .name("filewall-ui-socket".into())
            .spawn(move || {
                if demo {
                    worker::run_demo(req_tx, dec_rx);
                } else {
                    worker::run_socket(&cfg.socket, req_tx, dec_rx, cfg.fallback_ms);
                }
            })
            .expect("spawn worker thread");

        // Hand the decision sender to the app, then pump requests through.
        if output.send(Message::WorkerReady(dec_tx)).await.is_err() {
            return;
        }
        while let Some(req) = req_rx.next().await {
            if output.send(Message::Prompt(req)).await.is_err() {
                break;
            }
        }
    })
}
