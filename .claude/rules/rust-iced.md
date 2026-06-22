# Rust + iced (0.13) Rules — filewall-ui-iced

**`time::every` / timers need an async-executor feature**
`iced = { default-features = false, features = ["tiny-skia"] }` has no executor,
so `iced::time::every` won't resolve. Add `"smol"` (light) or `"tokio"`.

**The palette has NO `warning` colour**
`iced::theme::Palette` exposes only `background, text, primary, success, danger`
(extended adds `secondary`). No warning/yellow role — use `danger` for caution,
or you're back to a custom colour. Built-in Catppuccin themes exist:
`Theme::CatppuccinMocha` / `CatppuccinLatte` (+ Frappe/Macchiato). Read a colour
via `theme.extended_palette().danger.base.color`.

**Daemon mode + blocking socket worker: bridge with `stream::channel`**
Use `iced::daemon` (no window until `window::open`) for an on-demand helper. Run
blocking I/O on a `std::thread`; expose it as `Subscription::run(builder_fn)`
where `builder_fn` is a **plain `fn`** (capturing closures give an unstable
subscription identity). Inside, `iced::stream::channel(.., |out| async {..})`
forwards the worker's channel into `out`; send GUI→worker replies over a
`std::sync::mpsc` whose `Sender` is handed to the app in the first message.

**Fail-closed window handling**
`window::Settings { exit_on_close_request: false, .. }` so the X button doesn't
silently destroy the window — intercept `window::Event::CloseRequested`. A fresh
`Level::AlwaysOnTop` window grabs focus, so a stray Enter (e.g. the keypress that
launched the binary) lands on it; Enter→deny is intended, not a bug.
