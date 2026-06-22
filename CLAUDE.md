# filewall

Project-local tech rules (moved here from `~/.claude/rules/` because they are
specific to this daemon's stack — libc signal handling, Unix-socket IPC,
fanotify marks/permission events, the yad and native (iced) access-prompt UIs,
and the xdg-desktop-portal color-scheme the iced UI follows):

@.claude/rules/rust-libc.md
@.claude/rules/rust-unix-socket.md
@.claude/rules/rust-fanotify.md
@.claude/rules/yad-ui.md
@.claude/rules/rust-iced.md
@.claude/rules/xdg-portal-color-scheme.md
