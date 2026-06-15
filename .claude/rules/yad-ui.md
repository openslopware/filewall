# yad (filewall-ui prompt) Rules

**The FIRST `--button` is yad's keyboard default — keep "Deny once" first**
filewall-ui renders the prompt with `yad`, mapping buttons to exit codes via
`--button=LABEL:CODE` (10=AllowOnce, 11=DenyOnce, 12=AllowAlways, 13=DenyAlways;
`classify` treats anything else as DenyOnce). Verified on yad 14.2: **Enter
activates the first `--button`**, and **Escape also returns the first button's
code (11), NOT 252**. So the dialog fails closed on keyboard dismissal ONLY
because `--button="Deny once:11"` is listed first. Reordering (e.g. an "Always
allow" first) makes Enter/Escape silently grant access — a security regression.
Keep the safe deny first; put the broad "Always allow ALL" last.

**Testing yad's button/focus behavior under Wayland**
yad is GTK3 and defaults to the Wayland backend, which xdotool can't drive. Force
X11: `GDK_BACKEND=x11 yad ... &`, then `xdotool search --sync --name "<title>"`,
`windowactivate --sync`, `key Return`, read the exit code. ALWAYS validate the rig
with a positive control (mouse-click a known button by window geometry, confirm
its code) before trusting a "fails closed" result — a dead rig yields a benign
code too.

**Markup is ON — escape every interpolated value**
The prompt uses Pango markup (bold + red whole-tree warning), so zenity's
`--no-markup` anti-spoof guarantee is gone. Every attacker-influenced field (exe,
cmdline, cwd, path, object) MUST pass through `pango_escape` (`&`→`&amp;` first,
then `<`,`>`). `build_dialog_text` is the pure, testable chokepoint.
