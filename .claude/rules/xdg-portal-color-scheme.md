# xdg-desktop-portal color-scheme Rules

**Light mode is usually reported as `0`, not `2`**
`org.freedesktop.portal.Settings` → `org.freedesktop.appearance` / `color-scheme`
is a uint32: 0 = no preference, 1 = prefer dark, 2 = prefer light. GNOME-style
portals only ever emit `0` (light/default) and `1` (dark) — never `2`. So treat
it as "`1` → dark, everything else → light"; never gate light on `2` or it
silently never fires.

**`Read` double-wraps the variant; prefer `ReadOne`**
`Settings.ReadOne(ss) → v` returns a single variant (`v u 1`). Older
`Settings.Read(ss) → v` double-wraps (`v v u 1`). Call `ReadOne` first, fall back
to `Read`, peel nested variants to the `u32`. Probe with:
`busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Settings ReadOne ss org.freedesktop.appearance color-scheme`
