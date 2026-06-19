//! Pick the prompt window's light/dark theme from the user's desktop preference.
//!
//! xdg-desktop-portal exposes `org.freedesktop.portal.Settings`; the relevant
//! setting is `org.freedesktop.appearance` / `color-scheme`, a `uint32`:
//!   0 — no preference / default
//!   1 — prefer dark
//!   2 — prefer light
//!
//! We read it synchronously over the session bus. `ReadOne` returns the value
//! wrapped in a single variant (`v u`); the older `Read` double-wraps it
//! (`v v u`), so we unwrap nested variants down to the `u32`. Any failure (no
//! bus, no portal, headless) falls back to a default theme — the prompt still
//! renders; it just doesn't follow the desktop's scheme.

use iced::Theme;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

const PORTAL_DEST: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const PORTAL_IFACE: &str = "org.freedesktop.portal.Settings";
const NAMESPACE: &str = "org.freedesktop.appearance";
const KEY: &str = "color-scheme";

/// Theme used when the preference can't be read (no portal / headless). The
/// freedesktop convention treats "no preference" as light.
pub const FALLBACK: Theme = Theme::CatppuccinLatte;

/// Open a session-bus connection for reading the portal. `None` if there is no
/// session bus (e.g. headless); the caller then uses [`FALLBACK`]. Reused across
/// prompts so each re-detect is a cheap method call, not a fresh connection.
pub fn connect() -> Option<Connection> {
    Connection::session().ok()
}

/// The current color-scheme as an iced [`Theme`], or `None` if it can't be read.
pub fn detect(conn: &Connection) -> Option<Theme> {
    read_scheme(conn).map(theme_from_scheme)
}

/// Map the portal's `color-scheme` value to a theme. `1` (prefer dark) →
/// Catppuccin Mocha, `2` (prefer light) → Catppuccin Latte, anything else (no
/// preference / unknown) → [`FALLBACK`].
pub fn theme_from_scheme(scheme: u32) -> Theme {
    match scheme {
        1 => Theme::CatppuccinMocha,
        2 => Theme::CatppuccinLatte,
        _ => FALLBACK,
    }
}

fn read_scheme(conn: &Connection) -> Option<u32> {
    // Prefer ReadOne (single variant wrap); fall back to Read (double-wrapped on
    // older portals). unwrap_u32 peels either nesting depth.
    for method in ["ReadOne", "Read"] {
        if let Ok(reply) = conn.call_method(
            Some(PORTAL_DEST),
            PORTAL_PATH,
            Some(PORTAL_IFACE),
            method,
            &(NAMESPACE, KEY),
        ) {
            if let Ok(val) = reply.body().deserialize::<OwnedValue>() {
                if let Some(n) = unwrap_u32(&val) {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Peel nested variants (`v`, `v v`, …) down to a `u32`.
fn unwrap_u32(v: &Value<'_>) -> Option<u32> {
    match v {
        Value::U32(n) => Some(*n),
        Value::Value(inner) => unwrap_u32(inner),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_mapping() {
        assert_eq!(theme_from_scheme(1), Theme::CatppuccinMocha);
        assert_eq!(theme_from_scheme(2), Theme::CatppuccinLatte);
        // No preference / unknown values use the fallback (Catppuccin Latte).
        assert_eq!(theme_from_scheme(0), FALLBACK);
        assert_eq!(theme_from_scheme(99), FALLBACK);
    }

    #[test]
    fn unwrap_handles_single_and_double_variant_wrap() {
        // ReadOne: v u  -> a single U32.
        let single = Value::U32(1);
        assert_eq!(unwrap_u32(&single), Some(1));
        // Read: v v u -> a variant wrapping a U32.
        let double = Value::Value(Box::new(Value::U32(2)));
        assert_eq!(unwrap_u32(&double), Some(2));
        // Wrong type -> None.
        assert_eq!(unwrap_u32(&Value::Bool(true)), None);
    }
}
