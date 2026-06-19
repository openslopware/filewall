//! Pure presentation logic for a prompt: path abbreviation, scope/warning
//! selection, and button labels. Deliberately *duplicated* from the yad helper
//! (`filewall-ui`) rather than shared, per the design decision to keep the two
//! UIs independent. Unlike the yad version there is **no markup escaping**: iced
//! renders these strings as plain `text` widgets (no Pango/markup parser), so the
//! whole markup-injection class is gone — attacker-controlled fields are shown
//! verbatim and are never interpreted.

use filewall_proto::PromptRequest;

/// What an "Always" rule would cover. Drives the loud red warning (tree) vs. the
/// neutral single-file line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    File,
    Tree,
}

/// Display-ready fields derived from a [`PromptRequest`]. Pure given `home`, so
/// the scope/label/abbreviation logic is unit-testable without a GUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptView {
    pub proc_name: String,
    pub path: String,
    pub exe: String,
    pub object: String,
    pub cwd: String,
    pub cmdline: String,
    pub pid: u32,
    pub scope: Scope,
    pub cwd_pinned: bool,
}

/// Cap a field's display length so a hostile, very long `cmdline`/`path` cannot
/// blow up the window layout and push the buttons off-screen.
const MAX_FIELD: usize = 400;

fn cap(s: &str) -> String {
    if s.chars().count() <= MAX_FIELD {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_FIELD).collect();
    out.push('\u{2026}'); // …
    out
}

/// Abbreviate a leading `$HOME` to `~` for readability. Only matches whole path
/// components (so `/home/alice` does not shorten `/home/alice2/...`). An empty
/// `home` disables abbreviation. (Copied from `filewall-ui`.)
pub fn abbrev(path: &str, home: &str) -> String {
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

impl PromptView {
    pub fn build(req: &PromptRequest, home: &str) -> Self {
        let esc = |s: &str| cap(&abbrev(s, home));

        let proc_name = std::path::Path::new(&req.exe)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| req.exe.clone());

        let cmdline = if req.cmdline.is_empty() {
            "<unavailable>".to_string()
        } else {
            cap(&req.cmdline)
        };

        PromptView {
            proc_name: cap(&proc_name),
            path: esc(&req.path),
            exe: esc(&req.exe),
            object: esc(&req.always_object),
            cwd: esc(&req.cwd),
            cmdline,
            pid: req.pid,
            scope: if req.always_tree { Scope::Tree } else { Scope::File },
            cwd_pinned: req.always_cwd_pinned,
        }
    }

    pub fn allow_always_label(&self) -> &'static str {
        match self.scope {
            Scope::Tree => "Always allow ALL",
            Scope::File => "Always allow file",
        }
    }

    pub fn deny_always_label(&self) -> &'static str {
        match self.scope {
            Scope::Tree => "Always deny ALL",
            Scope::File => "Always deny file",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ui_timeout_ms: 0,
        }
    }

    #[test]
    fn abbrev_replaces_home_prefix_only() {
        assert_eq!(abbrev("/home/alice/.ssh/id", "/home/alice"), "~/.ssh/id");
        assert_eq!(abbrev("/home/alice", "/home/alice"), "~");
        assert_eq!(abbrev("/etc/hosts", "/home/alice"), "/etc/hosts");
        // A path that merely starts with the same chars must NOT be abbreviated.
        assert_eq!(abbrev("/home/alice2/x", "/home/alice"), "/home/alice2/x");
        // Empty home disables abbreviation.
        assert_eq!(abbrev("/home/alice/.ssh", ""), "/home/alice/.ssh");
    }

    #[test]
    fn tree_scope_selects_all_labels_and_warning() {
        let v = PromptView::build(&req_fixture(), "/home/u");
        assert_eq!(v.scope, Scope::Tree);
        assert_eq!(v.allow_always_label(), "Always allow ALL");
        assert_eq!(v.deny_always_label(), "Always deny ALL");
        assert_eq!(v.object, "~/.ssh"); // abbreviated
        assert_eq!(v.proc_name, "node"); // basename
    }

    #[test]
    fn file_scope_selects_file_labels() {
        let mut req = req_fixture();
        req.always_tree = false;
        req.always_object = "/home/u/.ssh/id_ed25519".into();
        let v = PromptView::build(&req, "/home/u");
        assert_eq!(v.scope, Scope::File);
        assert_eq!(v.allow_always_label(), "Always allow file");
        assert_eq!(v.path, "~/.ssh/id_ed25519");
    }

    #[test]
    fn cwd_pin_flag_is_carried() {
        let mut req = req_fixture();
        req.always_cwd_pinned = true;
        let v = PromptView::build(&req, "/home/u");
        assert!(v.cwd_pinned);
        assert_eq!(v.cwd, "~/work");
    }

    #[test]
    fn markup_metachars_are_shown_verbatim_not_escaped() {
        // No Pango parser here: a malicious cmdline must survive intact (it is
        // rendered as plain text by iced, never interpreted).
        let mut req = req_fixture();
        req.cmdline = "node </span><b>SPOOF".into();
        let v = PromptView::build(&req, "/home/u");
        assert_eq!(v.cmdline, "node </span><b>SPOOF");
    }

    #[test]
    fn empty_cmdline_shows_placeholder() {
        let mut req = req_fixture();
        req.cmdline = String::new();
        let v = PromptView::build(&req, "/home/u");
        assert_eq!(v.cmdline, "<unavailable>");
    }

    #[test]
    fn overlong_field_is_truncated() {
        let mut req = req_fixture();
        req.cmdline = "a".repeat(MAX_FIELD + 50);
        let v = PromptView::build(&req, "/home/u");
        assert_eq!(v.cmdline.chars().count(), MAX_FIELD + 1); // + ellipsis
        assert!(v.cmdline.ends_with('\u{2026}'));
    }
}
