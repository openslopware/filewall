//! Learned-rule schema and store, shared by `filewalld` and `filewallctl`.
//!
//! A learned rule pins a *literal* executable path (the trust anchor) to an
//! object (a file or a watched tree), optionally constrained by the process
//! cwd. Matching never globs — generalization is an explicit act elsewhere.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// What a learned rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Whether a rule's object is a single file or a watched tree root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectKind {
    File,
    Tree,
}

/// One persisted decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedRule {
    /// Creation time, seconds since the Unix epoch.
    pub created_unix: u64,
    pub action: RuleAction,
    /// Literal executable path as observed (`/proc/<pid>/exe`).
    pub exe: String,
    /// File path (kind=file) or tree root (kind=tree) the rule covers.
    pub object: PathBuf,
    pub object_kind: ObjectKind,
    /// Optional cwd constraint; recorded only when the watch opts in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

impl LearnedRule {
    /// Does this rule apply to an access of `path` by `exe` from `cwd`?
    pub fn matches(&self, path: &Path, exe: &str, cwd: Option<&str>) -> bool {
        if self.exe != exe {
            return false;
        }
        let object_ok = match self.object_kind {
            ObjectKind::File => path == self.object,
            ObjectKind::Tree => path.starts_with(&self.object),
        };
        if !object_ok {
            return false;
        }
        match &self.cwd {
            None => true,
            Some(rule_cwd) => cwd == Some(rule_cwd.as_str()),
        }
    }
}

/// The full learned-rule set, mirrored to `rules.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Rules {
    #[serde(default, rename = "rule")]
    pub rules: Vec<LearnedRule>,
}

impl Rules {
    /// Load from disk. A missing or unparseable file yields an empty set (with a
    /// stderr warning on parse error) — a corrupt learned file must never brick
    /// the daemon.
    pub fn load(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => return Rules::default(),
        };
        match toml::from_str(&text) {
            Ok(rs) => rs,
            Err(e) => {
                eprintln!(
                    "[filewall] warning: ignoring corrupt rules file {}: {e}",
                    path.display()
                );
                Rules::default()
            }
        }
    }

    /// Persist atomically: write a temp file in the same dir, then rename.
    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        let body =
            toml::to_string(self).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let tmp = dir.join(format!(
            ".rules.{}.{}.{}.tmp",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        std::fs::write(&tmp, body.as_bytes())?;
        std::fs::rename(&tmp, path)
    }

    pub fn push(&mut self, rule: LearnedRule) {
        self.rules.push(rule);
    }

    /// Deny-wins evaluation across all learned rules.
    pub fn evaluate(&self, path: &Path, exe: &str, cwd: Option<&str>) -> Option<RuleAction> {
        let mut allow = false;
        for r in &self.rules {
            if r.matches(path, exe, cwd) {
                match r.action {
                    RuleAction::Deny => return Some(RuleAction::Deny),
                    RuleAction::Allow => allow = true,
                }
            }
        }
        if allow {
            Some(RuleAction::Allow)
        } else {
            None
        }
    }
}

/// Seconds since the Unix epoch (for `LearnedRule::created_unix`).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn tree_allow(exe: &str, root: &str) -> LearnedRule {
        LearnedRule {
            created_unix: 0,
            action: RuleAction::Allow,
            exe: exe.into(),
            object: PathBuf::from(root),
            object_kind: ObjectKind::Tree,
            cwd: None,
        }
    }

    #[test]
    fn tree_rule_matches_subpath_same_exe() {
        let r = tree_allow("/usr/bin/git", "/home/u/.ssh");
        assert!(r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.aws/creds"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/node", None));
    }

    #[test]
    fn file_rule_requires_exact_path() {
        let r = LearnedRule {
            created_unix: 0,
            action: RuleAction::Allow,
            exe: "/usr/bin/git".into(),
            object: PathBuf::from("/home/u/.ssh/id_ed25519"),
            object_kind: ObjectKind::File,
            cwd: None,
        };
        assert!(r.matches(Path::new("/home/u/.ssh/id_ed25519"), "/usr/bin/git", None));
        assert!(!r.matches(Path::new("/home/u/.ssh/other"), "/usr/bin/git", None));
    }

    #[test]
    fn cwd_constraint_must_match_when_present() {
        let mut r = tree_allow("/usr/bin/node", "/home/u/.ssh");
        r.cwd = Some("/home/u/projects/foo".into());
        assert!(r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", Some("/home/u/projects/foo")));
        assert!(!r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", Some("/elsewhere")));
        assert!(!r.matches(Path::new("/home/u/.ssh/k"), "/usr/bin/node", None));
    }

    #[test]
    fn evaluate_is_deny_wins() {
        let mut rs = Rules::default();
        rs.push(tree_allow("/usr/bin/node", "/home/u/.ssh"));
        let mut deny = tree_allow("/usr/bin/node", "/home/u/.ssh");
        deny.action = RuleAction::Deny;
        rs.push(deny);
        assert_eq!(
            rs.evaluate(Path::new("/home/u/.ssh/k"), "/usr/bin/node", None),
            Some(RuleAction::Deny)
        );
    }

    #[test]
    fn evaluate_returns_none_when_nothing_matches() {
        let rs = Rules::default();
        assert_eq!(rs.evaluate(Path::new("/x"), "/usr/bin/node", None), None);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let mut rs = Rules::default();
        rs.push(tree_allow("/usr/bin/git", "/home/u/.ssh"));
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-rules-test-{}-{}-{}.toml",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        rs.save_atomic(&path).unwrap();
        let back = Rules::load(&path);
        assert_eq!(back.rules.len(), 1);
        assert_eq!(back.rules[0].exe, "/usr/bin/git");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_is_empty() {
        let rs = Rules::load(Path::new("/nonexistent/filewall/rules.toml"));
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn load_corrupt_file_is_empty() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let path = std::env::temp_dir().join(format!(
            "filewall-rules-corrupt-{}-{}.toml",
            std::process::id(),
            ts.subsec_nanos()
        ));
        std::fs::write(&path, b"this is not valid toml {{{").unwrap();
        let rs = Rules::load(&path);
        assert!(rs.rules.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
