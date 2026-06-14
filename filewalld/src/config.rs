//! Configuration loading. Minimal TOML for the MVP:
//!
//! ```toml
//! default_action = "prompt"
//! prompt_timeout_seconds = 30
//! socket_path = "/run/filewall/prompt.sock"
//!
//! [[watch]]
//! path = "/home/user/.ssh"
//! allow = ["/usr/bin/ssh", "/usr/bin/ssh-*"]
//! exclude = ["**/Cache", "**/Cache_Data"]  # subtrees to leave unmarked
//! ```

use crate::policy::{Action, Policy, WatchPolicy};
use filewall_rules::ObjectKind;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_action")]
    pub default_action: Action,
    #[serde(default = "default_timeout")]
    pub prompt_timeout_seconds: u64,
    #[serde(default = "default_socket")]
    pub socket_path: PathBuf,
    #[serde(default = "default_rules_path")]
    pub rules_path: PathBuf,
    #[serde(default)]
    pub watch: Vec<WatchConfig>,
}

#[derive(Debug, Deserialize)]
pub struct WatchConfig {
    pub path: String,
    #[serde(default)]
    pub allow: Vec<String>,
    /// Glob patterns (matched against absolute paths) of sub-paths to skip when
    /// marking. A matching directory prunes its whole subtree — use this to keep
    /// noisy, non-sensitive trees (e.g. browser caches) from exhausting the
    /// kernel's fanotify mark limit. Globs follow the same rules as `allow`
    /// (`*` does not cross `/`, `**` does).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// "file" | "tree" — what an "Always" decision records. Default: file.
    #[serde(default = "default_learn_object")]
    pub learn_object: ObjectKind,
    /// Subset of ["exe","cwd"]; "cwd" opts the watch into cwd-pinned rules.
    #[serde(default)]
    pub learn_match: Vec<String>,
}

fn default_action() -> Action {
    Action::Prompt
}
fn default_timeout() -> u64 {
    30
}
fn default_socket() -> PathBuf {
    PathBuf::from("/run/filewall/prompt.sock")
}
fn default_learn_object() -> ObjectKind {
    ObjectKind::File
}
fn default_rules_path() -> PathBuf {
    PathBuf::from("/var/lib/filewall/rules.toml")
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("compiling glob in watch '{0}': {1}")]
    Glob(String, #[source] globset::Error),
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        Self::from_str(&text)
    }

    pub fn from_str(text: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(text)?)
    }

    /// Build the compiled [`Policy`], resolving each watch path and expanding a
    /// leading `~` to the user's home directory.
    pub fn build_policy(&self) -> Result<Policy, ConfigError> {
        let mut watches = Vec::new();
        for w in &self.watch {
            let root = canonicalize_root(expand_home(&w.path));
            let learn_cwd = w.learn_match.iter().any(|m| m == "cwd");
            let wp = WatchPolicy::new(
                root,
                &w.allow,
                self.default_action,
                w.learn_object,
                learn_cwd,
                &w.exclude,
            )
            .map_err(|e| ConfigError::Glob(w.path.clone(), e))?;
            watches.push(wp);
        }
        Ok(Policy::new(watches))
    }
}

/// Resolve a watch root to its canonical form so it matches the fully-resolved
/// paths the kernel reports for accesses (via `/proc/self/fd/N`). Without this,
/// a watch configured on a symlinked directory never `covers()` the canonical
/// accessed path, so every access falls through to the allow default.
///
/// If canonicalization fails (e.g. the path doesn't exist yet), keep the
/// expanded path so config loading stays non-fatal; nothing under a missing
/// path can be marked or accessed anyway.
fn canonicalize_root(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Expand a leading `~` or `~/...` to `$HOME`. Other paths pass through.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Outcome;
    use std::path::Path;

    #[test]
    fn parses_full_config() {
        let cfg = Config::from_str(
            r#"
            default_action = "prompt"
            prompt_timeout_seconds = 15
            socket_path = "/run/filewall/prompt.sock"

            [[watch]]
            path = "/home/user/.ssh"
            allow = ["/usr/bin/ssh", "/usr/bin/ssh-*"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.default_action, Action::Prompt);
        assert_eq!(cfg.prompt_timeout_seconds, 15);
        assert_eq!(cfg.watch.len(), 1);
        assert_eq!(cfg.watch[0].path, "/home/user/.ssh");
    }

    #[test]
    fn applies_defaults_when_omitted() {
        let cfg = Config::from_str(
            r#"
            [[watch]]
            path = "/home/user/.ssh"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.default_action, Action::Prompt);
        assert_eq!(cfg.prompt_timeout_seconds, 30);
        assert_eq!(cfg.socket_path, PathBuf::from("/run/filewall/prompt.sock"));
        assert!(cfg.watch[0].allow.is_empty());
    }

    #[test]
    fn build_policy_evaluates() {
        let cfg = Config::from_str(
            r#"
            [[watch]]
            path = "/home/user/.ssh"
            allow = ["/usr/bin/ssh"]
            "#,
        )
        .unwrap();
        let policy = cfg.build_policy().unwrap();
        assert_eq!(
            policy.evaluate(Path::new("/home/user/.ssh/id_ed25519"), "/usr/bin/ssh"),
            Outcome::Allow
        );
        assert_eq!(
            policy.evaluate(Path::new("/home/user/.ssh/id_ed25519"), "/usr/bin/node"),
            Outcome::Prompt
        );
    }

    #[test]
    fn learn_settings_default_and_parse() {
        let cfg = Config::from_str(
            r#"
            rules_path = "/var/lib/filewall/rules.toml"
            [[watch]]
            path = "/home/u/.ssh"
            [[watch]]
            path = "/home/u/.aws"
            learn_object = "tree"
            learn_match = ["exe", "cwd"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.rules_path, PathBuf::from("/var/lib/filewall/rules.toml"));
        // defaults
        assert_eq!(cfg.watch[0].learn_object, filewall_rules::ObjectKind::File);
        assert!(cfg.watch[0].learn_match.is_empty());
        // explicit
        assert_eq!(cfg.watch[1].learn_object, filewall_rules::ObjectKind::Tree);
        assert!(cfg.watch[1].learn_match.iter().any(|m| m == "cwd"));
    }

    #[test]
    fn watch_on_symlinked_dir_still_covers_canonical_access() {
        // Regression: a watch configured on a symlinked directory must still
        // govern accesses, which the kernel reports via their canonical path.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let base = std::env::temp_dir().join(format!(
            "filewall-symlink-{}-{}-{}",
            std::process::id(),
            ts.as_secs(),
            ts.subsec_nanos()
        ));
        let real = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let cfg = Config::from_str(&format!(
            r#"
            [[watch]]
            path = "{}"
            allow = ["/usr/bin/ssh"]
            "#,
            link.display()
        ))
        .unwrap();
        let policy = cfg.build_policy().unwrap();

        // The kernel reports the canonical path for an access; policy must cover it.
        let canonical_file = std::fs::canonicalize(&real).unwrap().join("secret");
        assert_eq!(
            policy.evaluate(&canonical_file, "/usr/bin/node"),
            Outcome::Prompt,
            "symlinked watch must prompt for a non-allowed exe, not fall through to allow"
        );
        assert_eq!(
            policy.evaluate(&canonical_file, "/usr/bin/ssh"),
            Outcome::Allow
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn exclude_defaults_and_parses() {
        let cfg = Config::from_str(
            r#"
            [[watch]]
            path = "/a"
            [[watch]]
            path = "/b"
            exclude = ["**/Cache", "**/Cache_Data"]
            "#,
        )
        .unwrap();
        assert!(cfg.watch[0].exclude.is_empty());
        assert_eq!(cfg.watch[1].exclude, vec!["**/Cache", "**/Cache_Data"]);
        // An invalid exclude glob is surfaced as a build error.
        let bad = Config::from_str(
            r#"
            [[watch]]
            path = "/x"
            exclude = ["[invalid"]
            "#,
        )
        .unwrap();
        assert!(matches!(bad.build_policy(), Err(ConfigError::Glob(_, _))));
    }

    #[test]
    fn expands_home_tilde() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(expand_home("~/.ssh"), PathBuf::from("/home/tester/.ssh"));
        assert_eq!(expand_home("~"), PathBuf::from("/home/tester"));
        assert_eq!(expand_home("/abs/path"), PathBuf::from("/abs/path"));
    }

    #[test]
    fn invalid_glob_is_reported() {
        let cfg = Config::from_str(
            r#"
            [[watch]]
            path = "/x"
            allow = ["/usr/bin/[invalid"]
            "#,
        )
        .unwrap();
        assert!(matches!(cfg.build_policy(), Err(ConfigError::Glob(_, _))));
    }
}
