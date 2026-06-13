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
            let root = expand_home(&w.path);
            let learn_cwd = w.learn_match.iter().any(|m| m == "cwd");
            let wp = WatchPolicy::new(root, &w.allow, self.default_action, w.learn_object, learn_cwd)
                .map_err(|e| ConfigError::Glob(w.path.clone(), e))?;
            watches.push(wp);
        }
        Ok(Policy::new(watches))
    }
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
