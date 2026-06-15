//! Pure policy logic: given the path being accessed and the resolved executable
//! of the accessing process, decide whether to allow, prompt, or deny.
//!
//! This module has no I/O and no fanotify dependency so it can be unit-tested in
//! isolation — it is the heart of the daemon's correctness.

use filewall_rules::{now_unix, LearnedRule, ObjectKind, RuleAction};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The action to take when no allow rule matches. Also the result type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Prompt,
    Allow,
    Deny,
}

/// Outcome of evaluating an access against policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Prompt,
    Deny,
}

impl From<Action> for Outcome {
    fn from(a: Action) -> Self {
        match a {
            Action::Prompt => Outcome::Prompt,
            Action::Allow => Outcome::Allow,
            Action::Deny => Outcome::Deny,
        }
    }
}

/// Combine the config outcome with any learned-rule verdict, deny-wins.
pub fn combine(cfg: Outcome, learned: Option<RuleAction>) -> Outcome {
    match (cfg, learned) {
        (_, Some(RuleAction::Deny)) => Outcome::Deny,
        (Outcome::Deny, _) => Outcome::Deny,
        (_, Some(RuleAction::Allow)) => Outcome::Allow,
        (Outcome::Allow, _) => Outcome::Allow,
        (Outcome::Prompt, None) => Outcome::Prompt,
    }
}

/// A single watched directory tree with its compiled allowlist.
pub struct WatchPolicy {
    /// Canonical root directory this policy covers.
    root: PathBuf,
    /// Globs matched against the accessing process's executable path.
    allow: GlobSet,
    /// What to do when the executable is not in `allow`.
    default_action: Action,
    /// Object granularity a learned "Always" rule records.
    learn_object: ObjectKind,
    /// Whether learned rules from this watch pin the process cwd.
    learn_cwd: bool,
    /// Globs (matched against absolute paths) of sub-paths to skip when marking.
    /// A matching directory prunes its whole subtree; a matching file is skipped.
    exclude: GlobSet,
}

impl WatchPolicy {
    /// Compile a watch policy. `allow_patterns` are shell-style globs matched
    /// against absolute executable paths; `*` does not cross `/`, `**` does.
    pub fn new(
        root: impl Into<PathBuf>,
        allow_patterns: &[String],
        default_action: Action,
        learn_object: ObjectKind,
        learn_cwd: bool,
        exclude_patterns: &[String],
    ) -> Result<Self, globset::Error> {
        let mut builder = GlobSetBuilder::new();
        for pat in allow_patterns {
            let glob: Glob = GlobBuilder::new(pat).literal_separator(true).build()?;
            builder.add(glob);
        }
        let mut exclude = GlobSetBuilder::new();
        for pat in exclude_patterns {
            let glob: Glob = GlobBuilder::new(pat).literal_separator(true).build()?;
            exclude.add(glob);
        }
        Ok(Self {
            root: root.into(),
            allow: builder.build()?,
            default_action,
            learn_object,
            learn_cwd,
            exclude: exclude.build()?,
        })
    }

    /// The object an "Always" rule would target for an access of `path`, per
    /// this watch's `learn_object`. Single source of truth shared by the prompt
    /// (what we display) and `learned_rule` (what we persist) so they can't drift.
    pub fn always_target(&self, path: &Path) -> (PathBuf, ObjectKind) {
        match self.learn_object {
            ObjectKind::Tree => (self.root.clone(), ObjectKind::Tree),
            ObjectKind::File => (path.to_path_buf(), ObjectKind::File),
        }
    }

    /// Whether learned rules from this watch pin the process cwd.
    pub fn learn_cwd(&self) -> bool {
        self.learn_cwd
    }

    /// Build a learned rule for an access this watch covered, honoring the
    /// watch's `learn_object`/`learn_cwd` policy.
    pub fn learned_rule(
        &self,
        action: RuleAction,
        exe: &str,
        path: &Path,
        cwd: Option<&str>,
    ) -> LearnedRule {
        let (object, object_kind) = self.always_target(path);
        LearnedRule {
            created_unix: now_unix(),
            action,
            exe: exe.to_string(),
            object,
            object_kind,
            cwd: if self.learn_cwd {
                cwd.map(|s| s.to_string())
            } else {
                None
            },
        }
    }

    /// Does this policy govern accesses to `path`?
    pub fn covers(&self, path: &Path) -> bool {
        path.starts_with(&self.root)
    }

    /// True if `path` matches one of this watch's exclude globs, so it (and, for
    /// a directory, its whole subtree) should be left unmarked.
    pub fn is_excluded(&self, path: &Path) -> bool {
        self.exclude.is_match(path)
    }

    /// Decide the outcome for a process whose executable is `exe`.
    pub fn evaluate(&self, exe: &str) -> Outcome {
        if self.allow.is_match(exe) {
            Outcome::Allow
        } else {
            self.default_action.into()
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// All watch policies. `evaluate` routes an access to the covering watch.
pub struct Policy {
    watches: Vec<WatchPolicy>,
}

impl Policy {
    pub fn new(watches: Vec<WatchPolicy>) -> Self {
        Self { watches }
    }

    /// Evaluate an access to `path` by a process with executable `exe`.
    ///
    /// If no watch covers the path (shouldn't happen — we only mark watched
    /// files), default to `Allow` so we never block unrelated traffic.
    pub fn evaluate(&self, path: &Path, exe: &str) -> Outcome {
        match self.watches.iter().find(|w| w.covers(path)) {
            Some(w) => w.evaluate(exe),
            None => Outcome::Allow,
        }
    }

    pub fn watches(&self) -> &[WatchPolicy] {
        &self.watches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use filewall_rules::{ObjectKind, RuleAction};

    fn ssh_policy() -> WatchPolicy {
        WatchPolicy::new(
            "/home/user/.ssh",
            &[
                "/usr/bin/ssh".to_string(),
                "/usr/bin/ssh-*".to_string(),
                "/usr/lib/openssh/*".to_string(),
            ],
            Action::Prompt,
            ObjectKind::File,
            false,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn combine_deny_wins() {
        use filewall_rules::RuleAction::{Allow as LA, Deny as LD};
        // learned deny beats config allow
        assert_eq!(combine(Outcome::Allow, Some(LD)), Outcome::Deny);
        // config deny beats learned allow
        assert_eq!(combine(Outcome::Deny, Some(LA)), Outcome::Deny);
        // learned allow upgrades a prompt
        assert_eq!(combine(Outcome::Prompt, Some(LA)), Outcome::Allow);
        // config allow with no learned rule
        assert_eq!(combine(Outcome::Allow, None), Outcome::Allow);
        // nothing matches -> prompt
        assert_eq!(combine(Outcome::Prompt, None), Outcome::Prompt);
    }

    #[test]
    fn learned_rule_tree_uses_watch_root() {
        let p = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::Tree, false, &[]).unwrap();
        let r = p.learned_rule(
            RuleAction::Allow,
            "/usr/bin/node",
            Path::new("/home/u/.ssh/id_ed25519"),
            Some("/home/u/p"),
        );
        assert_eq!(r.object_kind, ObjectKind::Tree);
        assert_eq!(r.object, PathBuf::from("/home/u/.ssh"));
        assert_eq!(r.exe, "/usr/bin/node");
        assert_eq!(r.cwd, None); // learn_cwd = false
    }

    #[test]
    fn learned_rule_file_uses_exact_path_and_cwd() {
        let p = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::File, true, &[]).unwrap();
        let r = p.learned_rule(
            RuleAction::Deny,
            "/usr/bin/node",
            Path::new("/home/u/.ssh/id_ed25519"),
            Some("/home/u/p"),
        );
        assert_eq!(r.object_kind, ObjectKind::File);
        assert_eq!(r.object, PathBuf::from("/home/u/.ssh/id_ed25519"));
        assert_eq!(r.action, RuleAction::Deny);
        assert_eq!(r.cwd.as_deref(), Some("/home/u/p"));
    }

    #[test]
    fn exact_allow_matches() {
        assert_eq!(ssh_policy().evaluate("/usr/bin/ssh"), Outcome::Allow);
    }

    #[test]
    fn unlisted_binary_prompts() {
        assert_eq!(ssh_policy().evaluate("/usr/bin/node"), Outcome::Prompt);
        assert_eq!(ssh_policy().evaluate("/usr/bin/cat"), Outcome::Prompt);
    }

    #[test]
    fn star_suffix_glob_matches() {
        let p = ssh_policy();
        assert_eq!(p.evaluate("/usr/bin/ssh-add"), Outcome::Allow);
        assert_eq!(p.evaluate("/usr/bin/ssh-keygen"), Outcome::Allow);
    }

    #[test]
    fn single_star_does_not_cross_slash() {
        // "/usr/lib/openssh/*" must not match a deeper path.
        let p = ssh_policy();
        assert_eq!(p.evaluate("/usr/lib/openssh/sftp-server"), Outcome::Allow);
        assert_eq!(p.evaluate("/usr/lib/openssh/sub/evil"), Outcome::Prompt);
    }

    #[test]
    fn double_star_crosses_slash() {
        let p = WatchPolicy::new(
            "/home/user/.aws",
            &["/usr/lib/python*/site-packages/awscli/**".to_string()],
            Action::Prompt,
            ObjectKind::File,
            false,
            &[],
        )
        .unwrap();
        assert_eq!(
            p.evaluate("/usr/lib/python3.12/site-packages/awscli/clidriver.py"),
            Outcome::Allow
        );
    }

    #[test]
    fn default_action_deny_is_honored() {
        let p = WatchPolicy::new("/x", &["/usr/bin/ssh".to_string()], Action::Deny, ObjectKind::File, false, &[]).unwrap();
        assert_eq!(p.evaluate("/usr/bin/node"), Outcome::Deny);
    }

    #[test]
    fn covers_matches_subpaths_only() {
        let p = ssh_policy();
        assert!(p.covers(Path::new("/home/user/.ssh/id_ed25519")));
        assert!(!p.covers(Path::new("/home/user/.aws/credentials")));
    }

    #[test]
    fn exclude_globs_prune_paths() {
        let p = WatchPolicy::new(
            "/home/u/.config",
            &[],
            Action::Prompt,
            ObjectKind::File,
            false,
            &["**/Cache".to_string(), "**/*.tmp".to_string()],
        )
        .unwrap();
        // A matching directory (subtree gets pruned by the walker).
        assert!(p.is_excluded(Path::new("/home/u/.config/app/Cache")));
        // A matching file anywhere in the tree.
        assert!(p.is_excluded(Path::new("/home/u/.config/x/y.tmp")));
        // Non-matching paths are kept.
        assert!(!p.is_excluded(Path::new("/home/u/.config/keep.txt")));
        // No exclude patterns -> nothing is excluded.
        let none =
            WatchPolicy::new("/x", &[], Action::Prompt, ObjectKind::File, false, &[]).unwrap();
        assert!(!none.is_excluded(Path::new("/x/anything/Cache")));
    }

    #[test]
    fn always_target_tree_is_root_file_is_path() {
        let tree = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::Tree, false, &[]).unwrap();
        let (obj, kind) = tree.always_target(Path::new("/home/u/.ssh/id_ed25519"));
        assert_eq!(kind, ObjectKind::Tree);
        assert_eq!(obj, PathBuf::from("/home/u/.ssh"));

        let file = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, ObjectKind::File, false, &[]).unwrap();
        let (obj, kind) = file.always_target(Path::new("/home/u/.ssh/id_ed25519"));
        assert_eq!(kind, ObjectKind::File);
        assert_eq!(obj, PathBuf::from("/home/u/.ssh/id_ed25519"));
    }

    #[test]
    fn always_target_agrees_with_learned_rule() {
        // The scope we would *display* must equal the scope we would *persist*.
        for kind in [ObjectKind::Tree, ObjectKind::File] {
            for learn_cwd in [false, true] {
                let p = WatchPolicy::new("/home/u/.ssh", &[], Action::Prompt, kind, learn_cwd, &[]).unwrap();
                let path = Path::new("/home/u/.ssh/id_ed25519");
                let (obj, obj_kind) = p.always_target(path);
                let rule = p.learned_rule(RuleAction::Allow, "/usr/bin/node", path, Some("/home/u/p"));
                assert_eq!(rule.object, obj);
                assert_eq!(rule.object_kind, obj_kind);
                assert_eq!(rule.cwd.is_some(), p.learn_cwd());
            }
        }
    }

    #[test]
    fn policy_routes_to_covering_watch() {
        let ssh = WatchPolicy::new("/home/user/.ssh", &["/usr/bin/ssh".to_string()], Action::Prompt, ObjectKind::File, false, &[])
            .unwrap();
        let aws = WatchPolicy::new("/home/user/.aws", &["/usr/bin/aws".to_string()], Action::Prompt, ObjectKind::File, false, &[])
            .unwrap();
        let policy = Policy::new(vec![ssh, aws]);

        assert_eq!(
            policy.evaluate(Path::new("/home/user/.ssh/id_ed25519"), "/usr/bin/ssh"),
            Outcome::Allow
        );
        assert_eq!(
            policy.evaluate(Path::new("/home/user/.aws/credentials"), "/usr/bin/ssh"),
            Outcome::Prompt
        );
        // Path no watch covers -> allow (never block unrelated traffic).
        assert_eq!(
            policy.evaluate(Path::new("/etc/hosts"), "/usr/bin/node"),
            Outcome::Allow
        );
    }
}
