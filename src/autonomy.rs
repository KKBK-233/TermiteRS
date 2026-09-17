use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// 新自治流程的权限模式；原有显式 CLI 命令不受这里影响。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionMode {
    #[default]
    Deny,
    Ask,
    Allow,
}

impl PermissionMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Ask => "ask",
            Self::Allow => "allow",
        }
    }
}

/// 权限按动作独立配置，不能由模型输出或远端内容修改。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyPermissions {
    #[serde(default = "default_github_read")]
    pub github_read: PermissionMode,
    #[serde(default)]
    pub linear_read: PermissionMode,
    #[serde(default = "default_ask")]
    pub edit_code: PermissionMode,
    #[serde(default = "default_ask")]
    pub run_tests: PermissionMode,
    #[serde(default = "default_ask")]
    pub local_commit: PermissionMode,
    #[serde(default)]
    pub push_branch: PermissionMode,
    #[serde(default)]
    pub github_reply: PermissionMode,
    #[serde(default)]
    pub linear_write: PermissionMode,
    #[serde(default)]
    pub merge_pr: PermissionMode,
}

impl Default for AutonomyPermissions {
    fn default() -> Self {
        Self {
            github_read: default_github_read(),
            linear_read: PermissionMode::Deny,
            edit_code: default_ask(),
            run_tests: default_ask(),
            local_commit: default_ask(),
            push_branch: PermissionMode::Deny,
            github_reply: PermissionMode::Deny,
            linear_write: PermissionMode::Deny,
            merge_pr: PermissionMode::Deny,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AutonomyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub permissions: AutonomyPermissions,
    #[serde(default)]
    pub scope: AutonomyScope,
}

/// 对象范围与动作权限同时成立才可以执行；空范围不代表全部。
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AutonomyScope {
    #[serde(default)]
    pub github_owners: Vec<String>,
    #[serde(default)]
    pub github_repositories: Vec<String>,
    #[serde(default)]
    pub github_author: String,
    #[serde(default)]
    pub local_repositories: Vec<PathBuf>,
    #[serde(default)]
    pub linear_assignee: String,
}

pub enum AutonomyTarget<'a> {
    Github {
        repository: &'a str,
        author: &'a str,
    },
    Local {
        path: &'a Path,
    },
    Push {
        path: &'a Path,
        repository: &'a str,
        author: &'a str,
    },
    Linear {
        assignee: &'a str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyAction {
    GithubRead,
    LinearRead,
    EditCode,
    RunTests,
    LocalCommit,
    PushBranch,
    GithubReply,
    LinearWrite,
    MergePr,
}

impl AutonomyAction {
    pub const ALL: [Self; 9] = [
        Self::GithubRead,
        Self::LinearRead,
        Self::EditCode,
        Self::RunTests,
        Self::LocalCommit,
        Self::PushBranch,
        Self::GithubReply,
        Self::LinearWrite,
        Self::MergePr,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::GithubRead => "github_read",
            Self::LinearRead => "linear_read",
            Self::EditCode => "edit_code",
            Self::RunTests => "run_tests",
            Self::LocalCommit => "local_commit",
            Self::PushBranch => "push_branch",
            Self::GithubReply => "github_reply",
            Self::LinearWrite => "linear_write",
            Self::MergePr => "merge_pr",
        }
    }
}

impl AutonomyPermissions {
    fn mode(&self, action: AutonomyAction) -> PermissionMode {
        match action {
            AutonomyAction::GithubRead => self.github_read,
            AutonomyAction::LinearRead => self.linear_read,
            AutonomyAction::EditCode => self.edit_code,
            AutonomyAction::RunTests => self.run_tests,
            AutonomyAction::LocalCommit => self.local_commit,
            AutonomyAction::PushBranch => self.push_branch,
            AutonomyAction::GithubReply => self.github_reply,
            AutonomyAction::LinearWrite => self.linear_write,
            AutonomyAction::MergePr => self.merge_pr,
        }
    }
}

impl AutonomyConfig {
    /// 所有自治动作统一经由此处判断；未启用时，具体字段即使为 allow 也不生效。
    fn gate(&self, action: AutonomyAction) -> PermissionMode {
        if self.enabled {
            self.permissions.mode(action)
        } else {
            PermissionMode::Deny
        }
    }

    /// 执行前必须同时验证动作和具体目标；目标类型不匹配时失败关闭。
    pub fn authorize(&self, action: AutonomyAction, target: AutonomyTarget<'_>) -> PermissionMode {
        let in_scope = match (action, target) {
            (
                AutonomyAction::GithubRead | AutonomyAction::GithubReply | AutonomyAction::MergePr,
                AutonomyTarget::Github { repository, author },
            ) => self.scope.github_matches(repository, author),
            (
                AutonomyAction::EditCode | AutonomyAction::RunTests | AutonomyAction::LocalCommit,
                AutonomyTarget::Local { path },
            ) => self.scope.local_matches(path),
            (
                AutonomyAction::PushBranch,
                AutonomyTarget::Push {
                    path,
                    repository,
                    author,
                },
            ) => self.scope.local_matches(path) && self.scope.github_matches(repository, author),
            (
                AutonomyAction::LinearRead | AutonomyAction::LinearWrite,
                AutonomyTarget::Linear { assignee },
            ) => self.scope.linear_matches(assignee),
            _ => false,
        };
        if in_scope {
            self.gate(action)
        } else {
            PermissionMode::Deny
        }
    }

    pub fn render(&self) -> String {
        let mut output = format!("自治流程：{}\n", if self.enabled { "启用" } else { "停用" });
        for action in AutonomyAction::ALL {
            let configured = self.permissions.mode(action);
            let effective = self.gate(action);
            output.push_str(&format!(
                "- {}: {}{}\n",
                action.key(),
                effective.label(),
                if configured != effective {
                    format!("（配置为 {}，但总开关未启用）", configured.label())
                } else {
                    String::new()
                }
            ));
        }
        output.push_str(
            "范围规则：未填写的作者、负责人或仓库列表不表示全部；执行前还会检查具体目标。\n",
        );
        output.trim_end().to_string()
    }
}

impl AutonomyScope {
    fn github_matches(&self, repository: &str, author: &str) -> bool {
        if self.github_author.is_empty() || !self.github_author.eq_ignore_ascii_case(author) {
            return false;
        }
        let Some((owner, name)) = repository.split_once('/') else {
            return false;
        };
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return false;
        }
        self.github_repositories
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(repository))
            || self
                .github_owners
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(owner))
    }

    fn local_matches(&self, path: &Path) -> bool {
        let Ok(target) = path.canonicalize() else {
            return false;
        };
        self.local_repositories
            .iter()
            .filter_map(|allowed| allowed.canonicalize().ok())
            .any(|allowed| allowed == target)
    }

    fn linear_matches(&self, assignee: &str) -> bool {
        !self.linear_assignee.is_empty() && self.linear_assignee == assignee
    }
}

fn default_github_read() -> PermissionMode {
    PermissionMode::Allow
}

fn default_ask() -> PermissionMode {
    PermissionMode::Ask
}

#[cfg(test)]
mod tests {
    use super::{AutonomyAction, AutonomyConfig, AutonomyTarget, PermissionMode};

    #[test]
    fn default_policy_does_not_grant_automatic_writes() {
        let mut config = AutonomyConfig::default();
        assert_eq!(
            config.gate(AutonomyAction::GithubRead),
            PermissionMode::Deny
        );
        config.enabled = true;
        assert_eq!(
            config.gate(AutonomyAction::GithubRead),
            PermissionMode::Allow
        );
        assert_eq!(config.gate(AutonomyAction::EditCode), PermissionMode::Ask);
        assert_eq!(
            config.gate(AutonomyAction::PushBranch),
            PermissionMode::Deny
        );
        assert_eq!(config.gate(AutonomyAction::MergePr), PermissionMode::Deny);
    }

    #[test]
    fn every_permission_is_independently_configurable() {
        let config: AutonomyConfig = serde_yaml::from_str(
            r#"enabled: true
permissions:
  github_read: deny
  linear_read: allow
  edit_code: allow
  run_tests: deny
  local_commit: ask
  push_branch: allow
  github_reply: ask
  linear_write: deny
  merge_pr: allow
"#,
        )
        .unwrap();
        assert_eq!(
            config.gate(AutonomyAction::GithubRead),
            PermissionMode::Deny
        );
        assert_eq!(
            config.gate(AutonomyAction::LinearRead),
            PermissionMode::Allow
        );
        assert_eq!(config.gate(AutonomyAction::EditCode), PermissionMode::Allow);
        assert_eq!(config.gate(AutonomyAction::RunTests), PermissionMode::Deny);
        assert_eq!(
            config.gate(AutonomyAction::LocalCommit),
            PermissionMode::Ask
        );
        assert_eq!(
            config.gate(AutonomyAction::PushBranch),
            PermissionMode::Allow
        );
        assert_eq!(
            config.gate(AutonomyAction::GithubReply),
            PermissionMode::Ask
        );
        assert_eq!(
            config.gate(AutonomyAction::LinearWrite),
            PermissionMode::Deny
        );
        assert_eq!(config.gate(AutonomyAction::MergePr), PermissionMode::Allow);
    }

    #[test]
    fn typo_in_permission_is_rejected() {
        let result = serde_yaml::from_str::<AutonomyConfig>(
            "enabled: true\npermissions:\n  push_branc: allow\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn allow_still_requires_matching_personal_scope() {
        let mut config = AutonomyConfig {
            enabled: true,
            ..AutonomyConfig::default()
        };
        config.permissions.github_reply = PermissionMode::Allow;
        config.scope.github_owners = vec!["D-Nine-Chain".to_string()];
        config.scope.github_author = "KKBK-233".to_string();
        assert_eq!(
            config.authorize(
                AutonomyAction::GithubReply,
                AutonomyTarget::Github {
                    repository: "D-Nine-Chain/d9-v2-pallets",
                    author: "KKBK-233",
                },
            ),
            PermissionMode::Allow
        );
        assert_eq!(
            config.authorize(
                AutonomyAction::GithubReply,
                AutonomyTarget::Github {
                    repository: "D-Nine-Chain/d9-v2-pallets",
                    author: "someone-else",
                },
            ),
            PermissionMode::Deny
        );
        assert_eq!(
            config.authorize(
                AutonomyAction::GithubReply,
                AutonomyTarget::Github {
                    repository: "Other/repo",
                    author: "KKBK-233",
                },
            ),
            PermissionMode::Deny
        );
    }

    #[test]
    fn local_scope_uses_resolved_exact_repository_path() {
        let root = std::env::temp_dir().join(format!("termiters-policy-{}", uuid::Uuid::new_v4()));
        let allowed = root.join("allowed");
        let other = root.join("other");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let mut config = AutonomyConfig {
            enabled: true,
            ..AutonomyConfig::default()
        };
        config.permissions.edit_code = PermissionMode::Allow;
        config.scope.local_repositories = vec![allowed.clone()];
        assert_eq!(
            config.authorize(
                AutonomyAction::EditCode,
                AutonomyTarget::Local { path: &allowed },
            ),
            PermissionMode::Allow
        );
        assert_eq!(
            config.authorize(
                AutonomyAction::EditCode,
                AutonomyTarget::Local { path: &other },
            ),
            PermissionMode::Deny
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn push_requires_both_local_and_personal_github_scope() {
        let root =
            std::env::temp_dir().join(format!("termiters-push-policy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut config = AutonomyConfig {
            enabled: true,
            ..AutonomyConfig::default()
        };
        config.permissions.push_branch = PermissionMode::Allow;
        config.scope.local_repositories.push(root.clone());
        config
            .scope
            .github_repositories
            .push("D-Nine-Chain/repo".to_string());
        config.scope.github_author = "KKBK-233".to_string();
        assert_eq!(
            config.authorize(
                AutonomyAction::PushBranch,
                AutonomyTarget::Push {
                    path: &root,
                    repository: "D-Nine-Chain/repo",
                    author: "KKBK-233",
                },
            ),
            PermissionMode::Allow
        );
        assert_eq!(
            config.authorize(
                AutonomyAction::PushBranch,
                AutonomyTarget::Push {
                    path: &root,
                    repository: "D-Nine-Chain/repo",
                    author: "other",
                },
            ),
            PermissionMode::Deny
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn linear_action_requires_matching_assignee() {
        let mut config = AutonomyConfig {
            enabled: true,
            ..AutonomyConfig::default()
        };
        config.permissions.linear_write = PermissionMode::Ask;
        config.scope.linear_assignee = "user-id".to_string();
        assert_eq!(
            config.authorize(
                AutonomyAction::LinearWrite,
                AutonomyTarget::Linear {
                    assignee: "user-id"
                },
            ),
            PermissionMode::Ask
        );
        assert_eq!(
            config.authorize(
                AutonomyAction::LinearWrite,
                AutonomyTarget::Linear {
                    assignee: "other-id"
                },
            ),
            PermissionMode::Deny
        );
    }
}
