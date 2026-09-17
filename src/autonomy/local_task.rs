//! 本地自治任务的受限执行环：模型只选动作，文件与测试由 Rust 校验并执行。

use std::{
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::{config::Config, git::Git};

use super::{AutonomyAction, AutonomyTarget, PermissionMode};

const MAX_STEPS: usize = 8;
const MAX_FILE_BYTES: u64 = 24 * 1024;
const MAX_OBSERVATION_BYTES: usize = 12 * 1024;

/// JSON 动作协议没有命令字段；测试只能引用可信配置中的序号。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalTaskStep {
    Inspect,
    ReadFile { path: String },
    RunTests { test_index: usize },
    Finish { summary: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalTaskContext<'a> {
    pub request: &'a str,
    pub repository: &'a Path,
    pub observation: &'a str,
    pub tests: &'a [String],
    pub step: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTaskState {
    Finished,
    Stopped,
}

#[derive(Debug)]
pub struct LocalTaskResult {
    pub state: LocalTaskState,
    pub summary: String,
    pub trace: Vec<String>,
}

pub struct LocalTaskRunner<'a> {
    config: &'a Config,
}

impl<'a> LocalTaskRunner<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    /// 每轮重新检查动作权限；ask 仅批准当前一步，不改变持久配置。
    pub fn run<P, A>(&self, request: &str, mut plan: P, mut approve: A) -> Result<LocalTaskResult>
    where
        P: FnMut(&LocalTaskContext<'_>) -> Result<LocalTaskStep>,
        A: FnMut(&str) -> Result<bool>,
    {
        let root = self
            .config
            .repo
            .path
            .canonicalize()
            .context("本地仓库不存在")?;
        let git = Git::new(&root);
        let top = git.run_git(&["rev-parse", "--show-toplevel"])?;
        ensure!(top.success(), "自治任务目标不是 Git 仓库");
        ensure!(
            Path::new(top.stdout.trim()).canonicalize()? == root,
            "自治任务只接受仓库根目录"
        );
        self.check_permission(AutonomyAction::LocalRead, &root, &mut approve)?;

        let branch = git.run_git(&["symbolic-ref", "--short", "HEAD"])?;
        let tests = if branch.success() {
            self.config
                .branches
                .iter()
                .find(|entry| entry.name == branch.stdout.trim())
                .map(|entry| entry.tests.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut observation = format!(
            "仓库：{}；当前分支：{}；可选测试数：{}。",
            root.display(),
            branch.stdout.trim(),
            tests.len()
        );
        let mut trace = Vec::new();
        for step in 1..=MAX_STEPS {
            let context = LocalTaskContext {
                request,
                repository: &root,
                observation: &observation,
                tests: &tests,
                step,
            };
            match plan(&context)? {
                LocalTaskStep::Inspect => {
                    self.check_permission(AutonomyAction::LocalRead, &root, &mut approve)?;
                    let status = git.run_git(&["status", "--short"])?;
                    ensure!(status.success(), "读取 Git 状态失败");
                    let files = git.run_git(&["ls-files"])?;
                    ensure!(files.success(), "列出仓库文件失败");
                    observation = bounded(format!(
                        "Git 状态：\n{}\n跟踪文件：\n{}",
                        status.stdout, files.stdout
                    ));
                    trace.push("已读取 Git 状态和跟踪文件名。".to_string());
                }
                LocalTaskStep::ReadFile { path } => {
                    self.check_permission(AutonomyAction::LocalRead, &root, &mut approve)?;
                    observation = bounded(read_tracked_file(&git, &root, &path)?);
                    trace.push(format!("已读取受限文件：{path}"));
                }
                LocalTaskStep::RunTests { test_index } => {
                    let Some(command) = tests.get(test_index) else {
                        bail!("模型选择了未配置的测试序号 {test_index}");
                    };
                    self.check_permission(AutonomyAction::RunTests, &root, &mut approve)?;
                    let output = git.run_test_sandboxed(command)?;
                    observation = bounded(format!(
                        "测试：{command}\n退出码：{}\nstdout:\n{}\nstderr:\n{}",
                        output.status, output.stdout, output.stderr
                    ));
                    trace.push(format!("沙箱测试 `{command}`：退出码 {}", output.status));
                }
                LocalTaskStep::Finish { summary } => {
                    ensure!(!summary.trim().is_empty(), "模型没有给出任务结论");
                    return Ok(LocalTaskResult {
                        state: LocalTaskState::Finished,
                        summary,
                        trace,
                    });
                }
            }
        }
        Ok(LocalTaskResult {
            state: LocalTaskState::Stopped,
            summary: format!("达到 {MAX_STEPS} 步上限，任务已停止。"),
            trace,
        })
    }

    fn check_permission<A>(
        &self,
        action: AutonomyAction,
        root: &Path,
        approve: &mut A,
    ) -> Result<()>
    where
        A: FnMut(&str) -> Result<bool>,
    {
        match self
            .config
            .autonomy
            .authorize(action, AutonomyTarget::Local { path: root })
        {
            PermissionMode::Deny => {
                bail!("权限拒绝 {}：仓库不在 scope 内或动作被禁用", action.key())
            }
            PermissionMode::Ask => {
                if !approve(action.key())? {
                    bail!("等待人工决定：{}", action.key());
                }
            }
            PermissionMode::Allow => {}
        }
        Ok(())
    }
}

/// 仅向模型提供小型、已跟踪、非链接的代码或文档文件。
fn read_tracked_file(git: &Git, root: &Path, path: &str) -> Result<String> {
    let relative = Path::new(path);
    ensure!(
        !relative.is_absolute()
            && relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "文件路径必须是仓库内相对路径"
    );
    let lower = path.to_ascii_lowercase();
    ensure!(
        ![
            ".env",
            "secret",
            "credential",
            "token",
            "private",
            ".pem",
            ".key"
        ]
        .iter()
        .any(|part| lower.contains(part)),
        "敏感文件不进入模型上下文"
    );
    let suffix = relative
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    ensure!(
        [
            "rs", "go", "py", "ts", "tsx", "js", "jsx", "java", "kt", "md"
        ]
        .contains(&suffix.as_str()),
        "文件类型未获准进入模型上下文"
    );
    let tracked = git.run_git(&["ls-files", "--error-unmatch", "--", path])?;
    ensure!(tracked.success(), "文件不是 Git 跟踪文件");
    let full = root.join(relative);
    let metadata = fs::symlink_metadata(&full)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= MAX_FILE_BYTES,
        "文件不是普通小文件"
    );
    ensure!(full.canonicalize()?.starts_with(root), "文件解析后越出仓库");
    let content = fs::read_to_string(&full).with_context(|| format!("无法读取 {path}"))?;
    Ok(format!("文件 {path}：\n{content}"))
}

fn bounded(input: String) -> String {
    if input.len() <= MAX_OBSERVATION_BYTES {
        return input;
    }
    let mut end = MAX_OBSERVATION_BYTES;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[输出已截断]", &input[..end])
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, process::Command};

    use super::*;

    fn fixture() -> (PathBuf, Config) {
        let root =
            std::env::temp_dir().join(format!("termiters-local-task-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(root.join("src/private.rs"), "hidden\n").unwrap();
        let output = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .args(["add", "src/main.rs", "src/private.rs"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success());
        let normalized = root.to_string_lossy().replace('\\', "/");
        let raw = format!(
            "repo:\n  path: '{normalized}'\n  upstream: unused\n  fork: unused\nbranches:\n  - name: main\n    tests: ['echo fixture']\nautonomy:\n  enabled: true\n  scope:\n    local_repositories: ['{normalized}']\n  permissions:\n    local_read: allow\n    run_tests: deny\n"
        );
        let config = serde_yaml::from_str(&raw).unwrap();
        (root, config)
    }

    #[test]
    fn model_can_inspect_and_read_tracked_code_then_finish() {
        let (root, config) = fixture();
        let steps = [
            LocalTaskStep::Inspect,
            LocalTaskStep::ReadFile {
                path: "src/main.rs".into(),
            },
            LocalTaskStep::Finish {
                summary: "只完成检查".into(),
            },
        ];
        let mut steps = steps.into_iter();
        let mut observations = Vec::new();
        let result = LocalTaskRunner::new(&config)
            .run(
                "检查代码",
                |context| {
                    observations.push(context.observation.to_string());
                    Ok(steps.next().unwrap())
                },
                |_| panic!("allow 不应请求批准"),
            )
            .unwrap();
        assert_eq!(result.state, LocalTaskState::Finished);
        assert_eq!(result.trace.len(), 2);
        assert!(observations[1].contains("src/main.rs"));
        assert!(observations[2].contains("fn main()"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_read_rejects_traversal_sensitive_and_untracked_paths() {
        let (root, _) = fixture();
        let git = Git::new(&root);
        assert!(read_tracked_file(&git, &root, "../outside.rs").is_err());
        assert!(read_tracked_file(&git, &root, "src/private.rs").is_err());
        fs::write(root.join("src/untracked.rs"), "unknown").unwrap();
        assert!(read_tracked_file(&git, &root, "src/untracked.rs").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_action_requires_permission_and_never_accepts_model_command() {
        let (root, mut config) = fixture();
        let result = LocalTaskRunner::new(&config).run(
            "测试",
            |_| Ok(LocalTaskStep::RunTests { test_index: 0 }),
            |_| panic!("deny 不应请求批准"),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("权限拒绝 run_tests")
        );
        config.autonomy.permissions.run_tests = PermissionMode::Ask;
        let result = LocalTaskRunner::new(&config).run(
            "测试",
            |_| Ok(LocalTaskStep::RunTests { test_index: 0 }),
            |_| Ok(false),
        );
        assert!(result.unwrap_err().to_string().contains("等待人工决定"));
        assert!(
            serde_json::from_str::<LocalTaskStep>(r#"{"action":"run_tests","command":"rm -rf ."}"#)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn read_scope_is_required_even_when_mode_is_allow() {
        let (root, mut config) = fixture();
        config.autonomy.scope.local_repositories.clear();
        let result =
            LocalTaskRunner::new(&config).run("检查", |_| Ok(LocalTaskStep::Inspect), |_| Ok(true));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("权限拒绝 local_read")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
