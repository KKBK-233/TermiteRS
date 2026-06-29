use anyhow::{Context, Result, bail};
use chrono::Utc;
use similar::TextDiff;

use crate::{
    command::CommandOutput,
    config::{BranchConfig, Config, SyncStrategy},
    git::{ConflictFileContent, ConflictSnapshot, Git},
    llm::{ConflictProposal, ResolvedFile},
};

use super::types::{AutoResolvedSync, ConflictSide, JobView, StoredProposal};
pub(super) fn configured_branch<'a>(config: &'a Config, name: &str) -> Result<&'a BranchConfig> {
    config
        .branches
        .iter()
        .find(|branch| branch.name == name)
        .with_context(|| format!("分支不在白名单中：{name}"))
}

pub(super) fn ensure_state(job: &JobView, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&job.state.as_str()) {
        Ok(())
    } else {
        bail!("任务状态 {} 不允许执行该操作", job.state)
    }
}

pub(super) fn capture_conflict_files(
    git: &Git,
    branch: &BranchConfig,
) -> Result<(ConflictSnapshot, Vec<ConflictFileContent>)> {
    let snapshot = git.conflict_snapshot(80 * 1024)?;
    let files = git.conflict_file_contents(
        &snapshot.files,
        branch.auto_resolve.max_file_bytes.max(40 * 1024),
    )?;
    Ok((snapshot, files))
}

pub(super) fn command_output_details(action: &str, output: &CommandOutput) -> String {
    format!(
        "{}\n\nexit code: {}\n\nstdout:\n{}\n\nstderr:\n{}",
        action,
        output.status,
        output.stdout.trim(),
        output.stderr.trim()
    )
}

pub(super) fn has_staged_changes(git: &Git) -> Result<bool> {
    let output = git.run_git(&["diff", "--cached", "--quiet"])?;
    match output.status {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("检查暂存区失败：{}", output.stderr.trim()),
    }
}

pub(super) fn continue_autoresolved_sync(
    git: &Git,
    branch: &BranchConfig,
    action: &str,
    first_output: &CommandOutput,
) -> Result<AutoResolvedSync> {
    let mut details = command_output_details(action, first_output);
    let mut last_head = git.head().unwrap_or_default();
    for _ in 0..20 {
        if !has_staged_changes(git)? {
            return Ok(AutoResolvedSync::Failed(details));
        }

        let output = git.continue_sync(branch.sync)?;
        if output.success() {
            return Ok(AutoResolvedSync::Completed);
        }
        details.push_str("\n\n--- git continue ---\n");
        details.push_str(&command_output_details(
            "Git 已有暂存解决结果，但继续同步仍未完成",
            &output,
        ));

        let (snapshot, files) = capture_conflict_files(git, branch)?;
        if !snapshot.files.is_empty() {
            return Ok(AutoResolvedSync::Conflict(snapshot, files));
        }

        let current_head = git.head().unwrap_or_default();
        if current_head == last_head {
            details.push_str("\n\nGit continue 没有产生新冲突，也没有推进 HEAD，已停止重试。");
            return Ok(AutoResolvedSync::Failed(details));
        }
        last_head = current_head;
    }

    details.push_str("\n\n自动继续次数超过 20 次，已停止。");
    Ok(AutoResolvedSync::Failed(details))
}

pub(super) fn run_tests(git: &Git, branch: &BranchConfig) -> Result<String> {
    if branch.tests.is_empty() && branch.auto_resolve.require_tests {
        bail!("该分支要求测试，但未配置测试命令");
    }
    let mut output_text = String::new();
    for test in &branch.tests {
        let output = git.run_test(test)?;
        output_text.push_str(&format!("$ {test}\n{}\n{}\n", output.stdout, output.stderr));
        if !output.success() {
            bail!("测试失败：{test}\n{}", output.stderr.trim());
        }
    }
    Ok(output_text)
}

pub(super) fn validate_files(
    files: &[ResolvedFile],
    conflict_files: &[String],
) -> std::result::Result<(), String> {
    if files.is_empty() {
        return Err("DeepSeek 没有返回候选文件".to_string());
    }
    for file in files {
        if !conflict_files.contains(&file.path) {
            return Err(format!("候选文件不属于冲突文件：{}", file.path));
        }
        if file.content.contains("<<<<<<<")
            || file.content.contains("=======")
            || file.content.contains(">>>>>>>")
        {
            return Err(format!("候选文件仍包含冲突标记：{}", file.path));
        }
        if file.content.contains("... file truncated by TermiteRS ...") {
            return Err(format!("候选文件基于被截断的内容：{}", file.path));
        }
    }
    Ok(())
}

pub(super) fn deterministic_proposal(
    files: &[ConflictFileContent],
    option_id: &str,
    sync: crate::config::SyncStrategy,
) -> Result<Option<ConflictProposal>> {
    let branch_side = if matches!(sync, crate::config::SyncStrategy::Rebase) {
        ConflictSide::Theirs
    } else {
        ConflictSide::Ours
    };
    let upstream_side = if matches!(sync, crate::config::SyncStrategy::Rebase) {
        ConflictSide::Ours
    } else {
        ConflictSide::Theirs
    };
    let (summary, side) = match option_id {
        "accept-mine" => ("全盘接受分支版本", branch_side),
        "accept-theirs" => ("全盘采用主干版本", upstream_side),
        _ => return Ok(None),
    };
    anyhow::ensure!(
        !files.is_empty(),
        "当前任务没有可用于生成候选修改的冲突文件内容，请放弃后重新同步生成新的冲突现场"
    );

    let mut resolved = Vec::new();
    for file in files {
        anyhow::ensure!(
            !file.content.contains("... file truncated by TermiteRS ..."),
            "{} 内容已被截断，不能执行全盘接收",
            file.path
        );
        resolved.push(ResolvedFile {
            path: file.path.clone(),
            content: resolve_conflict_side(&file.content, side)
                .with_context(|| format!("无法解析 {}", file.path))?,
        });
    }

    Ok(Some(ConflictProposal {
        summary: summary.to_string(),
        files: resolved,
    }))
}

pub(super) fn resolve_conflict_side(content: &str, side: ConflictSide) -> Result<String> {
    enum Mode {
        Normal,
        Ours,
        Theirs,
    }

    let mut mode = Mode::Normal;
    let mut output = String::new();
    let mut ours = String::new();
    let mut theirs = String::new();
    let mut saw_conflict = false;

    for segment in content.split_inclusive('\n') {
        let marker = segment.trim_end_matches(['\r', '\n']);
        if marker.starts_with("<<<<<<<") {
            anyhow::ensure!(matches!(mode, Mode::Normal), "冲突标记嵌套或顺序错误");
            saw_conflict = true;
            ours.clear();
            theirs.clear();
            mode = Mode::Ours;
        } else if marker.starts_with("=======") {
            anyhow::ensure!(matches!(mode, Mode::Ours), "冲突分隔符顺序错误");
            mode = Mode::Theirs;
        } else if marker.starts_with(">>>>>>>") {
            anyhow::ensure!(matches!(mode, Mode::Theirs), "冲突结束标记顺序错误");
            output.push_str(match side {
                ConflictSide::Ours => &ours,
                ConflictSide::Theirs => &theirs,
            });
            mode = Mode::Normal;
        } else {
            match mode {
                Mode::Normal => output.push_str(segment),
                Mode::Ours => ours.push_str(segment),
                Mode::Theirs => theirs.push_str(segment),
            }
        }
    }

    anyhow::ensure!(matches!(mode, Mode::Normal), "冲突标记未闭合");
    anyhow::ensure!(saw_conflict, "文件不包含 Git 冲突标记");
    Ok(output)
}

pub(super) fn path_is_allowed(path: &str, allowed_paths: &[String]) -> bool {
    let normalized = path.replace('\\', "/");
    allowed_paths.iter().any(|allowed| {
        let allowed = allowed.replace('\\', "/");
        let allowed = allowed.trim_end_matches('/');
        normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
    })
}

pub(super) fn proposal_diff(
    original_files: &[ConflictFileContent],
    proposal: &ConflictProposal,
) -> Result<String> {
    let mut output = String::new();
    for file in &proposal.files {
        let original = original_files
            .iter()
            .find(|original| original.path == file.path)
            .with_context(|| format!("找不到冲突文件内容：{}", file.path))?;
        let diff = TextDiff::from_lines(&original.content, &file.content);
        output.push_str(
            &diff
                .unified_diff()
                .header(&format!("a/{}", file.path), &format!("b/{}", file.path))
                .to_string(),
        );
        output.push('\n');
    }
    Ok(output)
}

pub(super) fn optional_short_ref(git: &Git, reference: &str) -> Option<String> {
    git.run_git(&["rev-parse", "--short", reference])
        .ok()
        .filter(|output| output.success())
        .map(|output| output.stdout.trim().to_string())
}

pub(super) fn dashboard_link(config: &Config, job_id: &str) -> String {
    let base = config.service.public_dashboard_url.trim_end_matches('/');
    if base.is_empty() {
        "请登录博客后台处理。".to_string()
    } else {
        format!("{base}?job={job_id}")
    }
}

pub(super) fn timestamp() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Arc, Mutex};

    use rusqlite::params;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use super::*;
    use crate::git::ConflictFileContent;
    use crate::llm::{ConflictProposal, ResolvedFile};
    use crate::service::state::ServiceState;

    #[test]
    fn proposal_validation_rejects_non_conflict_file() {
        let files = vec![ResolvedFile {
            path: "src/other.py".to_string(),
            content: "pass\n".to_string(),
        }];
        assert!(validate_files(&files, &["src/main.py".to_string()]).is_err());
    }

    #[test]
    fn proposal_diff_does_not_write_files() {
        let original = vec![ConflictFileContent {
            path: "src/main.py".to_string(),
            content: "old\n".to_string(),
        }];
        let proposal = ConflictProposal {
            summary: "replace".to_string(),
            files: vec![ResolvedFile {
                path: "src/main.py".to_string(),
                content: "new\n".to_string(),
            }],
        };
        let diff = proposal_diff(&original, &proposal).unwrap();
        assert!(diff.contains("-old"));
        assert!(diff.contains("+new"));
    }

    #[test]
    fn deterministic_accept_mine_uses_branch_side_during_rebase() {
        let files = vec![ConflictFileContent {
            path: "src/main.py".to_string(),
            content: "keep\n<<<<<<< HEAD\nupstream\n=======\nbranch\n>>>>>>> my/branch\nend\n"
                .to_string(),
        }];
        let proposal =
            deterministic_proposal(&files, "accept-mine", crate::config::SyncStrategy::Rebase)
                .unwrap()
                .unwrap();
        assert_eq!(proposal.files[0].content, "keep\nbranch\nend\n");
    }

    #[test]
    fn deterministic_accept_theirs_uses_upstream_side_during_rebase() {
        let files = vec![ConflictFileContent {
            path: "src/main.py".to_string(),
            content: "keep\n<<<<<<< HEAD\nupstream\n=======\nbranch\n>>>>>>> my/branch\nend\n"
                .to_string(),
        }];
        let proposal =
            deterministic_proposal(&files, "accept-theirs", crate::config::SyncStrategy::Rebase)
                .unwrap()
                .unwrap();
        assert_eq!(proposal.files[0].content, "keep\nupstream\nend\n");
    }

    #[test]
    fn cleanup_old_jobs_deletes_only_old_terminal_jobs() {
        let root = std::env::temp_dir().join(format!("termiters-cleanup-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("termite.db");
        let (event_sender, _) = broadcast::channel(1);
        let state = ServiceState {
            config_path: root.join("termite.yml"),
            data_dir: root.clone(),
            database_path,
            events: event_sender,
            repository_lock: Arc::new(Mutex::new(())),
            password_attempts: Arc::new(Mutex::new(Vec::new())),
        };
        state.initialize_database().unwrap();

        let old = (Utc::now() - chrono::Duration::days(31)).to_rfc3339();
        let fresh = Utc::now().to_rfc3339();
        let connection = state.open_database().unwrap();
        for (job_id, state_name, updated_at) in [
            ("old-completed", "completed", old.as_str()),
            ("old-abandoned", "abandoned", old.as_str()),
            ("old-failed", "failed", old.as_str()),
            ("old-running", "running", old.as_str()),
            ("fresh-completed", "completed", fresh.as_str()),
        ] {
            connection
                .execute(
                    "INSERT INTO jobs (id, kind, branch, state, created_at, updated_at)
                     VALUES (?1, 'sync', 'main', ?2, ?3, ?4)",
                    params![job_id, state_name, old, updated_at],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO messages (job_id, role, content, created_at)
                     VALUES (?1, 'assistant', 'ok', ?2)",
                    params![job_id, old],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO events (id, job_id, kind, message, created_at)
                     VALUES (?1, ?2, 'state', 'ok', ?3)",
                    params![format!("event-{job_id}"), job_id, old],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO challenges (id, job_id, expected_remote_head, expires_at, used)
                     VALUES (?1, ?2, 'head', 0, 0)",
                    params![format!("challenge-{job_id}"), job_id],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO notifications (job_id, event, created_at)
                     VALUES (?1, 'done', ?2)",
                    params![job_id, old],
                )
                .unwrap();
        }
        drop(connection);

        let report = state.cleanup_old_jobs(30).unwrap();
        assert_eq!(report.jobs, 3);
        assert_eq!(report.messages, 3);
        assert_eq!(report.events, 3);
        assert_eq!(report.challenges, 3);
        assert_eq!(report.notifications, 3);

        let connection = state.open_database().unwrap();
        let mut statement = connection
            .prepare("SELECT id FROM jobs ORDER BY id")
            .unwrap();
        let remaining = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining, vec!["fresh-completed", "old-running"]);

        for table in ["messages", "events", "challenges", "notifications"] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 2, "{table}");
        }

        drop(statement);
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }
}
