use anyhow::{Result, bail};
use rusqlite::params;
use tracing::{error, warn};

use crate::{
    config::{BranchConfig, Config},
    doctor::Doctor,
    git::{ConflictFileContent, ConflictSnapshot, Git},
    llm::{AutoResolveConflictRequest, LlmService},
};

use super::state::ServiceState;
use super::types::AutoResolvedSync;
use super::util::{
    capture_conflict_files, command_output_details, configured_branch, continue_autoresolved_sync,
    dashboard_link, has_staged_changes, optional_short_ref, path_is_allowed, run_tests, timestamp,
    validate_files,
};

impl ServiceState {
    pub(crate) fn execute_check(&self, job_id: &str) {
        if let Err(err) = self.execute_check_inner(job_id) {
            error!("check job {job_id} failed: {err:#}");
            let _ = self.set_state(job_id, "failed", &format!("{err:#}"));
        }
    }

    pub(crate) fn execute_check_inner(&self, job_id: &str) -> Result<()> {
        self.set_state(job_id, "running", "正在检查仓库")?;
        let _guard = self
            .repository_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        let config = self.config()?;
        let report = Doctor::new(config.clone()).run();
        let git = Git::new(config.repo.path.clone());
        git.fetch_all(&config.repo)?;
        self.open_database()?.execute(
            "UPDATE jobs SET test_output = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, report, timestamp()],
        )?;
        self.set_state(job_id, "completed", "仓库检查完成")
    }

    pub(crate) fn execute_sync(&self, job_id: &str, branch_name: &str) {
        if let Err(err) = self.execute_sync_inner(job_id, branch_name) {
            error!("sync job {job_id} failed: {err:#}");
            let _ = self.cleanup_failed_worktree(job_id);
            let _ = self.set_state(job_id, "failed", &format!("{err:#}"));
        }
    }

    pub(crate) fn execute_sync_inner(&self, job_id: &str, branch_name: &str) -> Result<()> {
        self.set_state(job_id, "running", "正在获取远端状态")?;
        let config = self.config()?;
        let branch = configured_branch(&config, branch_name)?.clone();
        let worktree_path = self.data_dir.join("worktrees").join(job_id);
        let main_git = Git::new(config.repo.path.clone());

        {
            let _guard = self
                .repository_lock
                .lock()
                .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
            main_git.ensure_repo()?;
            main_git.ensure_remotes(&config.repo)?;
            main_git.fetch_all(&config.repo)?;
            if worktree_path.exists() {
                bail!("任务 worktree 已存在：{}", worktree_path.display());
            }
            let worktree = worktree_path.to_string_lossy().to_string();
            let remote_ref = format!("{}/{}", config.repo.fork_remote, branch_name);
            let branch_ref = if optional_short_ref(&main_git, &remote_ref).is_some() {
                remote_ref
            } else {
                branch_name.to_owned()
            };
            let output =
                main_git.run_git(&["worktree", "add", "--detach", &worktree, &branch_ref])?;
            if !output.success() {
                bail!("创建 worktree 失败：{}", output.stderr.trim());
            }
        }

        let git = Git::new(worktree_path.clone());
        let base_ref = format!(
            "{}/{}",
            config.repo.upstream_remote, config.repo.base_branch
        );
        let before_head = git
            .run_git(&["rev-parse", "HEAD"])?
            .stdout
            .trim()
            .to_string();
        let base_head = git
            .run_git(&["rev-parse", &base_ref])?
            .stdout
            .trim()
            .to_string();
        let remote_head = main_git
            .remote_head(&config.repo.fork_remote, branch_name)?
            .unwrap_or_default();
        self.open_database()?.execute(
            "UPDATE jobs SET worktree_path = ?2, base_ref = ?3, before_head = ?4, base_head = ?5, remote_head = ?6, updated_at = ?7 WHERE id = ?1",
            params![
                job_id,
                worktree_path.to_string_lossy(),
                base_ref,
                before_head,
                base_head,
                remote_head,
                timestamp()
            ],
        )?;
        self.emit(Some(job_id), "git", "隔离 worktree 已创建，开始同步")?;

        let output = match branch.sync {
            crate::config::SyncStrategy::Rebase => git.rebase(&base_ref)?,
            crate::config::SyncStrategy::Merge => git.merge(&base_ref)?,
        };
        if output.success() {
            return self.finish_automatic_sync(job_id, &config, &branch, &git);
        }

        let (mut snapshot, mut files) = capture_conflict_files(&git, &branch)?;
        if snapshot.files.is_empty() {
            match continue_autoresolved_sync(
                &git,
                &branch,
                "同步失败，但没有检测到 Git 未合并冲突文件",
                &output,
            )? {
                AutoResolvedSync::Completed => {
                    return self.finish_automatic_sync(job_id, &config, &branch, &git);
                }
                AutoResolvedSync::Conflict(next_snapshot, next_files) => {
                    snapshot = next_snapshot;
                    files = next_files;
                }
                AutoResolvedSync::Failed(details) => {
                    git.abort_rebase_or_merge();
                    let _ = self.remove_worktree(job_id);
                    self.open_database()?.execute(
                        "UPDATE jobs SET state = 'failed', summary = '同步失败，未检测到冲突文件', test_output = ?2, updated_at = ?3 WHERE id = ?1",
                        params![job_id, details, timestamp()],
                    )?;
                    self.emit(
                        Some(job_id),
                        "sync",
                        "同步失败，但没有检测到可分析的冲突文件",
                    )?;
                    return Ok(());
                }
            }
        }
        match self.try_low_risk_auto_resolve(&config, &branch, &git, &snapshot, &files) {
            Ok(Some(decision)) => {
                if decision {
                    return self.finish_automatic_sync(job_id, &config, &branch, &git);
                }
                (snapshot, files) = capture_conflict_files(&git, &branch)?;
                if snapshot.files.is_empty() {
                    self.open_database()?.execute(
                        "UPDATE jobs SET state = 'failed', summary = '低风险自动修复后未检测到剩余冲突文件，但同步尚未完成', updated_at = ?2 WHERE id = ?1",
                        params![job_id, timestamp()],
                    )?;
                    self.emit(
                        Some(job_id),
                        "sync",
                        "低风险自动修复后没有剩余冲突文件，任务已停止等待人工检查",
                    )?;
                    return Ok(());
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!("低风险自动修复失败，保留冲突现场等待人工指导：{err:#}");
            }
        }

        self.save_conflict(job_id, &snapshot, &files)?;
        let llm = LlmService::new(config.llm.clone());
        let request = AutoResolveConflictRequest {
            branch: branch.name.clone(),
            base: base_ref,
            snapshot: snapshot.clone(),
            files: files.clone(),
        };
        let mut options_error = None;
        let options = match llm.conflict_options(&request, "尚无人工补充要求") {
            Ok(Some(options)) => Some(options),
            Ok(None) => {
                warn!("DeepSeek 未启用，冲突任务保留等待后续处理");
                None
            }
            Err(err) => {
                let message = format!("{err:#}");
                warn!("生成功能冲突方案失败，冲突任务保留：{message}");
                options_error = Some(message);
                None
            }
        };
        let risk = "functional";
        let summary = options
            .as_ref()
            .map(|options| options.summary.as_str())
            .unwrap_or("功能性冲突已保留，DeepSeek 方案暂时不可用");
        let options_json = options.as_ref().map(serde_json::to_string).transpose()?;
        self.open_database()?.execute(
            "UPDATE jobs SET state = 'waiting_guidance', risk = ?2, summary = ?3, options_json = ?4, updated_at = ?5 WHERE id = ?1",
            params![
                job_id,
                risk,
                summary,
                options_json,
                timestamp()
            ],
        )?;
        self.emit(Some(job_id), "conflict", "功能性冲突正在等待人工指导")?;
        if let Some(message) = options_error {
            warn!("DeepSeek 方案生成失败，等待后台人工处理：{message}");
        }
        Ok(())
    }

    pub(crate) fn try_low_risk_auto_resolve(
        &self,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
        snapshot: &ConflictSnapshot,
        files: &[ConflictFileContent],
    ) -> Result<Option<bool>> {
        if !branch.auto_resolve.enabled
            || branch.auto_resolve.allowed_paths.is_empty()
            || snapshot.files.len() > branch.auto_resolve.max_conflict_files
            || snapshot
                .files
                .iter()
                .any(|path| !path_is_allowed(path, &branch.auto_resolve.allowed_paths))
        {
            return Ok(None);
        }
        let request = AutoResolveConflictRequest {
            branch: branch.name.clone(),
            base: format!(
                "{}/{}",
                config.repo.upstream_remote, config.repo.base_branch
            ),
            snapshot: snapshot.clone(),
            files: files.to_vec(),
        };
        let Some(decision) = LlmService::new(config.llm.clone()).auto_resolve_conflict(&request)?
        else {
            return Ok(None);
        };
        if !decision.risk.eq_ignore_ascii_case("low")
            || validate_files(&decision.files, &snapshot.files).is_err()
        {
            return Ok(Some(false));
        }
        for file in &decision.files {
            git.write_file(&file.path, &file.content)?;
            git.add_file(&file.path)?;
        }
        let output = git.continue_sync(branch.sync)?;
        Ok(Some(output.success()))
    }

    pub(crate) fn finish_automatic_sync(
        &self,
        job_id: &str,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
    ) -> Result<()> {
        let test_output = run_tests(git, branch)?;
        self.open_database()?.execute(
            "UPDATE jobs SET test_output = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, test_output, timestamp()],
        )?;
        self.push_job(config, branch, git, job_id, false)?;
        self.remove_worktree(job_id)?;
        self.set_state(job_id, "completed", "同步、测试和推送完成")?;
        self.notify_once(
            job_id,
            "completed",
            &format!("{} 同步完成", branch.name),
            "TermiteRS 已完成同步、测试和推送。",
        )
    }

    pub(crate) fn save_conflict(
        &self,
        job_id: &str,
        snapshot: &ConflictSnapshot,
        files: &[ConflictFileContent],
    ) -> Result<()> {
        self.open_database()?.execute(
            "UPDATE jobs SET snapshot_json = ?2, files_json = ?3, updated_at = ?4 WHERE id = ?1",
            params![
                job_id,
                serde_json::to_string(snapshot)?,
                serde_json::to_string(files)?,
                timestamp()
            ],
        )?;
        Ok(())
    }
}
