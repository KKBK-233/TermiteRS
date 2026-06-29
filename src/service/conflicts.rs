use anyhow::{Context, Result, bail};
use rusqlite::params;
use tracing::error;

use crate::{
    config::{BranchConfig, Config},
    git::Git,
    llm::{AutoResolveConflictRequest, LlmService},
};

use super::state::ServiceState;
use super::types::{AutoResolvedSync, JobView, StoredProposal};
use super::util::{
    capture_conflict_files, configured_branch, continue_autoresolved_sync, dashboard_link,
    deterministic_proposal, ensure_state, proposal_diff, run_tests, timestamp, validate_files,
};

impl ServiceState {
    pub(crate) fn add_message_and_refresh_options(
        &self,
        job_id: &str,
        message: &str,
    ) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        let now = timestamp();
        self.open_database()?.execute(
            "INSERT INTO messages (job_id, role, content, created_at) VALUES (?1, 'user', ?2, ?3)",
            params![job_id, message, now],
        )?;
        let (config, branch, request) = self.conflict_request(&job)?;
        let conversation = self.conversation_text(job_id)?;
        let options = LlmService::new(config.llm.clone())
            .conflict_options(&request, &conversation)?
            .context("DeepSeek 未启用")?;
        self.open_database()?.execute(
            "UPDATE jobs SET options_json = ?2, proposal_json = NULL, summary = ?3, updated_at = ?4 WHERE id = ?1",
            params![
                job_id,
                serde_json::to_string(&options)?,
                options.summary,
                timestamp()
            ],
        )?;
        self.open_database()?.execute(
            "INSERT INTO messages (job_id, role, content, created_at) VALUES (?1, 'assistant', ?2, ?3)",
            params![
                job_id,
                format!(
                    "已生成 {} 个方案：{}",
                    options.options.len(),
                    options
                        .options
                        .iter()
                        .map(|option| option.title.as_str())
                        .collect::<Vec<_>>()
                        .join("、")
                ),
                timestamp()
            ],
        )?;
        let _ = branch;
        self.emit(Some(job_id), "conflict", "DeepSeek 已根据新指导更新方案")
    }

    pub(crate) fn mark_generating_proposal(&self, job_id: &str, option_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        anyhow::ensure!(
            !job.conflict_files.is_empty(),
            "当前任务没有可用于生成候选修改的冲突文件内容，请放弃后重新同步生成新的冲突现场"
        );
        let options = job.options.clone().context("当前任务没有可选方案")?;
        options
            .options
            .iter()
            .find(|option| option.id == option_id)
            .context("选择的方案不存在")?;
        self.open_database()?.execute(
            "UPDATE jobs SET state = 'generating_proposal', proposal_json = NULL, summary = '正在生成候选修改', updated_at = ?2 WHERE id = ?1",
            params![job_id, timestamp()],
        )?;
        self.emit(Some(job_id), "proposal", "正在生成候选修改")
    }

    pub(crate) fn execute_generate_proposal(
        &self,
        job_id: &str,
        option_id: &str,
        requirements: &str,
    ) {
        match self.generate_proposal_inner(job_id, option_id, requirements) {
            Ok(_) => {
                let _ = self.set_state(job_id, "waiting_guidance", "候选修改已生成，等待确认应用");
            }
            Err(err) => {
                error!("proposal job {job_id} failed: {err:#}");
                let _ = self.set_state(
                    job_id,
                    "waiting_guidance",
                    &format!("生成候选修改失败：{err:#}"),
                );
            }
        }
    }

    pub(crate) fn generate_proposal_inner(
        &self,
        job_id: &str,
        option_id: &str,
        requirements: &str,
    ) -> Result<StoredProposal> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["generating_proposal"])?;
        let options = job.options.clone().context("当前任务没有可选方案")?;
        let option = options
            .options
            .iter()
            .find(|option| option.id == option_id)
            .context("选择的方案不存在")?;
        let (config, branch, request) = self.conflict_request(&job)?;
        let conversation = self.conversation_text(job_id)?;
        let selected = serde_json::to_string(option)?;
        let proposal = match deterministic_proposal(&request.files, option_id, branch.sync)? {
            Some(proposal) => proposal,
            None => LlmService::new(config.llm.clone())
                .conflict_proposal(&request, &conversation, &selected, requirements)?
                .context("DeepSeek 未启用")?,
        };
        validate_files(&proposal.files, &request.snapshot.files).map_err(anyhow::Error::msg)?;
        let diff = proposal_diff(&request.files, &proposal)?;
        let stored = StoredProposal {
            summary: proposal.summary,
            files: proposal.files,
            diff,
            selected_option: option_id.to_string(),
            requirements: requirements.to_string(),
        };
        self.open_database()?.execute(
            "UPDATE jobs SET proposal_json = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, serde_json::to_string(&stored)?, timestamp()],
        )?;
        self.emit(Some(job_id), "proposal", "候选修改已生成，尚未写入文件")?;
        Ok(stored)
    }

    pub(crate) fn mark_applying(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        if job.proposal.is_none() {
            bail!("请先生成候选修改");
        }
        self.set_state(job_id, "applying", "正在应用候选修改并执行测试")
    }

    pub(crate) fn execute_apply(&self, job_id: &str) {
        if let Err(err) = self.execute_apply_inner(job_id) {
            error!("apply job {job_id} failed: {err:#}");
            let _ = self.set_state(job_id, "waiting_guidance", &format!("{err:#}"));
        }
    }

    pub(crate) fn execute_apply_inner(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        let proposal = job.proposal.clone().context("候选修改不存在")?;
        let config = self.config()?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let git = Git::new(&job.worktree_path);
        for file in &proposal.files {
            git.write_file(&file.path, &file.content)?;
            git.add_file(&file.path)?;
        }

        let rebase_in_progress = git
            .run_git(&["rev-parse", "-q", "--verify", "REBASE_HEAD"])?
            .success();
        let merge_in_progress = git
            .run_git(&["rev-parse", "-q", "--verify", "MERGE_HEAD"])?
            .success();
        let in_progress = rebase_in_progress || merge_in_progress;
        if in_progress {
            let output = git.continue_sync(branch.sync)?;
            if !output.success() {
                let (snapshot, files) = capture_conflict_files(&git, &branch)?;
                if snapshot.files.is_empty() {
                    match continue_autoresolved_sync(
                        &git,
                        &branch,
                        "继续同步失败，但没有检测到新的 Git 冲突文件",
                        &output,
                    )? {
                        AutoResolvedSync::Completed => {}
                        AutoResolvedSync::Conflict(next_snapshot, next_files) => {
                            self.save_conflict(job_id, &next_snapshot, &next_files)?;
                            self.open_database()?.execute(
                                "UPDATE jobs SET state = 'waiting_guidance', proposal_json = NULL, options_json = NULL, summary = '继续同步时出现新的冲突', updated_at = ?2 WHERE id = ?1",
                                params![job_id, timestamp()],
                            )?;
                            self.add_message_and_refresh_options(
                                job_id,
                                "继续同步时出现了下一组冲突，请重新分析。",
                            )?;
                            return Ok(());
                        }
                        AutoResolvedSync::Failed(details) => {
                            self.open_database()?.execute(
                                "UPDATE jobs SET state = 'test_failed', proposal_json = NULL, test_output = ?2, summary = '继续同步失败，未检测到新的冲突文件', updated_at = ?3 WHERE id = ?1",
                                params![job_id, details, timestamp()],
                            )?;
                            self.emit(
                                Some(job_id),
                                "sync",
                                "候选修改已写入，但继续同步失败且没有新的冲突文件",
                            )?;
                            self.notify_once(
                                job_id,
                                "sync_continue_failed",
                                &format!("{} 继续同步失败", branch.name),
                                &format!(
                                    "候选修改已经写入隔离 worktree，但 git continue 没有产生新的冲突文件。\n\n{}\n\n{}",
                                    details,
                                    dashboard_link(&config, job_id)
                                ),
                            )?;
                            return Ok(());
                        }
                    }
                } else {
                    self.save_conflict(job_id, &snapshot, &files)?;
                    self.open_database()?.execute(
                        "UPDATE jobs SET state = 'waiting_guidance', proposal_json = NULL, options_json = NULL, summary = '继续同步时出现新的冲突', updated_at = ?2 WHERE id = ?1",
                        params![job_id, timestamp()],
                    )?;
                    self.add_message_and_refresh_options(
                        job_id,
                        "继续同步时出现了下一组冲突，请重新分析。",
                    )?;
                    return Ok(());
                }
            }
        } else {
            let output = git.run_git(&["commit", "--amend", "--no-edit"])?;
            if !output.success() {
                bail!("更新候选提交失败：{}", output.stderr.trim());
            }
        }

        match run_tests(&git, &branch) {
            Ok(output) => {
                self.open_database()?.execute(
                    "UPDATE jobs SET state = 'waiting_push', test_output = ?2, summary = '修改已应用且测试通过，等待推送确认', updated_at = ?3 WHERE id = ?1",
                    params![job_id, output, timestamp()],
                )?;
                self.emit(Some(job_id), "state", "测试通过，等待独立密码确认推送")?;
                self.notify_once(
                    job_id,
                    "waiting_push",
                    &format!("{} 等待推送确认", branch.name),
                    &format!(
                        "候选修改已经应用并通过测试，需要在后台输入 TermiteRS 独立操作密码确认推送。\n\n{}",
                        dashboard_link(&config, job_id)
                    ),
                )
            }
            Err(err) => {
                self.open_database()?.execute(
                    "UPDATE jobs SET state = 'test_failed', test_output = ?2, summary = '测试失败，等待继续指导', updated_at = ?3 WHERE id = ?1",
                    params![job_id, format!("{err:#}"), timestamp()],
                )?;
                self.emit(Some(job_id), "test", "测试失败，任务已返回人工指导阶段")?;
                self.notify_once(
                    job_id,
                    "test_failed",
                    &format!("{} 测试失败", branch.name),
                    &format!("{err:#}"),
                )
            }
        }
    }

    pub(crate) fn conflict_request(
        &self,
        job: &JobView,
    ) -> Result<(Config, BranchConfig, AutoResolveConflictRequest)> {
        let config = self.config()?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let connection = self.open_database()?;
        let (snapshot_json, files_json): (String, String) = connection.query_row(
            "SELECT snapshot_json, files_json FROM jobs WHERE id = ?1",
            params![job.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let request = AutoResolveConflictRequest {
            branch: job.branch.clone(),
            base: job.base_ref.clone(),
            snapshot: serde_json::from_str(&snapshot_json)?,
            files: serde_json::from_str(&files_json)?,
        };
        Ok((config, branch, request))
    }

    pub(crate) fn conversation_text(&self, job_id: &str) -> Result<String> {
        let job = self.job(job_id)?;
        if job.messages.is_empty() {
            return Ok("尚无人工补充要求".to_string());
        }
        Ok(job
            .messages
            .iter()
            .map(|message| format!("{}: {}", message.role, message.content))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}
