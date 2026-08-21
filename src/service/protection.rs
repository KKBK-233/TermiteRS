use anyhow::Result;
use rusqlite::params;
use tracing::error;

use crate::protection::{OsvAdvisorySignal, ProtectionStore, investigate_security_signal};

use super::{state::ServiceState, types::ProtectionInvestigationRequest, util::timestamp};

impl ServiceState {
    pub(crate) fn execute_protection_investigation(
        &self,
        job_id: &str,
        request: ProtectionInvestigationRequest,
    ) {
        if let Err(error) = self.execute_protection_investigation_inner(job_id, request) {
            let details = format!("{error:#}");
            error!("protection investigation {job_id} failed: {details}");
            let _ = self.set_state(job_id, "failed", &details);
        }
    }

    /// 外部消息任务复用服务状态与事件流，但仓库检查和候选生成仍在独占锁内完成。
    fn execute_protection_investigation_inner(
        &self,
        job_id: &str,
        request: ProtectionInvestigationRequest,
    ) -> Result<()> {
        self.set_state(job_id, "running", "正在隔离调查外部安全消息")?;
        let _guard = self
            .repository_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        let config = self.config()?;
        let output = investigate_security_signal(
            &config,
            &request.summary,
            request.reference.as_deref(),
            &request.content,
            request.branch.as_deref(),
        )?;
        let output_json = serde_json::to_string_pretty(&output)?;
        let worktree_path = output
            .candidate
            .as_ref()
            .map(|candidate| candidate.worktree_path.as_str())
            .unwrap_or("");
        let risk = if output.finding.affected == Some(true) {
            output.finding.severity.as_str()
        } else {
            "none"
        };
        self.open_database()?.execute(
            "UPDATE jobs SET risk = ?2, summary = ?3, worktree_path = ?4,
             test_output = ?5, updated_at = ?6 WHERE id = ?1",
            params![
                job_id,
                risk,
                output.finding.summary,
                worktree_path,
                output_json,
                timestamp(),
            ],
        )?;
        if let Some(error) = output.candidate_error {
            self.set_state(job_id, "failed", &format!("安全候选失败关闭：{error}"))
        } else if output.finding.affected == Some(true) {
            self.set_state(
                job_id,
                "completed",
                "安全消息已调查，候选和投送草稿等待人工处理",
            )
        } else {
            self.set_state(job_id, "completed", "安全消息调查完成，当前无需修复")
        }
    }

    pub(crate) fn execute_osv_advisories(
        &self,
        job_id: &str,
        advisories: Vec<OsvAdvisorySignal>,
        branch: String,
    ) {
        if let Err(error) = self.execute_osv_advisories_inner(job_id, advisories, &branch) {
            let details = format!("{error:#}");
            error!("OSV advisory job {job_id} failed: {details}");
            let _ = self.set_state(job_id, "failed", &details);
        }
    }

    /// 同一轮 OSV 公告串行调查，避免多个候选并发修改 Git worktree 管理状态。
    fn execute_osv_advisories_inner(
        &self,
        job_id: &str,
        advisories: Vec<OsvAdvisorySignal>,
        branch: &str,
    ) -> Result<()> {
        self.set_state(job_id, "running", "正在调查 OSV 依赖安全公告")?;
        let _guard = self
            .repository_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        let config = self.config()?;
        let store = ProtectionStore::open(&self.database_path)?;
        let mut outputs = Vec::new();
        let mut failures = Vec::new();
        let mut affected = 0usize;
        let mut last_worktree = String::new();
        for advisory in advisories {
            for cursor in &advisory.related_ids {
                store.mark_osv_advisory(&cursor.id, &cursor.modified, "running", None)?;
            }
            match investigate_security_signal(
                &config,
                &advisory.summary,
                Some(&advisory.reference),
                &advisory.content,
                Some(branch),
            ) {
                Ok(output) => {
                    if output.finding.affected == Some(true) {
                        affected += 1;
                    }
                    if let Some(candidate) = &output.candidate {
                        last_worktree = candidate.worktree_path.clone();
                    }
                    let state = if output.candidate_error.is_some() {
                        "failed"
                    } else {
                        "completed"
                    };
                    for cursor in &advisory.related_ids {
                        store.mark_osv_advisory(
                            &cursor.id,
                            &cursor.modified,
                            state,
                            output.candidate_error.as_deref(),
                        )?;
                    }
                    if let Some(error) = &output.candidate_error {
                        failures.push(format!("{}: {error}", advisory.id));
                    }
                    outputs.push(output);
                }
                Err(error) => {
                    let details = format!("{error:#}");
                    for cursor in &advisory.related_ids {
                        store.mark_osv_advisory(
                            &cursor.id,
                            &cursor.modified,
                            "failed",
                            Some(&details),
                        )?;
                    }
                    failures.push(format!("{}: {details}", advisory.id));
                }
            }
        }
        self.open_database()?.execute(
            "UPDATE jobs SET risk = ?2, summary = ?3, worktree_path = ?4,
             test_output = ?5, updated_at = ?6 WHERE id = ?1",
            params![
                job_id,
                if affected > 0 { "security" } else { "none" },
                format!(
                    "OSV 调查完成：影响 {} 项，失败 {} 项",
                    affected,
                    failures.len()
                ),
                last_worktree,
                serde_json::to_string_pretty(&outputs)?,
                timestamp(),
            ],
        )?;
        if failures.is_empty() {
            self.set_state(job_id, "completed", "OSV 依赖安全公告调查完成")
        } else {
            self.set_state(
                job_id,
                "failed",
                &format!("OSV 调查失败关闭：{}", failures.join(" | ")),
            )
        }
    }
}
