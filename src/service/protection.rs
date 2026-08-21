use anyhow::Result;
use rusqlite::params;
use tracing::error;

use crate::protection::investigate_security_signal;

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
}
