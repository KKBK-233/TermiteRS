use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use tracing::warn;
use uuid::Uuid;

use crate::{
    config::{BranchConfig, Config, PushStrategy},
    git::Git,
    notify::Notifier,
};

use super::state::ServiceState;
use super::types::{CHALLENGE_TTL_SECONDS, ChallengeResponse};
use super::util::{configured_branch, dashboard_link, ensure_state, timestamp};

impl ServiceState {
    pub(crate) fn create_push_challenge(&self, job_id: &str) -> Result<ChallengeResponse> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_push"])?;
        let id = Uuid::new_v4().to_string();
        let expires = Utc::now().timestamp() + CHALLENGE_TTL_SECONDS;
        self.open_database()?.execute(
            "INSERT INTO challenges (id, job_id, expected_remote_head, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, job_id, job.remote_head, expires],
        )?;
        Ok(ChallengeResponse {
            challenge_id: id,
            expires_at: chrono::DateTime::from_timestamp(expires, 0)
                .context("invalid challenge expiry")?
                .to_rfc3339(),
        })
    }

    pub(crate) fn confirm_push(&self, challenge_id: &str, password: &str) -> Result<()> {
        self.enforce_password_rate_limit()?;
        let config = self.config()?;
        let hash = PasswordHash::new(&config.service.operation_password_hash)
            .map_err(|err| anyhow::anyhow!("操作密码哈希无效：{err}"))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_err()
        {
            bail!("操作密码错误");
        }

        let connection = self.open_database()?;
        let challenge = connection
            .query_row(
                "SELECT job_id, expected_remote_head, expires_at, used FROM challenges WHERE id = ?1",
                params![challenge_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .context("推送挑战不存在")?;
        if challenge.3 != 0 {
            bail!("推送挑战已经使用");
        }
        if challenge.2 < Utc::now().timestamp() {
            bail!("推送挑战已经过期");
        }
        connection.execute(
            "UPDATE challenges SET used = 1 WHERE id = ?1 AND used = 0",
            params![challenge_id],
        )?;

        let job = self.job(&challenge.0)?;
        ensure_state(&job, &["waiting_push"])?;
        self.set_state(&job.id, "pushing", "正在校验远端并推送")?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let git = Git::new(&job.worktree_path);
        git.fetch_branch(&config.repo.fork_remote, &job.branch)?;
        let current_remote = git
            .remote_head(&config.repo.fork_remote, &job.branch)?
            .unwrap_or_default();
        if current_remote != challenge.1 {
            self.set_state(
                &job.id,
                "waiting_push",
                "远端分支已经变化，需要重新检查后再推送",
            )?;
            bail!("远端 SHA 已变化，拒绝推送");
        }
        self.push_job(&config, &branch, &git, &job.id, true)?;
        self.remove_worktree(&job.id)?;
        self.set_state(&job.id, "completed", "人工确认的修改已推送")?;
        self.notify_once(
            &job.id,
            "pushed",
            &format!("{} 已推送", branch.name),
            "人工确认的功能冲突修改已经成功推送。",
        )
    }

    pub(crate) fn push_job(
        &self,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
        job_id: &str,
        require_lease: bool,
    ) -> Result<()> {
        if matches!(branch.push, PushStrategy::None) {
            return Ok(());
        }
        let job = self.job(job_id)?;
        git.fetch_branch(&config.repo.fork_remote, &branch.name)?;
        let current_remote = git
            .remote_head(&config.repo.fork_remote, &branch.name)?
            .unwrap_or_default();
        if current_remote != job.remote_head {
            bail!(
                "远端分支已变化，拒绝推送。expected={} current={}",
                display_remote_head(&job.remote_head),
                display_remote_head(&current_remote)
            );
        }
        let output = if require_lease || matches!(branch.push, PushStrategy::ForceWithLease) {
            if job.remote_head.is_empty() {
                let refspec = format!("HEAD:refs/heads/{}", branch.name);
                git.run_git(&["push", &config.repo.fork_remote, &refspec])?
            } else {
                git.push_with_lease(&config.repo.fork_remote, &branch.name, &job.remote_head)?
            }
        } else {
            let refspec = format!("HEAD:refs/heads/{}", branch.name);
            git.run_git(&["push", &config.repo.fork_remote, &refspec])?
        };
        if !output.success() {
            bail!("推送失败：{}", output.stderr.trim());
        }
        Ok(())
    }

    pub(crate) fn abandon(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(
            &job,
            &["waiting_guidance", "test_failed", "waiting_push", "failed"],
        )?;
        if !job.worktree_path.is_empty() && Path::new(&job.worktree_path).exists() {
            Git::new(&job.worktree_path).abort_rebase_or_merge();
        }
        self.remove_worktree(job_id)?;
        self.set_state(job_id, "abandoned", "任务已由管理员放弃")?;
        Ok(())
    }

    pub(crate) fn remove_worktree(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        if job.worktree_path.is_empty() {
            return Ok(());
        }
        let config = self.config()?;
        let main_git = Git::new(config.repo.path);
        let output = main_git.run_git(&["worktree", "remove", "--force", &job.worktree_path])?;
        if !output.success() && Path::new(&job.worktree_path).exists() {
            warn!("git worktree remove failed: {}", output.stderr.trim());
            fs::remove_dir_all(&job.worktree_path)?;
            let _ = main_git.run_git(&["worktree", "prune"]);
        }
        Ok(())
    }

    pub(crate) fn cleanup_failed_worktree(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        if !job.worktree_path.is_empty() && Path::new(&job.worktree_path).exists() {
            Git::new(&job.worktree_path).abort_rebase_or_merge();
            self.remove_worktree(job_id)?;
        }
        Ok(())
    }

    pub(crate) fn notify_once(
        &self,
        job_id: &str,
        event: &str,
        subject: &str,
        body: &str,
    ) -> Result<()> {
        let connection = self.open_database()?;
        if connection
            .query_row(
                "SELECT 1 FROM notifications WHERE job_id = ?1 AND event = ?2",
                params![job_id, event],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Ok(());
        }
        match Notifier::new(self.config()?.notify).send(subject, body) {
            Ok(true) => {
                connection.execute(
                    "INSERT INTO notifications (job_id, event, created_at) VALUES (?1, ?2, ?3)",
                    params![job_id, event, timestamp()],
                )?;
            }
            Ok(false) => {
                warn!("notification {event} was not sent because no channel is enabled");
            }
            Err(err) => {
                warn!("failed to send {event} notification: {err:#}");
            }
        }
        Ok(())
    }

    pub(crate) fn enforce_password_rate_limit(&self) -> Result<()> {
        let now = Instant::now();
        let mut attempts = self
            .password_attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("password rate limiter poisoned"))?;
        attempts.retain(|attempt| now.duration_since(*attempt) < Duration::from_secs(60));
        if attempts.len() >= 5 {
            bail!("操作密码尝试过于频繁，请稍后再试");
        }
        attempts.push(now);
        Ok(())
    }
}

fn display_remote_head(head: &str) -> &str {
    if head.is_empty() { "not found" } else { head }
}
