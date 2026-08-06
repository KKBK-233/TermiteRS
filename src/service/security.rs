use std::{fs, path::Path};

use anyhow::{Result, bail};
use rusqlite::{OptionalExtension, params};
use tracing::warn;

use crate::{
    config::{BranchConfig, Config, PushStrategy},
    git::Git,
    notify::Notifier,
    release::ensure_release_tag,
};

use super::state::ServiceState;
use super::util::{configured_branch, ensure_state, timestamp};

impl ServiceState {
    /// 将已通过测试的候选修改直接推送；远端 SHA 变化时仍拒绝覆盖。
    pub(crate) fn push_reviewed_job(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_push"])?;
        let config = self.config()?;
        self.set_state(&job.id, "pushing", "正在校验远端并自动推送")?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let git = Git::new(&job.worktree_path);
        let release_tag = match self.push_job(&config, &branch, &git, &job.id, true) {
            Ok(tag) => tag,
            Err(err) => {
                self.set_state(
                    &job.id,
                    "waiting_push",
                    &format!("自动推送失败，等待重试：{err:#}"),
                )?;
                return Err(err);
            }
        };
        let cleanup_error = self.remove_worktree(&job.id).err();
        let mut summary = match &release_tag {
            Some(tag) => format!("候选修改已自动推送，并发布标签 {tag}"),
            None => "候选修改已自动推送".to_string(),
        };
        if let Some(err) = cleanup_error {
            summary.push_str(&format!("；清理 worktree 失败：{err:#}"));
        }
        self.set_state(&job.id, "completed", &summary)?;
        self.notify_once(
            &job.id,
            "pushed",
            &format!("{} 已推送", branch.name),
            &summary,
        )
    }

    pub(crate) fn push_job(
        &self,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
        job_id: &str,
        require_lease: bool,
    ) -> Result<Option<String>> {
        if matches!(branch.push, PushStrategy::None) {
            return Ok(None);
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
        ensure_release_tag(git, &config.repo.fork_remote, &branch.release)
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
}

fn display_remote_head(head: &str) -> &str {
    if head.is_empty() { "not found" } else { head }
}
