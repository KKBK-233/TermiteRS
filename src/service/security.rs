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
use super::util::{configured_branch, timestamp};

impl ServiceState {
    /// 将已通过测试的候选修改直接推送；远端 SHA 变化时仍拒绝覆盖。
    pub(crate) fn push_reviewed_job(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        let config = self.config()?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        self.transition_state(
            job_id,
            &["waiting_push"],
            "pushing",
            "正在校验远端并自动推送",
        )?;
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
        let head_output = git.run_git(&["rev-parse", "HEAD"])?;
        anyhow::ensure!(
            head_output.success(),
            "无法读取候选提交：{}",
            head_output.stderr
        );
        let candidate_head = head_output.stdout.trim();
        git.fetch_branch(&config.repo.fork_remote, &branch.name)?;
        let current_remote = git
            .remote_head(&config.repo.fork_remote, &branch.name)?
            .unwrap_or_default();
        if current_remote != job.remote_head && current_remote != candidate_head {
            bail!(
                "远端分支已变化，拒绝推送。expected={} current={}",
                display_remote_head(&job.remote_head),
                display_remote_head(&current_remote)
            );
        }
        if current_remote != candidate_head {
            let output = if job.remote_head.is_empty() {
                git.push_new_branch_with_lease(&config.repo.fork_remote, &branch.name)?
            } else if require_lease || matches!(branch.push, PushStrategy::ForceWithLease) {
                git.push_with_lease(&config.repo.fork_remote, &branch.name, &job.remote_head)?
            } else {
                let refspec = format!("HEAD:refs/heads/{}", branch.name);
                git.run_git(&["push", &config.repo.fork_remote, &refspec])?
            };
            if !output.success() {
                bail!("推送失败：{}", output.stderr.trim());
            }
        }
        // 分支推送成功后立即记录新基线；标签失败时重试只补发标签。
        self.open_database()?.execute(
            "UPDATE jobs SET remote_head = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, candidate_head, timestamp()],
        )?;
        ensure_release_tag(git, &config.repo.fork_remote, &branch.release)
    }

    pub(crate) fn abandon(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        self.transition_state(
            job_id,
            &["waiting_guidance", "test_failed", "waiting_push", "failed"],
            "abandoning",
            "正在放弃并清理任务",
        )?;
        let result = (|| {
            if !job.worktree_path.is_empty() && Path::new(&job.worktree_path).exists() {
                Git::new(&job.worktree_path).abort_rebase_or_merge();
            }
            self.remove_worktree(job_id)?;
            self.set_state(job_id, "abandoned", "任务已由管理员放弃")
        })();
        if let Err(err) = &result {
            let _ = self.set_state(job_id, "failed", &format!("放弃任务时清理失败：{err:#}"));
        }
        result
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        process::Command,
        sync::{Arc, Mutex},
    };

    use rusqlite::params;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use crate::{config::Config, git::Git};

    use super::ServiceState;

    #[test]
    fn tag_failure_retries_without_replacing_remote_branch() {
        let root = std::env::temp_dir().join(format!("termiters-tag-retry-{}", Uuid::new_v4()));
        let repo = root.join("repo");
        let remote = root.join("fork.git");
        fs::create_dir_all(&repo).unwrap();
        let bare = Command::new("git")
            .args(["init", "--bare"])
            .arg(&remote)
            .output()
            .unwrap();
        assert!(bare.status.success());
        let git = Git::new(&repo);
        run(&git, &["init"]);
        run(&git, &["config", "user.name", "TermiteRS Test"]);
        run(&git, &["config", "user.email", "termite@example.com"]);
        fs::write(repo.join("sample.txt"), "base\n").unwrap();
        run(&git, &["add", "sample.txt"]);
        run(&git, &["commit", "-m", "base"]);
        run(&git, &["branch", "-M", "main"]);
        run(&git, &["remote", "add", "fork", remote.to_str().unwrap()]);
        run(&git, &["push", "fork", "main"]);
        let base = head(&git);
        fs::write(repo.join("sample.txt"), "candidate\n").unwrap();
        run(&git, &["commit", "-am", "candidate"]);
        let candidate = head(&git);

        let mut config: Config = serde_yaml::from_str(
            "repo:\n  path: .\n  upstream: unused\n  fork: unused\nbranches:\n  - name: main\n    push: force-with-lease\n    release:\n      enabled: true\n      tag_prefix: bad prefix\n",
        )
        .unwrap();
        config.repo.path = repo.clone();
        let data_dir = root.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let (events, _) = broadcast::channel(8);
        let state = ServiceState {
            config_path: root.join("termite.yml"),
            data_dir: data_dir.clone(),
            database_path: data_dir.join("termite.db"),
            events,
            repository_lock: Arc::new(Mutex::new(())),
        };
        state.initialize_database().unwrap();
        let job_id = state.create_job("sync", "main").unwrap();
        state.open_database().unwrap().execute(
            "UPDATE jobs SET worktree_path = ?2, remote_head = ?3, state = 'waiting_push' WHERE id = ?1",
            params![job_id, repo.to_str().unwrap(), base],
        ).unwrap();

        assert!(
            state
                .push_job(&config, &config.branches[0], &git, &job_id, true)
                .is_err()
        );
        assert_eq!(
            git.remote_head("fork", "main").unwrap().as_deref(),
            Some(candidate.as_str())
        );
        assert_eq!(state.job(&job_id).unwrap().remote_head, candidate);

        config.branches[0].release.tag_prefix = "v".to_string();
        assert_eq!(
            state
                .push_job(&config, &config.branches[0], &git, &job_id, true)
                .unwrap(),
            Some("v0".to_string())
        );
        assert_eq!(
            git.remote_head("fork", "main").unwrap().as_deref(),
            Some(candidate.as_str())
        );
        assert!(
            git.run_git(&["ls-remote", "--tags", "fork", "refs/tags/v0"])
                .unwrap()
                .stdout
                .contains(&candidate)
        );

        fs::write(repo.join("sample.txt"), "another candidate\n").unwrap();
        run(&git, &["commit", "-am", "another candidate"]);
        state
            .open_database()
            .unwrap()
            .execute(
                "UPDATE jobs SET remote_head = ?2 WHERE id = ?1",
                params![job_id, base],
            )
            .unwrap();
        assert!(
            state
                .push_job(&config, &config.branches[0], &git, &job_id, true)
                .is_err()
        );
        assert_eq!(
            git.remote_head("fork", "main").unwrap().as_deref(),
            Some(candidate.as_str())
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn run(git: &Git, args: &[&str]) {
        let output = git.run_git(args).unwrap();
        assert!(output.success(), "git {args:?}: {}", output.stderr);
    }

    fn head(git: &Git) -> String {
        git.run_git(&["rev-parse", "HEAD"])
            .unwrap()
            .stdout
            .trim()
            .to_string()
    }
}
