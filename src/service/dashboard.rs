use anyhow::Result;

use crate::git::Git;

use super::state::ServiceState;
use super::types::{ACTIVE_STATES, BranchDashboard, Dashboard, StatusView};
use super::util::optional_short_ref;

impl ServiceState {
    pub(crate) fn dashboard(&self) -> Result<Dashboard> {
        let config = self.config()?;
        let git = Git::new(config.repo.path.clone());
        let jobs = self.jobs()?;
        let active = jobs
            .iter()
            .filter(|job| ACTIVE_STATES.contains(&job.state.as_str()))
            .collect::<Vec<_>>();
        let upstream_ref = format!(
            "{}/{}",
            config.repo.upstream_remote, config.repo.base_branch
        );
        let upstream_head = optional_short_ref(&git, &upstream_ref);
        let mut branches = Vec::new();
        for branch in &config.branches {
            let local_head = optional_short_ref(&git, &branch.name);
            let remote_ref = format!("{}/{}", config.repo.fork_remote, branch.name);
            let remote_head = optional_short_ref(&git, &remote_ref);
            let compare_ref = if local_head.is_some() {
                Some(branch.name.clone())
            } else if remote_head.is_some() {
                Some(remote_ref.clone())
            } else {
                None
            };
            let upstream_count = match (compare_ref.as_deref(), upstream_head.as_ref()) {
                (Some(compare_ref), Some(_)) => git.ahead_behind(compare_ref, &upstream_ref).ok(),
                _ => None,
            };
            let current = active.iter().find(|job| job.branch == branch.name);
            branches.push(BranchDashboard {
                name: branch.name.clone(),
                note: branch.note.clone().unwrap_or_default(),
                local_head,
                upstream_head: upstream_head.clone(),
                remote_head,
                upstream_ahead: upstream_count.map(|count| count.ahead),
                upstream_behind: upstream_count.map(|count| count.behind),
                current_job_id: current.map(|job| job.id.clone()),
                current_state: current.map(|job| job.state.clone()),
            });
        }
        Ok(Dashboard {
            repository: config.repo.path.display().to_string(),
            fork_url: config.repo.fork.clone(),
            upstream_url: config.repo.upstream.clone(),
            branches,
            jobs,
            stats: self.job_stats()?,
        })
    }

    pub(crate) fn status_view(&self) -> Result<StatusView> {
        let config = self.config()?;
        let jobs = self.jobs()?;
        let active_jobs = jobs
            .iter()
            .filter(|job| ACTIVE_STATES.contains(&job.state.as_str()))
            .count();
        Ok(StatusView {
            repository: config.repo.path.display().to_string(),
            upstream_url: config.repo.upstream,
            fork_url: config.repo.fork,
            branch_count: config.branches.len(),
            active_jobs,
            stats: self.job_stats()?,
        })
    }

    pub(crate) fn branches_view(&self) -> Result<Vec<BranchDashboard>> {
        Ok(self.dashboard()?.branches)
    }

    pub(crate) fn branch_view(&self, name: &str) -> Result<BranchDashboard> {
        self.branches_view()?
            .into_iter()
            .find(|branch| branch.name == name)
            .ok_or_else(|| anyhow::anyhow!("分支不在 TermiteRS 白名单中：{name}"))
    }
}
