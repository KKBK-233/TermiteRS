use anyhow::Result;
use tracing::{info, warn};

use crate::config::{BranchConfig, Config, PushStrategy, SyncStrategy};
use crate::git::Git;
use crate::llm::{ConflictAnalysisRequest, LlmService};
use crate::notify::Notifier;
use crate::report::{BranchReport, BranchStatus, SyncReport};

const MAX_REPORTED_COMMITS: usize = 12;
const MAX_REPORTED_FILES: usize = 30;

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub branch: Option<String>,
    pub dry_run: bool,
    pub notify_on_noop: bool,
}

impl SyncOptions {
    pub fn status_only() -> Self {
        Self {
            branch: None,
            dry_run: true,
            notify_on_noop: false,
        }
    }
}

pub struct SyncRunner {
    config: Config,
    options: SyncOptions,
    git: Git,
    llm: LlmService,
    notifier: Notifier,
}

impl SyncRunner {
    pub fn new(config: Config, options: SyncOptions) -> Self {
        let git = Git::new(config.repo.path.clone());
        let llm = LlmService::new(config.llm.clone());
        let notifier = Notifier::new(config.notify.clone());
        Self {
            config,
            options,
            git,
            llm,
            notifier,
        }
    }

    pub fn status(&self) -> Result<SyncReport> {
        self.git.ensure_repo()?;
        self.git.ensure_remotes(&self.config.repo)?;
        self.git.fetch_all(&self.config.repo)?;

        let mut report = SyncReport::default();
        for branch in self.selected_branches() {
            report.push(self.status_branch(branch)?);
        }
        Ok(report)
    }

    pub fn run(&self) -> Result<SyncReport> {
        self.git.ensure_repo()?;
        self.git.ensure_remotes(&self.config.repo)?;
        self.git.fetch_all(&self.config.repo)?;

        let mut report = SyncReport::default();
        if self.options.dry_run {
            for branch in self.selected_branches() {
                report.push(
                    BranchReport::new(&branch.name, branch.kind, BranchStatus::Skipped)
                        .detail("dry run: fetch completed, sync/test/push skipped"),
                );
            }
            return Ok(report);
        }

        for branch in self.selected_branches() {
            let branch_report = self.sync_branch(branch)?;
            report.push(branch_report);
        }
        if self.notifier.sync_summary_enabled() {
            if self.options.notify_on_noop || report.has_activity() {
                self.notify_sync_summary(&report)?;
            } else {
                info!("sync summary skipped because daemon tick had no activity");
            }
        } else {
            self.notify_failed_branches(&report)?;
        }
        Ok(report)
    }

    fn selected_branches(&self) -> Vec<&BranchConfig> {
        self.config
            .branches
            .iter()
            .filter(|branch| {
                self.options
                    .branch
                    .as_ref()
                    .map(|selected| selected == &branch.name)
                    .unwrap_or(true)
            })
            .collect()
    }

    fn sync_branch(&self, branch: &BranchConfig) -> Result<BranchReport> {
        info!("sync branch {}", branch.name);
        self.git.checkout(&branch.name)?;
        let base = format!(
            "{}/{}",
            self.config.repo.upstream_remote, self.config.repo.base_branch
        );
        let before_head = self.git.head()?;
        let base_head = self.git.short_ref(&base)?;
        let upstream_commits = self.upstream_commits_since_branch_base(&base)?;
        let remote_branch = format!("{}/{}", self.config.repo.fork_remote, branch.name);
        let remote_before = if self
            .git
            .remote_branch_exists(&self.config.repo.fork_remote, &branch.name)?
        {
            Some(self.git.short_ref(&remote_branch)?)
        } else {
            None
        };
        self.notify_sync_start(branch, &base)?;

        let sync_output = match branch.sync {
            SyncStrategy::Rebase => self.git.rebase(&base)?,
            SyncStrategy::Merge => self.git.merge(&base)?,
        };

        if !sync_output.success() {
            warn!("branch {} has conflicts", branch.name);
            let snapshot = self.git.conflict_snapshot(80 * 1024)?;
            self.git.abort_rebase_or_merge();
            let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Conflict)
                .active()
                .detail(branch_note_detail(branch))
                .detail(format!("before sync: {before_head}"))
                .detail(format!("target base: {base} @ {base_head}"))
                .detail(format!(
                    "sync failed with code {} against {}",
                    sync_output.status, base
                ))
                .detail(format!("conflict files: {}", snapshot.files.join(", ")));
            push_commit_details(&mut entry, "upstream commits planned", &upstream_commits);
            if !snapshot.status.trim().is_empty() {
                entry.push_detail(format!(
                    "git status: {}",
                    snapshot.status.replace('\n', "; ")
                ));
            }
            if !snapshot.combined_diff.trim().is_empty() {
                entry.push_detail("combined diff captured for future LLM analysis");
            }
            let analysis_request = ConflictAnalysisRequest {
                branch: branch.name.clone(),
                base,
                snapshot,
            };
            match self.llm.analyze_conflict(&analysis_request) {
                Ok(Some(analysis)) => {
                    entry.push_detail(format!("LLM analysis: {}", one_line(&analysis)));
                }
                Ok(None) => {
                    entry.push_detail("LLM analysis skipped");
                }
                Err(err) => {
                    entry.push_detail(format!("LLM analysis failed: {err:#}"));
                }
            }
            return Ok(entry);
        }

        for test in &branch.tests {
            let output = self.git.run_test(test)?;
            if !output.success() {
                let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail(format!("test failed: {test}"))
                    .detail(format!("exit code: {}", output.status));
                if !output.stderr.trim().is_empty() {
                    entry.push_detail(format!("stderr: {}", one_line(&output.stderr)));
                }
                return Ok(entry);
            }
        }

        let after_sync_head = self.git.head()?;
        let commits_to_push = if remote_before.is_some() {
            self.git
                .log_oneline(&format!("{remote_branch}..HEAD"), MAX_REPORTED_COMMITS)?
        } else {
            self.git.log_oneline("HEAD", MAX_REPORTED_COMMITS)?
        };
        let files_to_push = if remote_before.is_some() {
            self.git
                .changed_files(&format!("{remote_branch}..HEAD"), MAX_REPORTED_FILES)?
        } else {
            self.git
                .changed_files(
                    &format!("{}^..{}", after_sync_head, after_sync_head),
                    MAX_REPORTED_FILES,
                )
                .unwrap_or_default()
        };

        match branch.push {
            PushStrategy::None => {}
            PushStrategy::Normal => {
                let output = self
                    .git
                    .push(&self.config.repo.fork_remote, &branch.name, false)?;
                if !output.success() {
                    return Ok(push_failed_report(branch, output.status, output.stderr));
                }
            }
            PushStrategy::ForceWithLease => {
                let output = self
                    .git
                    .push(&self.config.repo.fork_remote, &branch.name, true)?;
                if !output.success() {
                    return Ok(push_failed_report(branch, output.status, output.stderr));
                }
            }
        }

        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Success);
        entry.head = Some(after_sync_head.clone());
        if !upstream_commits.is_empty()
            || !commits_to_push.is_empty()
            || !files_to_push.is_empty()
            || before_head != after_sync_head
        {
            entry.mark_active();
        }
        entry.push_detail(branch_note_detail(branch));
        entry.push_detail(format!("before sync: {before_head}"));
        entry.push_detail(format!("after sync: {after_sync_head}"));
        entry.push_detail(format!("target base: {base} @ {base_head}"));
        if let Some(remote_before) = &remote_before {
            entry.push_detail(format!(
                "remote before push: {remote_branch} @ {remote_before}"
            ));
        } else {
            entry.push_detail(format!("remote before push: {remote_branch} not found"));
        }
        push_commit_details(&mut entry, "upstream commits included", &upstream_commits);
        push_commit_details(&mut entry, "commits pushed to remote", &commits_to_push);
        push_list_details(&mut entry, "files pushed to remote", &files_to_push);
        if branch.tests.is_empty() {
            entry.push_detail("no tests configured");
        } else {
            entry.push_detail(format!("{} test command(s) passed", branch.tests.len()));
        }
        match branch.push {
            PushStrategy::None => {
                entry.push_detail("push skipped by config");
            }
            PushStrategy::Normal | PushStrategy::ForceWithLease => {
                entry.push_detail(format!("pushed to {remote_branch}"));
            }
        }
        Ok(entry)
    }

    fn upstream_commits_since_branch_base(&self, base: &str) -> Result<Vec<String>> {
        let Some(merge_base) = self.git.merge_base("HEAD", base)? else {
            return Ok(Vec::new());
        };
        self.git
            .log_oneline(&format!("{merge_base}..{base}"), MAX_REPORTED_COMMITS)
    }

    fn status_branch(&self, branch: &BranchConfig) -> Result<BranchReport> {
        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Skipped);
        entry.push_detail("status only: fetch completed, sync/test/push skipped");

        if !self.git.local_branch_exists(&branch.name)? {
            return Ok(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .detail("local branch not found"),
            );
        }

        entry.head = Some(self.git.short_ref(&branch.name)?);

        let base = format!(
            "{}/{}",
            self.config.repo.upstream_remote, self.config.repo.base_branch
        );
        if self.git.ref_exists(&base)? {
            let count = self.git.ahead_behind(&branch.name, &base)?;
            entry.push_detail(format!(
                "vs {base}: ahead {}, behind {}",
                count.ahead, count.behind
            ));
        } else {
            entry.push_detail(format!("base ref not found: {base}"));
        }

        if self
            .git
            .remote_branch_exists(&self.config.repo.fork_remote, &branch.name)?
        {
            let remote_branch = format!("{}/{}", self.config.repo.fork_remote, branch.name);
            let count = self.git.ahead_behind(&branch.name, &remote_branch)?;
            entry.push_detail(format!(
                "vs {remote_branch}: ahead {}, behind {}",
                count.ahead, count.behind
            ));
        } else {
            entry.push_detail(format!(
                "remote branch not found: {}/{}",
                self.config.repo.fork_remote, branch.name
            ));
        }

        Ok(entry)
    }

    fn notify_if_needed(&self, report: &BranchReport) -> Result<()> {
        if report.status == BranchStatus::Success || report.status == BranchStatus::Skipped {
            return Ok(());
        }

        let subject = format!("{} {:?}", report.branch, report.status);
        let body = report.render_text();
        match self.notifier.send_failure(&subject, &body) {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!("failed to send notification for {}: {err:#}", report.branch);
            }
        }
        Ok(())
    }

    fn notify_failed_branches(&self, report: &SyncReport) -> Result<()> {
        for entry in &report.entries {
            self.notify_if_needed(entry)?;
        }
        Ok(())
    }

    fn notify_sync_start(&self, branch: &BranchConfig, base: &str) -> Result<()> {
        if !self.notifier.sync_start_enabled() {
            return Ok(());
        }

        match self
            .notifier
            .send_sync_start(&branch.name, base, branch.sync)
        {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!(
                    "failed to send sync start notification for {}: {err:#}",
                    branch.name
                );
            }
        }
        Ok(())
    }

    fn notify_sync_summary(&self, report: &SyncReport) -> Result<()> {
        if !self.notifier.sync_summary_enabled() {
            return Ok(());
        }

        let raw_report = report.render_text();
        let summary = match self.llm.summarize_sync_report(report) {
            Ok(Some(summary)) => summary,
            Ok(None) => raw_report.clone(),
            Err(err) => {
                warn!("failed to summarize sync report with LLM: {err:#}");
                raw_report.clone()
            }
        };

        match self.notifier.send_sync_summary(&summary, &raw_report) {
            Ok(true) => {}
            Ok(false) => {}
            Err(err) => {
                warn!("failed to send sync summary notification: {err:#}");
            }
        }
        Ok(())
    }
}

fn push_failed_report(branch: &BranchConfig, status: i32, stderr: String) -> BranchReport {
    BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
        .active()
        .detail(branch_note_detail(branch))
        .detail(format!("push failed with code {status}"))
        .detail(format!("stderr: {}", one_line(&stderr)))
}

fn branch_note_detail(branch: &BranchConfig) -> String {
    branch
        .note
        .as_ref()
        .map(|note| format!("note: {note}"))
        .unwrap_or_else(|| "note: none".to_string())
}

fn push_commit_details(entry: &mut BranchReport, title: &str, commits: &[String]) {
    if commits.is_empty() {
        entry.push_detail(format!("{title}: none"));
        return;
    }

    entry.push_detail(format!("{title} ({}):", commits.len()));
    for commit in commits {
        entry.push_detail(format!("  {commit}"));
    }
}

fn push_list_details(entry: &mut BranchReport, title: &str, items: &[String]) {
    if items.is_empty() {
        entry.push_detail(format!("{title}: none"));
        return;
    }

    entry.push_detail(format!("{title} ({}):", items.len()));
    for item in items {
        entry.push_detail(format!("  {item}"));
    }
}

fn one_line(text: &str) -> String {
    let mut line = text.replace('\r', "").replace('\n', " | ");
    if line.len() > 500 {
        line.truncate(500);
        line.push_str("...");
    }
    line
}
