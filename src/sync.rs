use anyhow::Result;
use tracing::{info, warn};

use crate::command::CommandOutput;
use crate::config::{BranchConfig, Config, PushStrategy, SyncStrategy};
use crate::git::Git;
use crate::llm::{
    AutoResolveConflictRequest, AutoResolveDecision, ConflictAnalysisRequest, LlmService,
};
use crate::notify::Notifier;
use crate::report::{BranchReport, BranchStatus, SyncReport};
use crate::text::truncate_to_char_boundary;

const MAX_REPORTED_COMMITS: usize = 12;
const MAX_REPORTED_FILES: usize = 30;

struct AutoResolveOutcome {
    applied: bool,
    details: Vec<String>,
}

enum AutoContinueOutcome {
    Applied(Vec<String>),
    Stopped {
        snapshot: crate::git::ConflictSnapshot,
        details: Vec<String>,
    },
}

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
        let remote_before = self
            .git
            .remote_head(&self.config.repo.fork_remote, &branch.name)?;
        self.notify_sync_start(branch, &base)?;

        let sync_output = match branch.sync {
            SyncStrategy::Rebase => self.git.rebase(&base)?,
            SyncStrategy::Merge => self.git.merge(&base)?,
        };

        let mut auto_resolve_details = Vec::new();
        if !sync_output.success() {
            warn!("branch {} has conflicts", branch.name);
            let snapshot = self.git.conflict_snapshot(80 * 1024)?;
            if snapshot.files.is_empty() {
                match self.try_continue_autoresolved_sync(branch, &sync_output)? {
                    Some(AutoContinueOutcome::Applied(details)) => {
                        auto_resolve_details = details;
                    }
                    Some(AutoContinueOutcome::Stopped { snapshot, details }) => {
                        self.git.abort_rebase_or_merge();
                        return Ok(self.conflict_report(
                            branch,
                            &base,
                            &base_head,
                            &before_head,
                            sync_output.status,
                            snapshot,
                            upstream_commits,
                            details,
                        ));
                    }
                    None => {
                        self.git.abort_rebase_or_merge();
                        return Ok(self.conflict_report(
                            branch,
                            &base,
                            &base_head,
                            &before_head,
                            sync_output.status,
                            snapshot,
                            upstream_commits,
                            Vec::new(),
                        ));
                    }
                }
            } else if let Some(outcome) =
                self.try_auto_resolve_conflict(branch, &base, snapshot.clone())?
            {
                if outcome.applied {
                    auto_resolve_details = outcome.details;
                } else {
                    self.git.abort_rebase_or_merge();
                    return Ok(self.conflict_report(
                        branch,
                        &base,
                        &base_head,
                        &before_head,
                        sync_output.status,
                        snapshot,
                        upstream_commits,
                        outcome.details,
                    ));
                }
            } else {
                self.git.abort_rebase_or_merge();
                return Ok(self.conflict_report(
                    branch,
                    &base,
                    &base_head,
                    &before_head,
                    sync_output.status,
                    snapshot,
                    upstream_commits,
                    Vec::new(),
                ));
            }
        }

        for test in &branch.tests {
            let output = self.git.run_test(test)?;
            if !output.success() {
                let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail(format!("test failed: {test}"))
                    .detail(format!("exit code: {}", output.status));
                if !auto_resolve_details.is_empty() {
                    for detail in auto_resolve_details {
                        entry.push_detail(detail);
                    }
                }
                if !output.stderr.trim().is_empty() {
                    entry.push_detail(format!("stderr: {}", one_line(&output.stderr)));
                }
                return Ok(entry);
            }
        }

        if branch.tests.is_empty()
            && branch.auto_resolve.enabled
            && branch.auto_resolve.require_tests
            && !auto_resolve_details.is_empty()
        {
            return Ok(
                BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                    .active()
                    .detail("auto resolve failed: require_tests is true but no tests configured"),
            );
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
                if let Some(report) =
                    self.verify_remote_before_push(branch, remote_before.as_deref())?
                {
                    return Ok(report);
                }
                let output = self
                    .git
                    .push(&self.config.repo.fork_remote, &branch.name, false)?;
                if !output.success() {
                    return Ok(push_failed_report(branch, output.status, output.stderr));
                }
            }
            PushStrategy::ForceWithLease => {
                if let Some(report) =
                    self.verify_remote_before_push(branch, remote_before.as_deref())?
                {
                    return Ok(report);
                }
                let output = if let Some(expected_remote_head) = remote_before.as_deref() {
                    self.git.push_with_lease(
                        &self.config.repo.fork_remote,
                        &branch.name,
                        expected_remote_head,
                    )?
                } else {
                    self.git
                        .push(&self.config.repo.fork_remote, &branch.name, false)?
                };
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
                "remote before push: {remote_branch} @ {}",
                short_head(remote_before)
            ));
        } else {
            entry.push_detail(format!("remote before push: {remote_branch} not found"));
        }
        push_commit_details(&mut entry, "upstream commits included", &upstream_commits);
        push_commit_details(&mut entry, "commits pushed to remote", &commits_to_push);
        push_list_details(&mut entry, "files pushed to remote", &files_to_push);
        for detail in auto_resolve_details {
            entry.push_detail(detail);
        }
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

    fn verify_remote_before_push(
        &self,
        branch: &BranchConfig,
        expected_remote_head: Option<&str>,
    ) -> Result<Option<BranchReport>> {
        self.git
            .fetch_branch(&self.config.repo.fork_remote, &branch.name)?;
        let current_remote_head = self
            .git
            .remote_head(&self.config.repo.fork_remote, &branch.name)?;
        if current_remote_head.as_deref() == expected_remote_head {
            return Ok(None);
        }

        let remote_branch = format!("{}/{}", self.config.repo.fork_remote, branch.name);
        Ok(Some(
            BranchReport::new(&branch.name, branch.kind, BranchStatus::Failed)
                .active()
                .detail(branch_note_detail(branch))
                .detail("push blocked: remote branch changed before push")
                .detail(format!("remote branch: {remote_branch}"))
                .detail(format!(
                    "expected remote head: {}",
                    display_remote_head(expected_remote_head)
                ))
                .detail(format!(
                    "current remote head: {}",
                    display_remote_head(current_remote_head.as_deref())
                ))
                .detail("rerun sync after fetching the latest remote branch"),
        ))
    }

    fn conflict_report(
        &self,
        branch: &BranchConfig,
        base: &str,
        base_head: &str,
        before_head: &str,
        sync_status: i32,
        snapshot: crate::git::ConflictSnapshot,
        upstream_commits: Vec<String>,
        auto_resolve_details: Vec<String>,
    ) -> BranchReport {
        let mut entry = BranchReport::new(&branch.name, branch.kind, BranchStatus::Conflict)
            .active()
            .detail(branch_note_detail(branch))
            .detail(format!("before sync: {before_head}"))
            .detail(format!("target base: {base} @ {base_head}"))
            .detail(format!(
                "sync failed with code {} against {}",
                sync_status, base
            ))
            .detail(format!("conflict files: {}", snapshot.files.join(", ")));
        push_commit_details(&mut entry, "upstream commits planned", &upstream_commits);
        for detail in auto_resolve_details {
            entry.push_detail(detail);
        }
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
            base: base.to_string(),
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
        entry
    }

    fn try_auto_resolve_conflict(
        &self,
        branch: &BranchConfig,
        base: &str,
        snapshot: crate::git::ConflictSnapshot,
    ) -> Result<Option<AutoResolveOutcome>> {
        let config = &branch.auto_resolve;
        if !config.enabled {
            return Ok(None);
        }

        let mut details = vec!["auto resolve: enabled".to_string()];
        if config.allowed_paths.is_empty() {
            details.push("auto resolve skipped: allowed_paths is empty".to_string());
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }
        if snapshot.files.len() > config.max_conflict_files {
            details.push(format!(
                "auto resolve skipped: {} conflict files exceeds limit {}",
                snapshot.files.len(),
                config.max_conflict_files
            ));
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }
        if let Some(path) = snapshot
            .files
            .iter()
            .find(|path| !path_is_allowed(path, &config.allowed_paths))
        {
            details.push(format!("auto resolve skipped: path not allowed: {path}"));
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }

        let files = self
            .git
            .conflict_file_contents(&snapshot.files, config.max_file_bytes)?;
        let request = AutoResolveConflictRequest {
            branch: branch.name.clone(),
            base: base.to_string(),
            snapshot: snapshot.clone(),
            files,
        };
        let decision = match self.llm.auto_resolve_conflict(&request) {
            Ok(Some(decision)) => decision,
            Ok(None) => {
                details.push("auto resolve skipped: LLM disabled".to_string());
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    details,
                }));
            }
            Err(err) => {
                details.push(format!("auto resolve failed: {err:#}"));
                return Ok(Some(AutoResolveOutcome {
                    applied: false,
                    details,
                }));
            }
        };

        details.push(format!("auto resolve risk: {}", decision.risk));
        details.push(format!(
            "auto resolve summary: {}",
            one_line(&decision.summary)
        ));
        if !decision.risk.eq_ignore_ascii_case("low") {
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }
        if let Err(reason) = validate_auto_resolve_decision(&decision, &snapshot.files) {
            details.push(format!("auto resolve rejected: {reason}"));
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }

        for file in &decision.files {
            self.git.write_file(&file.path, &file.content)?;
            self.git.add_file(&file.path)?;
        }
        let output = self.git.continue_sync(branch.sync)?;
        if !output.success() {
            details.push(format!(
                "auto resolve failed: continue sync exited {}",
                output.status
            ));
            if !output.stderr.trim().is_empty() {
                details.push(format!("continue stderr: {}", one_line(&output.stderr)));
            }
            return Ok(Some(AutoResolveOutcome {
                applied: false,
                details,
            }));
        }

        details.push(format!(
            "auto resolve applied files: {}",
            decision.files.len()
        ));
        Ok(Some(AutoResolveOutcome {
            applied: true,
            details,
        }))
    }

    fn try_continue_autoresolved_sync(
        &self,
        branch: &BranchConfig,
        first_output: &CommandOutput,
    ) -> Result<Option<AutoContinueOutcome>> {
        if !has_staged_changes(&self.git)? {
            return Ok(None);
        }

        let mut details = vec![
            "rerere/autostaged resolution detected: continuing sync".to_string(),
            format!(
                "initial continue stderr: {}",
                one_line(&first_output.stderr)
            ),
        ];
        let mut last_head = self.git.head().unwrap_or_default();
        for _ in 0..20 {
            let output = self.git.continue_sync(branch.sync)?;
            if output.success() {
                details.push("rerere/autostaged resolution applied".to_string());
                return Ok(Some(AutoContinueOutcome::Applied(details)));
            }
            if !output.stderr.trim().is_empty() {
                details.push(format!("continue stderr: {}", one_line(&output.stderr)));
            }

            let snapshot = self.git.conflict_snapshot(80 * 1024)?;
            if !snapshot.files.is_empty() {
                details.push("continue stopped on another conflict".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }

            let current_head = self.git.head().unwrap_or_default();
            if current_head == last_head {
                details.push("continue did not advance HEAD; stopped retrying".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }
            last_head = current_head;
            if !has_staged_changes(&self.git)? {
                details.push("continue stopped without staged changes".to_string());
                return Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }));
            }
        }

        let snapshot = self.git.conflict_snapshot(80 * 1024)?;
        details.push("continue retried more than 20 times; stopped".to_string());
        Ok(Some(AutoContinueOutcome::Stopped { snapshot, details }))
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

        let raw_report = report.render_email_text();
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

fn display_remote_head(head: Option<&str>) -> String {
    head.map(short_head)
        .unwrap_or_else(|| "not found".to_string())
}

fn short_head(head: &str) -> String {
    head.chars().take(8).collect()
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

fn validate_auto_resolve_decision(
    decision: &AutoResolveDecision,
    conflict_files: &[String],
) -> std::result::Result<(), String> {
    if decision.files.is_empty() {
        return Err("no resolved files returned".to_string());
    }

    for file in &decision.files {
        if !conflict_files.iter().any(|path| path == &file.path) {
            return Err(format!(
                "resolved file is not a conflict file: {}",
                file.path
            ));
        }
        if file.content.contains("<<<<<<<")
            || file.content.contains("=======")
            || file.content.contains(">>>>>>>")
        {
            return Err(format!(
                "resolved file still contains conflict markers: {}",
                file.path
            ));
        }
        if file.content.contains("... file truncated by TermiteRS ...") {
            return Err(format!(
                "resolved file was based on truncated content: {}",
                file.path
            ));
        }
    }

    Ok(())
}

fn has_staged_changes(git: &Git) -> Result<bool> {
    let output = git.run_git(&["diff", "--cached", "--quiet"])?;
    match output.status {
        0 => Ok(false),
        1 => Ok(true),
        _ => anyhow::bail!("failed to inspect staged changes: {}", output.stderr.trim()),
    }
}

fn path_is_allowed(path: &str, allowed_paths: &[String]) -> bool {
    let normalized = path.replace('\\', "/");
    allowed_paths.iter().any(|allowed| {
        let allowed = allowed.replace('\\', "/");
        let allowed = allowed.trim_end_matches('/');
        normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
    })
}

fn one_line(text: &str) -> String {
    let mut line = text.replace('\r', "").replace('\n', " | ");
    if line.len() > 500 {
        truncate_to_char_boundary(&mut line, 500);
        line.push_str("...");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::ResolvedFile;

    #[test]
    fn allowed_path_does_not_match_neighbor_prefix() {
        let allowed = vec!["src".to_string()];

        assert!(path_is_allowed("src/char/Linnai.py", &allowed));
        assert!(!path_is_allowed("src2/char/Linnai.py", &allowed));
    }

    #[test]
    fn auto_resolve_rejects_conflict_markers() {
        let decision = AutoResolveDecision {
            risk: "low".to_string(),
            summary: "test".to_string(),
            files: vec![ResolvedFile {
                path: "src/char/Linnai.py".to_string(),
                content: "<<<<<<< HEAD\nx\n>>>>>>> upstream".to_string(),
            }],
        };
        let conflict_files = vec!["src/char/Linnai.py".to_string()];

        assert!(validate_auto_resolve_decision(&decision, &conflict_files).is_err());
    }
}
