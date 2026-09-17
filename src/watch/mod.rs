mod github;
pub mod model;
mod store;

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

use crate::config::{Config, WatchGithubConfig};
use crate::llm::LlmService;

use self::{
    github::GithubCollector,
    model::{
        PullRequestSnapshot, WatchAssessment, WatchAssessmentPlan, WatchEvent, WatchScanReport,
        WatchTask, WatchTaskPlan,
    },
    store::WatchStore,
};

pub struct WatchRunner {
    config: Config,
}

pub struct WatchSupervisor {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl WatchSupervisor {
    pub fn start(config: Config) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let runner = WatchRunner::new(config);
            while !thread_stop.load(Ordering::Relaxed) {
                for _ in 0..10 {
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_secs(1));
                }
                match runner.run_due_tasks() {
                    Ok(results) => {
                        for result in results
                            .into_iter()
                            .filter(|result| !result.contains("0 个新事件"))
                        {
                            println!("\n[watch] {result}");
                        }
                    }
                    Err(error) => eprintln!("watch 调度失败：{error:#}"),
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for WatchSupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl WatchRunner {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn scan(&self) -> Result<WatchScanReport> {
        anyhow::ensure!(self.config.watch.enabled, "watch.enabled 尚未启用");
        self.scan_scope("config", self.config.watch.github.clone())
    }

    fn scan_scope(
        &self,
        task_id: &str,
        github_config: WatchGithubConfig,
    ) -> Result<WatchScanReport> {
        let collector = GithubCollector::new(github_config);
        let author = collector.current_user()?;
        let repositories = collector.repositories()?;
        let store = WatchStore::open(&self.config.watch.data_dir)?;
        let initial_baseline = !store.initialized(task_id)?;
        let mut report = WatchScanReport {
            repositories_scanned: repositories.len(),
            initial_baseline,
            ..WatchScanReport::default()
        };
        let previous_snapshots = store.snapshots(task_id)?;
        let mut seen = HashSet::new();
        let mut successful_repositories = HashSet::new();

        for repository in repositories {
            let pull_requests = match collector.pull_requests(&repository, &author) {
                Ok(pull_requests) => pull_requests,
                Err(error) => {
                    report.warnings.push(format!("{repository}: {error:#}"));
                    continue;
                }
            };
            successful_repositories.insert(repository.clone());
            for snapshot in pull_requests {
                report.pull_requests_observed += 1;
                seen.insert(snapshot.key());
                if let Some(previous) = store.snapshot(task_id, &snapshot.key())? {
                    if previous != snapshot {
                        let changes = describe_changes(&previous, &snapshot);
                        let material = serde_json::to_string(&snapshot)?;
                        if let Some(event) = store.insert_event(
                            task_id,
                            &snapshot.key(),
                            "github-pr-changed",
                            &changes,
                            &snapshot.url,
                            &material,
                        )? {
                            report.events.push(event);
                        }
                    }
                } else if !initial_baseline
                    && let Some(event) = store.insert_event(
                        task_id,
                        &snapshot.key(),
                        "github-pr-discovered",
                        &format!("发现新的个人 PR：{}", snapshot.title),
                        &snapshot.url,
                        &snapshot.head_oid,
                    )?
                {
                    report.events.push(event);
                }
                store.upsert_snapshot(task_id, &snapshot)?;
                report.pull_requests.push(snapshot);
            }
        }

        for previous in previous_snapshots {
            if seen.contains(&previous.key())
                || !successful_repositories.contains(&previous.repository)
            {
                continue;
            }
            match collector.pull_request_lifecycle(&previous.repository, previous.number) {
                Ok(lifecycle) if lifecycle.state != "OPEN" => {
                    let kind = if lifecycle.state == "MERGED" {
                        "github-pr-merged"
                    } else {
                        "github-pr-closed"
                    };
                    let occurred_at = if lifecycle.state == "MERGED" {
                        &lifecycle.merged_at
                    } else {
                        &lifecycle.closed_at
                    };
                    let summary = format!(
                        "个人 PR 已{}：{}",
                        if lifecycle.state == "MERGED" {
                            "合并"
                        } else {
                            "关闭"
                        },
                        lifecycle.title
                    );
                    if let Some(event) = store.insert_event(
                        task_id,
                        &previous.key(),
                        kind,
                        &summary,
                        &lifecycle.url,
                        occurred_at,
                    )? {
                        report.events.push(event);
                    }
                    store.delete_snapshot(task_id, &previous.key())?;
                }
                Ok(_) => report.warnings.push(format!(
                    "{} 未出现在 open 列表但远端仍为 OPEN，已保留快照",
                    previous.key()
                )),
                Err(error) => report
                    .warnings
                    .push(format!("{} 无法确认关闭状态：{error:#}", previous.key())),
            }
        }
        store.mark_initialized(task_id)?;
        report.events_created = report.events.len();
        Ok(report)
    }

    pub fn status(&self) -> Result<Vec<PullRequestSnapshot>> {
        WatchStore::open(&self.config.watch.data_dir)?.snapshots("config")
    }

    pub fn events(&self, limit: usize) -> Result<Vec<WatchEvent>> {
        WatchStore::open(&self.config.watch.data_dir)?.events(limit)
    }

    pub fn assessments(&self, limit: usize) -> Result<Vec<WatchAssessment>> {
        WatchStore::open(&self.config.watch.data_dir)?.assessments(limit)
    }

    pub fn create_task(&self, plan: WatchTaskPlan, prompt: &str) -> Result<WatchTask> {
        anyhow::ensure!(plan.action == "create", "当前计划不是创建任务");
        let owner = non_empty_or(plan.owner, &self.config.watch.github.owner);
        anyhow::ensure!(!owner.is_empty(), "持续追踪任务需要 GitHub owner");
        let author = non_empty_or(plan.author, &self.config.watch.github.author);
        anyhow::ensure!(valid_github_name(&owner), "GitHub owner 格式无效");
        anyhow::ensure!(
            author.is_empty() || valid_github_name(&author),
            "GitHub author 格式无效"
        );
        anyhow::ensure!(
            plan.repositories
                .iter()
                .all(|repository| valid_repository(repository)),
            "仓库必须使用 owner/name 格式"
        );
        let interval_seconds = if plan.interval_seconds == 0 {
            self.config.watch.interval_seconds
        } else {
            plan.interval_seconds
        };
        anyhow::ensure!(
            (60..=86_400).contains(&interval_seconds),
            "追踪间隔必须在 60 到 86400 秒之间"
        );
        let name = if plan.name.trim().is_empty() {
            format!("{owner} 个人事项")
        } else {
            plan.name.trim().to_string()
        };
        let now = Utc::now().to_rfc3339();
        WatchStore::open(&self.config.watch.data_dir)?.save_task(WatchTask {
            id: Uuid::new_v4().to_string(),
            name,
            prompt: prompt.to_string(),
            owner,
            author,
            repositories: plan.repositories,
            interval_seconds,
            instructions: plan.instructions,
            state: "active".to_string(),
            last_run_at: String::new(),
            last_result: String::new(),
            next_run_at: now.clone(),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn tasks(&self) -> Result<Vec<WatchTask>> {
        WatchStore::open(&self.config.watch.data_dir)?.tasks()
    }

    pub fn set_task_state(&self, name: &str, state: &str) -> Result<bool> {
        anyhow::ensure!(matches!(state, "active" | "paused"), "无效的任务状态");
        WatchStore::open(&self.config.watch.data_dir)?.set_task_state(name, state)
    }

    pub fn run_due_tasks(&self) -> Result<Vec<String>> {
        let mut store = WatchStore::open(&self.config.watch.data_dir)?;
        let tasks = store.claim_due_tasks()?;
        let mut results = Vec::new();
        for task in tasks {
            let github = WatchGithubConfig {
                owner: task.owner.clone(),
                author: task.author.clone(),
                repositories: task.repositories.clone(),
            };
            match self.scan_scope(&task.id, github) {
                Ok(report) => {
                    let pending_events = store.unassessed_events(&task.id)?;
                    let assessments =
                        match self.assess_events(&store, &task, &report, &pending_events) {
                            Ok(assessments) => assessments,
                            Err(error) => {
                                let result = format!("{}：事件评估失败：{error:#}", task.name);
                                store.finish_task_run(&task, &result, true)?;
                                results.push(result);
                                continue;
                            }
                        };
                    let decision_count = assessments
                        .iter()
                        .filter(|assessment| assessment.requires_user_decision)
                        .count();
                    let result = format!(
                        "{}：{} 个 PR，{} 个新事件，{} 个待判断",
                        task.name,
                        report.pull_requests_observed,
                        report.events_created,
                        decision_count
                    );
                    store.finish_task_run(&task, &result, false)?;
                    results.push(result);
                }
                Err(error) => {
                    let result = format!("{}：失败：{error:#}", task.name);
                    store.finish_task_run(&task, &result, true)?;
                    results.push(result);
                }
            }
        }
        Ok(results)
    }

    fn assess_events(
        &self,
        store: &WatchStore,
        task: &WatchTask,
        report: &WatchScanReport,
        events: &[WatchEvent],
    ) -> Result<Vec<WatchAssessment>> {
        let llm = LlmService::new(self.config.llm.clone());
        let mut assessments = Vec::new();
        for event in events {
            let snapshot = report
                .pull_requests
                .iter()
                .find(|snapshot| snapshot.key() == event.entity_key);
            let plan = llm
                .assess_watch_event(event, snapshot, &task.instructions)
                .ok()
                .flatten()
                .unwrap_or_else(|| deterministic_assessment(event, snapshot));
            let assessment = WatchAssessment {
                id: Uuid::new_v4().to_string(),
                event_id: event.id.clone(),
                task_id: task.id.clone(),
                entity_key: event.entity_key.clone(),
                summary: plan.summary,
                evidence: plan.evidence,
                recommendation: plan.recommendation,
                requires_user_decision: plan.requires_user_decision,
                created_at: Utc::now().to_rfc3339(),
            };
            if store.save_assessment(&assessment)? {
                assessments.push(assessment);
            }
        }
        Ok(assessments)
    }
}

fn deterministic_assessment(
    event: &WatchEvent,
    snapshot: Option<&PullRequestSnapshot>,
) -> WatchAssessmentPlan {
    let failed = snapshot
        .map(|snapshot| snapshot.check_summary().failed)
        .unwrap_or_default();
    let closed = matches!(event.kind.as_str(), "github-pr-merged" | "github-pr-closed");
    WatchAssessmentPlan {
        summary: event.summary.clone(),
        evidence: vec![event.evidence_url.clone()],
        recommendation: if closed {
            "记录生命周期结果，无需自动操作。".to_string()
        } else if failed > 0 {
            "检查失败日志并判断是否需要修改代码；修改和推送前等待用户确认。".to_string()
        } else {
            "检查本次变化，涉及回复、修改或合并时等待用户确认。".to_string()
        },
        requires_user_decision: !closed,
    }
}

fn non_empty_or(value: String, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.trim().to_string()
    } else {
        value.trim().to_string()
    }
}

fn valid_github_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    !name.contains('/') && valid_github_name(owner) && valid_github_name(name)
}

fn describe_changes(previous: &PullRequestSnapshot, current: &PullRequestSnapshot) -> String {
    let mut changes = Vec::new();
    if previous.head_oid != current.head_oid {
        changes.push(format!(
            "head {} → {}",
            short_oid(&previous.head_oid),
            short_oid(&current.head_oid)
        ));
    }
    if previous.is_draft != current.is_draft {
        changes.push(format!(
            "Draft {} → {}",
            previous.is_draft, current.is_draft
        ));
    }
    if previous.merge_state != current.merge_state {
        changes.push(format!(
            "合并状态 {} → {}",
            previous.merge_state, current.merge_state
        ));
    }
    if previous.review_decision != current.review_decision {
        changes.push(format!(
            "审查 {} → {}",
            display_empty(&previous.review_decision),
            display_empty(&current.review_decision)
        ));
    }
    let previous_checks = previous.check_summary();
    let current_checks = current.check_summary();
    if previous_checks != current_checks {
        changes.push(format!(
            "CI [{}] → [{}]",
            previous_checks.render(),
            current_checks.render()
        ));
    }
    if changes.is_empty() {
        changes.push("PR 元数据已更新".to_string());
    }
    changes.join("；")
}

fn short_oid(value: &str) -> &str {
    value.get(..value.len().min(8)).unwrap_or(value)
}

fn display_empty(value: &str) -> &str {
    if value.is_empty() { "未决定" } else { value }
}

pub fn render_scan_report(report: &WatchScanReport) -> String {
    let mut output = format!(
        "扫描仓库：{}\n个人 open PR：{}\n新增事件：{}\n",
        report.repositories_scanned, report.pull_requests_observed, report.events_created
    );
    if report.initial_baseline {
        output.push_str("本次为首次扫描，只建立基线。\n");
    }
    for pull_request in &report.pull_requests {
        output.push_str(&format!(
            "- {} {} [{}] CI: {}\n",
            pull_request.key(),
            pull_request.title,
            pull_request.merge_state,
            pull_request.check_summary().render()
        ));
    }
    for warning in &report.warnings {
        output.push_str(&format!("警告：{warning}\n"));
    }
    output.trim_end().to_string()
}

pub fn render_status(snapshots: &[PullRequestSnapshot]) -> String {
    if snapshots.is_empty() {
        return "尚无个人 PR 快照，请先运行 watch scan。".to_string();
    }
    snapshots
        .iter()
        .map(|snapshot| {
            format!(
                "{} {}\n  {} | review: {} | CI: {}\n  {}",
                snapshot.key(),
                snapshot.title,
                snapshot.merge_state,
                display_empty(&snapshot.review_decision),
                snapshot.check_summary().render(),
                snapshot.url
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn render_events(events: &[WatchEvent]) -> String {
    if events.is_empty() {
        return "暂无状态变化事件。".to_string();
    }
    events
        .iter()
        .map(|event| {
            format!(
                "{} [{}] {}\n  {}\n  {}",
                event.created_at, event.kind, event.entity_key, event.summary, event.evidence_url
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn render_assessments(assessments: &[WatchAssessment]) -> String {
    if assessments.is_empty() {
        return "暂无事件评估。".to_string();
    }
    assessments
        .iter()
        .map(|assessment| {
            let evidence = if assessment.evidence.is_empty() {
                "无附加证据".to_string()
            } else {
                assessment.evidence.join("；")
            };
            format!(
                "{} [{}] {}\n  {}\n  建议：{}\n  证据：{}",
                assessment.created_at,
                if assessment.requires_user_decision {
                    "待判断"
                } else {
                    "仅记录"
                },
                assessment.entity_key,
                assessment.summary,
                assessment.recommendation,
                evidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn render_tasks(tasks: &[WatchTask]) -> String {
    if tasks.is_empty() {
        return "尚未创建持续追踪任务。".to_string();
    }
    tasks
        .iter()
        .map(|task| {
            format!(
                "{} [{}]\n  {}/{}，每 {} 秒\n  上次：{}\n  下次：{}",
                task.name,
                task.state,
                task.owner,
                if task.author.is_empty() {
                    "当前 gh 用户"
                } else {
                    &task.author
                },
                task.interval_seconds,
                if task.last_result.is_empty() {
                    "尚未运行"
                } else {
                    &task.last_result
                },
                task.next_run_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{describe_changes, deterministic_assessment};
    use crate::watch::model::{CheckSnapshot, PullRequestSnapshot, WatchEvent};

    fn snapshot() -> PullRequestSnapshot {
        PullRequestSnapshot {
            repository: "owner/repo".to_string(),
            number: 1,
            title: "test".to_string(),
            url: "url".to_string(),
            is_draft: true,
            head_ref_name: "fix/test".to_string(),
            head_oid: "aaaaaaaa".to_string(),
            base_ref_name: "main".to_string(),
            merge_state: "BEHIND".to_string(),
            review_decision: String::new(),
            updated_at: "now".to_string(),
            checks: Vec::new(),
        }
    }

    #[test]
    fn change_description_reports_material_state() {
        let previous = snapshot();
        let mut current = snapshot();
        current.head_oid = "bbbbbbbb".to_string();
        current.merge_state = "BLOCKED".to_string();
        current.checks.push(CheckSnapshot {
            name: "build".to_string(),
            status: "COMPLETED".to_string(),
            conclusion: "FAILURE".to_string(),
            details_url: "url".to_string(),
        });
        let changes = describe_changes(&previous, &current);
        assert!(changes.contains("head aaaaaaaa → bbbbbbbb"));
        assert!(changes.contains("合并状态 BEHIND → BLOCKED"));
        assert!(changes.contains("失败 1"));
    }

    #[test]
    fn failed_ci_requires_user_decision() {
        let mut current = snapshot();
        current.checks.push(CheckSnapshot {
            name: "build".to_string(),
            status: "COMPLETED".to_string(),
            conclusion: "FAILURE".to_string(),
            details_url: "url".to_string(),
        });
        let event = WatchEvent {
            id: "event".to_string(),
            task_id: "task".to_string(),
            entity_key: current.key(),
            kind: "github-pr-changed".to_string(),
            fingerprint: "fingerprint".to_string(),
            summary: "CI 失败".to_string(),
            evidence_url: "url".to_string(),
            created_at: "now".to_string(),
        };
        let assessment = deterministic_assessment(&event, Some(&current));
        assert!(assessment.requires_user_decision);
        assert!(assessment.recommendation.contains("等待用户确认"));
    }
}
