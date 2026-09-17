mod github;
pub mod model;
mod store;

use std::collections::HashSet;

use anyhow::Result;

use crate::config::Config;

use self::{
    github::GithubCollector,
    model::{PullRequestSnapshot, WatchEvent, WatchScanReport},
    store::WatchStore,
};

pub struct WatchRunner {
    config: Config,
}

impl WatchRunner {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn scan(&self) -> Result<WatchScanReport> {
        anyhow::ensure!(self.config.watch.enabled, "watch.enabled 尚未启用");
        let collector = GithubCollector::new(self.config.watch.github.clone());
        let author = collector.current_user()?;
        let repositories = collector.repositories()?;
        let store = WatchStore::open(&self.config.watch.data_dir)?;
        let initial_baseline = !store.initialized()?;
        let mut report = WatchScanReport {
            repositories_scanned: repositories.len(),
            initial_baseline,
            ..WatchScanReport::default()
        };
        let previous_snapshots = store.snapshots()?;
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
                if let Some(previous) = store.snapshot(&snapshot.key())? {
                    if previous != snapshot {
                        let changes = describe_changes(&previous, &snapshot);
                        let material = serde_json::to_string(&snapshot)?;
                        if store.insert_event(
                            &snapshot.key(),
                            "github-pr-changed",
                            &changes,
                            &snapshot.url,
                            &material,
                        )? {
                            report.events_created += 1;
                        }
                    }
                } else if !initial_baseline
                    && store.insert_event(
                        &snapshot.key(),
                        "github-pr-discovered",
                        &format!("发现新的个人 PR：{}", snapshot.title),
                        &snapshot.url,
                        &snapshot.head_oid,
                    )?
                {
                    report.events_created += 1;
                }
                store.upsert_snapshot(&snapshot)?;
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
                    if store.insert_event(
                        &previous.key(),
                        kind,
                        &summary,
                        &lifecycle.url,
                        occurred_at,
                    )? {
                        report.events_created += 1;
                    }
                    store.delete_snapshot(&previous.key())?;
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
        store.mark_initialized()?;
        Ok(report)
    }

    pub fn status(&self) -> Result<Vec<PullRequestSnapshot>> {
        WatchStore::open(&self.config.watch.data_dir)?.snapshots()
    }

    pub fn events(&self, limit: usize) -> Result<Vec<WatchEvent>> {
        WatchStore::open(&self.config.watch.data_dir)?.events(limit)
    }
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

#[cfg(test)]
mod tests {
    use super::describe_changes;
    use crate::watch::model::{CheckSnapshot, PullRequestSnapshot};

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
}
