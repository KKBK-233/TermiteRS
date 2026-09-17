use serde::{Deserialize, Serialize};

/// 单个检查的规范化快照，屏蔽 GitHub CheckRun 与 StatusContext 的字段差异。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckSnapshot {
    pub name: String,
    pub status: String,
    pub conclusion: String,
    pub details_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PullRequestSnapshot {
    pub repository: String,
    pub number: u64,
    pub title: String,
    pub url: String,
    pub is_draft: bool,
    pub head_ref_name: String,
    pub head_oid: String,
    pub base_ref_name: String,
    pub merge_state: String,
    pub review_decision: String,
    pub updated_at: String,
    pub checks: Vec<CheckSnapshot>,
}

impl PullRequestSnapshot {
    pub fn key(&self) -> String {
        format!("{}#{}", self.repository, self.number)
    }

    pub fn check_summary(&self) -> CheckSummary {
        let mut summary = CheckSummary::default();
        for check in &self.checks {
            let conclusion = check.conclusion.to_ascii_uppercase();
            let status = check.status.to_ascii_uppercase();
            if matches!(
                conclusion.as_str(),
                "FAILURE" | "TIMED_OUT" | "CANCELLED" | "ACTION_REQUIRED" | "STARTUP_FAILURE"
            ) || matches!(status.as_str(), "FAILURE" | "ERROR")
            {
                summary.failed += 1;
            } else if matches!(
                status.as_str(),
                "EXPECTED" | "PENDING" | "QUEUED" | "IN_PROGRESS" | "REQUESTED" | "WAITING"
            ) {
                summary.pending += 1;
            } else if conclusion == "SUCCESS" || status == "SUCCESS" {
                summary.passed += 1;
            } else {
                summary.neutral += 1;
            }
        }
        summary
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PullRequestLifecycle {
    pub state: String,
    pub merged_at: String,
    pub closed_at: String,
    pub url: String,
    pub title: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckSummary {
    pub passed: usize,
    pub failed: usize,
    pub pending: usize,
    pub neutral: usize,
}

impl CheckSummary {
    pub fn render(&self) -> String {
        format!(
            "通过 {} / 失败 {} / 进行中 {} / 其他 {}",
            self.passed, self.failed, self.pending, self.neutral
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WatchEvent {
    pub id: String,
    pub entity_key: String,
    pub kind: String,
    pub fingerprint: String,
    pub summary: String,
    pub evidence_url: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WatchScanReport {
    pub repositories_scanned: usize,
    pub pull_requests_observed: usize,
    pub events_created: usize,
    pub initial_baseline: bool,
    pub warnings: Vec<String>,
    pub pull_requests: Vec<PullRequestSnapshot>,
}
