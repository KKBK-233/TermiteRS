use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::config::WatchGithubConfig;

use super::model::{CheckSnapshot, PullRequestLifecycle, PullRequestSnapshot};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubPullRequest {
    number: u64,
    title: String,
    url: String,
    is_draft: bool,
    head_ref_name: String,
    head_ref_oid: String,
    base_ref_name: String,
    merge_state_status: String,
    review_decision: String,
    updated_at: String,
    #[serde(default)]
    status_check_rollup: Vec<Value>,
}

pub struct GithubCollector {
    config: WatchGithubConfig,
}

impl GithubCollector {
    pub fn new(config: WatchGithubConfig) -> Self {
        Self { config }
    }

    pub fn current_user(&self) -> Result<String> {
        if !self.config.author.trim().is_empty() {
            return Ok(self.config.author.trim().to_string());
        }
        let value = run_gh_json(&["api", "user"])?;
        value["login"]
            .as_str()
            .map(ToOwned::to_owned)
            .context("gh api user 未返回 login")
    }

    pub fn repositories(&self) -> Result<Vec<String>> {
        if !self.config.repositories.is_empty() {
            return Ok(self
                .config
                .repositories
                .iter()
                .map(|repository| normalize_repository(&self.config.owner, repository))
                .collect());
        }
        anyhow::ensure!(
            !self.config.owner.trim().is_empty(),
            "watch.github.owner 与 repositories 不能同时为空"
        );
        let value = run_gh_json(&[
            "repo",
            "list",
            self.config.owner.trim(),
            "--limit",
            "200",
            "--json",
            "nameWithOwner,isArchived",
        ])?;
        let repositories = value
            .as_array()
            .context("gh repo list 未返回数组")?
            .iter()
            .filter(|repository| !repository["isArchived"].as_bool().unwrap_or(false))
            .filter_map(|repository| repository["nameWithOwner"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        Ok(repositories)
    }

    pub fn pull_requests(
        &self,
        repository: &str,
        author: &str,
    ) -> Result<Vec<PullRequestSnapshot>> {
        let value = run_gh_json(&[
            "pr",
            "list",
            "--repo",
            repository,
            "--author",
            author,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title,url,isDraft,headRefName,headRefOid,baseRefName,mergeStateStatus,reviewDecision,updatedAt,statusCheckRollup",
        ])?;
        let raw: Vec<GithubPullRequest> =
            serde_json::from_value(value).context("无法解析 gh pr list 输出")?;
        Ok(raw
            .into_iter()
            .map(|pull_request| PullRequestSnapshot {
                repository: repository.to_string(),
                number: pull_request.number,
                title: pull_request.title,
                url: pull_request.url,
                is_draft: pull_request.is_draft,
                head_ref_name: pull_request.head_ref_name,
                head_oid: pull_request.head_ref_oid,
                base_ref_name: pull_request.base_ref_name,
                merge_state: pull_request.merge_state_status,
                review_decision: pull_request.review_decision,
                updated_at: pull_request.updated_at,
                checks: normalize_checks(&pull_request.status_check_rollup),
            })
            .collect())
    }

    pub fn pull_request_lifecycle(
        &self,
        repository: &str,
        number: u64,
    ) -> Result<PullRequestLifecycle> {
        let value = run_gh_json(&[
            "pr",
            "view",
            &number.to_string(),
            "--repo",
            repository,
            "--json",
            "state,mergedAt,closedAt,url,title",
        ])?;
        Ok(PullRequestLifecycle {
            state: value["state"].as_str().unwrap_or("UNKNOWN").to_string(),
            merged_at: value["mergedAt"].as_str().unwrap_or_default().to_string(),
            closed_at: value["closedAt"].as_str().unwrap_or_default().to_string(),
            url: value["url"].as_str().unwrap_or_default().to_string(),
            title: value["title"].as_str().unwrap_or_default().to_string(),
        })
    }
}

fn normalize_repository(owner: &str, repository: &str) -> String {
    if repository.contains('/') || owner.trim().is_empty() {
        repository.to_string()
    } else {
        format!("{}/{}", owner.trim(), repository)
    }
}

fn normalize_checks(checks: &[Value]) -> Vec<CheckSnapshot> {
    let mut normalized = checks
        .iter()
        .map(|check| {
            let is_context = check["__typename"].as_str() == Some("StatusContext");
            CheckSnapshot {
                name: check[if is_context { "context" } else { "name" }]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                status: check[if is_context { "state" } else { "status" }]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                conclusion: check["conclusion"].as_str().unwrap_or_default().to_string(),
                details_url: check[if is_context {
                    "targetUrl"
                } else {
                    "detailsUrl"
                }]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            }
        })
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| {
        (&left.name, &left.details_url).cmp(&(&right.name, &right.details_url))
    });
    normalized
}

fn run_gh_json(args: &[&str]) -> Result<Value> {
    let output = Command::new("gh")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .context("无法启动 gh；请先安装 GitHub CLI 并完成登录")?;
    if !output.status.success() {
        bail!(
            "gh {} 失败：{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("gh 输出不是有效 JSON")
}

#[cfg(test)]
mod tests {
    use super::{normalize_checks, normalize_repository};

    #[test]
    fn repository_name_uses_owner_only_when_needed() {
        assert_eq!(
            normalize_repository("D-Nine-Chain", "d9-v2-node"),
            "D-Nine-Chain/d9-v2-node"
        );
        assert_eq!(
            normalize_repository("ignored", "KKBK-233/TermiteRS"),
            "KKBK-233/TermiteRS"
        );
    }

    #[test]
    fn checks_normalize_check_runs_and_status_contexts() {
        let checks = serde_json::json!([
            {"__typename":"CheckRun","name":"build","status":"COMPLETED","conclusion":"FAILURE","detailsUrl":"https://example/build"},
            {"__typename":"StatusContext","context":"CodeRabbit","state":"SUCCESS","targetUrl":"https://example/review"}
        ]);
        let normalized = normalize_checks(checks.as_array().unwrap());
        assert_eq!(normalized.len(), 2);
        assert_eq!(normalized[0].name, "CodeRabbit");
        assert_eq!(normalized[1].conclusion, "FAILURE");
    }
}
