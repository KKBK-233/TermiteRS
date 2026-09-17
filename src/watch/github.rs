use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::config::WatchGithubConfig;
use crate::text::truncate_to_char_boundary;

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

    /// 只在 PR 已发生变化时补取有限的评论与失败日志，避免每轮全量拉取正文。
    pub fn change_evidence(
        &self,
        previous: &PullRequestSnapshot,
        current: &PullRequestSnapshot,
    ) -> Result<Vec<String>> {
        let mut evidence = Vec::new();
        if previous.updated_at != current.updated_at {
            evidence.extend(self.recent_activity_since(
                &current.repository,
                current.number,
                &previous.updated_at,
            )?);
        }
        if previous.check_summary() != current.check_summary() {
            evidence.extend(self.failed_check_logs(current)?);
        }
        bound_evidence(&mut evidence, 24_000);
        Ok(evidence)
    }

    pub fn failed_check_logs(&self, snapshot: &PullRequestSnapshot) -> Result<Vec<String>> {
        let mut run_ids = snapshot
            .checks
            .iter()
            .filter(|check| check_failed(check))
            .filter_map(|check| action_run_id(&check.details_url))
            .collect::<Vec<_>>();
        run_ids.sort_unstable();
        run_ids.dedup();
        let mut evidence = Vec::new();
        for run_id in run_ids.into_iter().take(3) {
            let log = run_gh_text(&[
                "run",
                "view",
                &run_id,
                "--repo",
                &snapshot.repository,
                "--log-failed",
            ]);
            match log {
                Ok(log) => {
                    let log = bounded_terminal_tail(&log, 8_000);
                    evidence.push(format!("GitHub Actions run {run_id} 失败日志：\n{log}"));
                }
                Err(error) => evidence.push(format!(
                    "GitHub Actions run {run_id} 失败日志读取失败：{error:#}"
                )),
            }
        }
        Ok(evidence)
    }

    fn recent_activity_since(
        &self,
        repository: &str,
        number: u64,
        since: &str,
    ) -> Result<Vec<String>> {
        let (owner, name) = repository
            .split_once('/')
            .context("仓库名不是 owner/name 格式")?;
        let query = r#"query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){comments(last:10){nodes{id author{login} body createdAt url}} reviews(last:10){nodes{id author{login} body state submittedAt url}} reviewThreads(last:10){nodes{isResolved comments(last:5){nodes{id author{login} body createdAt url}}}}}}}"#;
        let number_text = number.to_string();
        let value = run_gh_json(&[
            "api",
            "graphql",
            "-f",
            &format!("query={query}"),
            "-F",
            &format!("owner={owner}"),
            "-F",
            &format!("name={name}"),
            "-F",
            &format!("number={number_text}"),
        ])?;
        Ok(normalize_activity(&value, since))
    }
}

fn normalize_activity(value: &Value, since: &str) -> Vec<String> {
    let pull_request = &value["data"]["repository"]["pullRequest"];
    let mut activity = Vec::new();
    append_activity_nodes(
        &mut activity,
        &pull_request["comments"]["nodes"],
        "评论",
        "createdAt",
        since,
    );
    append_activity_nodes(
        &mut activity,
        &pull_request["reviews"]["nodes"],
        "审查",
        "submittedAt",
        since,
    );
    if let Some(threads) = pull_request["reviewThreads"]["nodes"].as_array() {
        for thread in threads {
            let kind = if thread["isResolved"].as_bool().unwrap_or(false) {
                "已解决审查线程"
            } else {
                "未解决审查线程"
            };
            append_activity_nodes(
                &mut activity,
                &thread["comments"]["nodes"],
                kind,
                "createdAt",
                since,
            );
        }
    }
    activity
}

fn append_activity_nodes(
    output: &mut Vec<String>,
    nodes: &Value,
    kind: &str,
    time_field: &str,
    since: &str,
) {
    let Some(nodes) = nodes.as_array() else {
        return;
    };
    for node in nodes {
        let occurred_at = node[time_field].as_str().unwrap_or_default();
        if occurred_at <= since {
            continue;
        }
        let author = node["author"]["login"].as_str().unwrap_or("unknown");
        let state = node["state"].as_str().unwrap_or_default();
        let url = node["url"].as_str().unwrap_or_default();
        let body = bounded_terminal_text(node["body"].as_str().unwrap_or_default(), 2_000);
        output.push(format!(
            "{kind} {author} {} {}：\n{body}",
            if state.is_empty() { occurred_at } else { state },
            url
        ));
    }
}

fn check_failed(check: &super::model::CheckSnapshot) -> bool {
    let conclusion = check.conclusion.to_ascii_uppercase();
    let status = check.status.to_ascii_uppercase();
    matches!(
        conclusion.as_str(),
        "FAILURE" | "TIMED_OUT" | "CANCELLED" | "ACTION_REQUIRED" | "STARTUP_FAILURE"
    ) || matches!(status.as_str(), "FAILURE" | "ERROR")
}

fn action_run_id(url: &str) -> Option<String> {
    let (_, tail) = url.split_once("/actions/runs/")?;
    let run_id = tail.split('/').next()?;
    (!run_id.is_empty() && run_id.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| run_id.to_string())
}

fn bound_evidence(evidence: &mut Vec<String>, max_bytes: usize) {
    let mut remaining = max_bytes;
    evidence.retain_mut(|item| {
        if remaining == 0 {
            return false;
        }
        truncate_to_char_boundary(item, remaining);
        remaining = remaining.saturating_sub(item.len());
        !item.is_empty()
    });
}

fn bounded_terminal_text(value: &str, max_bytes: usize) -> String {
    let mut output = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();
    truncate_to_char_boundary(&mut output, max_bytes);
    output
}

fn bounded_terminal_tail(value: &str, max_bytes: usize) -> String {
    let cleaned = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        .collect::<String>();
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let marker = "... 日志开头已截断 ...\n";
    let mut start = cleaned.len() - max_bytes.saturating_sub(marker.len());
    while start < cleaned.len() && !cleaned.is_char_boundary(start) {
        start += 1;
    }
    format!("{marker}{}", &cleaned[start..])
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

fn run_gh_text(args: &[&str]) -> Result<String> {
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        action_run_id, bounded_terminal_tail, bounded_terminal_text, normalize_activity,
        normalize_checks, normalize_repository,
    };

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

    #[test]
    fn extracts_action_run_id_only_from_numeric_github_path() {
        assert_eq!(
            action_run_id("https://github.com/o/r/actions/runs/123/job/456"),
            Some("123".to_string())
        );
        assert_eq!(
            action_run_id("https://example.com/actions/runs/not-a-number"),
            None
        );
    }

    #[test]
    fn activity_keeps_only_new_untrusted_evidence() {
        let value = serde_json::json!({
            "data": {"repository": {"pullRequest": {
                "comments": {"nodes": [
                    {"author":{"login":"bot"},"body":"old","createdAt":"2026-09-16T00:00:00Z","url":"old"},
                    {"author":{"login":"bot"},"body":"new instruction","createdAt":"2026-09-17T00:00:00Z","url":"new"}
                ]},
                "reviews": {"nodes": []},
                "reviewThreads": {"nodes": [
                    {"isResolved":false,"comments":{"nodes":[
                        {"author":{"login":"reviewer"},"body":"finding","createdAt":"2026-09-17T01:00:00Z","url":"thread"}
                    ]}}
                ]}
            }}}
        });
        let activity = normalize_activity(&value, "2026-09-16T12:00:00Z");
        assert_eq!(activity.len(), 2);
        assert!(activity[0].contains("new instruction"));
        assert!(activity[1].contains("未解决审查线程"));
    }

    #[test]
    fn evidence_removes_terminal_control_sequences() {
        assert_eq!(
            bounded_terminal_text("ok\u{1b}[31m\nnext", 100),
            "ok[31m\nnext"
        );
        let tail = bounded_terminal_tail(&format!("{}最终错误", "前文".repeat(100)), 80);
        assert!(tail.contains("最终错误"));
        assert!(tail.len() <= 80);
    }
}
