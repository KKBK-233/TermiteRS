use std::{env, path::Path};

use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use super::{
    DeliveryDraft, DeliveryKind, DeliveryReceipt, EvaluatedSecurityReview, ProtectionFinding,
    ProtectionStore, StaticScanReport,
};

const GITHUB_API_BASE: &str = "https://api.github.com";

/// 从常见 GitHub 远端地址提取 Issue 目标，无法可靠识别时不准备自动投送。
pub fn github_repository_from_remote(remote: &str) -> Option<String> {
    let path = remote
        .strip_prefix("git@github.com:")
        .or_else(|| remote.strip_prefix("https://github.com/"))
        .or_else(|| remote.strip_prefix("ssh://git@github.com/"))?;
    let path = path.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repository = parts.next()?;
    if owner.is_empty() || repository.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{repository}"))
}

/// 根据静态扫描证据准备 Issue 草稿；本函数不包含任何网络或 GitHub 写操作。
pub fn prepare_issue_draft(
    finding_id: impl Into<String>,
    repository: impl Into<String>,
    report: &StaticScanReport,
) -> Option<DeliveryDraft> {
    if report.blockers.is_empty() {
        return None;
    }

    let finding_id = finding_id.into();
    let destination = repository.into();
    let mut body = String::from("TermiteRS 在执行任何项目构建之前发现供应链阻断项。\n\n");
    body.push_str(&format!("项目：{}\n", report.project));
    body.push_str(&format!("扫描文件：{}\n", report.scanned_files));
    body.push_str("构建状态：已阻止\n\n证据：\n");
    for indicator in &report.blockers {
        body.push_str(&format!(
            "- [{}] {}（{}）：{}\n",
            indicator.rule_id, indicator.summary, indicator.path, indicator.evidence
        ));
    }
    body.push_str("\n该草稿尚未发送，需要人工确认目标仓库和公开范围。\n");

    Some(DeliveryDraft {
        id: format!("draft-{}", &report.dedupe_key[..32]),
        finding_id,
        kind: DeliveryKind::GithubIssue,
        destination,
        title: format!("[供应链阻断] {} 检测到高危依赖行为", report.project),
        body,
        labels: vec![
            "security".to_string(),
            "supply-chain".to_string(),
            "blocker".to_string(),
        ],
        dedupe_key: format!("github-issue:{}:{}", report.project, report.dedupe_key),
        approval_required: true,
        created_at: Utc::now().to_rfc3339(),
    })
}

/// 为逐提交安全结论准备待批准 Issue；不会执行网络请求或公开漏洞细节。
pub fn prepare_security_review_issue_draft(
    finding: &ProtectionFinding,
    review: &EvaluatedSecurityReview,
    repository: impl Into<String>,
) -> Option<DeliveryDraft> {
    if matches!(review.disposition, super::SecurityDisposition::Allow) {
        return None;
    }
    let destination = repository.into();
    let mut body = format!(
        "TermiteRS 的项目保护门禁停止了提交 {} 的自动投送。\n\n项目：{}\n结论：{:?}\n等级：{:?}\n摘要：{}\n\n策略依据：\n",
        review.commit,
        finding.project,
        review.disposition,
        review.decision.severity,
        review.decision.summary
    );
    for reason in &review.policy_reasons {
        body.push_str(&format!("- {reason}\n"));
    }
    body.push_str(
        "\n详细证据保存在 TermiteRS 本地 Finding 中。公开前需要人工确认披露范围和目标仓库。\n",
    );
    Some(DeliveryDraft {
        id: format!("draft-review-{}", &finding.dedupe_key[..32]),
        finding_id: finding.id.clone(),
        kind: DeliveryKind::GithubIssue,
        destination,
        title: format!("[安全门禁] {} 提交需要处理", finding.project),
        body,
        labels: vec!["security".to_string(), "termiters".to_string()],
        dedupe_key: format!("github-review-issue:{}", finding.dedupe_key),
        approval_required: true,
        created_at: Utc::now().to_rfc3339(),
    })
}

#[derive(Debug, Serialize)]
struct GithubIssueRequest {
    title: String,
    body: String,
    labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GithubIssueResponse {
    number: u64,
    html_url: String,
    body: Option<String>,
}

/// 只有显式批准才能把已保存草稿投送到 GitHub；重复调用会复用本地或远端回执。
pub fn publish_github_issue(
    data_dir: impl AsRef<Path>,
    draft_id: &str,
    token_env: &str,
    approved: bool,
) -> Result<DeliveryReceipt> {
    publish_github_issue_at(
        data_dir.as_ref(),
        draft_id,
        token_env,
        approved,
        GITHUB_API_BASE,
    )
}

fn publish_github_issue_at(
    data_dir: &Path,
    draft_id: &str,
    token_env: &str,
    approved: bool,
    api_base: &str,
) -> Result<DeliveryReceipt> {
    anyhow::ensure!(approved, "发布 GitHub Issue 必须显式传入 --approve");
    let mut store = ProtectionStore::open(data_dir.join("termite.db"))?;
    if let Some(receipt) = store.delivery_receipt(draft_id)? {
        return Ok(receipt);
    }
    let draft = store
        .delivery_draft(draft_id)?
        .with_context(|| format!("找不到 Issue 草稿：{draft_id}"))?;
    anyhow::ensure!(
        matches!(draft.kind, DeliveryKind::GithubIssue),
        "草稿不是 GitHub Issue"
    );
    anyhow::ensure!(draft.approval_required, "草稿没有处于人工批准投送协议中");
    validate_repository(&draft.destination)?;
    let token =
        env::var(token_env).with_context(|| format!("缺少 GitHub Token 环境变量：{token_env}"))?;
    let client = Client::builder()
        .user_agent("TermiteRS-security-delivery/1")
        .build()?;
    let endpoint = format!(
        "{}/repos/{}/issues",
        api_base.trim_end_matches('/'),
        draft.destination
    );
    let marker = format!("<!-- TermiteRS:{} -->", draft.id);

    // 发布前先查询远端标记，覆盖“请求成功但本地写回失败”后的重试场景。
    let existing = client
        .get(&endpoint)
        .query(&[("state", "all"), ("per_page", "100")])
        .bearer_auth(&token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("查询 GitHub Issue 幂等标记失败")?
        .error_for_status()
        .context("GitHub Issue 查询返回失败状态")?
        .json::<Vec<GithubIssueResponse>>()?
        .into_iter()
        .find(|issue| {
            issue
                .body
                .as_deref()
                .is_some_and(|body| body.contains(&marker))
        });
    let issue = if let Some(issue) = existing {
        issue
    } else {
        let request = github_issue_request(&draft, &marker);
        client
            .post(&endpoint)
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .json(&request)
            .send()
            .context("发布 GitHub Issue 失败")?
            .error_for_status()
            .context("GitHub Issue 发布返回失败状态")?
            .json::<GithubIssueResponse>()?
    };
    let receipt = DeliveryReceipt {
        draft_id: draft.id,
        destination: draft.destination,
        remote_id: issue.number.to_string(),
        remote_url: issue.html_url,
        delivered_at: Utc::now().to_rfc3339(),
    };
    store.mark_delivery_complete(&receipt)?;
    Ok(receipt)
}

fn github_issue_request(draft: &DeliveryDraft, marker: &str) -> GithubIssueRequest {
    GithubIssueRequest {
        title: draft.title.clone(),
        body: format!("{}\n\n{}", draft.body.trim_end(), marker),
        labels: draft.labels.clone(),
    }
}

fn validate_repository(repository: &str) -> Result<()> {
    let mut parts = repository.split('/');
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    anyhow::ensure!(
        valid(owner) && valid(name) && parts.next().is_none(),
        "非法 GitHub 仓库：{repository}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        thread,
    };

    use uuid::Uuid;

    use super::*;
    use crate::protection::{FindingState, SecuritySignal, SecuritySignalSource};

    #[test]
    fn issue_payload_contains_stable_idempotency_marker() {
        let draft = DeliveryDraft {
            id: "draft-123".to_string(),
            finding_id: "finding-1".to_string(),
            kind: DeliveryKind::GithubIssue,
            destination: "owner/repo".to_string(),
            title: "security finding".to_string(),
            body: "evidence".to_string(),
            labels: vec!["security".to_string()],
            dedupe_key: "dedupe".to_string(),
            approval_required: true,
            created_at: "now".to_string(),
        };
        let request = github_issue_request(&draft, "<!-- TermiteRS:draft-123 -->");
        assert!(request.body.contains("<!-- TermiteRS:draft-123 -->"));
        assert!(validate_repository("owner/repo").is_ok());
        assert!(validate_repository("https://github.com/owner/repo").is_err());
    }

    #[test]
    fn approved_publish_uses_remote_marker_and_local_receipt_for_retries() {
        let root = std::env::temp_dir().join(format!("termiters-issue-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = ProtectionStore::open(root.join("termite.db")).unwrap();
        let signal = SecuritySignal {
            id: "signal-1".to_string(),
            project: "fixture".to_string(),
            source: SecuritySignalSource::UserReport,
            summary: "fixture".to_string(),
            reference: None,
            dedupe_key: "signal-dedupe".to_string(),
            received_at: "now".to_string(),
        };
        let finding = ProtectionFinding {
            id: "finding-1".to_string(),
            project: "fixture".to_string(),
            signal_id: signal.id.clone(),
            state: FindingState::Affected,
            classification: "fixture".to_string(),
            severity: "p1".to_string(),
            confidence: "high".to_string(),
            affected: Some(true),
            build_allowed: false,
            summary: "fixture".to_string(),
            evidence: vec!["evidence".to_string()],
            dedupe_key: "finding-dedupe".to_string(),
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        };
        let draft = DeliveryDraft {
            id: "draft-live-test".to_string(),
            finding_id: finding.id.clone(),
            kind: DeliveryKind::GithubIssue,
            destination: "owner/repo".to_string(),
            title: "security finding".to_string(),
            body: "evidence".to_string(),
            labels: vec!["security".to_string()],
            dedupe_key: "draft-dedupe".to_string(),
            approval_required: true,
            created_at: "now".to_string(),
        };
        store.upsert_signal(&signal).unwrap();
        store.upsert_finding(&finding).unwrap();
        store.upsert_delivery_draft(&draft).unwrap();
        drop(store);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let first_request = read_http_request(&mut first);
            assert!(first_request.starts_with("GET /repos/owner/repo/issues?"));
            write_json_response(&mut first, "[]");

            let (mut second, _) = listener.accept().unwrap();
            let second_request = read_http_request(&mut second);
            write_json_response(
                &mut second,
                r#"{"number":42,"html_url":"https://github.com/owner/repo/issues/42","body":"evidence\n<!-- TermiteRS:draft-live-test -->"}"#,
            );
            sender.send(second_request).unwrap();
        });
        let token_env = format!("TERMITERS_GITHUB_TEST_{}", Uuid::new_v4().simple());
        // 该测试使用唯一变量名，生命周期只覆盖本测试进程中的一次本地请求。
        unsafe { std::env::set_var(&token_env, "test-token") };
        let first = publish_github_issue_at(
            &root,
            &draft.id,
            &token_env,
            true,
            &format!("http://{address}"),
        )
        .unwrap();
        server.join().unwrap();
        let posted = receiver.recv().unwrap();
        assert!(posted.starts_with("POST /repos/owner/repo/issues HTTP/1.1"));
        assert!(posted.contains("TermiteRS:draft-live-test"));
        assert_eq!(first.remote_id, "42");

        // 本地回执存在时不再访问已经关闭的测试服务器。
        let repeated = publish_github_issue_at(
            &root,
            &draft.id,
            &token_env,
            true,
            &format!("http://{address}"),
        )
        .unwrap();
        assert_eq!(first, repeated);
        unsafe { std::env::remove_var(&token_env) };
        fs::remove_dir_all(root).unwrap();
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap();
            }
            request.push_str(&line);
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
        request.push_str(std::str::from_utf8(&body).unwrap());
        request
    }

    fn write_json_response(stream: &mut TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }
}
