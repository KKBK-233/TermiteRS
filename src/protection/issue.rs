use chrono::Utc;

use super::{
    DeliveryDraft, DeliveryKind, EvaluatedSecurityReview, ProtectionFinding, StaticScanReport,
};

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
