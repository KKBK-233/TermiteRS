use chrono::Utc;

use super::{DeliveryDraft, DeliveryKind, StaticScanReport};

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
