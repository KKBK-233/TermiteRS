use std::fs;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ring::digest::{SHA256, digest};

use crate::{
    config::Config,
    git::Git,
    llm::{LlmService, SecurityReviewRequest},
};

use super::{
    CommitSecurityReviewBatch, EvaluatedSecurityReview, FindingState, ProtectionFinding,
    ProtectionStore, SecurityDisposition, SecuritySignal, SecuritySignalSource,
    evaluate_security_review, github_repository_from_remote, policy_fingerprint,
    prepare_security_review_issue_draft,
};

const MAX_REVIEW_COMMITS: usize = 512;
const REVIEW_PROMPT_OVERHEAD_BYTES: usize = 16 * 1024;

/// 对范围内每个新提交逐一审计并按项目策略指纹去重，不允许把大补丁截断后放行。
pub fn run_commit_security_reviews(
    config: &Config,
    git: &Git,
    from: &str,
    to: &str,
) -> Result<Option<CommitSecurityReviewBatch>> {
    if !config.protection.enabled {
        return Ok(None);
    }
    let commits = git
        .commits_in_range(from, to, MAX_REVIEW_COMMITS)
        .context("项目保护门禁无法枚举待审计提交")?;
    if commits.is_empty() {
        return Ok(None);
    }
    let llm_config = config
        .llm
        .as_ref()
        .filter(|llm| llm.enabled)
        .context("项目保护门禁需要启用 DS 才能逐提交安全审计")?;
    anyhow::ensure!(
        llm_config.max_prompt_bytes > REVIEW_PROMPT_OVERHEAD_BYTES,
        "LLM max_prompt_bytes 太小，无法容纳安全审计协议"
    );

    fs::create_dir_all(&config.service.data_dir)?;
    let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
    let project = configured_project_name(config);
    let fingerprint = policy_fingerprint(&config.protection);
    let llm = LlmService::new(config.llm.clone());
    let mut reviews = Vec::new();
    let mut cache_hits = 0;
    for commit in commits {
        let dedupe_key = review_dedupe_key(&project, &fingerprint, &commit);
        let review = if let Some(review) = store.security_review(&dedupe_key)? {
            cache_hits += 1;
            review
        } else {
            let patch = git.security_commit_patch(
                &commit,
                llm_config.max_prompt_bytes - REVIEW_PROMPT_OVERHEAD_BYTES,
            )?;
            let decision = llm
                .review_security_change(&SecurityReviewRequest {
                    project: project.clone(),
                    project_description: config.protection.project.description.clone(),
                    profiles: config.protection.profiles.clone(),
                    commit: commit.clone(),
                    patch,
                })?
                .context("项目保护门禁未获得 DS 安全审计结果")?;
            let review = evaluate_security_review(&commit, decision, &config.protection);
            store.upsert_security_review(&dedupe_key, &review)?;
            persist_review_finding(&store, config, &project, &dedupe_key, &review)?;
            review
        };
        reviews.push(review);
    }
    let disposition = aggregate_disposition(&reviews);
    Ok(Some(CommitSecurityReviewBatch {
        project,
        from: from.to_string(),
        to: to.to_string(),
        reviews,
        disposition,
        cache_hits,
    }))
}

pub fn ensure_reviews_can_proceed(batch: &CommitSecurityReviewBatch) -> Result<()> {
    match batch.disposition {
        SecurityDisposition::Allow => Ok(()),
        SecurityDisposition::VerifyRequired => {
            bail!("项目保护门禁检测到隐藏安全修复，等待独立 FixContract 验证")
        }
        SecurityDisposition::NeedsReview => {
            bail!("项目保护门禁无法确定提交安全性，等待人工复核")
        }
        SecurityDisposition::Block => bail!("项目保护门禁确认提交引入不可接受安全风险"),
    }
}

fn persist_review_finding(
    store: &ProtectionStore,
    config: &Config,
    project: &str,
    dedupe_key: &str,
    review: &EvaluatedSecurityReview,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let suffix = &dedupe_key[..32];
    let signal = SecuritySignal {
        id: format!("signal-review-{suffix}"),
        project: project.to_string(),
        source: SecuritySignalSource::UpstreamCommit,
        summary: review.decision.summary.clone(),
        reference: Some(review.commit.clone()),
        dedupe_key: format!("signal:{dedupe_key}"),
        received_at: now.clone(),
    };
    let finding = ProtectionFinding {
        id: format!("finding-review-{suffix}"),
        project: project.to_string(),
        signal_id: signal.id.clone(),
        state: match review.disposition {
            SecurityDisposition::Allow => FindingState::Unaffected,
            SecurityDisposition::VerifyRequired => FindingState::Investigating,
            SecurityDisposition::NeedsReview => FindingState::Uncertain,
            SecurityDisposition::Block => FindingState::Affected,
        },
        classification: if review.decision.introduced_risk {
            "security-risk-introduced".to_string()
        } else if review.decision.security_fix_detected {
            "hidden-security-fix".to_string()
        } else {
            "no-security-change".to_string()
        },
        severity: enum_text(&review.decision.severity)?,
        confidence: enum_text(&review.decision.confidence)?,
        affected: review.decision.affected,
        build_allowed: matches!(
            review.disposition,
            SecurityDisposition::Allow | SecurityDisposition::VerifyRequired
        ),
        summary: review.decision.summary.clone(),
        evidence: review
            .decision
            .evidence
            .iter()
            .chain(&review.policy_reasons)
            .cloned()
            .collect(),
        dedupe_key: format!("finding:{dedupe_key}"),
        created_at: now.clone(),
        updated_at: now,
    };
    store.upsert_signal(&signal)?;
    store.upsert_finding(&finding)?;
    if let Some(repository) = github_repository_from_remote(&config.repo.fork)
        && let Some(draft) = prepare_security_review_issue_draft(&finding, review, repository)
    {
        store.upsert_delivery_draft(&draft)?;
    }
    Ok(())
}

fn aggregate_disposition(reviews: &[EvaluatedSecurityReview]) -> SecurityDisposition {
    if reviews
        .iter()
        .any(|review| review.disposition == SecurityDisposition::Block)
    {
        SecurityDisposition::Block
    } else if reviews
        .iter()
        .any(|review| review.disposition == SecurityDisposition::NeedsReview)
    {
        SecurityDisposition::NeedsReview
    } else if reviews
        .iter()
        .any(|review| review.disposition == SecurityDisposition::VerifyRequired)
    {
        SecurityDisposition::VerifyRequired
    } else {
        SecurityDisposition::Allow
    }
}

fn configured_project_name(config: &Config) -> String {
    let name = config.protection.project.name.trim();
    if !name.is_empty() {
        name.to_string()
    } else {
        config
            .repo
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("protected-project")
            .to_string()
    }
}

fn review_dedupe_key(project: &str, policy_fingerprint: &str, commit: &str) -> String {
    hex_digest(format!("commit-review:{project}:{policy_fingerprint}:{commit}").as_bytes())
}

fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .context("安全审计枚举序列化失败")
}

fn hex_digest(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_never_allows_a_single_blocked_commit() {
        let mut decision = crate::protection::SecurityReviewDecision {
            security_fix_detected: false,
            introduced_risk: false,
            severity: crate::protection::SecuritySeverity::Informational,
            categories: Vec::new(),
            affected: Some(false),
            production_reachable: Some(false),
            confidence: crate::protection::SecurityConfidence::High,
            summary: "普通提交".to_string(),
            mechanism: "没有安全边界变化".to_string(),
            evidence: Vec::new(),
            fix_contract: None,
        };
        let allow = evaluate_security_review("a", decision.clone(), &Default::default());
        decision.introduced_risk = true;
        decision.affected = Some(true);
        decision.production_reachable = Some(true);
        decision.severity = crate::protection::SecuritySeverity::P0;
        let blocked = evaluate_security_review("b", decision, &Default::default());
        assert_eq!(
            aggregate_disposition(&[allow, blocked]),
            SecurityDisposition::Block
        );
    }
}
