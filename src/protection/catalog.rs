use ring::digest::{SHA256, digest};

use crate::config::ProtectionConfig;

use super::{
    EvaluatedSecurityReview, SecurityCategory, SecurityConfidence, SecurityDisposition,
    SecurityReviewDecision, SecuritySeverity,
};

pub const CATALOG_VERSION: &str = "security-catalog-v2";

/// 根据程序内置安全目录和企业预设计算门禁结论，LLM 无权覆盖本函数。
pub fn evaluate_security_review(
    commit: impl Into<String>,
    decision: SecurityReviewDecision,
    protection: &ProtectionConfig,
) -> EvaluatedSecurityReview {
    let fingerprint = policy_fingerprint(protection);
    let applicable =
        decision.affected != Some(false) && decision.production_reachable != Some(false);
    let strict = protection
        .profiles
        .iter()
        .any(|profile| profile == "strict");
    let universal = decision.categories.iter().any(is_universal_category);
    let mut reasons = Vec::new();

    let disposition = if !applicable
        && (universal
            || matches!(
                decision.severity,
                SecuritySeverity::P0 | SecuritySeverity::P1
            ))
        && (decision.introduced_risk || decision.security_fix_detected)
    {
        reasons.push(
            "只有模型声称当前不可达，缺少程序化依赖或运行时可达性证明，不能自动放行".to_string(),
        );
        SecurityDisposition::NeedsReview
    } else if !applicable {
        reasons.push("低等级问题的审计证据表明当前项目不受影响或生产路径不可达".to_string());
        SecurityDisposition::Allow
    } else if decision.introduced_risk
        && (universal
            || matches!(
                decision.severity,
                SecuritySeverity::P0 | SecuritySeverity::P1
            )
            || (strict && decision.severity == SecuritySeverity::P2))
    {
        if universal {
            reasons.push("提交引入了不可接受漏洞目录中的通用能力".to_string());
        }
        reasons.push(format!("提交引入 {:?} 级安全风险", decision.severity));
        SecurityDisposition::Block
    } else if decision.introduced_risk
        && (decision.confidence == SecurityConfidence::Low
            || decision.affected.is_none()
            || decision.production_reachable.is_none())
    {
        reasons.push("提交可能引入风险，但影响或可达性证据不足".to_string());
        SecurityDisposition::NeedsReview
    } else if decision.security_fix_detected
        && matches!(
            decision.severity,
            SecuritySeverity::P0 | SecuritySeverity::P1 | SecuritySeverity::P2
        )
    {
        if decision.fix_contract.is_some() {
            reasons.push("检测到适用的安全修复，必须独立验证 FixContract".to_string());
            SecurityDisposition::VerifyRequired
        } else {
            reasons.push("检测到安全修复，但 DS 未给出可验证的 FixContract".to_string());
            SecurityDisposition::NeedsReview
        }
    } else if decision.confidence == SecurityConfidence::Low
        && (decision.security_fix_detected || decision.introduced_risk)
    {
        reasons.push("安全相关判断置信度过低".to_string());
        SecurityDisposition::NeedsReview
    } else {
        reasons.push("未发现达到当前项目阻断阈值的适用风险".to_string());
        SecurityDisposition::Allow
    };

    EvaluatedSecurityReview {
        commit: commit.into(),
        decision,
        disposition,
        policy_reasons: reasons,
        policy_fingerprint: fingerprint,
    }
}

pub fn policy_fingerprint(protection: &ProtectionConfig) -> String {
    let mut profiles = protection.profiles.clone();
    profiles.sort();
    let source = format!(
        "{}\n{}\n{}\n{}",
        CATALOG_VERSION,
        protection.project.name.trim(),
        protection.project.description.trim(),
        profiles.join(",")
    );
    hex_digest(source.as_bytes())
}

fn is_universal_category(category: &SecurityCategory) -> bool {
    matches!(
        category,
        SecurityCategory::RemoteCodeExecution
            | SecurityCategory::CommandInjection
            | SecurityCategory::CodeInjection
            | SecurityCategory::ServerSideRequestForgery
            | SecurityCategory::AuthenticationBypass
            | SecurityCategory::AuthorizationBypass
            | SecurityCategory::SignatureBypass
            | SecurityCategory::ProofVerificationBypass
            | SecurityCategory::ArbitraryFileRead
            | SecurityCategory::ArbitraryFileWrite
            | SecurityCategory::PathTraversal
            | SecurityCategory::UnsafeDeserialization
            | SecurityCategory::SecretOrKeyDisclosure
            | SecurityCategory::SupplyChainMalware
            | SecurityCategory::ConsensusSafety
            | SecurityCategory::UnauthorizedUpgrade
    )
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
    use crate::config::ProtectionConfig;
    use crate::protection::{FixContract, SecurityConfidence, SecurityReviewDecision};

    fn decision() -> SecurityReviewDecision {
        SecurityReviewDecision {
            security_fix_detected: false,
            introduced_risk: true,
            severity: SecuritySeverity::P2,
            categories: vec![SecurityCategory::ServerSideRequestForgery],
            affected: Some(true),
            production_reachable: Some(true),
            confidence: SecurityConfidence::High,
            summary: "新增可控 URL 请求".to_string(),
            mechanism: "外部输入直接进入 HTTP 客户端".to_string(),
            evidence: vec!["src/fetch.rs 新增 Client::get(user_url)".to_string()],
            fix_contract: None,
        }
    }

    #[test]
    fn universal_vulnerability_is_blocked_even_when_reported_as_p2() {
        let review = evaluate_security_review("abc", decision(), &ProtectionConfig::default());
        assert_eq!(review.disposition, SecurityDisposition::Block);
    }

    #[test]
    fn model_only_unreachable_claim_cannot_allow_universal_vulnerability() {
        let mut input = decision();
        input.affected = Some(false);
        input.production_reachable = Some(false);
        let review = evaluate_security_review("abc", input, &ProtectionConfig::default());
        assert_eq!(review.disposition, SecurityDisposition::NeedsReview);
    }

    #[test]
    fn hidden_security_fix_requires_independent_contract_verification() {
        let mut input = decision();
        input.introduced_risk = false;
        input.security_fix_detected = true;
        input.severity = SecuritySeverity::P1;
        input.fix_contract = Some(FixContract {
            security_property: "外部 URL 只能访问允许域名".to_string(),
            vulnerable_behavior: "任意 URL 被请求".to_string(),
            fixed_behavior: "非允许域名被拒绝".to_string(),
            attack_preconditions: vec!["可控 URL".to_string()],
            regression_cases: vec!["内网 URL 返回拒绝".to_string()],
        });
        let review = evaluate_security_review("abc", input, &ProtectionConfig::default());
        assert_eq!(review.disposition, SecurityDisposition::VerifyRequired);
    }
}
