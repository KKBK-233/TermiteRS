use std::fs;

use anyhow::{Context, Result, bail};
use ring::digest::{SHA256, digest};

use crate::{
    config::Config,
    git::Git,
    llm::{LlmService, SecurityContractVerificationRequest},
    text::truncate_to_char_boundary,
};

use super::{
    CommitSecurityReviewBatch, EvaluatedContractVerification, ProtectionStore, SecurityConfidence,
    SecurityContractVerificationDecision, SecurityDisposition,
};

const VERIFICATION_PROMPT_OVERHEAD_BYTES: usize = 24 * 1024;
const MAX_TEST_EVIDENCE_BYTES: usize = 16 * 1024;

/// 在沙箱测试通过后，由独立提示验证所有待验证 FixContract；任一失败都会阻止推送。
pub fn verify_required_contracts(
    config: &Config,
    git: &Git,
    batch: &CommitSecurityReviewBatch,
    test_commands: &[String],
    test_output: &str,
) -> Result<Vec<EvaluatedContractVerification>> {
    let required = batch
        .reviews
        .iter()
        .filter(|review| review.disposition == SecurityDisposition::VerifyRequired)
        .collect::<Vec<_>>();
    if required.is_empty() {
        return Ok(Vec::new());
    }
    let llm_config = config
        .llm
        .as_ref()
        .filter(|llm| llm.enabled)
        .context("FixContract 验证需要启用 DS")?;
    anyhow::ensure!(
        llm_config.max_prompt_bytes > VERIFICATION_PROMPT_OVERHEAD_BYTES * 2,
        "LLM max_prompt_bytes 太小，无法容纳 FixContract 验证协议"
    );
    let mut bounded_test_output = test_output.to_string();
    if bounded_test_output.len() > MAX_TEST_EVIDENCE_BYTES {
        truncate_to_char_boundary(&mut bounded_test_output, MAX_TEST_EVIDENCE_BYTES);
        bounded_test_output.push_str(
            "\n... test output truncated by TermiteRS; process exit status was successful ...\n",
        );
    }

    fs::create_dir_all(&config.service.data_dir)?;
    let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
    let llm = LlmService::new(config.llm.clone());
    let final_patch =
        git.security_range_patch(&batch.from, &batch.to, llm_config.max_prompt_bytes / 2)?;
    let mut verifications = Vec::new();
    for review in required {
        let contract = review
            .decision
            .fix_contract
            .clone()
            .context("VerifyRequired 审计缺少 FixContract")?;
        let dedupe_key = verification_dedupe_key(
            &review.commit,
            &contract,
            test_commands,
            &bounded_test_output,
            &final_patch,
        )?;
        let verification = if let Some(cached) = store.contract_verification(&dedupe_key)? {
            cached
        } else {
            let decision = llm
                .verify_security_contract(&SecurityContractVerificationRequest {
                    project: batch.project.clone(),
                    commit: review.commit.clone(),
                    contract,
                    final_patch: final_patch.clone(),
                    test_commands: test_commands.to_vec(),
                    test_output: bounded_test_output.clone(),
                })?
                .context("独立验证器未返回 FixContract 结论")?;
            let verification =
                evaluate_contract_decision(review.commit.clone(), dedupe_key, decision);
            store.upsert_contract_verification(&verification)?;
            verification
        };
        if !verification.passed {
            bail!(
                "FixContract 独立验证失败：{}：{}；缺失回归：{}",
                verification.commit,
                verification.decision.summary,
                verification.decision.missing_regressions.join("；")
            );
        }
        verifications.push(verification);
    }
    Ok(verifications)
}

fn evaluate_contract_decision(
    commit: String,
    dedupe_key: String,
    decision: SecurityContractVerificationDecision,
) -> EvaluatedContractVerification {
    let passed = decision.security_property_present
        && decision.vulnerable_behavior_removed
        && decision.regression_evidence_present
        && decision.confidence != SecurityConfidence::Low
        && !decision.evidence.is_empty()
        && decision.missing_regressions.is_empty();
    EvaluatedContractVerification {
        commit,
        passed,
        decision,
        dedupe_key,
    }
}

fn verification_dedupe_key(
    commit: &str,
    contract: &impl serde::Serialize,
    test_commands: &[String],
    test_output: &str,
    final_patch: &str,
) -> Result<String> {
    let source = serde_json::to_vec(&(commit, contract, test_commands, test_output, final_patch))?;
    Ok(hex_digest(&source))
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
    fn verifier_cannot_pass_without_all_three_contract_properties() {
        let decision = SecurityContractVerificationDecision {
            security_property_present: true,
            vulnerable_behavior_removed: true,
            regression_evidence_present: false,
            confidence: SecurityConfidence::High,
            summary: "实现已修改但没有回归测试".to_string(),
            evidence: vec!["src/security.rs".to_string()],
            missing_regressions: vec!["恶意输入应被拒绝".to_string()],
        };
        let verification = evaluate_contract_decision("abc".into(), "key".into(), decision);
        assert!(!verification.passed);
    }

    #[test]
    fn verifier_pass_requires_concrete_evidence_and_no_missing_case() {
        let decision = SecurityContractVerificationDecision {
            security_property_present: true,
            vulnerable_behavior_removed: true,
            regression_evidence_present: true,
            confidence: SecurityConfidence::Medium,
            summary: "契约和回归用例均存在".to_string(),
            evidence: vec!["tests/security.rs::rejects_payload".to_string()],
            missing_regressions: Vec::new(),
        };
        let verification = evaluate_contract_decision("abc".into(), "key".into(), decision);
        assert!(verification.passed);
    }
}
