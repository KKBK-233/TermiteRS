use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::Utc;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    config::{BranchConfig, Config, ProtectionAutomation},
    git::Git,
    llm::{LlmService, SignalFileSelectionRequest, SignalInvestigationRequest},
    notify::Notifier,
};

use super::{
    CandidateArtifact, CommitSecurityReviewBatch, DeliveryDraft, EvaluatedSecurityReview,
    FindingState, ProtectionFinding, ProtectionStore, RemediationPlan, SecurityCategory,
    SecurityDisposition, SecuritySeverity, SecuritySignal, SecuritySignalSource,
    SignalFileSelection, SignalInvestigationDecision, VerificationResult,
    cargo_reachability_snapshot, enforce_prebuild_gate, github_repository_from_remote,
    policy_fingerprint, prepare_signal_issue_draft, run_commit_security_reviews,
    verify_required_contracts,
};

const MAX_SIGNAL_BYTES: usize = 64 * 1024;
const MAX_TRACKED_FILES: usize = 10_000;
const MAX_EVIDENCE_FILE_BYTES: usize = 48 * 1024;
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_CANDIDATE_BYTES: usize = 768 * 1024;

#[derive(Debug, Serialize)]
pub struct SignalInvestigationOutput {
    pub signal: SecuritySignal,
    pub finding: ProtectionFinding,
    pub selection: SignalFileSelection,
    pub decision: SignalInvestigationDecision,
    pub plan: RemediationPlan,
    pub candidate: Option<CandidateArtifact>,
    pub verification: Option<VerificationResult>,
    pub issue_draft: Option<DeliveryDraft>,
    pub candidate_error: Option<String>,
    pub notification_sent: bool,
    pub notification_error: Option<String>,
}

/// 将人工粘贴的公告或社交媒体消息映射到当前项目；引用地址仅作为文本保存，绝不抓取。
pub fn investigate_security_signal(
    config: &Config,
    summary: &str,
    reference: Option<&str>,
    content: &str,
    branch_name: Option<&str>,
) -> Result<SignalInvestigationOutput> {
    anyhow::ensure!(config.protection.enabled, "安全消息调查要求启用 protection");
    anyhow::ensure!(!summary.trim().is_empty(), "安全消息摘要不能为空");
    anyhow::ensure!(content.len() <= MAX_SIGNAL_BYTES, "安全消息正文超过 64 KiB");
    let llm = LlmService::new(config.llm.clone());
    let git = Git::new(config.repo.path.clone());
    git.ensure_repo()?;
    let project = configured_project_name(config);
    let tracked_files = tracked_regular_files(&git)?;
    let cargo_reachability = cargo_reachability_snapshot(&config.repo.path)?;
    let selection = llm
        .select_signal_files(&SignalFileSelectionRequest {
            project: project.clone(),
            project_description: config.protection.project.description.clone(),
            signal_summary: summary.to_string(),
            signal_reference: reference.map(ToOwned::to_owned),
            signal_content: content.to_string(),
            tracked_files: tracked_files.clone(),
            cargo_reachability: cargo_reachability.clone(),
        })?
        .context("DS 未返回安全消息取证文件选择")?;
    let file_evidence = read_selected_files(&config.repo.path, &tracked_files, &selection)?;
    let decision = llm
        .investigate_signal(&SignalInvestigationRequest {
            project: project.clone(),
            project_description: config.protection.project.description.clone(),
            signal_summary: summary.to_string(),
            signal_reference: reference.map(ToOwned::to_owned),
            signal_content: content.to_string(),
            file_evidence,
            cargo_reachability: cargo_reachability.clone(),
        })?
        .context("DS 未返回安全消息调查结论")?;

    fs::create_dir_all(&config.service.data_dir)?;
    let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
    let now = Utc::now().to_rfc3339();
    let dedupe = hex_digest(
        serde_json::to_string(&(project.as_str(), summary, reference, content))?.as_bytes(),
    );
    let suffix = &dedupe[..32];
    let signal = SecuritySignal {
        id: format!("signal-user-{suffix}"),
        project: project.clone(),
        source: SecuritySignalSource::UserReport,
        summary: summary.to_string(),
        reference: reference.map(ToOwned::to_owned),
        dedupe_key: format!("user-report:{dedupe}"),
        received_at: now.clone(),
    };
    let requires_action = requires_remediation(config, &decision);
    let mut finding = ProtectionFinding {
        id: format!("finding-user-{suffix}"),
        project: project.clone(),
        signal_id: signal.id.clone(),
        state: if decision.review.affected == Some(false) {
            FindingState::Unaffected
        } else if requires_action {
            FindingState::Affected
        } else {
            FindingState::Uncertain
        },
        classification: "external-security-signal".to_string(),
        severity: enum_text(&decision.review.severity)?,
        confidence: enum_text(&decision.review.confidence)?,
        affected: decision.review.affected,
        build_allowed: !requires_action && decision.review.affected == Some(false),
        summary: decision.review.summary.clone(),
        evidence: decision
            .review
            .evidence
            .iter()
            .cloned()
            .chain(dependency_evidence(&decision, cargo_reachability.as_ref()))
            .collect(),
        dedupe_key: format!("finding-user:{dedupe}"),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let plan = RemediationPlan {
        id: format!("plan-user-{suffix}"),
        finding_id: finding.id.clone(),
        action: decision.recommended_action,
        summary: decision.candidate_summary.clone(),
        requirements: decision
            .review
            .fix_contract
            .as_ref()
            .map(|contract| contract.regression_cases.clone())
            .unwrap_or_default(),
        created_at: now,
    };
    store.upsert_signal(&signal)?;
    store.upsert_finding(&finding)?;
    store.upsert_remediation_plan(&plan)?;

    let (notification_sent, notification_error) = if requires_action {
        match Notifier::new(config.notify.clone()).send(
            &format!("{} 安全消息告警", project),
            &format!(
                "{}\n\n判断：{}\n严重性：{}\n引用：{}\n\nTermiteRS 尚未推送、发布或部署任何修改。",
                summary,
                decision.review.summary,
                enum_text(&decision.review.severity)?,
                reference.unwrap_or("无")
            ),
        ) {
            Ok(sent) => (sent, None),
            Err(error) => (false, Some(format!("{error:#}"))),
        }
    } else {
        (false, None)
    };

    let (candidate, verification, candidate_error) = if requires_action
        && matches!(
            config.protection.automation,
            ProtectionAutomation::Candidate
        ) {
        let candidate_id = format!("candidate-{}", Uuid::new_v4());
        match prepare_candidate(
            config,
            &git,
            &tracked_files,
            &finding,
            &decision,
            branch_name,
            &candidate_id,
        ) {
            Ok((candidate, verification)) => {
                store.upsert_candidate(&candidate)?;
                store.upsert_verification(&verification)?;
                (Some(candidate), Some(verification), None)
            }
            Err(error) => {
                let details = format!("{error:#}");
                let failed = failed_candidate_artifacts(
                    config,
                    &finding,
                    &decision,
                    &candidate_id,
                    &details,
                );
                store.upsert_candidate(&failed.0)?;
                store.upsert_verification(&failed.1)?;
                (Some(failed.0), Some(failed.1), Some(details))
            }
        }
    } else {
        (None, None, None)
    };
    if verification.as_ref().is_some_and(|result| result.passed) {
        finding.state = FindingState::AwaitingDelivery;
        finding.updated_at = Utc::now().to_rfc3339();
        store.upsert_finding(&finding)?;
    }
    let issue_draft = github_repository_from_remote(&config.repo.fork).and_then(|repository| {
        prepare_signal_issue_draft(
            &finding,
            repository,
            candidate.as_ref(),
            verification.as_ref(),
        )
    });
    if let Some(draft) = &issue_draft {
        store.upsert_delivery_draft(draft)?;
    }

    Ok(SignalInvestigationOutput {
        signal,
        finding,
        selection,
        decision,
        plan,
        candidate,
        verification,
        issue_draft,
        candidate_error,
        notification_sent,
        notification_error,
    })
}

fn prepare_candidate(
    config: &Config,
    main_git: &Git,
    tracked_files: &[String],
    finding: &ProtectionFinding,
    decision: &SignalInvestigationDecision,
    branch_name: Option<&str>,
    candidate_id: &str,
) -> Result<(CandidateArtifact, VerificationResult)> {
    anyhow::ensure!(
        !decision.changes.is_empty(),
        "当前项目需要修复，但 DS 没有给出候选修改"
    );
    let contract = decision
        .review
        .fix_contract
        .clone()
        .context("安全候选缺少 FixContract")?;
    anyhow::ensure!(
        !contract.regression_cases.is_empty(),
        "安全候选缺少回归用例"
    );
    validate_candidate_changes(&config.repo.path, tracked_files, decision)?;
    let branch = configured_test_branch(config, branch_name)?;
    anyhow::ensure!(!branch.tests.is_empty(), "安全候选没有配置任何沙箱测试命令");
    anyhow::ensure!(
        branch.has_behavioral_tests(),
        "安全候选至少需要一条行为测试命令"
    );

    let worktree_path = config
        .service
        .data_dir
        .join("protection/worktrees")
        .join(candidate_id);
    fs::create_dir_all(worktree_path.parent().context("候选 worktree 缺少父目录")?)?;
    let worktree = worktree_path.to_string_lossy().to_string();
    let base = main_git
        .run_git(&["rev-parse", "HEAD"])?
        .stdout
        .trim()
        .to_string();
    let output = main_git.run_git(&["worktree", "add", "--detach", &worktree, &base])?;
    anyhow::ensure!(
        output.success(),
        "创建安全候选 worktree 失败：{}",
        output.stderr.trim()
    );
    let git = Git::new(&worktree_path);
    for change in &decision.changes {
        git.write_file(&change.path, &change.content)?;
    }
    let diff_check = git.run_git(&["diff", "--check"])?;
    anyhow::ensure!(
        diff_check.success(),
        "安全候选格式检查失败：{}",
        diff_check.stderr.trim()
    );
    let changed = git.run_git(&["status", "--porcelain"])?;
    anyhow::ensure!(!changed.stdout.trim().is_empty(), "DS 候选没有产生文件修改");
    enforce_prebuild_gate(config, &worktree_path)?;
    git.run_git(&["add", "--all"])?;
    let commit = git.run_git(&[
        "-c",
        "user.name=TermiteRS Candidate",
        "-c",
        "user.email=termiters@localhost",
        "commit",
        "-m",
        "security candidate",
    ])?;
    anyhow::ensure!(
        commit.success(),
        "提交隔离候选失败：{}",
        commit.stderr.trim()
    );

    let review_batch = run_commit_security_reviews(config, &git, &base, "HEAD")?
        .context("安全候选提交没有可审计差异")?;
    super::ensure_reviews_can_proceed(&review_batch)?;
    let mut test_output = String::new();
    for command in &branch.tests {
        let output = git.run_test_sandboxed(command)?;
        test_output.push_str(&format!(
            "$ {command}\n{}\n{}\n",
            output.stdout, output.stderr
        ));
        anyhow::ensure!(
            output.success(),
            "安全候选沙箱测试失败：{command}\n{}",
            output.stderr.trim()
        );
    }
    verify_required_contracts(config, &git, &review_batch, &branch.tests, &test_output)?;

    let head = git
        .run_git(&["rev-parse", "HEAD"])?
        .stdout
        .trim()
        .to_string();
    let signal_contract_batch = CommitSecurityReviewBatch {
        project: configured_project_name(config),
        from: base.clone(),
        to: "HEAD".to_string(),
        reviews: vec![EvaluatedSecurityReview {
            commit: head.clone(),
            decision: crate::protection::SecurityReviewDecision {
                security_fix_detected: true,
                introduced_risk: false,
                fix_contract: Some(contract),
                ..decision.review.clone()
            },
            disposition: SecurityDisposition::VerifyRequired,
            policy_reasons: vec!["外部安全消息要求独立验证原始 FixContract".to_string()],
            policy_fingerprint: policy_fingerprint(&config.protection),
        }],
        disposition: SecurityDisposition::VerifyRequired,
        cache_hits: 0,
    };
    let contract_results = verify_required_contracts(
        config,
        &git,
        &signal_contract_batch,
        &branch.tests,
        &test_output,
    )?;
    let patch = git.security_range_patch(&base, "HEAD", MAX_CANDIDATE_BYTES)?;
    let content_sha256 = hex_digest(patch.as_bytes());
    let now = Utc::now().to_rfc3339();
    let candidate = CandidateArtifact {
        id: candidate_id.to_string(),
        finding_id: finding.id.clone(),
        worktree_path: worktree,
        content_sha256,
        summary: decision.candidate_summary.clone(),
        created_at: now.clone(),
    };
    let verification = VerificationResult {
        id: format!("verification-{candidate_id}"),
        candidate_id: candidate_id.to_string(),
        verifier: "static-gate+sandbox-tests+commit-review+fix-contract".to_string(),
        passed: true,
        summary: "候选通过静态门禁、沙箱测试、逐提交审计和独立安全契约验证".to_string(),
        evidence: contract_results
            .into_iter()
            .flat_map(|result| result.decision.evidence)
            .collect(),
        created_at: now,
    };
    Ok((candidate, verification))
}

/// 失败候选也必须可追踪；保留隔离 worktree 和失败验证，绝不把异常吞掉后继续投送。
fn failed_candidate_artifacts(
    config: &Config,
    finding: &ProtectionFinding,
    decision: &SignalInvestigationDecision,
    candidate_id: &str,
    error: &str,
) -> (CandidateArtifact, VerificationResult) {
    let worktree_path = config
        .service
        .data_dir
        .join("protection/worktrees")
        .join(candidate_id);
    let patch = if worktree_path.is_dir() {
        let git = Git::new(&worktree_path);
        let subject = git
            .run_git(&["log", "-1", "--pretty=%s"])
            .ok()
            .map(|output| output.stdout.trim().to_string());
        let args = if subject.as_deref() == Some("security candidate") {
            vec!["show", "--format=", "--patch", "HEAD"]
        } else {
            vec!["diff", "--patch", "HEAD"]
        };
        git.run_git(&args)
            .ok()
            .map(|output| output.stdout)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let now = Utc::now().to_rfc3339();
    (
        CandidateArtifact {
            id: candidate_id.to_string(),
            finding_id: finding.id.clone(),
            worktree_path: worktree_path.to_string_lossy().to_string(),
            content_sha256: hex_digest(patch.as_bytes()),
            summary: format!("候选未通过门禁：{}；{}", decision.candidate_summary, error),
            created_at: now.clone(),
        },
        VerificationResult {
            id: format!("verification-{candidate_id}"),
            candidate_id: candidate_id.to_string(),
            verifier: "candidate-pipeline-failed-closed".to_string(),
            passed: false,
            summary: error.to_string(),
            evidence: vec!["测试、推送、发布和部署均未获得授权".to_string()],
            created_at: now,
        },
    )
}

fn tracked_regular_files(git: &Git) -> Result<Vec<String>> {
    let output = git.run_git(&["ls-files", "-z"])?;
    anyhow::ensure!(output.success(), "无法枚举 Git 跟踪文件");
    let files = output
        .stdout
        .split('\0')
        .filter(|path| !path.is_empty())
        .filter(|path| candidate_path_allowed(path))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(files.len() <= MAX_TRACKED_FILES, "Git 跟踪文件超过取证上限");
    Ok(files)
}

fn read_selected_files(
    root: &Path,
    tracked_files: &[String],
    selection: &SignalFileSelection,
) -> Result<Vec<(String, String)>> {
    let tracked = tracked_files
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut total = 0usize;
    let mut evidence = Vec::new();
    for path in &selection.paths {
        anyhow::ensure!(
            tracked.contains(path.as_str()),
            "DS 选择了未授权文件：{path}"
        );
        let full_path = safe_existing_file(root, path)?;
        let bytes = fs::read(&full_path)?;
        anyhow::ensure!(
            bytes.len() <= MAX_EVIDENCE_FILE_BYTES,
            "取证文件超过 48 KiB：{path}"
        );
        total += bytes.len();
        anyhow::ensure!(total <= MAX_EVIDENCE_BYTES, "取证文件总量超过 64 KiB");
        let content =
            String::from_utf8(bytes).with_context(|| format!("取证文件不是 UTF-8：{path}"))?;
        evidence.push((path.clone(), content));
    }
    anyhow::ensure!(!evidence.is_empty(), "DS 没有选择任何可审计文件");
    Ok(evidence)
}

fn validate_candidate_changes(
    root: &Path,
    tracked_files: &[String],
    decision: &SignalInvestigationDecision,
) -> Result<()> {
    let tracked = tracked_files
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut total = 0usize;
    let mut seen = HashSet::new();
    for change in &decision.changes {
        anyhow::ensure!(
            tracked.contains(change.path.as_str()),
            "候选试图修改未授权文件：{}",
            change.path
        );
        anyhow::ensure!(
            seen.insert(change.path.as_str()),
            "候选重复修改文件：{}",
            change.path
        );
        safe_existing_file(root, &change.path)?;
        total += change.content.len();
        anyhow::ensure!(total <= MAX_CANDIDATE_BYTES, "候选文件总量超过 768 KiB");
    }
    Ok(())
}

fn safe_existing_file(root: &Path, path: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        candidate_path_allowed(path),
        "受保护路径不能进入候选：{path}"
    );
    let full = root.join(path);
    let metadata =
        fs::symlink_metadata(&full).with_context(|| format!("无法读取候选文件元数据：{path}"))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "候选文件必须是普通文件：{path}"
    );
    let root = root.canonicalize()?;
    let canonical = full.canonicalize()?;
    anyhow::ensure!(canonical.starts_with(root), "候选文件越过仓库边界：{path}");
    Ok(canonical)
}

fn candidate_path_allowed(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let candidate = Path::new(&normalized);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return false;
    }
    let lower = normalized.to_ascii_lowercase();
    !lower.starts_with(".git/")
        && !lower.starts_with(".github/workflows/")
        && !lower.contains("/.env")
        && !lower.ends_with(".env")
        && !lower.ends_with("termite.yml")
        && !lower.ends_with("termiters.yml")
        && !lower.contains("secret")
        && !lower.contains("credential")
}

fn configured_test_branch<'a>(
    config: &'a Config,
    requested: Option<&str>,
) -> Result<&'a BranchConfig> {
    if let Some(requested) = requested {
        return config
            .branches
            .iter()
            .find(|branch| branch.name == requested)
            .with_context(|| format!("未配置候选测试分支：{requested}"));
    }
    config
        .branches
        .first()
        .context("未配置可用于安全候选的分支测试")
}

fn requires_remediation(config: &Config, decision: &SignalInvestigationDecision) -> bool {
    if decision.review.affected == Some(false) {
        return false;
    }
    let universal = decision.review.categories.iter().any(|category| {
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
    });
    universal
        || matches!(
            decision.review.severity,
            SecuritySeverity::P0 | SecuritySeverity::P1
        )
        || (config
            .protection
            .profiles
            .iter()
            .any(|profile| profile == "strict")
            && decision.review.severity == SecuritySeverity::P2)
}

fn dependency_evidence(
    decision: &SignalInvestigationDecision,
    snapshot: Option<&crate::protection::CargoReachabilitySnapshot>,
) -> Vec<String> {
    if decision.affected_packages.is_empty() {
        return Vec::new();
    }
    let Some(snapshot) = snapshot else {
        return vec!["程序化依赖证据：项目没有可解析的 Cargo.lock 依赖图".to_string()];
    };
    let mut evidence = Vec::new();
    for claimed in &decision.affected_packages {
        let normalized = claimed.trim().to_ascii_lowercase().replace('_', "-");
        let versions = snapshot
            .reachable_packages
            .iter()
            .filter(|package| package.name.to_ascii_lowercase().replace('_', "-") == normalized)
            .map(|package| package.version.as_str())
            .collect::<Vec<_>>();
        if versions.is_empty() {
            evidence.push(format!(
                "程序化依赖证据：{claimed} 不在 Cargo.lock 根包依赖闭包中"
            ));
        } else {
            evidence.push(format!(
                "程序化依赖证据：{claimed} 进入 Cargo.lock 根包依赖闭包，版本 {}；这不等同于生产运行时可达",
                versions.join(",")
            ));
        }
    }
    if !snapshot.ambiguous_edges.is_empty() {
        evidence.push(format!(
            "程序化依赖证据：存在 {} 条无法唯一解析的锁文件边，按保守结果处理",
            snapshot.ambiguous_edges.len()
        ));
    }
    evidence
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

fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    Ok(serde_json::to_string(value)?.trim_matches('"').to_string())
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
    fn candidate_paths_reject_credentials_and_automation() {
        assert!(candidate_path_allowed("src/main.rs"));
        assert!(!candidate_path_allowed("../src/main.rs"));
        assert!(!candidate_path_allowed(".github/workflows/release.yml"));
        assert!(!candidate_path_allowed("deploy/credentials.json"));
        assert!(!candidate_path_allowed("termite.yml"));
    }
}
