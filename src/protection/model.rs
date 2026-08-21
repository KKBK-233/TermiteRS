use serde::{Deserialize, Serialize};

/// 不同来源的安全消息统一进入同一种信号模型，后续不再绑定 GitHub 提交。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySignalSource {
    UpstreamCommit,
    DependencyAdvisory,
    PackageRelease,
    UserReport,
    ProductionIndicator,
    StaticSupplyChainScan,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecuritySignal {
    pub id: String,
    pub project: String,
    pub source: SecuritySignalSource,
    pub summary: String,
    pub reference: Option<String>,
    pub dedupe_key: String,
    pub received_at: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingState {
    Discovered,
    Investigating,
    Affected,
    Unaffected,
    Uncertain,
    CandidatePrepared,
    Verified,
    AwaitingDelivery,
    Delivered,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectionFinding {
    pub id: String,
    pub project: String,
    pub signal_id: String,
    pub state: FindingState,
    pub classification: String,
    pub severity: String,
    pub confidence: String,
    pub affected: Option<bool>,
    pub build_allowed: bool,
    pub summary: String,
    pub evidence: Vec<String>,
    pub dedupe_key: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationAction {
    KeepCurrent,
    PinVersion,
    ApplyUpstreamPatch,
    UpgradeVersion,
    LocalSecurityPatch,
    ConfigurationMitigation,
    DisableFeature,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationPlan {
    pub id: String,
    pub finding_id: String,
    pub action: RemediationAction,
    pub summary: String,
    pub requirements: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CandidateArtifact {
    pub id: String,
    pub finding_id: String,
    pub worktree_path: String,
    pub content_sha256: String,
    pub summary: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationResult {
    pub id: String,
    pub candidate_id: String,
    pub verifier: String,
    pub passed: bool,
    pub summary: String,
    pub evidence: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryKind {
    Email,
    GithubIssue,
    GithubBranch,
    PullRequest,
    Artifact,
    Deployment,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeliveryDraft {
    pub id: String,
    pub finding_id: String,
    pub kind: DeliveryKind,
    pub destination: String,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub dedupe_key: String,
    pub approval_required: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StaticIndicator {
    pub rule_id: String,
    pub severity: String,
    pub path: String,
    pub summary: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StaticScanReport {
    pub project: String,
    pub root: String,
    pub scanned_files: usize,
    pub build_allowed: bool,
    pub blockers: Vec<StaticIndicator>,
    pub warnings: Vec<StaticIndicator>,
    pub dedupe_key: String,
}

/// 这些类别属于跨行业不可接受的通用漏洞能力，模型只能选择，不能扩展或删除。
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityCategory {
    RemoteCodeExecution,
    CommandInjection,
    CodeInjection,
    ServerSideRequestForgery,
    AuthenticationBypass,
    AuthorizationBypass,
    SignatureBypass,
    ProofVerificationBypass,
    ArbitraryFileRead,
    ArbitraryFileWrite,
    PathTraversal,
    UnsafeDeserialization,
    SecretOrKeyDisclosure,
    SupplyChainMalware,
    ConsensusSafety,
    UnauthorizedUpgrade,
    PermanentServiceHalt,
    ResourceExhaustion,
    InformationDisclosure,
    Other,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    P0,
    P1,
    P2,
    P3,
    Informational,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FixContract {
    pub security_property: String,
    pub vulnerable_behavior: String,
    pub fixed_behavior: String,
    #[serde(default)]
    pub attack_preconditions: Vec<String>,
    #[serde(default)]
    pub regression_cases: Vec<String>,
}

/// DS 只描述从不可信提交证据中观察到的事实，不拥有最终放行权。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecurityReviewDecision {
    pub security_fix_detected: bool,
    pub introduced_risk: bool,
    pub severity: SecuritySeverity,
    #[serde(default)]
    pub categories: Vec<SecurityCategory>,
    pub affected: Option<bool>,
    pub production_reachable: Option<bool>,
    pub confidence: SecurityConfidence,
    pub summary: String,
    pub mechanism: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub fix_contract: Option<FixContract>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityDisposition {
    Allow,
    VerifyRequired,
    NeedsReview,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvaluatedSecurityReview {
    pub commit: String,
    pub decision: SecurityReviewDecision,
    pub disposition: SecurityDisposition,
    pub policy_reasons: Vec<String>,
    pub policy_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommitSecurityReviewBatch {
    pub project: String,
    pub from: String,
    pub to: String,
    pub reviews: Vec<EvaluatedSecurityReview>,
    pub disposition: SecurityDisposition,
    pub cache_hits: usize,
}

/// 独立验证器只报告 FixContract 的三类证据，最终 passed 由程序重新计算。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecurityContractVerificationDecision {
    pub security_property_present: bool,
    pub vulnerable_behavior_removed: bool,
    pub regression_evidence_present: bool,
    pub confidence: SecurityConfidence,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub missing_regressions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvaluatedContractVerification {
    pub commit: String,
    pub passed: bool,
    pub decision: SecurityContractVerificationDecision,
    pub dedupe_key: String,
}
