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
