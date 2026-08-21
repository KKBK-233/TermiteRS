mod catalog;
mod dependency;
mod investigate;
mod issue;
mod model;
mod review;
mod runner;
mod store;
mod supply_chain;
mod verify;

pub use catalog::{CATALOG_VERSION, evaluate_security_review, policy_fingerprint};
pub use dependency::scan_locked_cargo_dependencies;
pub use investigate::{SignalInvestigationOutput, investigate_security_signal};
pub use issue::{
    github_repository_from_remote, prepare_issue_draft, prepare_security_review_issue_draft,
};
pub use model::{
    CandidateArtifact, CandidateFileChange, CommitSecurityReviewBatch, DeliveryDraft, DeliveryKind,
    EvaluatedContractVerification, EvaluatedSecurityReview, FindingState, FixContract,
    ProtectionFinding, RemediationAction, RemediationPlan, SecurityCategory, SecurityConfidence,
    SecurityContractVerificationDecision, SecurityDisposition, SecurityReviewDecision,
    SecuritySeverity, SecuritySignal, SecuritySignalSource, SignalFileSelection,
    SignalInvestigationDecision, StaticIndicator, StaticScanReport, VerificationResult,
};
pub use review::{ensure_reviews_can_proceed, run_commit_security_reviews};
pub use runner::{ProtectionScanOutput, enforce_prebuild_gate, run_protection_scan};
pub use store::ProtectionStore;
pub(crate) use store::initialize_protection_schema;
pub use supply_chain::scan_supply_chain_tree;
pub use verify::verify_required_contracts;
