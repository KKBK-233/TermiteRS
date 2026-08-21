mod issue;
mod model;
mod runner;
mod store;
mod supply_chain;

pub use issue::prepare_issue_draft;
pub use model::{
    CandidateArtifact, DeliveryDraft, DeliveryKind, FindingState, ProtectionFinding,
    RemediationAction, RemediationPlan, SecuritySignal, SecuritySignalSource, StaticIndicator,
    StaticScanReport, VerificationResult,
};
pub use runner::{ProtectionScanOutput, run_protection_scan};
pub use store::ProtectionStore;
pub(crate) use store::initialize_protection_schema;
pub use supply_chain::scan_supply_chain_tree;
