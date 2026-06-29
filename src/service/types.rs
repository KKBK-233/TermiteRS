use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::git::{ConflictFileContent, ConflictSnapshot};
use crate::llm::{ConflictOptionsDecision, ResolvedFile};

pub(crate) const ACTIVE_STATES: &[&str] = &[
    "queued",
    "running",
    "waiting_guidance",
    "generating_proposal",
    "applying",
    "test_failed",
    "waiting_push",
    "pushing",
];

pub(crate) const CHALLENGE_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub id: String,
    pub job_id: Option<String>,
    pub kind: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupReport {
    pub cutoff: String,
    pub jobs: usize,
    pub messages: usize,
    pub events: usize,
    pub challenges: usize,
    pub notifications: usize,
    pub worktrees: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct Dashboard {
    pub(crate) repository: String,
    pub(crate) fork_url: String,
    pub(crate) upstream_url: String,
    pub(crate) branches: Vec<BranchDashboard>,
    pub(crate) jobs: Vec<JobView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BranchDashboard {
    pub(crate) name: String,
    pub(crate) note: String,
    pub(crate) local_head: Option<String>,
    pub(crate) upstream_head: Option<String>,
    pub(crate) remote_head: Option<String>,
    pub(crate) upstream_ahead: Option<u32>,
    pub(crate) upstream_behind: Option<u32>,
    pub(crate) current_job_id: Option<String>,
    pub(crate) current_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct JobView {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) branch: String,
    pub(crate) state: String,
    pub(crate) risk: String,
    pub(crate) summary: String,
    pub(crate) worktree_path: String,
    pub(crate) base_ref: String,
    pub(crate) before_head: String,
    pub(crate) base_head: String,
    pub(crate) remote_head: String,
    pub(crate) conflict_files: Vec<String>,
    pub(crate) options: Option<ConflictOptionsDecision>,
    pub(crate) proposal: Option<StoredProposal>,
    pub(crate) test_output: String,
    pub(crate) messages: Vec<ConversationMessage>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConversationMessage {
    pub(crate) role: String,
    pub(crate) content: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct StoredProposal {
    pub(crate) summary: String,
    pub(crate) files: Vec<ResolvedFile>,
    pub(crate) diff: String,
    pub(crate) selected_option: String,
    pub(crate) requirements: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SyncRequest {
    pub(crate) branch: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct MessageRequest {
    pub(crate) message: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProposalRequest {
    pub(crate) option_id: String,
    pub(crate) requirements: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ConflictSide {
    Ours,
    Theirs,
}

pub(crate) enum AutoResolvedSync {
    Completed,
    Conflict(ConflictSnapshot, Vec<ConflictFileContent>),
    Failed(String),
}

#[derive(Debug, Deserialize)]
pub(crate) struct PushConfirmRequest {
    pub(crate) challenge_id: String,
    pub(crate) password: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AcceptedResponse {
    pub(crate) job_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChallengeResponse {
    pub(crate) challenge_id: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApiMessage {
    pub(crate) message: String,
}

pub(crate) struct ServicePaths {
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
    pub(crate) database_path: PathBuf,
}

pub(crate) struct ServiceRuntime {
    pub(crate) events: broadcast::Sender<ServiceEvent>,
    pub(crate) repository_lock: std::sync::Arc<std::sync::Mutex<()>>,
    pub(crate) password_attempts: std::sync::Arc<std::sync::Mutex<Vec<Instant>>>,
}
