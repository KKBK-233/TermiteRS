use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub repo: RepoConfig,
    #[serde(default)]
    pub branches: Vec<BranchConfig>,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub llm: Option<LlmConfig>,
    #[serde(default)]
    pub notify: Option<NotifyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoConfig {
    pub path: PathBuf,
    pub upstream: String,
    pub fork: String,
    #[serde(default = "default_base_branch")]
    pub base_branch: String,
    #[serde(default = "default_upstream_remote")]
    pub upstream_remote: String,
    #[serde(default = "default_fork_remote")]
    pub fork_remote: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BranchConfig {
    pub name: String,
    #[serde(default = "default_branch_kind")]
    pub kind: BranchKind,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default = "default_sync_strategy")]
    pub sync: SyncStrategy,
    #[serde(default = "default_push_strategy")]
    pub push: PushStrategy,
    #[serde(default)]
    pub tests: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_daemon_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default)]
    pub jitter_seconds: u64,
    #[serde(default = "default_daemon_run_on_start")]
    pub run_on_start: bool,
    #[serde(default = "default_daemon_max_consecutive_failures")]
    pub max_consecutive_failures: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: LlmProvider,
    #[serde(default = "default_llm_model")]
    pub model: String,
    #[serde(default = "default_llm_api_key_env")]
    pub api_key_env: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default = "default_llm_temperature")]
    pub temperature: f32,
    #[serde(default = "default_max_prompt_bytes")]
    pub max_prompt_bytes: usize,
    #[serde(default)]
    pub prompts: LlmPromptsConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LlmPromptsConfig {
    #[serde(default)]
    pub conflict_system: Option<String>,
    #[serde(default)]
    pub conflict_user: Option<String>,
    #[serde(default)]
    pub sync_summary_system: Option<String>,
    #[serde(default)]
    pub sync_summary_user: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmProvider {
    DeepSeek,
    OpenAi,
    OpenAiCompatible,
    Custom,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub policy: NotifyPolicyConfig,
    #[serde(default)]
    pub events: NotifyEventsConfig,
    #[serde(default = "default_subject_prefix")]
    pub subject_prefix: String,
    #[serde(default)]
    pub channels: Vec<NotifyChannelConfig>,
    #[serde(default)]
    pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyPolicyConfig {
    #[serde(default = "default_notify_policy_mode")]
    pub mode: NotifyPolicyMode,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct NotifyEventsConfig {
    #[serde(default)]
    pub sync_start: bool,
    #[serde(default)]
    pub sync_summary: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyPolicyMode {
    FirstSuccess,
    Fanout,
    PrimaryWithFallback,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyChannelConfig {
    pub name: String,
    pub kind: NotifyChannelKind,
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub tls: Option<SmtpTlsMode>,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,

    #[serde(default)]
    pub api_token_env: Option<String>,
    #[serde(default)]
    pub account_id_env: Option<String>,
    #[serde(default)]
    pub api_base_url: Option<String>,

    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyChannelKind {
    Smtp,
    CloudflareEmailService,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpTlsMode {
    StartTls,
    Implicit,
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BranchKind {
    Product,
    Pr,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyncStrategy {
    Rebase,
    Merge,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushStrategy {
    None,
    Normal,
    ForceWithLease,
}

impl Config {
    pub fn read_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        Ok(config)
    }

    pub fn example() -> &'static str {
        include_str!("../examples/termite.yml")
    }
}

fn default_base_branch() -> String {
    "master".to_string()
}

fn default_upstream_remote() -> String {
    "upstream".to_string()
}

fn default_fork_remote() -> String {
    "fork".to_string()
}

fn default_branch_kind() -> BranchKind {
    BranchKind::Product
}

fn default_sync_strategy() -> SyncStrategy {
    SyncStrategy::Rebase
}

fn default_push_strategy() -> PushStrategy {
    PushStrategy::ForceWithLease
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_daemon_interval_seconds(),
            jitter_seconds: 0,
            run_on_start: default_daemon_run_on_start(),
            max_consecutive_failures: default_daemon_max_consecutive_failures(),
        }
    }
}

fn default_daemon_interval_seconds() -> u64 {
    1800
}

fn default_daemon_run_on_start() -> bool {
    true
}

fn default_daemon_max_consecutive_failures() -> u32 {
    3
}

impl Default for LlmProvider {
    fn default() -> Self {
        Self::OpenAiCompatible
    }
}

fn default_llm_model() -> String {
    "deepseek-v4-pro".to_string()
}

fn default_llm_api_key_env() -> String {
    "DEEPSEEK_API_KEY".to_string()
}

fn default_llm_temperature() -> f32 {
    0.1
}

fn default_max_prompt_bytes() -> usize {
    80 * 1024
}

fn default_smtp_port() -> u16 {
    587
}

fn default_subject_prefix() -> String {
    "[TermiteRS]".to_string()
}

impl Default for NotifyPolicyConfig {
    fn default() -> Self {
        Self {
            mode: default_notify_policy_mode(),
        }
    }
}

impl Default for NotifyPolicyMode {
    fn default() -> Self {
        Self::PrimaryWithFallback
    }
}

fn default_notify_policy_mode() -> NotifyPolicyMode {
    NotifyPolicyMode::PrimaryWithFallback
}
