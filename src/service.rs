#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use std::{
    collections::HashSet,
    convert::Infallible,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{
        IntoResponse, Response, Sse,
        sse::{Event as SseEvent, KeepAlive},
    },
};
#[cfg(unix)]
use axum::{
    Router,
    routing::{get, post},
};
use chrono::Utc;
use futures_util::StreamExt;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
#[cfg(unix)]
use tracing::info;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    config::{BranchConfig, Config, PushStrategy},
    doctor::Doctor,
    git::{ConflictFileContent, ConflictSnapshot, Git},
    llm::{
        AutoResolveConflictRequest, ConflictOptionsDecision, ConflictProposal, LlmService,
        ResolvedFile,
    },
    notify::Notifier,
};

const ACTIVE_STATES: &[&str] = &[
    "queued",
    "running",
    "waiting_guidance",
    "applying",
    "test_failed",
    "waiting_push",
    "pushing",
];
const CHALLENGE_TTL_SECONDS: i64 = 300;

#[derive(Clone)]
struct ServiceState {
    config_path: PathBuf,
    data_dir: PathBuf,
    database_path: PathBuf,
    events: broadcast::Sender<ServiceEvent>,
    repository_lock: Arc<Mutex<()>>,
    password_attempts: Arc<Mutex<Vec<Instant>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub id: String,
    pub job_id: Option<String>,
    pub kind: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
struct Dashboard {
    repository: String,
    fork_url: String,
    upstream_url: String,
    branches: Vec<BranchDashboard>,
    jobs: Vec<JobView>,
}

#[derive(Debug, Serialize)]
struct BranchDashboard {
    name: String,
    note: String,
    local_head: Option<String>,
    upstream_head: Option<String>,
    remote_head: Option<String>,
    upstream_ahead: Option<u32>,
    upstream_behind: Option<u32>,
    current_job_id: Option<String>,
    current_state: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct JobView {
    id: String,
    kind: String,
    branch: String,
    state: String,
    risk: String,
    summary: String,
    worktree_path: String,
    base_ref: String,
    before_head: String,
    base_head: String,
    remote_head: String,
    conflict_files: Vec<String>,
    options: Option<ConflictOptionsDecision>,
    proposal: Option<StoredProposal>,
    test_output: String,
    messages: Vec<ConversationMessage>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ConversationMessage {
    role: String,
    content: String,
    created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct StoredProposal {
    summary: String,
    files: Vec<ResolvedFile>,
    diff: String,
    selected_option: String,
    requirements: String,
}

#[derive(Debug, Deserialize)]
struct SyncRequest {
    branch: String,
}

#[derive(Debug, Deserialize)]
struct MessageRequest {
    message: String,
}

#[derive(Debug, Deserialize)]
struct ProposalRequest {
    option_id: String,
    requirements: String,
}

#[derive(Debug, Deserialize)]
struct PushConfirmRequest {
    challenge_id: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AcceptedResponse {
    job_id: String,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct ApiMessage {
    message: String,
}

pub fn run(config_path: PathBuf) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = config_path;
        bail!("TermiteRS serve 仅支持提供 Unix Socket 的 Linux/Unix 环境");
    }

    #[cfg(unix)]
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to build TermiteRS service runtime")?;
        runtime.block_on(run_unix(config_path))
    }
}

#[cfg(unix)]
async fn run_unix(config_path: PathBuf) -> Result<()> {
    use hyperlocal::UnixListenerExt;
    use tokio::net::UnixListener;
    use tower::ServiceExt;

    let config = Config::read_from(&config_path)?;
    validate_service_config(&config)?;
    fs::create_dir_all(&config.service.data_dir)?;
    fs::create_dir_all(config.service.data_dir.join("worktrees"))?;
    if let Some(parent) = config.service.socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if config.service.socket_path.exists() {
        fs::remove_file(&config.service.socket_path)?;
    }

    let database_path = config.service.data_dir.join("termite.db");
    let (event_sender, _) = broadcast::channel(256);
    let state = ServiceState {
        config_path,
        data_dir: config.service.data_dir.clone(),
        database_path,
        events: event_sender,
        repository_lock: Arc::new(Mutex::new(())),
        password_attempts: Arc::new(Mutex::new(Vec::new())),
    };
    state.initialize_database()?;
    state.recover_interrupted_jobs()?;

    let app = Router::new()
        .route("/v1/dashboard", get(dashboard))
        .route("/v1/jobs/check", post(start_check))
        .route("/v1/jobs/sync", post(start_sync))
        .route("/v1/conflicts/:id/messages", post(add_message))
        .route("/v1/conflicts/:id/proposal", post(generate_proposal))
        .route("/v1/conflicts/:id/apply", post(apply_proposal))
        .route("/v1/conflicts/:id/abandon", post(abandon_job))
        .route("/v1/conflicts/:id/challenge", post(create_challenge))
        .route("/v1/push/confirm", post(confirm_push))
        .route("/v1/events", get(events))
        .with_state(state.clone());

    let listener = UnixListener::bind(&config.service.socket_path)?;
    set_socket_permissions(&config.service.socket_path)?;
    info!(
        "TermiteRS service listening on {}",
        config.service.socket_path.display()
    );

    listener
        .serve(move || {
            let app = app.clone();
            move |request| app.clone().oneshot(request)
        })
        .await
        .map_err(|err| anyhow::anyhow!("Unix Socket 服务异常：{err}"))?;
    Ok(())
}

fn validate_service_config(config: &Config) -> Result<()> {
    if config.service.operation_password_hash.trim().is_empty() {
        bail!("service.operation_password_hash 未配置");
    }
    PasswordHash::new(&config.service.operation_password_hash)
        .map_err(|err| anyhow::anyhow!("service.operation_password_hash 无效：{err}"))?;
    if config.branches.is_empty() {
        bail!("TermiteRS 至少需要一个维护分支");
    }
    let mut names = HashSet::new();
    for branch in &config.branches {
        if !names.insert(&branch.name) {
            bail!("维护分支重复：{}", branch.name);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(())
}

async fn dashboard(State(state): State<ServiceState>) -> Response {
    match state.dashboard() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn start_check(State(state): State<ServiceState>) -> Response {
    match state.create_job("check", "*") {
        Ok(job_id) => {
            let worker = state.clone();
            let worker_job_id = job_id.clone();
            thread::spawn(move || worker.execute_check(&worker_job_id));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn start_sync(
    State(state): State<ServiceState>,
    Json(request): Json<SyncRequest>,
) -> Response {
    let config = match state.config() {
        Ok(config) => config,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if config
        .branches
        .iter()
        .all(|branch| branch.name != request.branch)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("分支不在 TermiteRS 白名单中"),
        );
    }
    match state.create_job("sync", &request.branch) {
        Ok(job_id) => {
            let worker = state.clone();
            let worker_job_id = job_id.clone();
            let branch = request.branch;
            thread::spawn(move || worker.execute_sync(&worker_job_id, &branch));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn add_message(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<MessageRequest>,
) -> Response {
    if request.message.trim().is_empty() || request.message.chars().count() > 4000 {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("指导内容必须为 1 到 4000 个字符"),
        );
    }
    match state.add_message_and_refresh_options(&id, request.message.trim()) {
        Ok(()) => Json(ApiMessage {
            message: "已更新冲突方案".to_string(),
        })
        .into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn generate_proposal(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProposalRequest>,
) -> Response {
    match state.generate_proposal(&id, &request.option_id, &request.requirements) {
        Ok(proposal) => Json(proposal).into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn apply_proposal(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.mark_applying(&id) {
        Ok(()) => {
            let worker = state.clone();
            let worker_id = id.clone();
            thread::spawn(move || worker.execute_apply(&worker_id));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id: id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn abandon_job(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.abandon(&id) {
        Ok(()) => Json(ApiMessage {
            message: "任务已放弃并清理".to_string(),
        })
        .into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn create_challenge(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.create_push_challenge(&id) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

async fn confirm_push(
    State(state): State<ServiceState>,
    Json(request): Json<PushConfirmRequest>,
) -> Response {
    match state.confirm_push(&request.challenge_id, &request.password) {
        Ok(()) => Json(ApiMessage {
            message: "推送成功".to_string(),
        })
        .into_response(),
        Err(err) => api_error(StatusCode::UNAUTHORIZED, err),
    }
}

async fn events(
    State(state): State<ServiceState>,
) -> Sse<impl futures_util::Stream<Item = Result<SseEvent, Infallible>>> {
    let stream = BroadcastStream::new(state.events.subscribe()).filter_map(|item| async move {
        match item {
            Ok(event) => Some(Ok(SseEvent::default()
                .id(event.id.clone())
                .event(event.kind.clone())
                .json_data(event)
                .unwrap_or_else(|_| SseEvent::default().data("{}")))),
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

fn api_error(status: StatusCode, err: anyhow::Error) -> Response {
    (
        status,
        Json(ApiMessage {
            message: format!("{err:#}"),
        }),
    )
        .into_response()
}

impl ServiceState {
    fn config(&self) -> Result<Config> {
        Config::read_from(&self.config_path)
    }

    fn open_database(&self) -> Result<Connection> {
        Connection::open(&self.database_path)
            .with_context(|| format!("failed to open {}", self.database_path.display()))
    }

    fn initialize_database(&self) -> Result<()> {
        let connection = self.open_database()?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                branch TEXT NOT NULL,
                state TEXT NOT NULL,
                risk TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                worktree_path TEXT NOT NULL DEFAULT '',
                base_ref TEXT NOT NULL DEFAULT '',
                before_head TEXT NOT NULL DEFAULT '',
                base_head TEXT NOT NULL DEFAULT '',
                remote_head TEXT NOT NULL DEFAULT '',
                snapshot_json TEXT,
                files_json TEXT,
                options_json TEXT,
                proposal_json TEXT,
                test_output TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                job_id TEXT,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                expected_remote_head TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS notifications (
                job_id TEXT NOT NULL,
                event TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (job_id, event)
            );
            "#,
        )?;
        Ok(())
    }

    fn recover_interrupted_jobs(&self) -> Result<()> {
        let connection = self.open_database()?;
        let now = timestamp();
        connection.execute(
            "UPDATE jobs SET state = 'failed', summary = '服务重启时任务仍在执行，请重新发起', updated_at = ?1 WHERE state IN ('queued', 'running', 'applying', 'pushing')",
            params![now],
        )?;
        Ok(())
    }

    fn create_job(&self, kind: &str, branch: &str) -> Result<String> {
        let connection = self.open_database()?;
        if kind == "sync" {
            let placeholders = ACTIVE_STATES
                .iter()
                .map(|state| format!("'{state}'"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT id FROM jobs WHERE branch = ?1 AND state IN ({placeholders}) LIMIT 1"
            );
            if connection
                .query_row(&sql, params![branch], |row| row.get::<_, String>(0))
                .optional()?
                .is_some()
            {
                bail!("该分支已有活动任务");
            }
        }

        let id = Uuid::new_v4().to_string();
        let now = timestamp();
        connection.execute(
            "INSERT INTO jobs (id, kind, branch, state, created_at, updated_at) VALUES (?1, ?2, ?3, 'queued', ?4, ?4)",
            params![id, kind, branch, now],
        )?;
        self.emit(Some(&id), "job", "任务已进入队列")?;
        Ok(id)
    }

    fn emit(&self, job_id: Option<&str>, kind: &str, message: &str) -> Result<()> {
        let event = ServiceEvent {
            id: Uuid::new_v4().to_string(),
            job_id: job_id.map(ToOwned::to_owned),
            kind: kind.to_string(),
            message: message.to_string(),
            created_at: timestamp(),
        };
        self.open_database()?.execute(
            "INSERT INTO events (id, job_id, kind, message, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.id,
                event.job_id,
                event.kind,
                event.message,
                event.created_at
            ],
        )?;
        let _ = self.events.send(event);
        Ok(())
    }

    fn set_state(&self, job_id: &str, state: &str, summary: &str) -> Result<()> {
        self.open_database()?.execute(
            "UPDATE jobs SET state = ?2, summary = ?3, updated_at = ?4 WHERE id = ?1",
            params![job_id, state, summary, timestamp()],
        )?;
        self.emit(Some(job_id), "state", &format!("{state}: {summary}"))
    }

    fn execute_check(&self, job_id: &str) {
        if let Err(err) = self.execute_check_inner(job_id) {
            error!("check job {job_id} failed: {err:#}");
            let _ = self.set_state(job_id, "failed", &format!("{err:#}"));
        }
    }

    fn execute_check_inner(&self, job_id: &str) -> Result<()> {
        self.set_state(job_id, "running", "正在检查仓库")?;
        let _guard = self
            .repository_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
        let config = self.config()?;
        let report = Doctor::new(config.clone()).run();
        let git = Git::new(config.repo.path.clone());
        git.fetch_all(&config.repo)?;
        self.open_database()?.execute(
            "UPDATE jobs SET test_output = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, report, timestamp()],
        )?;
        self.set_state(job_id, "completed", "仓库检查完成")
    }

    fn execute_sync(&self, job_id: &str, branch_name: &str) {
        if let Err(err) = self.execute_sync_inner(job_id, branch_name) {
            error!("sync job {job_id} failed: {err:#}");
            let _ = self.cleanup_failed_worktree(job_id);
            let _ = self.set_state(job_id, "failed", &format!("{err:#}"));
        }
    }

    fn execute_sync_inner(&self, job_id: &str, branch_name: &str) -> Result<()> {
        self.set_state(job_id, "running", "正在获取远端状态")?;
        let config = self.config()?;
        let branch = configured_branch(&config, branch_name)?.clone();
        let worktree_path = self.data_dir.join("worktrees").join(job_id);
        let main_git = Git::new(config.repo.path.clone());

        {
            let _guard = self
                .repository_lock
                .lock()
                .map_err(|_| anyhow::anyhow!("repository lock poisoned"))?;
            main_git.ensure_repo()?;
            main_git.ensure_remotes(&config.repo)?;
            main_git.fetch_all(&config.repo)?;
            if worktree_path.exists() {
                bail!("任务 worktree 已存在：{}", worktree_path.display());
            }
            let worktree = worktree_path.to_string_lossy().to_string();
            let remote_ref = format!("{}/{}", config.repo.fork_remote, branch_name);
            let branch_ref = if optional_short_ref(&main_git, &remote_ref).is_some() {
                remote_ref
            } else {
                branch_name.to_owned()
            };
            let output =
                main_git.run_git(&["worktree", "add", "--detach", &worktree, &branch_ref])?;
            if !output.success() {
                bail!("创建 worktree 失败：{}", output.stderr.trim());
            }
        }

        let git = Git::new(worktree_path.clone());
        let base_ref = format!(
            "{}/{}",
            config.repo.upstream_remote, config.repo.base_branch
        );
        let before_head = git
            .run_git(&["rev-parse", "HEAD"])?
            .stdout
            .trim()
            .to_string();
        let base_head = git
            .run_git(&["rev-parse", &base_ref])?
            .stdout
            .trim()
            .to_string();
        let remote_head = main_git
            .remote_head(&config.repo.fork_remote, branch_name)?
            .unwrap_or_default();
        self.open_database()?.execute(
            "UPDATE jobs SET worktree_path = ?2, base_ref = ?3, before_head = ?4, base_head = ?5, remote_head = ?6, updated_at = ?7 WHERE id = ?1",
            params![
                job_id,
                worktree_path.to_string_lossy(),
                base_ref,
                before_head,
                base_head,
                remote_head,
                timestamp()
            ],
        )?;
        self.emit(Some(job_id), "git", "隔离 worktree 已创建，开始同步")?;

        let output = match branch.sync {
            crate::config::SyncStrategy::Rebase => git.rebase(&base_ref)?,
            crate::config::SyncStrategy::Merge => git.merge(&base_ref)?,
        };
        if output.success() {
            return self.finish_automatic_sync(job_id, &config, &branch, &git);
        }

        let mut snapshot = git.conflict_snapshot(80 * 1024)?;
        let mut files = git.conflict_file_contents(
            &snapshot.files,
            branch.auto_resolve.max_file_bytes.max(40 * 1024),
        )?;
        if let Some(decision) =
            self.try_low_risk_auto_resolve(&config, &branch, &git, &snapshot, &files)?
        {
            if decision {
                return self.finish_automatic_sync(job_id, &config, &branch, &git);
            }
            snapshot = git.conflict_snapshot(80 * 1024)?;
            files = git.conflict_file_contents(
                &snapshot.files,
                branch.auto_resolve.max_file_bytes.max(40 * 1024),
            )?;
        }

        self.save_conflict(job_id, &snapshot, &files)?;
        let llm = LlmService::new(config.llm.clone());
        let request = AutoResolveConflictRequest {
            branch: branch.name.clone(),
            base: base_ref,
            snapshot: snapshot.clone(),
            files: files.clone(),
        };
        let options = match llm.conflict_options(&request, "尚无人工补充要求") {
            Ok(Some(options)) => Some(options),
            Ok(None) => {
                warn!("DeepSeek 未启用，冲突任务保留等待后续处理");
                None
            }
            Err(err) => {
                warn!("生成功能冲突方案失败，冲突任务保留：{err:#}");
                None
            }
        };
        let risk = "functional";
        let summary = options
            .as_ref()
            .map(|options| options.summary.as_str())
            .unwrap_or("功能性冲突已保留，DeepSeek 方案暂时不可用");
        let options_json = options.as_ref().map(serde_json::to_string).transpose()?;
        self.open_database()?.execute(
            "UPDATE jobs SET state = 'waiting_guidance', risk = ?2, summary = ?3, options_json = ?4, updated_at = ?5 WHERE id = ?1",
            params![
                job_id,
                risk,
                summary,
                options_json,
                timestamp()
            ],
        )?;
        self.emit(Some(job_id), "conflict", "功能性冲突正在等待人工指导")?;
        self.notify_once(
            job_id,
            "waiting_guidance",
            &format!("{} 等待处理", branch.name),
            &format!(
                "分支 {} 发生功能性冲突。\n冲突文件：{}\n\n{}",
                branch.name,
                snapshot.files.join(", "),
                dashboard_link(&config, job_id)
            ),
        )?;
        Ok(())
    }

    fn try_low_risk_auto_resolve(
        &self,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
        snapshot: &ConflictSnapshot,
        files: &[ConflictFileContent],
    ) -> Result<Option<bool>> {
        if !branch.auto_resolve.enabled
            || branch.auto_resolve.allowed_paths.is_empty()
            || snapshot.files.len() > branch.auto_resolve.max_conflict_files
            || snapshot
                .files
                .iter()
                .any(|path| !path_is_allowed(path, &branch.auto_resolve.allowed_paths))
        {
            return Ok(None);
        }
        let request = AutoResolveConflictRequest {
            branch: branch.name.clone(),
            base: format!(
                "{}/{}",
                config.repo.upstream_remote, config.repo.base_branch
            ),
            snapshot: snapshot.clone(),
            files: files.to_vec(),
        };
        let Some(decision) = LlmService::new(config.llm.clone()).auto_resolve_conflict(&request)?
        else {
            return Ok(None);
        };
        if !decision.risk.eq_ignore_ascii_case("low")
            || validate_files(&decision.files, &snapshot.files).is_err()
        {
            return Ok(Some(false));
        }
        for file in &decision.files {
            git.write_file(&file.path, &file.content)?;
            git.add_file(&file.path)?;
        }
        let output = git.continue_sync(branch.sync)?;
        Ok(Some(output.success()))
    }

    fn finish_automatic_sync(
        &self,
        job_id: &str,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
    ) -> Result<()> {
        let test_output = run_tests(git, branch)?;
        self.open_database()?.execute(
            "UPDATE jobs SET test_output = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, test_output, timestamp()],
        )?;
        self.push_job(config, branch, git, job_id, false)?;
        self.remove_worktree(job_id)?;
        self.set_state(job_id, "completed", "同步、测试和推送完成")?;
        self.notify_once(
            job_id,
            "completed",
            &format!("{} 同步完成", branch.name),
            "TermiteRS 已完成同步、测试和推送。",
        )
    }

    fn save_conflict(
        &self,
        job_id: &str,
        snapshot: &ConflictSnapshot,
        files: &[ConflictFileContent],
    ) -> Result<()> {
        self.open_database()?.execute(
            "UPDATE jobs SET snapshot_json = ?2, files_json = ?3, updated_at = ?4 WHERE id = ?1",
            params![
                job_id,
                serde_json::to_string(snapshot)?,
                serde_json::to_string(files)?,
                timestamp()
            ],
        )?;
        Ok(())
    }

    fn add_message_and_refresh_options(&self, job_id: &str, message: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        let now = timestamp();
        self.open_database()?.execute(
            "INSERT INTO messages (job_id, role, content, created_at) VALUES (?1, 'user', ?2, ?3)",
            params![job_id, message, now],
        )?;
        let (config, branch, request) = self.conflict_request(&job)?;
        let conversation = self.conversation_text(job_id)?;
        let options = LlmService::new(config.llm.clone())
            .conflict_options(&request, &conversation)?
            .context("DeepSeek 未启用")?;
        self.open_database()?.execute(
            "UPDATE jobs SET options_json = ?2, proposal_json = NULL, summary = ?3, updated_at = ?4 WHERE id = ?1",
            params![
                job_id,
                serde_json::to_string(&options)?,
                options.summary,
                timestamp()
            ],
        )?;
        self.open_database()?.execute(
            "INSERT INTO messages (job_id, role, content, created_at) VALUES (?1, 'assistant', ?2, ?3)",
            params![
                job_id,
                format!(
                    "已生成 {} 个方案：{}",
                    options.options.len(),
                    options
                        .options
                        .iter()
                        .map(|option| option.title.as_str())
                        .collect::<Vec<_>>()
                        .join("、")
                ),
                timestamp()
            ],
        )?;
        let _ = branch;
        self.emit(Some(job_id), "conflict", "DeepSeek 已根据新指导更新方案")
    }

    fn generate_proposal(
        &self,
        job_id: &str,
        option_id: &str,
        requirements: &str,
    ) -> Result<StoredProposal> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        let options = job.options.clone().context("当前任务没有可选方案")?;
        let option = options
            .options
            .iter()
            .find(|option| option.id == option_id)
            .context("选择的方案不存在")?;
        let (config, _, request) = self.conflict_request(&job)?;
        let conversation = self.conversation_text(job_id)?;
        let selected = serde_json::to_string(option)?;
        let proposal = LlmService::new(config.llm.clone())
            .conflict_proposal(&request, &conversation, &selected, requirements)?
            .context("DeepSeek 未启用")?;
        validate_files(&proposal.files, &request.snapshot.files).map_err(anyhow::Error::msg)?;
        let diff = proposal_diff(&request.files, &proposal)?;
        let stored = StoredProposal {
            summary: proposal.summary,
            files: proposal.files,
            diff,
            selected_option: option_id.to_string(),
            requirements: requirements.to_string(),
        };
        self.open_database()?.execute(
            "UPDATE jobs SET proposal_json = ?2, updated_at = ?3 WHERE id = ?1",
            params![job_id, serde_json::to_string(&stored)?, timestamp()],
        )?;
        self.emit(Some(job_id), "proposal", "候选修改已生成，尚未写入文件")?;
        Ok(stored)
    }

    fn mark_applying(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_guidance", "test_failed"])?;
        if job.proposal.is_none() {
            bail!("请先生成候选修改");
        }
        self.set_state(job_id, "applying", "正在应用候选修改并执行测试")
    }

    fn execute_apply(&self, job_id: &str) {
        if let Err(err) = self.execute_apply_inner(job_id) {
            error!("apply job {job_id} failed: {err:#}");
            let _ = self.set_state(job_id, "waiting_guidance", &format!("{err:#}"));
        }
    }

    fn execute_apply_inner(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        let proposal = job.proposal.clone().context("候选修改不存在")?;
        let config = self.config()?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let git = Git::new(&job.worktree_path);
        for file in &proposal.files {
            git.write_file(&file.path, &file.content)?;
            git.add_file(&file.path)?;
        }

        let rebase_in_progress = git
            .run_git(&["rev-parse", "-q", "--verify", "REBASE_HEAD"])?
            .success();
        let merge_in_progress = git
            .run_git(&["rev-parse", "-q", "--verify", "MERGE_HEAD"])?
            .success();
        let in_progress = rebase_in_progress || merge_in_progress;
        if in_progress {
            let output = git.continue_sync(branch.sync)?;
            if !output.success() {
                let snapshot = git.conflict_snapshot(80 * 1024)?;
                let files = git.conflict_file_contents(
                    &snapshot.files,
                    branch.auto_resolve.max_file_bytes.max(40 * 1024),
                )?;
                self.save_conflict(job_id, &snapshot, &files)?;
                self.open_database()?.execute(
                    "UPDATE jobs SET state = 'waiting_guidance', proposal_json = NULL, options_json = NULL, summary = '继续同步时出现新的冲突', updated_at = ?2 WHERE id = ?1",
                    params![job_id, timestamp()],
                )?;
                self.add_message_and_refresh_options(
                    job_id,
                    "继续同步时出现了下一组冲突，请重新分析。",
                )?;
                return Ok(());
            }
        } else {
            let output = git.run_git(&["commit", "--amend", "--no-edit"])?;
            if !output.success() {
                bail!("更新候选提交失败：{}", output.stderr.trim());
            }
        }

        match run_tests(&git, &branch) {
            Ok(output) => {
                self.open_database()?.execute(
                    "UPDATE jobs SET state = 'waiting_push', test_output = ?2, summary = '修改已应用且测试通过，等待推送确认', updated_at = ?3 WHERE id = ?1",
                    params![job_id, output, timestamp()],
                )?;
                self.emit(Some(job_id), "state", "测试通过，等待独立密码确认推送")?;
                self.notify_once(
                    job_id,
                    "waiting_push",
                    &format!("{} 等待推送确认", branch.name),
                    &format!(
                        "候选修改已经应用并通过测试，需要在后台输入 TermiteRS 独立操作密码确认推送。\n\n{}",
                        dashboard_link(&config, job_id)
                    ),
                )
            }
            Err(err) => {
                self.open_database()?.execute(
                    "UPDATE jobs SET state = 'test_failed', test_output = ?2, summary = '测试失败，等待继续指导', updated_at = ?3 WHERE id = ?1",
                    params![job_id, format!("{err:#}"), timestamp()],
                )?;
                self.emit(Some(job_id), "test", "测试失败，任务已返回人工指导阶段")?;
                self.notify_once(
                    job_id,
                    "test_failed",
                    &format!("{} 测试失败", branch.name),
                    &format!("{err:#}"),
                )
            }
        }
    }

    fn create_push_challenge(&self, job_id: &str) -> Result<ChallengeResponse> {
        let job = self.job(job_id)?;
        ensure_state(&job, &["waiting_push"])?;
        let id = Uuid::new_v4().to_string();
        let expires = Utc::now().timestamp() + CHALLENGE_TTL_SECONDS;
        self.open_database()?.execute(
            "INSERT INTO challenges (id, job_id, expected_remote_head, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, job_id, job.remote_head, expires],
        )?;
        Ok(ChallengeResponse {
            challenge_id: id,
            expires_at: chrono::DateTime::from_timestamp(expires, 0)
                .context("invalid challenge expiry")?
                .to_rfc3339(),
        })
    }

    fn confirm_push(&self, challenge_id: &str, password: &str) -> Result<()> {
        self.enforce_password_rate_limit()?;
        let config = self.config()?;
        let hash = PasswordHash::new(&config.service.operation_password_hash)
            .map_err(|err| anyhow::anyhow!("操作密码哈希无效：{err}"))?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_err()
        {
            bail!("操作密码错误");
        }

        let connection = self.open_database()?;
        let challenge = connection
            .query_row(
                "SELECT job_id, expected_remote_head, expires_at, used FROM challenges WHERE id = ?1",
                params![challenge_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .context("推送挑战不存在")?;
        if challenge.3 != 0 {
            bail!("推送挑战已经使用");
        }
        if challenge.2 < Utc::now().timestamp() {
            bail!("推送挑战已经过期");
        }
        connection.execute(
            "UPDATE challenges SET used = 1 WHERE id = ?1 AND used = 0",
            params![challenge_id],
        )?;

        let job = self.job(&challenge.0)?;
        ensure_state(&job, &["waiting_push"])?;
        self.set_state(&job.id, "pushing", "正在校验远端并推送")?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let git = Git::new(&job.worktree_path);
        let current_remote = git
            .remote_head(&config.repo.fork_remote, &job.branch)?
            .unwrap_or_default();
        if current_remote != challenge.1 {
            self.set_state(
                &job.id,
                "waiting_push",
                "远端分支已经变化，需要重新检查后再推送",
            )?;
            bail!("远端 SHA 已变化，拒绝推送");
        }
        self.push_job(&config, &branch, &git, &job.id, true)?;
        self.remove_worktree(&job.id)?;
        self.set_state(&job.id, "completed", "人工确认的修改已推送")?;
        self.notify_once(
            &job.id,
            "pushed",
            &format!("{} 已推送", branch.name),
            "人工确认的功能冲突修改已经成功推送。",
        )
    }

    fn push_job(
        &self,
        config: &Config,
        branch: &BranchConfig,
        git: &Git,
        job_id: &str,
        require_lease: bool,
    ) -> Result<()> {
        if matches!(branch.push, PushStrategy::None) {
            return Ok(());
        }
        let job = self.job(job_id)?;
        let output = if require_lease || matches!(branch.push, PushStrategy::ForceWithLease) {
            let lease = format!(
                "--force-with-lease=refs/heads/{}:{}",
                branch.name, job.remote_head
            );
            let refspec = format!("HEAD:refs/heads/{}", branch.name);
            git.run_git(&["push", &lease, &config.repo.fork_remote, &refspec])?
        } else {
            let refspec = format!("HEAD:refs/heads/{}", branch.name);
            git.run_git(&["push", &config.repo.fork_remote, &refspec])?
        };
        if !output.success() {
            bail!("推送失败：{}", output.stderr.trim());
        }
        Ok(())
    }

    fn abandon(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        ensure_state(
            &job,
            &["waiting_guidance", "test_failed", "waiting_push", "failed"],
        )?;
        if !job.worktree_path.is_empty() && Path::new(&job.worktree_path).exists() {
            Git::new(&job.worktree_path).abort_rebase_or_merge();
        }
        self.remove_worktree(job_id)?;
        self.set_state(job_id, "abandoned", "任务已由管理员放弃")?;
        let config = self.config()?;
        self.notify_once(
            job_id,
            "abandoned",
            &format!("{} 已放弃", job.branch),
            &format!("任务已经清理。\n\n{}", dashboard_link(&config, job_id)),
        )
    }

    fn remove_worktree(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        if job.worktree_path.is_empty() {
            return Ok(());
        }
        let config = self.config()?;
        let main_git = Git::new(config.repo.path);
        let output = main_git.run_git(&["worktree", "remove", "--force", &job.worktree_path])?;
        if !output.success() && Path::new(&job.worktree_path).exists() {
            warn!("git worktree remove failed: {}", output.stderr.trim());
            fs::remove_dir_all(&job.worktree_path)?;
            let _ = main_git.run_git(&["worktree", "prune"]);
        }
        Ok(())
    }

    fn cleanup_failed_worktree(&self, job_id: &str) -> Result<()> {
        let job = self.job(job_id)?;
        if !job.worktree_path.is_empty() && Path::new(&job.worktree_path).exists() {
            Git::new(&job.worktree_path).abort_rebase_or_merge();
            self.remove_worktree(job_id)?;
        }
        Ok(())
    }

    fn conflict_request(
        &self,
        job: &JobView,
    ) -> Result<(Config, BranchConfig, AutoResolveConflictRequest)> {
        let config = self.config()?;
        let branch = configured_branch(&config, &job.branch)?.clone();
        let connection = self.open_database()?;
        let (snapshot_json, files_json): (String, String) = connection.query_row(
            "SELECT snapshot_json, files_json FROM jobs WHERE id = ?1",
            params![job.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let request = AutoResolveConflictRequest {
            branch: job.branch.clone(),
            base: job.base_ref.clone(),
            snapshot: serde_json::from_str(&snapshot_json)?,
            files: serde_json::from_str(&files_json)?,
        };
        Ok((config, branch, request))
    }

    fn conversation_text(&self, job_id: &str) -> Result<String> {
        let job = self.job(job_id)?;
        if job.messages.is_empty() {
            return Ok("尚无人工补充要求".to_string());
        }
        Ok(job
            .messages
            .iter()
            .map(|message| format!("{}: {}", message.role, message.content))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    fn notify_once(&self, job_id: &str, event: &str, subject: &str, body: &str) -> Result<()> {
        let connection = self.open_database()?;
        if connection
            .query_row(
                "SELECT 1 FROM notifications WHERE job_id = ?1 AND event = ?2",
                params![job_id, event],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Ok(());
        }
        connection.execute(
            "INSERT INTO notifications (job_id, event, created_at) VALUES (?1, ?2, ?3)",
            params![job_id, event, timestamp()],
        )?;
        if let Err(err) = Notifier::new(self.config()?.notify).send(subject, body) {
            warn!("failed to send {event} notification: {err:#}");
        }
        Ok(())
    }

    fn enforce_password_rate_limit(&self) -> Result<()> {
        let now = Instant::now();
        let mut attempts = self
            .password_attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("password rate limiter poisoned"))?;
        attempts.retain(|attempt| now.duration_since(*attempt) < Duration::from_secs(60));
        if attempts.len() >= 5 {
            bail!("操作密码尝试过于频繁，请稍后再试");
        }
        attempts.push(now);
        Ok(())
    }

    fn job(&self, job_id: &str) -> Result<JobView> {
        let connection = self.open_database()?;
        let mut job = connection
            .query_row(
                "SELECT id, kind, branch, state, risk, summary, worktree_path, base_ref, before_head, base_head, remote_head, options_json, proposal_json, test_output, created_at, updated_at FROM jobs WHERE id = ?1",
                params![job_id],
                row_to_job,
            )
            .optional()?
            .context("任务不存在")?;
        job.messages = load_messages(&connection, &job.id)?;
        let snapshot_json: Option<String> = connection.query_row(
            "SELECT snapshot_json FROM jobs WHERE id = ?1",
            params![job_id],
            |row| row.get(0),
        )?;
        job.conflict_files = snapshot_json
            .and_then(|raw| serde_json::from_str::<ConflictSnapshot>(&raw).ok())
            .map(|snapshot| snapshot.files)
            .unwrap_or_default();
        Ok(job)
    }

    fn jobs(&self) -> Result<Vec<JobView>> {
        let connection = self.open_database()?;
        let mut statement = connection.prepare(
            "SELECT id, kind, branch, state, risk, summary, worktree_path, base_ref, before_head, base_head, remote_head, options_json, proposal_json, test_output, created_at, updated_at FROM jobs ORDER BY created_at DESC LIMIT 50",
        )?;
        let rows = statement.query_map([], row_to_job)?;
        let mut jobs = Vec::new();
        for row in rows {
            let mut job = row?;
            job.messages = load_messages(&connection, &job.id)?;
            let snapshot_json: Option<String> = connection.query_row(
                "SELECT snapshot_json FROM jobs WHERE id = ?1",
                params![job.id],
                |row| row.get(0),
            )?;
            job.conflict_files = snapshot_json
                .and_then(|raw| serde_json::from_str::<ConflictSnapshot>(&raw).ok())
                .map(|snapshot| snapshot.files)
                .unwrap_or_default();
            jobs.push(job);
        }
        Ok(jobs)
    }

    fn dashboard(&self) -> Result<Dashboard> {
        let config = self.config()?;
        let git = Git::new(config.repo.path.clone());
        let jobs = self.jobs()?;
        let active = jobs
            .iter()
            .filter(|job| ACTIVE_STATES.contains(&job.state.as_str()))
            .collect::<Vec<_>>();
        let upstream_ref = format!(
            "{}/{}",
            config.repo.upstream_remote, config.repo.base_branch
        );
        let upstream_head = optional_short_ref(&git, &upstream_ref);
        let mut branches = Vec::new();
        for branch in &config.branches {
            let local_head = optional_short_ref(&git, &branch.name);
            let remote_ref = format!("{}/{}", config.repo.fork_remote, branch.name);
            let remote_head = optional_short_ref(&git, &remote_ref);
            let compare_ref = if local_head.is_some() {
                Some(branch.name.clone())
            } else if remote_head.is_some() {
                Some(remote_ref.clone())
            } else {
                None
            };
            let upstream_count = match (compare_ref.as_deref(), upstream_head.as_ref()) {
                (Some(compare_ref), Some(_)) => git.ahead_behind(compare_ref, &upstream_ref).ok(),
                _ => None,
            };
            let current = active.iter().find(|job| job.branch == branch.name);
            branches.push(BranchDashboard {
                name: branch.name.clone(),
                note: branch.note.clone().unwrap_or_default(),
                local_head,
                upstream_head: upstream_head.clone(),
                remote_head,
                upstream_ahead: upstream_count.map(|count| count.ahead),
                upstream_behind: upstream_count.map(|count| count.behind),
                current_job_id: current.map(|job| job.id.clone()),
                current_state: current.map(|job| job.state.clone()),
            });
        }
        Ok(Dashboard {
            repository: config.repo.path.display().to_string(),
            fork_url: config.repo.fork.clone(),
            upstream_url: config.repo.upstream.clone(),
            branches,
            jobs,
        })
    }
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobView> {
    let options_json: Option<String> = row.get(11)?;
    let proposal_json: Option<String> = row.get(12)?;
    Ok(JobView {
        id: row.get(0)?,
        kind: row.get(1)?,
        branch: row.get(2)?,
        state: row.get(3)?,
        risk: row.get(4)?,
        summary: row.get(5)?,
        worktree_path: row.get(6)?,
        base_ref: row.get(7)?,
        before_head: row.get(8)?,
        base_head: row.get(9)?,
        remote_head: row.get(10)?,
        conflict_files: Vec::new(),
        options: options_json.and_then(|raw| serde_json::from_str(&raw).ok()),
        proposal: proposal_json.and_then(|raw| serde_json::from_str(&raw).ok()),
        test_output: row.get(13)?,
        messages: Vec::new(),
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn load_messages(connection: &Connection, job_id: &str) -> Result<Vec<ConversationMessage>> {
    let mut statement = connection
        .prepare("SELECT role, content, created_at FROM messages WHERE job_id = ?1 ORDER BY id")?;
    let rows = statement.query_map(params![job_id], |row| {
        Ok(ConversationMessage {
            role: row.get(0)?,
            content: row.get(1)?,
            created_at: row.get(2)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn configured_branch<'a>(config: &'a Config, name: &str) -> Result<&'a BranchConfig> {
    config
        .branches
        .iter()
        .find(|branch| branch.name == name)
        .with_context(|| format!("分支不在白名单中：{name}"))
}

fn ensure_state(job: &JobView, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&job.state.as_str()) {
        Ok(())
    } else {
        bail!("任务状态 {} 不允许执行该操作", job.state)
    }
}

fn run_tests(git: &Git, branch: &BranchConfig) -> Result<String> {
    if branch.tests.is_empty() && branch.auto_resolve.require_tests {
        bail!("该分支要求测试，但未配置测试命令");
    }
    let mut output_text = String::new();
    for test in &branch.tests {
        let output = git.run_test(test)?;
        output_text.push_str(&format!("$ {test}\n{}\n{}\n", output.stdout, output.stderr));
        if !output.success() {
            bail!("测试失败：{test}\n{}", output.stderr.trim());
        }
    }
    Ok(output_text)
}

fn validate_files(
    files: &[ResolvedFile],
    conflict_files: &[String],
) -> std::result::Result<(), String> {
    if files.is_empty() {
        return Err("DeepSeek 没有返回候选文件".to_string());
    }
    for file in files {
        if !conflict_files.contains(&file.path) {
            return Err(format!("候选文件不属于冲突文件：{}", file.path));
        }
        if file.content.contains("<<<<<<<")
            || file.content.contains("=======")
            || file.content.contains(">>>>>>>")
        {
            return Err(format!("候选文件仍包含冲突标记：{}", file.path));
        }
        if file.content.contains("... file truncated by TermiteRS ...") {
            return Err(format!("候选文件基于被截断的内容：{}", file.path));
        }
    }
    Ok(())
}

fn path_is_allowed(path: &str, allowed_paths: &[String]) -> bool {
    let normalized = path.replace('\\', "/");
    allowed_paths.iter().any(|allowed| {
        let allowed = allowed.replace('\\', "/");
        let allowed = allowed.trim_end_matches('/');
        normalized == allowed || normalized.starts_with(&format!("{allowed}/"))
    })
}

fn proposal_diff(
    original_files: &[ConflictFileContent],
    proposal: &ConflictProposal,
) -> Result<String> {
    let mut output = String::new();
    for file in &proposal.files {
        let original = original_files
            .iter()
            .find(|original| original.path == file.path)
            .with_context(|| format!("找不到冲突文件内容：{}", file.path))?;
        let diff = TextDiff::from_lines(&original.content, &file.content);
        output.push_str(
            &diff
                .unified_diff()
                .header(&format!("a/{}", file.path), &format!("b/{}", file.path))
                .to_string(),
        );
        output.push('\n');
    }
    Ok(output)
}

fn optional_short_ref(git: &Git, reference: &str) -> Option<String> {
    git.run_git(&["rev-parse", "--short", reference])
        .ok()
        .filter(|output| output.success())
        .map(|output| output.stdout.trim().to_string())
}

fn dashboard_link(config: &Config, job_id: &str) -> String {
    let base = config.service.public_dashboard_url.trim_end_matches('/');
    if base.is_empty() {
        "请登录博客后台处理。".to_string()
    } else {
        format!("{base}?job={job_id}")
    }
}

fn timestamp() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_validation_rejects_non_conflict_file() {
        let files = vec![ResolvedFile {
            path: "src/other.py".to_string(),
            content: "pass\n".to_string(),
        }];
        assert!(validate_files(&files, &["src/main.py".to_string()]).is_err());
    }

    #[test]
    fn proposal_diff_does_not_write_files() {
        let original = vec![ConflictFileContent {
            path: "src/main.py".to_string(),
            content: "old\n".to_string(),
        }];
        let proposal = ConflictProposal {
            summary: "replace".to_string(),
            files: vec![ResolvedFile {
                path: "src/main.py".to_string(),
                content: "new\n".to_string(),
            }],
        };
        let diff = proposal_diff(&original, &proposal).unwrap();
        assert!(diff.contains("-old"));
        assert!(diff.contains("+new"));
    }
}
