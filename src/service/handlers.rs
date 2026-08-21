use std::{convert::Infallible, thread, time::Duration};

use anyhow::Result;
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{
        IntoResponse, Response, Sse,
        sse::{Event as SseEvent, KeepAlive},
    },
};
use futures_util::StreamExt;
use serde::Deserialize;
use tokio_stream::wrappers::BroadcastStream;

use super::state::ServiceState;
use super::types::{
    AcceptedResponse, ApiMessage, CleanupRequest, IssuePublishRequest, MessageRequest,
    ProposalRequest, ProtectionInvestigationRequest, SyncRequest,
};

pub(crate) async fn status(State(state): State<ServiceState>) -> Response {
    match state.status_view() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn dashboard(State(state): State<ServiceState>) -> Response {
    match state.dashboard() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn stats(State(state): State<ServiceState>) -> Response {
    match state.job_stats() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn branches(State(state): State<ServiceState>) -> Response {
    match state.branches_view() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn branch(
    State(state): State<ServiceState>,
    AxumPath(name): AxumPath<String>,
) -> Response {
    match state.branch_view(&name) {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::NOT_FOUND, err),
    }
}

pub(crate) async fn jobs(State(state): State<ServiceState>) -> Response {
    match state.jobs() {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn job(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.job(&id) {
        Ok(value) => Json(value).into_response(),
        Err(err) => api_error(StatusCode::NOT_FOUND, err),
    }
}

pub(crate) async fn config_summary(State(state): State<ServiceState>) -> Response {
    match state.dashboard() {
        Ok(value) => Json(serde_json::json!({
            "repository": value.repository,
            "upstream_url": value.upstream_url,
            "fork_url": value.fork_url,
            "branches": value.branches.into_iter().map(|branch| serde_json::json!({
                "name": branch.name,
                "note": branch.note,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(crate) async fn start_check(State(state): State<ServiceState>) -> Response {
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

pub(crate) async fn start_sync_all(State(state): State<ServiceState>) -> Response {
    let config = match state.config() {
        Ok(config) => config,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    match spawn_sync_all(&state, config, true) {
        Ok(job_ids) => Json(serde_json::json!({ "job_ids": job_ids })).into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ScheduledSyncRequest {
    #[serde(default)]
    notify_on_noop: bool,
}

pub(crate) async fn start_scheduled_sync_all(
    State(state): State<ServiceState>,
    Json(request): Json<ScheduledSyncRequest>,
) -> Response {
    let config = match state.config() {
        Ok(config) => config,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    match spawn_sync_all(&state, config, request.notify_on_noop) {
        Ok(job_ids) => Json(serde_json::json!({ "job_ids": job_ids })).into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

/// 为全部维护分支创建受管同步任务，自动与手动入口共用同一套状态记录。
fn spawn_sync_all(
    state: &ServiceState,
    config: crate::config::Config,
    notify_on_noop: bool,
) -> Result<Vec<String>> {
    for branch in &config.branches {
        state.ensure_no_active_sync(&branch.name)?;
    }
    let mut job_ids = Vec::new();
    for branch in config.branches {
        match state.create_job("sync", &branch.name) {
            Ok(job_id) => {
                let worker = state.clone();
                let worker_job_id = job_id.clone();
                let branch_name = branch.name;
                thread::spawn(move || {
                    worker.execute_sync(&worker_job_id, &branch_name, notify_on_noop)
                });
                job_ids.push(job_id);
            }
            Err(err) => return Err(err),
        }
    }
    Ok(job_ids)
}

pub(crate) async fn start_sync(
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
            thread::spawn(move || worker.execute_sync(&worker_job_id, &branch, true));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

pub(crate) async fn start_protection_investigation(
    State(state): State<ServiceState>,
    Json(request): Json<ProtectionInvestigationRequest>,
) -> Response {
    if request.summary.trim().is_empty()
        || request.summary.chars().count() > 500
        || request.content.trim().is_empty()
        || request.content.len() > 64 * 1024
        || request
            .reference
            .as_ref()
            .is_some_and(|value| value.len() > 2048)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("安全消息要求 1-500 字摘要、1-65536 字节正文和最多 2048 字节引用"),
        );
    }
    let config = match state.config() {
        Ok(config) => config,
        Err(error) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    if let Some(branch) = &request.branch
        && config
            .branches
            .iter()
            .all(|configured| configured.name != *branch)
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("测试分支不在白名单中"),
        );
    }
    let job_branch = request.branch.as_deref().unwrap_or("*").to_string();
    match state.create_job("protection", &job_branch) {
        Ok(job_id) => {
            let worker = state.clone();
            let worker_id = job_id.clone();
            thread::spawn(move || worker.execute_protection_investigation(&worker_id, request));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id })).into_response()
        }
        Err(error) => api_error(StatusCode::CONFLICT, error),
    }
}

pub(crate) async fn publish_protection_issue(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<IssuePublishRequest>,
) -> Response {
    if !request.approve {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("必须显式 approve=true"),
        );
    }
    if request.token_env.is_empty()
        || request.token_env.len() > 128
        || !request
            .token_env
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("Token 环境变量名非法"),
        );
    }
    match crate::protection::publish_github_issue(&state.data_dir, &id, &request.token_env, true) {
        Ok(receipt) => Json(receipt).into_response(),
        Err(error) => api_error(StatusCode::CONFLICT, error),
    }
}

pub(crate) async fn cancel_job(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.abandon(&id) {
        Ok(()) => Json(ApiMessage {
            message: "任务已取消并清理".to_string(),
        })
        .into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

pub(crate) async fn retry_job(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let job = match state.job(&id) {
        Ok(job) => job,
        Err(err) => return api_error(StatusCode::NOT_FOUND, err),
    };
    if job.kind == "check" {
        return start_check(State(state)).await;
    }
    if job.kind != "sync" {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("只支持重试 check 或 sync 任务"),
        );
    }
    let request = SyncRequest { branch: job.branch };
    start_sync(State(state), Json(request)).await
}

pub(crate) async fn cleanup_jobs(
    State(state): State<ServiceState>,
    Json(request): Json<CleanupRequest>,
) -> Response {
    match state.cleanup_old_jobs(request.days.unwrap_or(30)) {
        Ok(report) => Json(report).into_response(),
        Err(err) => api_error(StatusCode::BAD_REQUEST, err),
    }
}

pub(crate) async fn add_message(
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

pub(crate) async fn generate_proposal(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProposalRequest>,
) -> Response {
    if request.requirements.chars().count() > 4000 {
        return api_error(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!("补充修改要求不能超过 4000 个字符"),
        );
    }
    match state.mark_generating_proposal(&id, &request.option_id) {
        Ok(()) => {
            let worker = state.clone();
            let worker_id = id.clone();
            let option_id = request.option_id;
            let requirements = request.requirements;
            thread::spawn(move || {
                worker.execute_generate_proposal(&worker_id, &option_id, &requirements)
            });
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id: id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

pub(crate) async fn apply_proposal(
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

pub(crate) async fn abandon_job(
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

pub(crate) async fn retry_push(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.push_reviewed_job(&id) {
        Ok(()) => Json(ApiMessage {
            message: "推送成功".to_string(),
        })
        .into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

pub(crate) async fn events(
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
