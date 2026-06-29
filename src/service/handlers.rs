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
use tokio_stream::wrappers::BroadcastStream;

use super::state::ServiceState;
use super::types::{
    AcceptedResponse, ApiMessage, MessageRequest, ProposalRequest, PushConfirmRequest, SyncRequest,
};
pub(crate) async fn dashboard(State(state): State<ServiceState>) -> Response {
    match state.dashboard() {
        Ok(value) => Json(value).into_response(),
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
            thread::spawn(move || worker.execute_sync(&worker_job_id, &branch));
            (StatusCode::ACCEPTED, Json(AcceptedResponse { job_id })).into_response()
        }
        Err(err) => api_error(StatusCode::CONFLICT, err),
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

pub(crate) async fn create_challenge(
    State(state): State<ServiceState>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    match state.create_push_challenge(&id) {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => api_error(StatusCode::CONFLICT, err),
    }
}

pub(crate) async fn confirm_push(
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
