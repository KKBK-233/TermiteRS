#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

mod conflicts;
mod dashboard;
mod db;
mod handlers;
mod jobs;
mod protection;
mod security;
mod state;
mod types;
mod util;

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
#[cfg(unix)]
use axum::{
    Router,
    routing::{get, post},
};
use tokio::sync::broadcast;
#[cfg(unix)]
use tracing::info;

use crate::config::Config;

use self::state::ServiceState;
pub use self::types::CleanupReport;

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

pub fn cleanup_old_jobs(config_path: PathBuf, days: u32) -> Result<CleanupReport> {
    let config = Config::read_from(&config_path)?;
    let database_path = config.service.data_dir.join("termite.db");
    let (event_sender, _) = broadcast::channel(1);
    let state = ServiceState {
        config_path,
        data_dir: config.service.data_dir,
        database_path,
        events: event_sender,
        repository_lock: Arc::new(Mutex::new(())),
    };
    state.initialize_database()?;
    state.cleanup_old_jobs(days)
}

#[cfg(unix)]
async fn run_unix(config_path: PathBuf) -> Result<()> {
    use tokio::net::UnixListener;

    let config = Config::read_from(&config_path)?;
    validate_service_config(&config)?;
    fs::create_dir_all(&config.service.data_dir)?;
    fs::create_dir_all(config.service.data_dir.join("worktrees"))?;
    prepare_socket_path(&config.service.socket_path)?;
    if let Some(path) = &config.service.public_socket_path {
        prepare_socket_path(path)?;
    }

    let database_path = config.service.data_dir.join("termite.db");
    let (event_sender, _) = broadcast::channel(256);
    let state = ServiceState {
        config_path,
        data_dir: config.service.data_dir.clone(),
        database_path,
        events: event_sender,
        repository_lock: Arc::new(Mutex::new(())),
    };
    state.initialize_database()?;
    state.recover_interrupted_jobs()?;

    // 控制接口包含所有写操作，只允许 daemon 和受信任管理员访问。
    let control_app = Router::new()
        .route("/v1/status", get(handlers::status))
        .route("/v1/stats", get(handlers::stats))
        .route("/v1/dashboard", get(handlers::dashboard))
        .route("/v1/branches", get(handlers::branches))
        .route("/v1/branches/:name", get(handlers::branch))
        .route("/v1/config/summary", get(handlers::config_summary))
        .route("/v1/jobs", get(handlers::jobs))
        .route("/v1/jobs/:id", get(handlers::job))
        .route("/v1/jobs/check", post(handlers::start_check))
        .route("/v1/jobs/sync-all", post(handlers::start_sync_all))
        .route("/v1/jobs/sync", post(handlers::start_sync))
        .route(
            "/v1/protection/investigate",
            post(handlers::start_protection_investigation),
        )
        .route(
            "/v1/protection/issues/:id/publish",
            post(handlers::publish_protection_issue),
        )
        .route(
            "/v1/internal/scheduled-sync-all",
            post(handlers::start_scheduled_sync_all),
        )
        .route(
            "/v1/internal/scheduled-advisories",
            post(handlers::start_scheduled_advisories),
        )
        .route("/v1/jobs/:id/cancel", post(handlers::cancel_job))
        .route("/v1/jobs/:id/retry", post(handlers::retry_job))
        .route("/v1/jobs/cleanup", post(handlers::cleanup_jobs))
        .route("/v1/conflicts/:id/messages", post(handlers::add_message))
        .route(
            "/v1/conflicts/:id/proposal",
            post(handlers::generate_proposal),
        )
        .route("/v1/conflicts/:id/apply", post(handlers::apply_proposal))
        .route("/v1/conflicts/:id/abandon", post(handlers::abandon_job))
        .route("/v1/conflicts/:id/push", post(handlers::retry_push))
        .route("/v1/events", get(handlers::events))
        .with_state(state.clone());

    let control_listener = UnixListener::bind(&config.service.socket_path)?;
    set_socket_permissions(&config.service.socket_path)?;
    info!(
        "TermiteRS control service listening on {}",
        config.service.socket_path.display()
    );

    if let Some(public_socket_path) = &config.service.public_socket_path {
        // 只读接口只暴露查询与事件流，不注册任何 POST 写路由。
        let public_app = read_only_router(state);
        let public_listener = UnixListener::bind(public_socket_path)?;
        set_socket_permissions(public_socket_path)?;
        info!(
            "TermiteRS read-only service listening on {}",
            public_socket_path.display()
        );
        tokio::try_join!(
            serve_socket(control_listener, control_app),
            serve_socket(public_listener, public_app)
        )?;
    } else {
        serve_socket(control_listener, control_app).await?;
    }
    Ok(())
}

#[cfg(unix)]
fn read_only_router(state: ServiceState) -> Router {
    Router::new()
        .route("/v1/status", get(handlers::status))
        .route("/v1/stats", get(handlers::stats))
        .route("/v1/dashboard", get(handlers::dashboard))
        .route("/v1/branches", get(handlers::branches))
        .route("/v1/branches/:name", get(handlers::branch))
        .route("/v1/config/summary", get(handlers::config_summary))
        .route("/v1/jobs", get(handlers::jobs))
        .route("/v1/jobs/:id", get(handlers::job))
        .route("/v1/events", get(handlers::events))
        .with_state(state)
}

#[cfg(unix)]
async fn serve_socket(listener: tokio::net::UnixListener, app: Router) -> Result<()> {
    use hyperlocal::UnixListenerExt;
    use tower::ServiceExt;

    listener
        .serve(move || {
            let app = app.clone();
            move |request| app.clone().oneshot(request)
        })
        .await
        .map_err(|err| anyhow::anyhow!("Unix Socket 服务异常：{err}"))
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn validate_service_config(config: &Config) -> Result<()> {
    if config.branches.is_empty() {
        bail!("TermiteRS 至少需要一个维护分支");
    }
    let mut names = HashSet::new();
    for branch in &config.branches {
        if !names.insert(&branch.name) {
            bail!("维护分支重复：{}", branch.name);
        }
    }
    if let Some(public_socket_path) = &config.service.public_socket_path {
        if public_socket_path == &config.service.socket_path {
            bail!("service.public_socket_path 必须与控制 socket_path 不同");
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

#[cfg(all(test, unix))]
mod socket_tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn read_only_router_rejects_control_posts() {
        let (events, _) = broadcast::channel(1);
        let state = ServiceState {
            config_path: PathBuf::from("unused.yml"),
            data_dir: PathBuf::from("unused"),
            database_path: PathBuf::from("unused.db"),
            events,
            repository_lock: Arc::new(Mutex::new(())),
        };
        let response = read_only_router(state)
            .oneshot(Request::post("/v1/jobs/sync").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
