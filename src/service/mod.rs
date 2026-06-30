#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

mod conflicts;
mod dashboard;
mod db;
mod handlers;
mod jobs;
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
use argon2::PasswordHash;
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
        password_attempts: Arc::new(Mutex::new(Vec::new())),
    };
    state.initialize_database()?;
    state.cleanup_old_jobs(days)
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
        .route(
            "/v1/conflicts/:id/challenge",
            post(handlers::create_challenge),
        )
        .route("/v1/push/confirm", post(handlers::confirm_push))
        .route("/v1/events", get(handlers::events))
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
