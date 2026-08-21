use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
#[cfg(unix)]
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::protection::{ProtectionStore, investigate_security_signal, scan_osv_advisories};
use crate::sync::{SyncOptions, SyncRunner};

pub struct Daemon {
    config: Config,
    once: bool,
    notify_on_noop: bool,
}

impl Daemon {
    pub fn new(config: Config, once: bool, notify_on_noop: bool) -> Self {
        Self {
            config,
            once,
            notify_on_noop,
        }
    }

    pub fn run(&self) -> Result<()> {
        let mut failures = 0;

        if self.config.daemon.run_on_start {
            failures = self.run_tick(failures)?;
            if self.once {
                return Ok(());
            }
            ensure_failure_limit_not_reached(
                failures,
                self.config.daemon.max_consecutive_failures,
            )?;
        }

        loop {
            let sleep_seconds =
                self.config.daemon.interval_seconds + jitter(self.config.daemon.jitter_seconds);
            info!("daemon sleeping for {} seconds", sleep_seconds);
            thread::sleep(Duration::from_secs(sleep_seconds));

            failures = self.run_tick(failures)?;
            if self.once {
                return Ok(());
            }
            ensure_failure_limit_not_reached(
                failures,
                self.config.daemon.max_consecutive_failures,
            )?;
        }
    }

    fn run_tick(&self, failures: u32) -> Result<u32> {
        info!("daemon sync tick started");
        #[cfg(unix)]
        if self.wait_for_service_socket() {
            return match self.run_service_tick() {
                Ok(()) => {
                    info!("daemon managed sync tick completed");
                    Ok(0)
                }
                Err(err) => {
                    let next_failures = failures + 1;
                    error!("daemon managed sync tick failed ({next_failures}): {err:#}");
                    Ok(next_failures)
                }
            };
        }
        #[cfg(unix)]
        if self
            .config
            .service
            .socket_path
            .parent()
            .is_some_and(|parent| parent.exists())
        {
            let next_failures = failures + 1;
            error!(
                "daemon managed sync tick failed ({next_failures}): service runtime directory exists but Unix Socket is unavailable"
            );
            return Ok(next_failures);
        }

        let options = SyncOptions {
            branch: None,
            dry_run: false,
            notify_on_noop: self.notify_on_noop,
        };
        if let Err(error) = self.run_direct_advisory_tick() {
            let next_failures = failures + 1;
            error!("daemon advisory tick failed ({next_failures}): {error:#}");
            return Ok(next_failures);
        }
        match SyncRunner::new(self.config.clone(), options).run() {
            Ok(report) => {
                println!("{}", report.render_text());
                info!("daemon sync tick completed");
                Ok(0)
            }
            Err(err) => {
                let next_failures = failures + 1;
                error!("daemon sync tick failed ({next_failures}): {err:#}");
                Ok(next_failures)
            }
        }
    }

    /// 未启用常驻服务时仍执行同一 OSV 流程，完成前不会进入普通分支同步。
    fn run_direct_advisory_tick(&self) -> Result<()> {
        let advisories = scan_osv_advisories(&self.config)?;
        if advisories.is_empty() {
            return Ok(());
        }
        let branch = self
            .config
            .branches
            .first()
            .context("OSV 调查没有可用测试分支")?;
        let store = ProtectionStore::open(self.config.service.data_dir.join("termite.db"))?;
        for advisory in advisories {
            for cursor in &advisory.related_ids {
                store.mark_osv_advisory(&cursor.id, &cursor.modified, "running", None)?;
            }
            let result = investigate_security_signal(
                &self.config,
                &advisory.summary,
                Some(&advisory.reference),
                &advisory.content,
                Some(&branch.name),
            );
            match result {
                Ok(output) if output.candidate_error.is_none() => {
                    for cursor in &advisory.related_ids {
                        store.mark_osv_advisory(&cursor.id, &cursor.modified, "completed", None)?;
                    }
                }
                Ok(output) => {
                    let error = output
                        .candidate_error
                        .unwrap_or_else(|| "未知候选错误".to_string());
                    for cursor in &advisory.related_ids {
                        store.mark_osv_advisory(
                            &cursor.id,
                            &cursor.modified,
                            "failed",
                            Some(&error),
                        )?;
                    }
                    bail!("OSV {} 候选失败关闭：{}", advisory.id, error);
                }
                Err(error) => {
                    let details = format!("{error:#}");
                    for cursor in &advisory.related_ids {
                        store.mark_osv_advisory(
                            &cursor.id,
                            &cursor.modified,
                            "failed",
                            Some(&details),
                        )?;
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// systemd 的服务启动顺序不保证 Unix Socket 已完成绑定，短暂等待可避免首轮退回旧路径。
    #[cfg(unix)]
    fn wait_for_service_socket(&self) -> bool {
        for _ in 0..10 {
            if self.config.service.socket_path.exists() {
                return true;
            }
            thread::sleep(Duration::from_millis(500));
        }
        false
    }

    /// 服务在线时只负责调度，由服务进程统一操作仓库、记录任务和处理冲突。
    #[cfg(unix)]
    fn run_service_tick(&self) -> Result<()> {
        let client = reqwest::blocking::Client::builder()
            .unix_socket(self.config.service.socket_path.clone())
            .timeout(Duration::from_secs(120))
            .build()
            .context("failed to build TermiteRS daemon service client")?;
        let advisory_response = client
            .post("http://localhost/v1/internal/scheduled-advisories")
            .send()
            .context("failed to schedule managed advisory scan")?;
        let advisory_status = advisory_response.status();
        if !advisory_status.is_success() {
            let body = advisory_response.text().unwrap_or_default();
            bail!("managed advisory scheduling returned {advisory_status}: {body}");
        }
        let advisory_jobs: ScheduledSyncResponse = advisory_response
            .json()
            .context("failed to decode managed advisory response")?;
        wait_managed_jobs(&client, &advisory_jobs.job_ids, "advisory")?;

        let response = client
            .post("http://localhost/v1/internal/scheduled-sync-all")
            .json(&serde_json::json!({
                "notify_on_noop": self.notify_on_noop,
            }))
            .send()
            .context("failed to schedule managed sync")?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            bail!("managed sync scheduling returned {status}: {body}");
        }
        let accepted: ScheduledSyncResponse = response
            .json()
            .context("failed to decode managed sync response")?;
        if accepted.job_ids.is_empty() {
            info!("daemon managed sync tick skipped because no branches are configured");
            return Ok(());
        }

        wait_managed_jobs(&client, &accepted.job_ids, "sync")
    }
}

#[cfg(unix)]
fn wait_managed_jobs(
    client: &reqwest::blocking::Client,
    job_ids: &[String],
    purpose: &str,
) -> Result<()> {
    if job_ids.is_empty() {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(60 * 60);
    loop {
        let mut jobs = Vec::with_capacity(job_ids.len());
        for job_id in job_ids {
            let response = client
                .get(format!("http://localhost/v1/jobs/{job_id}"))
                .send()
                .with_context(|| format!("failed to query managed {purpose} job {job_id}"))?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                bail!("managed {purpose} job {job_id} returned {status}: {body}");
            }
            jobs.push(
                response
                    .json::<ManagedSyncJob>()
                    .with_context(|| format!("failed to decode managed {purpose} job {job_id}"))?,
            );
        }

        if jobs.iter().all(|job| is_terminal_state(&job.state)) {
            let failures = jobs
                .iter()
                .filter(|job| job.state != "completed")
                .map(|job| format!("{} [{}]: {}", job.branch, job.state, job.summary))
                .collect::<Vec<_>>();
            if !failures.is_empty() {
                bail!(
                    "managed {purpose} requires attention: {}",
                    failures.join(" | ")
                );
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("managed {purpose} did not finish within 3600 seconds");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// 达到连续失败上限时返回错误，让 systemd 等进程管理器能够识别异常并自动重启。
fn ensure_failure_limit_not_reached(failures: u32, max_failures: u32) -> Result<()> {
    if failures < max_failures {
        return Ok(());
    }

    warn!("daemon reached {max_failures} consecutive failure(s); requesting supervisor restart");
    bail!(
        "daemon reached {max_failures} consecutive failure(s); exiting so the process supervisor can restart it"
    )
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct ScheduledSyncResponse {
    job_ids: Vec<String>,
}

#[cfg(unix)]
#[derive(Debug, Deserialize)]
struct ManagedSyncJob {
    branch: String,
    state: String,
    summary: String,
}

#[cfg(unix)]
fn is_terminal_state(state: &str) -> bool {
    matches!(
        state,
        "completed" | "failed" | "abandoned" | "waiting_guidance" | "test_failed" | "waiting_push"
    )
}

fn jitter(max_seconds: u64) -> u64 {
    if max_seconds == 0 {
        return 0;
    }

    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_secs() % (max_seconds + 1)
}

#[cfg(test)]
mod tests {
    use super::ensure_failure_limit_not_reached;
    #[cfg(unix)]
    use super::is_terminal_state;

    #[cfg(unix)]
    #[test]
    fn managed_sync_waits_only_for_active_states() {
        assert!(!is_terminal_state("queued"));
        assert!(!is_terminal_state("running"));
        assert!(is_terminal_state("completed"));
        assert!(is_terminal_state("waiting_guidance"));
        assert!(is_terminal_state("failed"));
    }

    #[test]
    fn failure_limit_exits_with_error_for_supervisor_restart() {
        assert!(ensure_failure_limit_not_reached(2, 3).is_ok());

        let error = ensure_failure_limit_not_reached(3, 3).unwrap_err();
        assert!(error.to_string().contains("process supervisor can restart"));
    }
}
