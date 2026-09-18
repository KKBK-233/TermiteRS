use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, params_from_iter};
use uuid::Uuid;

use crate::git::{ConflictSnapshot, Git};
use crate::protection::initialize_protection_schema;

use super::state::ServiceState;
use super::types::{
    ACTIVE_STATES, CleanupReport, ConversationMessage, JobView, ServiceEvent, ServiceStats,
};
use super::util::timestamp;

impl ServiceState {
    pub(crate) fn initialize_database(&self) -> Result<()> {
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
        initialize_protection_schema(&connection)?;
        Ok(())
    }

    pub(crate) fn cleanup_old_jobs(&self, days: u32) -> Result<CleanupReport> {
        anyhow::ensure!(days > 0, "cleanup days must be greater than zero");

        let cutoff = (Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let connection = self.open_database()?;
        let targets = {
            let mut statement = connection.prepare(
                "SELECT id, worktree_path FROM jobs
                 WHERE state IN ('completed', 'abandoned', 'failed') AND updated_at < ?1",
            )?;
            statement
                .query_map(params![cutoff], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        drop(connection);

        let mut removed_worktrees = 0;
        for (job_id, worktree_path) in &targets {
            if worktree_path.is_empty() || !Path::new(worktree_path).exists() {
                continue;
            }
            Git::new(worktree_path).abort_rebase_or_merge();
            self.remove_worktree(job_id)?;
            if !Path::new(worktree_path).exists() {
                removed_worktrees += 1;
            }
        }

        if targets.is_empty() {
            return Ok(CleanupReport {
                cutoff,
                jobs: 0,
                messages: 0,
                events: 0,
                challenges: 0,
                notifications: 0,
                worktrees: removed_worktrees,
            });
        }

        let job_ids = targets
            .iter()
            .map(|(job_id, _)| job_id.clone())
            .collect::<Vec<_>>();
        let placeholders = std::iter::repeat_n("?", job_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut connection = self.open_database()?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        let transaction = connection.transaction()?;
        let messages = transaction.execute(
            &format!("DELETE FROM messages WHERE job_id IN ({placeholders})"),
            params_from_iter(job_ids.iter().map(String::as_str)),
        )?;
        let events = transaction.execute(
            &format!("DELETE FROM events WHERE job_id IN ({placeholders})"),
            params_from_iter(job_ids.iter().map(String::as_str)),
        )?;
        let challenges = transaction.execute(
            &format!("DELETE FROM challenges WHERE job_id IN ({placeholders})"),
            params_from_iter(job_ids.iter().map(String::as_str)),
        )?;
        let notifications = transaction.execute(
            &format!("DELETE FROM notifications WHERE job_id IN ({placeholders})"),
            params_from_iter(job_ids.iter().map(String::as_str)),
        )?;
        let jobs = transaction.execute(
            &format!("DELETE FROM jobs WHERE id IN ({placeholders})"),
            params_from_iter(job_ids.iter().map(String::as_str)),
        )?;
        transaction.commit()?;

        Ok(CleanupReport {
            cutoff,
            jobs,
            messages,
            events,
            challenges,
            notifications,
            worktrees: removed_worktrees,
        })
    }

    pub(crate) fn recover_interrupted_jobs(&self) -> Result<()> {
        let connection = self.open_database()?;
        let now = timestamp();
        connection.execute(
            "UPDATE jobs SET state = 'failed', summary = '服务重启时任务仍在执行，请重新发起', updated_at = ?1 WHERE state IN ('queued', 'running', 'generating_proposal', 'applying', 'pushing', 'abandoning')",
            params![now],
        )?;
        Ok(())
    }

    pub(crate) fn create_job(&self, kind: &str, branch: &str) -> Result<String> {
        let mut connection = self.open_database()?;
        // 写事务序列化同一分支的检查与创建，避免并发请求都看到空闲状态。
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if kind == "sync" {
            let placeholders = ACTIVE_STATES
                .iter()
                .map(|state| format!("'{state}'"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT id FROM jobs WHERE branch = ?1 AND state IN ({placeholders}) LIMIT 1"
            );
            if transaction
                .query_row(&sql, params![branch], |row| row.get::<_, String>(0))
                .optional()?
                .is_some()
            {
                bail!("该分支已有活动任务");
            }
        }

        let id = Uuid::new_v4().to_string();
        let now = timestamp();
        transaction.execute(
            "INSERT INTO jobs (id, kind, branch, state, created_at, updated_at) VALUES (?1, ?2, ?3, 'queued', ?4, ?4)",
            params![id, kind, branch, now],
        )?;
        transaction.commit()?;
        self.emit(Some(&id), "job", "任务已进入队列")?;
        Ok(id)
    }

    pub(crate) fn ensure_no_active_sync(&self, branch: &str) -> Result<()> {
        let connection = self.open_database()?;
        let placeholders = ACTIVE_STATES
            .iter()
            .map(|state| format!("'{state}'"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT id FROM jobs WHERE branch = ?1 AND state IN ({placeholders}) LIMIT 1");
        if connection
            .query_row(&sql, params![branch], |row| row.get::<_, String>(0))
            .optional()?
            .is_some()
        {
            bail!("该分支已有活动任务");
        }
        Ok(())
    }

    pub(crate) fn emit(&self, job_id: Option<&str>, kind: &str, message: &str) -> Result<()> {
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

    pub(crate) fn set_state(&self, job_id: &str, state: &str, summary: &str) -> Result<()> {
        self.open_database()?.execute(
            "UPDATE jobs SET state = ?2, summary = ?3, updated_at = ?4 WHERE id = ?1",
            params![job_id, state, summary, timestamp()],
        )?;
        self.emit(Some(job_id), "state", &format!("{state}: {summary}"))
    }

    /// 仅在任务仍处于允许状态时切换，阻止并发请求重复执行同一副作用。
    pub(crate) fn transition_state(
        &self,
        job_id: &str,
        allowed: &[&str],
        state: &str,
        summary: &str,
    ) -> Result<()> {
        anyhow::ensure!(!allowed.is_empty(), "缺少允许的任务状态");
        let placeholders = std::iter::repeat_n("?", allowed.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "UPDATE jobs SET state = ?1, summary = ?2, updated_at = ?3 WHERE id = ?4 AND state IN ({placeholders})"
        );
        let values = [
            state.to_string(),
            summary.to_string(),
            timestamp(),
            job_id.to_string(),
        ];
        let changed = self.open_database()?.execute(
            &sql,
            params_from_iter(
                values
                    .iter()
                    .map(String::as_str)
                    .chain(allowed.iter().copied()),
            ),
        )?;
        anyhow::ensure!(changed == 1, "任务状态已变化，不允许重复执行：{job_id}");
        self.emit(Some(job_id), "state", &format!("{state}: {summary}"))
    }

    pub(crate) fn job(&self, job_id: &str) -> Result<JobView> {
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

    pub(crate) fn jobs(&self) -> Result<Vec<JobView>> {
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

    /// 活动任务单独全量查询，避免最近 50 条历史记录掩盖长时间运行的任务。
    pub(crate) fn active_job_summaries(&self) -> Result<Vec<(String, String, String)>> {
        let connection = self.open_database()?;
        let placeholders = std::iter::repeat_n("?", ACTIVE_STATES.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT id, branch, state FROM jobs WHERE state IN ({placeholders}) ORDER BY created_at DESC"
        );
        let mut statement = connection.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(ACTIVE_STATES.iter()), |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub(crate) fn job_stats(&self) -> Result<ServiceStats> {
        let connection = self.open_database()?;
        let mut stats = ServiceStats {
            sync_total: 0,
            sync_completed: 0,
            sync_failed: 0,
            sync_conflict: 0,
            sync_active: 0,
            check_total: 0,
            job_total: 0,
        };

        let mut statement =
            connection.prepare("SELECT kind, state, COUNT(*) FROM jobs GROUP BY kind, state")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u32>(2)?,
            ))
        })?;
        for row in rows {
            let (kind, state, count) = row?;
            stats.job_total += count;
            if kind == "check" {
                stats.check_total += count;
            }
            if kind != "sync" {
                continue;
            }
            stats.sync_total += count;
            if ACTIVE_STATES.contains(&state.as_str()) {
                stats.sync_active += count;
            }
            match state.as_str() {
                "completed" => stats.sync_completed += count,
                "failed" => stats.sync_failed += count,
                "waiting_guidance" | "test_failed" | "waiting_push" => {
                    stats.sync_conflict += count;
                }
                _ => {}
            }
        }
        Ok(stats)
    }
}
pub(crate) fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobView> {
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

pub(crate) fn load_messages(
    connection: &Connection,
    job_id: &str,
) -> Result<Vec<ConversationMessage>> {
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

#[cfg(test)]
mod concurrency_tests {
    use std::sync::{Arc, Barrier, Mutex};

    use tokio::sync::broadcast;
    use uuid::Uuid;

    use super::ServiceState;

    #[test]
    fn concurrent_requests_create_only_one_sync_job() {
        let root = std::env::temp_dir().join(format!("termiters-job-race-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let (events, _) = broadcast::channel(8);
        let state = ServiceState {
            config_path: root.join("termite.yml"),
            data_dir: root.clone(),
            database_path: root.join("termite.db"),
            events,
            repository_lock: Arc::new(Mutex::new(())),
        };
        state.initialize_database().unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let threads = (0..2)
            .map(|_| {
                let state = state.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    state.create_job("sync", "main")
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(state.jobs().unwrap().len(), 1);

        let job_id = results.into_iter().find_map(Result::ok).unwrap();
        state
            .set_state(&job_id, "waiting_push", "等待推送")
            .unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let threads = (0..2)
            .map(|_| {
                let state = state.clone();
                let barrier = barrier.clone();
                let job_id = job_id.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    state.transition_state(&job_id, &["waiting_push"], "pushing", "开始推送")
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(state.job(&job_id).unwrap().state, "pushing");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_active_job_remains_visible_after_fifty_newer_jobs() {
        let root = std::env::temp_dir().join(format!("termiters-active-jobs-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let config_path = root.join("termite.yml");
        std::fs::write(
            &config_path,
            format!(
                "repo:\n  path: '{}'\n  upstream: unused\n  fork: unused\nbranches:\n  - name: main\n",
                root.display()
            ),
        )
        .unwrap();
        let (events, _) = broadcast::channel(8);
        let state = ServiceState {
            config_path,
            data_dir: root.clone(),
            database_path: root.join("termite.db"),
            events,
            repository_lock: Arc::new(Mutex::new(())),
        };
        state.initialize_database().unwrap();
        let active_id = state.create_job("sync", "main").unwrap();
        state
            .open_database()
            .unwrap()
            .execute(
                "UPDATE jobs SET created_at = '2000-01-01T00:00:00Z' WHERE id = ?1",
                [active_id.as_str()],
            )
            .unwrap();
        for _ in 0..50 {
            let id = state.create_job("check", "main").unwrap();
            state.set_state(&id, "completed", "完成").unwrap();
        }
        assert_eq!(state.jobs().unwrap().len(), 50);
        assert!(!state.jobs().unwrap().iter().any(|job| job.id == active_id));
        assert_eq!(state.status_view().unwrap().active_jobs, 1);
        let dashboard = state.dashboard().unwrap();
        assert_eq!(
            dashboard.branches[0].current_job_id.as_deref(),
            Some(active_id.as_str())
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
