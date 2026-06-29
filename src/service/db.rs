use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};
use uuid::Uuid;

use crate::git::{ConflictSnapshot, Git};

use super::state::ServiceState;
use super::types::{ACTIVE_STATES, CleanupReport, ConversationMessage, JobView, ServiceEvent};
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
            "UPDATE jobs SET state = 'failed', summary = '服务重启时任务仍在执行，请重新发起', updated_at = ?1 WHERE state IN ('queued', 'running', 'generating_proposal', 'applying', 'pushing')",
            params![now],
        )?;
        Ok(())
    }

    pub(crate) fn create_job(&self, kind: &str, branch: &str) -> Result<String> {
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
