use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;

use super::model::{PullRequestSnapshot, WatchEvent, WatchTask};

pub struct WatchStore {
    connection: Connection,
}

impl WatchStore {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        fs::create_dir_all(data_dir.as_ref())
            .with_context(|| format!("无法创建 watch 数据目录：{}", data_dir.as_ref().display()))?;
        let connection = Connection::open(data_dir.as_ref().join("watch.db"))?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS watch_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watch_tasks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                prompt TEXT NOT NULL,
                owner TEXT NOT NULL,
                author TEXT NOT NULL,
                repositories_json TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                instructions TEXT NOT NULL,
                state TEXT NOT NULL,
                last_run_at TEXT NOT NULL,
                last_result TEXT NOT NULL,
                next_run_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )?;

        // 把 1.13.0 的单配置快照平滑迁移为按任务隔离的快照，保留已有基线与事件。
        migrate_legacy_tables(&connection)?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS watch_snapshots (
                task_id TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (task_id, entity_key)
            );
            CREATE TABLE IF NOT EXISTS watch_events (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                summary TEXT NOT NULL,
                evidence_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(Self { connection })
    }

    pub fn initialized(&self, task_id: &str) -> Result<bool> {
        let key = format!("initialized:{task_id}");
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM watch_meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some())
    }

    pub fn mark_initialized(&self, task_id: &str) -> Result<()> {
        let key = format!("initialized:{task_id}");
        self.connection.execute(
            "INSERT INTO watch_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn snapshot(&self, task_id: &str, key: &str) -> Result<Option<PullRequestSnapshot>> {
        let raw = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM watch_snapshots WHERE task_id = ?1 AND entity_key = ?2",
                params![task_id, key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        raw.map(|raw| serde_json::from_str(&raw).context("无法解析历史 PR 快照"))
            .transpose()
    }

    pub fn upsert_snapshot(&self, task_id: &str, snapshot: &PullRequestSnapshot) -> Result<()> {
        let raw = serde_json::to_string(snapshot)?;
        let snapshot_fingerprint = fingerprint(&raw);
        self.connection.execute(
            r#"INSERT INTO watch_snapshots (task_id, entity_key, kind, snapshot_json, fingerprint, observed_at)
               VALUES (?1, ?2, 'github-pr', ?3, ?4, ?5)
               ON CONFLICT(task_id, entity_key) DO UPDATE SET
                 snapshot_json = excluded.snapshot_json,
                 fingerprint = excluded.fingerprint,
                 observed_at = excluded.observed_at"#,
            params![
                task_id,
                snapshot.key(),
                raw,
                snapshot_fingerprint,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn insert_event(
        &self,
        task_id: &str,
        entity_key: &str,
        kind: &str,
        summary: &str,
        evidence_url: &str,
        event_material: &str,
    ) -> Result<bool> {
        let event_fingerprint = fingerprint(&format!(
            "{task_id}\n{entity_key}\n{kind}\n{event_material}"
        ));
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO watch_events (id, task_id, entity_key, kind, fingerprint, summary, evidence_url, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                Uuid::new_v4().to_string(),
                task_id,
                entity_key,
                kind,
                event_fingerprint,
                summary,
                evidence_url,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn snapshots(&self, task_id: &str) -> Result<Vec<PullRequestSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_json FROM watch_snapshots WHERE task_id = ?1 ORDER BY entity_key",
        )?;
        let rows = statement.query_map(params![task_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let raw = row?;
            serde_json::from_str(&raw).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    raw.len(),
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
    }

    pub fn delete_snapshot(&self, task_id: &str, key: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM watch_snapshots WHERE task_id = ?1 AND entity_key = ?2",
            params![task_id, key],
        )?;
        Ok(())
    }

    pub fn events(&self, limit: usize) -> Result<Vec<WatchEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT id, task_id, entity_key, kind, fingerprint, summary, evidence_url, created_at FROM watch_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as u64], |row| {
            Ok(WatchEvent {
                id: row.get(0)?,
                task_id: row.get(1)?,
                entity_key: row.get(2)?,
                kind: row.get(3)?,
                fingerprint: row.get(4)?,
                summary: row.get(5)?,
                evidence_url: row.get(6)?,
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn save_task(&self, mut task: WatchTask) -> Result<WatchTask> {
        let existing = self.task_by_name(&task.name)?;
        let now = Utc::now().to_rfc3339();
        if let Some(existing) = existing {
            task.id = existing.id;
            task.created_at = existing.created_at;
        }
        task.updated_at = now;
        let repositories = serde_json::to_string(&task.repositories)?;
        self.connection.execute(
            r#"INSERT INTO watch_tasks
               (id, name, prompt, owner, author, repositories_json, interval_seconds, instructions, state, last_run_at, last_result, next_run_at, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
               ON CONFLICT(name) DO UPDATE SET
                 prompt = excluded.prompt,
                 owner = excluded.owner,
                 author = excluded.author,
                 repositories_json = excluded.repositories_json,
                 interval_seconds = excluded.interval_seconds,
                 instructions = excluded.instructions,
                 state = excluded.state,
                 next_run_at = excluded.next_run_at,
                 updated_at = excluded.updated_at"#,
            params![
                task.id,
                task.name,
                task.prompt,
                task.owner,
                task.author,
                repositories,
                task.interval_seconds,
                task.instructions,
                task.state,
                task.last_run_at,
                task.last_result,
                task.next_run_at,
                task.created_at,
                task.updated_at
            ],
        )?;
        self.task_by_name(&task.name)?
            .context("保存 watch 任务后无法重新读取")
    }

    pub fn tasks(&self) -> Result<Vec<WatchTask>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, prompt, owner, author, repositories_json, interval_seconds, instructions, state, last_run_at, last_result, next_run_at, created_at, updated_at FROM watch_tasks ORDER BY created_at",
        )?;
        let rows = statement.query_map([], row_to_task)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn claim_due_tasks(&mut self) -> Result<Vec<WatchTask>> {
        let now = Utc::now();
        let now_text = now.to_rfc3339();
        let lease_until = (now + Duration::minutes(5)).to_rfc3339();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT id, name, prompt, owner, author, repositories_json, interval_seconds, instructions, state, last_run_at, last_result, next_run_at, created_at, updated_at FROM watch_tasks WHERE state = 'active' AND next_run_at <= ?1 ORDER BY next_run_at",
            )?;
            let rows = statement.query_map(params![now_text], row_to_task)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut claimed = Vec::new();
        for task in candidates {
            let changed = transaction.execute(
                "UPDATE watch_tasks SET next_run_at = ?2, updated_at = ?3 WHERE id = ?1 AND state = 'active' AND next_run_at <= ?3",
                params![task.id, lease_until, now_text],
            )?;
            if changed == 1 {
                claimed.push(task);
            }
        }
        transaction.commit()?;
        Ok(claimed)
    }

    pub fn set_task_state(&self, name: &str, state: &str) -> Result<bool> {
        let changed = self.connection.execute(
            "UPDATE watch_tasks SET state = ?2, updated_at = ?3 WHERE name = ?1",
            params![name, state, Utc::now().to_rfc3339()],
        )?;
        Ok(changed == 1)
    }

    pub fn finish_task_run(&self, task: &WatchTask, result: &str, retry_soon: bool) -> Result<()> {
        let now = Utc::now();
        let delay = if retry_soon {
            60
        } else {
            task.interval_seconds.max(60)
        };
        self.connection.execute(
            "UPDATE watch_tasks SET last_run_at = ?2, last_result = ?3, next_run_at = ?4, updated_at = ?2 WHERE id = ?1",
            params![
                task.id,
                now.to_rfc3339(),
                result,
                (now + Duration::seconds(delay as i64)).to_rfc3339()
            ],
        )?;
        Ok(())
    }

    fn task_by_name(&self, name: &str) -> Result<Option<WatchTask>> {
        self.connection
            .query_row(
                "SELECT id, name, prompt, owner, author, repositories_json, interval_seconds, instructions, state, last_run_at, last_result, next_run_at, created_at, updated_at FROM watch_tasks WHERE name = ?1",
                params![name],
                row_to_task,
            )
            .optional()
            .map_err(Into::into)
    }
}

fn migrate_legacy_tables(connection: &Connection) -> Result<()> {
    if table_exists(connection, "watch_snapshots")?
        && !column_exists(connection, "watch_snapshots", "task_id")?
    {
        connection.execute_batch(
            r#"
            BEGIN IMMEDIATE;
            ALTER TABLE watch_snapshots RENAME TO watch_snapshots_v1;
            CREATE TABLE watch_snapshots (
                task_id TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (task_id, entity_key)
            );
            INSERT INTO watch_snapshots
                (task_id, entity_key, kind, snapshot_json, fingerprint, observed_at)
            SELECT 'config', entity_key, kind, snapshot_json, fingerprint, observed_at
            FROM watch_snapshots_v1;
            DROP TABLE watch_snapshots_v1;
            COMMIT;
            "#,
        )?;
    }

    if table_exists(connection, "watch_events")?
        && !column_exists(connection, "watch_events", "task_id")?
    {
        connection.execute_batch(
            r#"
            BEGIN IMMEDIATE;
            ALTER TABLE watch_events RENAME TO watch_events_v1;
            CREATE TABLE watch_events (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                kind TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                summary TEXT NOT NULL,
                evidence_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO watch_events
                (id, task_id, entity_key, kind, fingerprint, summary, evidence_url, created_at)
            SELECT id, 'config', entity_key, kind, fingerprint, summary, evidence_url, created_at
            FROM watch_events_v1;
            DROP TABLE watch_events_v1;
            COMMIT;
            "#,
        )?;
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn column_exists(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn row_to_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<WatchTask> {
    let repositories: String = row.get(5)?;
    let repositories = serde_json::from_str(&repositories).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            repositories.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(WatchTask {
        id: row.get(0)?,
        name: row.get(1)?,
        prompt: row.get(2)?,
        owner: row.get(3)?,
        author: row.get(4)?,
        repositories,
        interval_seconds: row.get(6)?,
        instructions: row.get(7)?,
        state: row.get(8)?,
        last_run_at: row.get(9)?,
        last_result: row.get(10)?,
        next_run_at: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn fingerprint(value: &str) -> String {
    digest(&SHA256, value.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use chrono::Utc;
    use rusqlite::Connection;
    use uuid::Uuid;

    use super::WatchStore;
    use crate::watch::model::{PullRequestSnapshot, WatchTask};

    #[test]
    fn snapshot_event_and_task_writes_are_idempotent() {
        let root = std::env::temp_dir().join(format!("termiters-watch-{}", Uuid::new_v4()));
        let store = WatchStore::open(&root).unwrap();
        let snapshot = PullRequestSnapshot {
            repository: "owner/repo".to_string(),
            number: 7,
            title: "test".to_string(),
            url: "https://example/pr/7".to_string(),
            is_draft: false,
            head_ref_name: "fix/test".to_string(),
            head_oid: "abc".to_string(),
            base_ref_name: "main".to_string(),
            merge_state: "CLEAN".to_string(),
            review_decision: String::new(),
            updated_at: "now".to_string(),
            checks: Vec::new(),
        };
        store.upsert_snapshot("task-1", &snapshot).unwrap();
        assert_eq!(
            store.snapshot("task-1", &snapshot.key()).unwrap(),
            Some(snapshot)
        );
        assert!(
            store
                .insert_event("task-1", "owner/repo#7", "changed", "changed", "url", "v1")
                .unwrap()
        );
        assert!(
            !store
                .insert_event("task-1", "owner/repo#7", "changed", "changed", "url", "v1")
                .unwrap()
        );

        let now = Utc::now().to_rfc3339();
        let task = store
            .save_task(WatchTask {
                id: Uuid::new_v4().to_string(),
                name: "个人 D9".to_string(),
                prompt: "持续追踪".to_string(),
                owner: "D-Nine-Chain".to_string(),
                author: "KKBK-233".to_string(),
                repositories: Vec::new(),
                interval_seconds: 600,
                instructions: "只读".to_string(),
                state: "active".to_string(),
                last_run_at: String::new(),
                last_result: String::new(),
                next_run_at: now.clone(),
                created_at: now.clone(),
                updated_at: now,
            })
            .unwrap();
        assert_eq!(task.name, "个人 D9");
        assert_eq!(store.tasks().unwrap().len(), 1);
        let mut store = store;
        assert_eq!(store.claim_due_tasks().unwrap().len(), 1);
        assert!(store.claim_due_tasks().unwrap().is_empty());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_database_is_migrated_without_losing_snapshots() {
        let root = std::env::temp_dir().join(format!("termiters-watch-v1-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let connection = Connection::open(root.join("watch.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE watch_snapshots (
                    entity_key TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );
                CREATE TABLE watch_events (
                    id TEXT PRIMARY KEY,
                    entity_key TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    summary TEXT NOT NULL,
                    evidence_url TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                INSERT INTO watch_snapshots VALUES
                    ('owner/repo#7', 'github-pr', '{"repository":"owner/repo","number":7,"title":"test","url":"url","is_draft":false,"head_ref_name":"fix","head_oid":"abc","base_ref_name":"main","merge_state":"CLEAN","review_decision":"","updated_at":"now","checks":[]}', 'old', 'now');
                INSERT INTO watch_events VALUES
                    ('event-1', 'owner/repo#7', 'changed', 'old-event', 'changed', 'url', 'now');
                "#,
            )
            .unwrap();
        drop(connection);

        let store = WatchStore::open(&root).unwrap();
        assert_eq!(store.snapshots("config").unwrap().len(), 1);
        let events = store.events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].task_id, "config");
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
