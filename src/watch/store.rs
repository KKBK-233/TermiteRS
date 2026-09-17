use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::Utc;
use ring::digest::{SHA256, digest};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use super::model::{PullRequestSnapshot, WatchEvent};

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
            CREATE TABLE IF NOT EXISTS watch_snapshots (
                entity_key TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS watch_events (
                id TEXT PRIMARY KEY,
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

    pub fn initialized(&self) -> Result<bool> {
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM watch_meta WHERE key = 'initialized'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .is_some())
    }

    pub fn mark_initialized(&self) -> Result<()> {
        self.connection.execute(
            "INSERT INTO watch_meta (key, value) VALUES ('initialized', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn snapshot(&self, key: &str) -> Result<Option<PullRequestSnapshot>> {
        let raw = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM watch_snapshots WHERE entity_key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        raw.map(|raw| serde_json::from_str(&raw).context("无法解析历史 PR 快照"))
            .transpose()
    }

    pub fn upsert_snapshot(&self, snapshot: &PullRequestSnapshot) -> Result<()> {
        let raw = serde_json::to_string(snapshot)?;
        let fingerprint = fingerprint(&raw);
        self.connection.execute(
            r#"INSERT INTO watch_snapshots (entity_key, kind, snapshot_json, fingerprint, observed_at)
               VALUES (?1, 'github-pr', ?2, ?3, ?4)
               ON CONFLICT(entity_key) DO UPDATE SET
                 snapshot_json = excluded.snapshot_json,
                 fingerprint = excluded.fingerprint,
                 observed_at = excluded.observed_at"#,
            params![snapshot.key(), raw, fingerprint, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn insert_event(
        &self,
        entity_key: &str,
        kind: &str,
        summary: &str,
        evidence_url: &str,
        event_material: &str,
    ) -> Result<bool> {
        let event_fingerprint = fingerprint(&format!("{entity_key}\n{kind}\n{event_material}"));
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO watch_events (id, entity_key, kind, fingerprint, summary, evidence_url, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                Uuid::new_v4().to_string(),
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

    pub fn snapshots(&self) -> Result<Vec<PullRequestSnapshot>> {
        let mut statement = self
            .connection
            .prepare("SELECT snapshot_json FROM watch_snapshots ORDER BY entity_key")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
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

    pub fn delete_snapshot(&self, key: &str) -> Result<()> {
        self.connection.execute(
            "DELETE FROM watch_snapshots WHERE entity_key = ?1",
            params![key],
        )?;
        Ok(())
    }

    pub fn events(&self, limit: usize) -> Result<Vec<WatchEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT id, entity_key, kind, fingerprint, summary, evidence_url, created_at FROM watch_events ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as u64], |row| {
            Ok(WatchEvent {
                id: row.get(0)?,
                entity_key: row.get(1)?,
                kind: row.get(2)?,
                fingerprint: row.get(3)?,
                summary: row.get(4)?,
                evidence_url: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
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

    use uuid::Uuid;

    use super::WatchStore;
    use crate::watch::model::PullRequestSnapshot;

    #[test]
    fn snapshot_and_event_writes_are_idempotent() {
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
        store.upsert_snapshot(&snapshot).unwrap();
        assert_eq!(store.snapshot(&snapshot.key()).unwrap(), Some(snapshot));
        assert!(
            store
                .insert_event("owner/repo#7", "changed", "changed", "url", "v1")
                .unwrap()
        );
        assert!(
            !store
                .insert_event("owner/repo#7", "changed", "changed", "url", "v1")
                .unwrap()
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
