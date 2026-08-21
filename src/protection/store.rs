use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    CandidateArtifact, DeliveryDraft, ProtectionFinding, RemediationPlan, SecuritySignal,
    VerificationResult,
};

/// 安全保护数据独立于同步任务保存，便于后续重新评估和投送去重。
pub struct ProtectionStore {
    connection: Connection,
}

impl ProtectionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let connection = Connection::open(path)
            .with_context(|| format!("打开保护数据库失败：{}", path.display()))?;
        initialize_protection_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        initialize_protection_schema(&connection)?;
        Ok(Self { connection })
    }

    pub fn upsert_signal(&self, signal: &SecuritySignal) -> Result<()> {
        self.connection.execute(
            "INSERT INTO security_signals
             (id, project, source, summary, reference, dedupe_key, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(dedupe_key) DO UPDATE SET summary = excluded.summary, reference = excluded.reference",
            params![
                signal.id,
                signal.project,
                enum_text(&signal.source)?,
                signal.summary,
                signal.reference,
                signal.dedupe_key,
                signal.received_at,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_finding(&self, finding: &ProtectionFinding) -> Result<()> {
        self.connection.execute(
            "INSERT INTO protection_findings
             (id, project, signal_id, state, classification, severity, confidence, affected,
              build_allowed, summary, evidence_json, dedupe_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(dedupe_key) DO UPDATE SET
              state = excluded.state, classification = excluded.classification,
              severity = excluded.severity, confidence = excluded.confidence,
              affected = excluded.affected, build_allowed = excluded.build_allowed,
              summary = excluded.summary, evidence_json = excluded.evidence_json,
              updated_at = excluded.updated_at",
            params![
                finding.id,
                finding.project,
                finding.signal_id,
                enum_text(&finding.state)?,
                finding.classification,
                finding.severity,
                finding.confidence,
                finding.affected.map(i64::from),
                i64::from(finding.build_allowed),
                finding.summary,
                serde_json::to_string(&finding.evidence)?,
                finding.dedupe_key,
                finding.created_at,
                finding.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_delivery_draft(&self, draft: &DeliveryDraft) -> Result<()> {
        self.connection.execute(
            "INSERT INTO delivery_drafts
             (id, finding_id, kind, destination, title, body, labels_json, dedupe_key,
              approval_required, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'prepared', ?10)
             ON CONFLICT(dedupe_key) DO UPDATE SET title = excluded.title, body = excluded.body,
              labels_json = excluded.labels_json",
            params![
                draft.id,
                draft.finding_id,
                enum_text(&draft.kind)?,
                draft.destination,
                draft.title,
                draft.body,
                serde_json::to_string(&draft.labels)?,
                draft.dedupe_key,
                i64::from(draft.approval_required),
                draft.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_remediation_plan(&self, plan: &RemediationPlan) -> Result<()> {
        self.connection.execute(
            "INSERT INTO remediation_plans
             (id, finding_id, action, summary, requirements_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET action = excluded.action, summary = excluded.summary,
              requirements_json = excluded.requirements_json",
            params![
                plan.id,
                plan.finding_id,
                enum_text(&plan.action)?,
                plan.summary,
                serde_json::to_string(&plan.requirements)?,
                plan.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_candidate(&self, candidate: &CandidateArtifact) -> Result<()> {
        self.connection.execute(
            "INSERT INTO protection_candidates
             (id, finding_id, worktree_path, content_sha256, summary, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET worktree_path = excluded.worktree_path,
              content_sha256 = excluded.content_sha256, summary = excluded.summary",
            params![
                candidate.id,
                candidate.finding_id,
                candidate.worktree_path,
                candidate.content_sha256,
                candidate.summary,
                candidate.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn upsert_verification(&self, verification: &VerificationResult) -> Result<()> {
        self.connection.execute(
            "INSERT INTO verification_results
             (id, candidate_id, verifier, passed, summary, evidence_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET verifier = excluded.verifier, passed = excluded.passed,
              summary = excluded.summary, evidence_json = excluded.evidence_json",
            params![
                verification.id,
                verification.candidate_id,
                verification.verifier,
                i64::from(verification.passed),
                verification.summary,
                serde_json::to_string(&verification.evidence)?,
                verification.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn finding_id_by_dedupe_key(&self, dedupe_key: &str) -> Result<Option<String>> {
        self.connection
            .query_row(
                "SELECT id FROM protection_findings WHERE dedupe_key = ?1",
                params![dedupe_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn delivery_draft_count(&self) -> Result<u32> {
        self.connection
            .query_row("SELECT COUNT(*) FROM delivery_drafts", [], |row| row.get(0))
            .map_err(Into::into)
    }
}

fn enum_text(value: &impl serde::Serialize) -> Result<String> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .context("枚举序列化结果不是字符串")
}

pub(crate) fn initialize_protection_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS security_signals (
            id TEXT PRIMARY KEY,
            project TEXT NOT NULL,
            source TEXT NOT NULL,
            summary TEXT NOT NULL,
            reference TEXT,
            dedupe_key TEXT NOT NULL UNIQUE,
            received_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS protection_findings (
            id TEXT PRIMARY KEY,
            project TEXT NOT NULL,
            signal_id TEXT NOT NULL REFERENCES security_signals(id),
            state TEXT NOT NULL,
            classification TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            affected INTEGER,
            build_allowed INTEGER NOT NULL,
            summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS remediation_plans (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL REFERENCES protection_findings(id),
            action TEXT NOT NULL,
            summary TEXT NOT NULL,
            requirements_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS protection_candidates (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL REFERENCES protection_findings(id),
            worktree_path TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verification_results (
            id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL REFERENCES protection_candidates(id),
            verifier TEXT NOT NULL,
            passed INTEGER NOT NULL,
            summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS delivery_drafts (
            id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL REFERENCES protection_findings(id),
            kind TEXT NOT NULL,
            destination TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            labels_json TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            approval_required INTEGER NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::protection::{
        CandidateArtifact, DeliveryKind, FindingState, ProtectionFinding, RemediationAction,
        RemediationPlan, SecuritySignalSource, VerificationResult,
    };

    #[test]
    fn finding_and_issue_draft_are_idempotent() {
        let store = ProtectionStore::in_memory().unwrap();
        let now = Utc::now().to_rfc3339();
        let signal = SecuritySignal {
            id: "signal-1".to_string(),
            project: "blog".to_string(),
            source: SecuritySignalSource::StaticSupplyChainScan,
            summary: "发现恶意依赖".to_string(),
            reference: None,
            dedupe_key: "signal:arrayref".to_string(),
            received_at: now.clone(),
        };
        store.upsert_signal(&signal).unwrap();
        let finding = ProtectionFinding {
            id: "finding-1".to_string(),
            project: "blog".to_string(),
            signal_id: signal.id.clone(),
            state: FindingState::Affected,
            classification: "confirmed-malicious-dependency".to_string(),
            severity: "blocker".to_string(),
            confidence: "high".to_string(),
            affected: Some(true),
            build_allowed: false,
            summary: "阻止构建".to_string(),
            evidence: vec!["arrayref 0.3.10".to_string()],
            dedupe_key: "finding:arrayref".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        store.upsert_finding(&finding).unwrap();
        store.upsert_finding(&finding).unwrap();
        assert_eq!(
            store
                .finding_id_by_dedupe_key("finding:arrayref")
                .unwrap()
                .as_deref(),
            Some("finding-1")
        );

        let draft = DeliveryDraft {
            id: "draft-1".to_string(),
            finding_id: finding.id,
            kind: DeliveryKind::GithubIssue,
            destination: "owner/repo".to_string(),
            title: "安全问题".to_string(),
            body: "证据".to_string(),
            labels: vec!["security".to_string()],
            dedupe_key: "issue:arrayref".to_string(),
            approval_required: true,
            created_at: now,
        };
        store.upsert_delivery_draft(&draft).unwrap();
        store.upsert_delivery_draft(&draft).unwrap();
        assert_eq!(store.delivery_draft_count().unwrap(), 1);

        let plan = RemediationPlan {
            id: "plan-1".to_string(),
            finding_id: "finding-1".to_string(),
            action: RemediationAction::PinVersion,
            summary: "固定到安全版本".to_string(),
            requirements: vec!["保持离线构建".to_string()],
            created_at: Utc::now().to_rfc3339(),
        };
        store.upsert_remediation_plan(&plan).unwrap();
        let candidate = CandidateArtifact {
            id: "candidate-1".to_string(),
            finding_id: "finding-1".to_string(),
            worktree_path: "/isolated/candidate".to_string(),
            content_sha256: "abc".to_string(),
            summary: "候选修复".to_string(),
            created_at: Utc::now().to_rfc3339(),
        };
        store.upsert_candidate(&candidate).unwrap();
        let verification = VerificationResult {
            id: "verification-1".to_string(),
            candidate_id: candidate.id,
            verifier: "static-gate".to_string(),
            passed: true,
            summary: "验证通过".to_string(),
            evidence: vec!["无阻断项".to_string()],
            created_at: Utc::now().to_rfc3339(),
        };
        store.upsert_verification(&verification).unwrap();
    }
}
