use std::{fs, path::Path};

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use crate::config::Config;

use super::{
    DeliveryDraft, FindingState, ProtectionFinding, ProtectionStore, SecuritySignal,
    SecuritySignalSource, StaticScanReport, prepare_issue_draft, scan_supply_chain_tree,
};

#[derive(Debug, Serialize)]
pub struct ProtectionScanOutput {
    pub signal: SecuritySignal,
    pub finding: ProtectionFinding,
    pub report: StaticScanReport,
    pub issue_draft: Option<DeliveryDraft>,
    pub recorded: bool,
}

/// 完成一次构建前静态审计，并在启用保护模式时幂等保存 Finding 和投送草稿。
pub fn run_protection_scan(
    config: &Config,
    scan_root: impl AsRef<Path>,
    issue_repository: Option<&str>,
) -> Result<ProtectionScanOutput> {
    let project = configured_project_name(config);
    let report = scan_supply_chain_tree(&project, scan_root)?;
    let now = Utc::now().to_rfc3339();
    let stable_suffix = &report.dedupe_key[..32];
    let signal = SecuritySignal {
        id: format!("signal-{stable_suffix}"),
        project: project.clone(),
        source: SecuritySignalSource::StaticSupplyChainScan,
        summary: if report.build_allowed {
            "构建前供应链静态扫描未发现阻断项".to_string()
        } else {
            format!(
                "构建前供应链静态扫描发现 {} 个阻断项",
                report.blockers.len()
            )
        },
        reference: None,
        dedupe_key: format!("static-scan:{project}:{}", report.dedupe_key),
        received_at: now.clone(),
    };
    let finding = ProtectionFinding {
        id: format!("finding-{stable_suffix}"),
        project: project.clone(),
        signal_id: signal.id.clone(),
        state: if report.build_allowed {
            FindingState::Unaffected
        } else {
            FindingState::Affected
        },
        classification: if report.build_allowed {
            "no-static-blocker".to_string()
        } else {
            "malicious-or-dangerous-build-dependency".to_string()
        },
        severity: if report.build_allowed {
            "informational".to_string()
        } else {
            "blocker".to_string()
        },
        confidence: if report.blockers.iter().any(|item| {
            matches!(
                item.rule_id.as_str(),
                "SC-RUST-ARRAYREF-0.3.10" | "SC-RUST-TYPOSQUAT-PROC-MACRO1"
            )
        }) {
            "high".to_string()
        } else {
            "medium".to_string()
        },
        affected: Some(!report.build_allowed),
        build_allowed: report.build_allowed,
        summary: signal.summary.clone(),
        evidence: report
            .blockers
            .iter()
            .chain(&report.warnings)
            .map(|item| format!("{} {}: {}", item.rule_id, item.path, item.evidence))
            .collect(),
        dedupe_key: format!("finding:{project}:{}", report.dedupe_key),
        created_at: now.clone(),
        updated_at: now,
    };
    let issue_draft = issue_repository
        .and_then(|repository| prepare_issue_draft(&finding.id, repository, &report));

    let recorded = if config.protection.enabled {
        fs::create_dir_all(&config.service.data_dir)?;
        let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
        store.upsert_signal(&signal)?;
        store.upsert_finding(&finding)?;
        if let Some(draft) = &issue_draft {
            store.upsert_delivery_draft(draft)?;
        }
        true
    } else {
        false
    };

    Ok(ProtectionScanOutput {
        signal,
        finding,
        report,
        issue_draft,
        recorded,
    })
}

fn configured_project_name(config: &Config) -> String {
    let name = config.protection.project.name.trim();
    if !name.is_empty() {
        return name.to_string();
    }
    config
        .repo
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("protected-project")
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn repeated_scan_reuses_finding_and_issue_draft() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/supply_chain/arrayref-0.3.10");
        let data_dir =
            std::env::temp_dir().join(format!("termiters-protection-{}", Uuid::new_v4()));
        let yaml = format!(
            r#"
repo:
  path: '{}'
  upstream: unused
  fork: unused
service:
  data_dir: '{}'
protection:
  enabled: true
  project:
    name: rust-blog
    description: 公开运行的 Rust 博客，禁止供应链恶意代码。
  profiles: [baseline, rust]
  automation: candidate
"#,
            fixture.display().to_string().replace('\\', "/"),
            data_dir.display().to_string().replace('\\', "/")
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();

        let first = run_protection_scan(&config, &fixture, Some("owner/rust-blog")).unwrap();
        let repeated = run_protection_scan(&config, &fixture, Some("owner/rust-blog")).unwrap();
        assert_eq!(first.finding.id, repeated.finding.id);

        let store = ProtectionStore::open(data_dir.join("termite.db")).unwrap();
        assert_eq!(store.delivery_draft_count().unwrap(), 1);
        drop(store);
        fs::remove_dir_all(data_dir).unwrap();
    }
}
