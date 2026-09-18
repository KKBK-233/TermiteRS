//! 自治任务报告：仅持久化可回看的摘要，不保存原始模型观察或凭据。

use std::{
    cmp::Reverse,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{TaskReportConfig, local_task::LocalTaskState};

const MAX_REQUEST_CHARS: usize = 4_000;
const MAX_SUMMARY_CHARS: usize = 16_000;
const MAX_TRACE_ITEMS: usize = 32;
const MAX_TRACE_CHARS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskReportOutcome {
    Finished,
    Stopped,
    Failed,
}

impl TaskReportOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Finished => "完成",
            Self::Stopped => "停止",
            Self::Failed => "失败",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReport {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub request: String,
    pub outcome: TaskReportOutcome,
    pub trace: Vec<String>,
    pub summary: String,
}

impl TaskReport {
    pub fn completed(
        request: &str,
        provider: &str,
        model: &str,
        state: LocalTaskState,
        trace: &[String],
        summary: &str,
        redactions: &[String],
    ) -> Self {
        let outcome = match state {
            LocalTaskState::Finished => TaskReportOutcome::Finished,
            LocalTaskState::Stopped => TaskReportOutcome::Stopped,
        };
        Self::new(
            request, provider, model, outcome, trace, summary, redactions,
        )
    }

    pub fn failed(
        request: &str,
        provider: &str,
        model: &str,
        error: &str,
        redactions: &[String],
    ) -> Self {
        Self::new(
            request,
            provider,
            model,
            TaskReportOutcome::Failed,
            &[],
            error,
            redactions,
        )
    }

    fn new(
        request: &str,
        provider: &str,
        model: &str,
        outcome: TaskReportOutcome,
        trace: &[String],
        summary: &str,
        redactions: &[String],
    ) -> Self {
        let sanitize =
            |value: &str, limit| bounded_text(&redact_exact_values(value, redactions), limit);
        Self {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            provider: sanitize(provider, 80),
            model: sanitize(model, 160),
            request: sanitize(request, MAX_REQUEST_CHARS),
            outcome,
            trace: trace
                .iter()
                .take(MAX_TRACE_ITEMS)
                .map(|line| sanitize(line, MAX_TRACE_CHARS))
                .collect(),
            summary: sanitize(summary, MAX_SUMMARY_CHARS),
        }
    }
}

pub struct TaskReportStore<'a> {
    config: &'a TaskReportConfig,
}

impl<'a> TaskReportStore<'a> {
    pub fn new(config: &'a TaskReportConfig) -> Self {
        Self { config }
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// 使用临时文件加原子重命名，避免中断时留下半份报告。
    pub fn save(&self, report: &TaskReport) -> Result<Option<String>> {
        if !self.enabled() {
            return Ok(None);
        }
        fs::create_dir_all(&self.config.data_dir)
            .with_context(|| format!("无法创建任务报告目录：{}", self.config.data_dir.display()))?;
        let final_path = self.config.data_dir.join(format!(
            "{}-{}.json",
            report.created_at.timestamp_millis(),
            report.id
        ));
        let temporary_path = self.config.data_dir.join(format!(".{}.tmp", report.id));
        let body = serde_json::to_vec_pretty(report).context("无法序列化任务报告")?;
        write_private_file(&temporary_path, &body)?;
        fs::rename(&temporary_path, &final_path)
            .with_context(|| format!("无法发布任务报告：{}", final_path.display()))?;
        Ok(Some(report.id.clone()))
    }

    pub fn list(&self, limit: usize) -> Result<Vec<TaskReport>> {
        if !self.enabled() || !self.config.data_dir.exists() {
            return Ok(Vec::new());
        }
        let entries = fs::read_dir(&self.config.data_dir)
            .with_context(|| format!("无法读取任务报告目录：{}", self.config.data_dir.display()))?;
        let mut reports = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
            .filter_map(|entry| read_report(entry.path()).ok())
            .collect::<Vec<_>>();
        reports.sort_by_key(|report| Reverse(report.created_at));
        reports.truncate(limit);
        Ok(reports)
    }

    pub fn get(&self, id_or_prefix: &str) -> Result<Option<TaskReport>> {
        let id_or_prefix = id_or_prefix.trim();
        if id_or_prefix.len() < 8
            || id_or_prefix.len() > 36
            || !id_or_prefix
                .chars()
                .all(|ch| ch.is_ascii_hexdigit() || ch == '-')
        {
            bail!("报告 ID 格式无效；请从 /reports 复制至少 8 位 ID");
        }
        let matches = self
            .list(usize::MAX)?
            .into_iter()
            .filter(|report| report.id.starts_with(id_or_prefix))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [report] => Ok(Some(report.clone())),
            _ => bail!("报告 ID 前缀不唯一；请提供更多位"),
        }
    }
}

pub fn render_report_list(reports: &[TaskReport]) -> String {
    if reports.is_empty() {
        return "暂无任务报告。".to_string();
    }
    reports
        .iter()
        .map(|report| {
            format!(
                "- {}  {}  [{}]  {}  {}",
                &report.id[..8],
                display_time(report.created_at),
                report.outcome.label(),
                report.model,
                one_line(&report.request, 120)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn render_report(report: &TaskReport) -> String {
    let trace = if report.trace.is_empty() {
        "- 无".to_string()
    } else {
        report
            .trace
            .iter()
            .map(|line| format!("- {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "报告 ID：{}\n时间：{}\n模型：{}/{}\n状态：{}\n\n请求：\n{}\n\n执行轨迹：\n{}\n\n模型结论：\n{}",
        report.id,
        display_time(report.created_at),
        report.provider,
        report.model,
        report.outcome.label(),
        report.request,
        trace,
        report.summary
    )
}

fn display_time(value: DateTime<Utc>) -> String {
    value
        .with_timezone(&Local)
        .format("%Y-%m-%d %H:%M:%S %:z")
        .to_string()
}

fn read_report(path: PathBuf) -> Result<TaskReport> {
    let body = fs::read(&path).with_context(|| format!("无法读取任务报告：{}", path.display()))?;
    serde_json::from_slice(&body).with_context(|| format!("任务报告格式无效：{}", path.display()))
}

fn write_private_file(path: &Path, body: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("无法新建临时任务报告：{}", path.display()))?;
    file.write_all(body)
        .with_context(|| format!("无法写入临时任务报告：{}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("无法同步临时任务报告：{}", path.display()))
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut output = value
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
        .take(max_chars + 1)
        .collect::<String>();
    if output.chars().count() > max_chars {
        output = output.chars().take(max_chars).collect();
        output.push_str("...[已截断]");
    }
    output
}

fn redact_exact_values(value: &str, redactions: &[String]) -> String {
    redactions
        .iter()
        .filter(|secret| secret.len() >= 8)
        .fold(value.to_string(), |output, secret| {
            output.replace(secret, "[凭据已隐藏]")
        })
}

fn one_line(value: &str, max_chars: usize) -> String {
    let normalized = value.replace(['\r', '\n'], " ");
    bounded_text(&normalized, max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, TaskReportConfig) {
        let root = std::env::temp_dir().join(format!("termiters-reports-{}", Uuid::new_v4()));
        let config = TaskReportConfig {
            enabled: true,
            data_dir: root.clone(),
        };
        (root, config)
    }

    #[test]
    fn disabled_store_does_not_create_directory() {
        let (root, mut config) = fixture();
        config.enabled = false;
        let report = TaskReport::failed("请求", "provider", "model", "失败", &[]);
        assert!(
            TaskReportStore::new(&config)
                .save(&report)
                .unwrap()
                .is_none()
        );
        assert!(!root.exists());
    }

    #[test]
    fn saves_lists_and_reads_redacted_report() {
        let (root, config) = fixture();
        let secret = "lin_api_test_secret_value".to_string();
        let report = TaskReport::completed(
            &format!("检查 {secret}"),
            "deep-seek",
            "deepseek-v4-flash",
            LocalTaskState::Finished,
            &[format!("没有输出 {secret}")],
            &format!("结论不包含 {secret}"),
            std::slice::from_ref(&secret),
        );
        let store = TaskReportStore::new(&config);
        let id = store.save(&report).unwrap().unwrap();
        let listed = store.list(20).unwrap();
        assert_eq!(listed.len(), 1);
        let loaded = store.get(&id[..8]).unwrap().unwrap();
        assert_eq!(loaded.id, id);
        let serialized = serde_json::to_string(&loaded).unwrap();
        assert!(!serialized.contains(&secret));
        assert!(serialized.contains("凭据已隐藏"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_path_like_report_id() {
        let (_, config) = fixture();
        assert!(TaskReportStore::new(&config).get("../secret").is_err());
    }
}
