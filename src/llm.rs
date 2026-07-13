use std::env;
use std::io::Read;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use crate::config::{LlmConfig, LlmProvider};
use crate::git::{ConflictFileContent, ConflictSnapshot, SyncPatchContext};
use crate::report::SyncReport;
use crate::text::truncate_to_char_boundary;

const DEFAULT_CONFLICT_SYSTEM_PROMPT: &str = "You are a senior software maintainer. Analyze git rebase conflicts. Explain whether the conflict is mechanical or functional, recommend a safe resolution strategy, and call out when human review is required. Do not invent missing code.";
const DEFAULT_CONFLICT_USER_PROMPT: &str = r#"Branch: {branch}
Base: {base}
Conflict files:
{conflict_files}

Git status:
{git_status}

Combined diff:
{combined_diff}
"#;
const DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT: &str = "你是一个谨慎的软件维护助手。你只能做低风险兼容性冲突修复。功能性冲突不等于高风险：如果当前补丁意图和上游新增逻辑能够在不猜测业务规则的前提下同时保留，应判定为 low 并给出兼容结果。rebase 时 HEAD 通常是新的上游基线，theirs 通常是正在重放的个人补丁；个人旧补丁中没有出现上游后来新增的条件，不代表个人补丁要删除该条件。必须只输出 JSON，不要 Markdown，不要解释。信息不足、语义互斥、需要选择业务规则或新增设计时，risk 必须是 high 或 medium，并且 files 为空。";
const DEFAULT_AUTO_RESOLVE_USER_PROMPT: &str = r#"请分析下面的 Git 冲突，并仅在低风险时给出修复后的完整文件内容。

低风险的定义：
- 只是在上游新增逻辑和本地已有逻辑之间做兼容保留。
- 不删除本地补丁的核心行为。
- 不删除上游新增的功能入口。
- 当前补丁与上游逻辑可以直接组合，不需要猜测用户未说明的业务取舍。
- 冲突被称为“功能性”本身不是拒绝理由；只有两边语义互斥或信息不足时才提高风险。
- 不重构，不改无关文件。

必须输出 JSON，格式如下：
{
  "risk": "low|medium|high",
  "summary": "一句中文说明",
  "files": [
    {
      "path": "repo/relative/path",
      "content": "修复后的完整文件内容"
    }
  ]
}

分支：{branch}
基线：{base}
冲突文件：
{conflict_files}

Git 状态：
{git_status}

Combined diff：
{combined_diff}

冲突文件内容：
{file_contents}
"#;
const DEFAULT_SYNC_SUMMARY_SYSTEM_PROMPT: &str = "你是一个严谨的软件分支维护助手。请只根据用户提供的同步报告进行中文总结，不要编造不存在的提交、测试或冲突。输出必须是纯文本，不要使用 Markdown、加粗、标题或代码块。";
const DEFAULT_SYNC_SUMMARY_USER_PROMPT: &str = r#"请总结下面这次 TermiteRS 同步报告。

要求：
- 使用中文。
- 控制在 5 条以内。
- 明确说明哪些分支成功、失败或冲突。
- 如果全部成功，说明可以继续观察或等待下次上游更新。
- 如果有失败或冲突，给出下一步处理建议。
- 不要编造报告之外的信息。
- 输出纯文本，不要使用 Markdown、加粗、标题或代码块。

同步报告：
{report}
"#;

#[derive(Debug, Clone)]
pub struct ConflictAnalysisRequest {
    pub branch: String,
    pub base: String,
    pub branch_note: Option<String>,
    pub patch_context: SyncPatchContext,
    pub snapshot: ConflictSnapshot,
}

#[derive(Debug, Clone)]
pub struct AutoResolveConflictRequest {
    pub branch: String,
    pub base: String,
    pub branch_note: Option<String>,
    pub patch_context: SyncPatchContext,
    pub snapshot: ConflictSnapshot,
    pub files: Vec<ConflictFileContent>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoResolveDecision {
    pub risk: String,
    pub summary: String,
    #[serde(default)]
    pub files: Vec<ResolvedFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictOption {
    pub id: String,
    pub title: String,
    pub description: String,
    pub tradeoffs: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictOptionsDecision {
    pub classification: String,
    pub summary: String,
    pub options: Vec<ConflictOption>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictProposal {
    pub summary: String,
    pub files: Vec<ResolvedFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResolvedFile {
    pub path: String,
    pub content: String,
}

pub struct LlmService {
    config: Option<LlmConfig>,
}

impl LlmService {
    pub fn new(config: Option<LlmConfig>) -> Self {
        Self { config }
    }

    pub fn analyze_conflict(&self, request: &ConflictAnalysisRequest) -> Result<Option<String>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = render_template(
            config
                .prompts
                .conflict_system
                .as_deref()
                .unwrap_or(DEFAULT_CONFLICT_SYSTEM_PROMPT),
            &conflict_template_values(request),
            config.max_prompt_bytes,
        );
        let user_prompt = build_conflict_prompt(request, config);
        call_chat(config, &system_prompt, &user_prompt).map(Some)
    }

    pub fn auto_resolve_conflict(
        &self,
        request: &AutoResolveConflictRequest,
    ) -> Result<Option<AutoResolveDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = render_template(
            config
                .prompts
                .auto_resolve_system
                .as_deref()
                .unwrap_or(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT),
            &auto_resolve_template_values(request),
            config.max_prompt_bytes,
        );
        let user_prompt = render_template(
            config
                .prompts
                .auto_resolve_user
                .as_deref()
                .unwrap_or(DEFAULT_AUTO_RESOLVE_USER_PROMPT),
            &auto_resolve_template_values(request),
            config.max_prompt_bytes,
        );
        let response = call_chat(config, &system_prompt, &user_prompt)?;
        let json = extract_json_object(&response)?;
        let decision = serde_json::from_str(json).context("failed to parse auto resolve JSON")?;
        Ok(Some(decision))
    }

    pub fn summarize_sync_report(&self, report: &SyncReport) -> Result<Option<String>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let values = sync_summary_template_values(report);
        let system_prompt = render_template(
            config
                .prompts
                .sync_summary_system
                .as_deref()
                .unwrap_or(DEFAULT_SYNC_SUMMARY_SYSTEM_PROMPT),
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = build_sync_summary_prompt(report, config);
        call_chat(config, &system_prompt, &user_prompt).map(Some)
    }

    pub fn conflict_options(
        &self,
        request: &AutoResolveConflictRequest,
        conversation: &str,
    ) -> Result<Option<ConflictOptionsDecision>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = "你是严谨的软件维护助手。当前冲突已被判定为不能自动处理。请给出 2 到 4 种明确且互不重复的修改方案，只输出 JSON。不要修改文件。";
        let values = auto_resolve_template_values(request);
        let context = render_template(
            "分支：{branch}\n基线：{base}\n冲突文件：\n{conflict_files}\n\nGit 状态：\n{git_status}\n\nCombined diff：\n{combined_diff}\n\n文件内容：\n{file_contents}",
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = format!(
            "{context}\n\n对话与人工要求：\n{conversation}\n\n输出格式：\n{{\"classification\":\"functional|uncertain\",\"summary\":\"中文摘要\",\"options\":[{{\"id\":\"短标识\",\"title\":\"方案名\",\"description\":\"具体做法\",\"tradeoffs\":\"取舍\"}}]}}"
        );
        let response = call_chat(config, system_prompt, &user_prompt)?;
        let json = extract_json_object(&response)?;
        let decision: ConflictOptionsDecision =
            serde_json::from_str(json).context("failed to parse conflict options JSON")?;
        if !(2..=4).contains(&decision.options.len()) {
            bail!("conflict options must contain 2 to 4 items");
        }
        Ok(Some(decision))
    }

    pub fn conflict_proposal(
        &self,
        request: &AutoResolveConflictRequest,
        conversation: &str,
        selected_option: &str,
        requirements: &str,
    ) -> Result<Option<ConflictProposal>> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        let system_prompt = "你是严谨的软件维护助手。请根据用户确认的方案生成候选修改，只输出 JSON。只能返回原冲突文件的完整内容，不得修改其他文件，不得保留 Git 冲突标记。";
        let values = auto_resolve_template_values(request);
        let context = render_template(
            "分支：{branch}\n基线：{base}\n冲突文件：\n{conflict_files}\n\nGit 状态：\n{git_status}\n\nCombined diff：\n{combined_diff}\n\n文件内容：\n{file_contents}",
            &values,
            config.max_prompt_bytes,
        );
        let user_prompt = format!(
            "{context}\n\n对话记录：\n{conversation}\n\n选定方案：\n{selected_option}\n\n补充要求：\n{requirements}\n\n输出格式：\n{{\"summary\":\"中文摘要\",\"files\":[{{\"path\":\"仓库相对路径\",\"content\":\"修改后的完整文件\"}}]}}"
        );
        let response = call_chat(config, system_prompt, &user_prompt)?;
        let json = extract_json_object(&response)?;
        serde_json::from_str(json)
            .context("failed to parse conflict proposal JSON")
            .map(Some)
    }

    pub fn assistant_reply_streaming<F>(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        mut on_delta: F,
    ) -> Result<Option<String>>
    where
        F: FnMut(&str) -> Result<()>,
    {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        if !config.enabled {
            return Ok(None);
        }

        call_chat_streaming(config, system_prompt, user_prompt, &mut on_delta).map(Some)
    }
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    stream: bool,
    messages: Vec<ChatMessage<'a>>,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

fn chat_completions_endpoint(config: &LlmConfig) -> Result<String> {
    let base = match (&config.base_url, config.provider) {
        (Some(base_url), _) => base_url.clone(),
        (None, LlmProvider::DeepSeek) => "https://api.deepseek.com".to_string(),
        (None, LlmProvider::OpenAi) => "https://api.openai.com/v1".to_string(),
        (None, LlmProvider::OpenAiCompatible | LlmProvider::Custom) => {
            bail!("base_url is required for provider {:?}", config.provider)
        }
    };

    let base = base.trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        Ok(base.to_string())
    } else {
        Ok(format!("{base}/chat/completions"))
    }
}

fn call_chat(config: &LlmConfig, system_prompt: &str, user_prompt: &str) -> Result<String> {
    let attempts = config.max_retries.saturating_add(1);
    for attempt in 1..=attempts {
        match call_chat_once(config, system_prompt, user_prompt) {
            Ok(content) => return Ok(content),
            Err(err) if attempt < attempts && is_retryable_llm_error(&err) => {
                warn!("LLM request attempt {attempt}/{attempts} failed, retrying: {err:#}");
                thread::sleep(Duration::from_secs(u64::from(attempt.min(5))));
            }
            Err(err) => return Err(err),
        }
    }
    bail!("LLM request did not run")
}

fn call_chat_once(config: &LlmConfig, system_prompt: &str, user_prompt: &str) -> Result<String> {
    let api_key = env::var(&config.api_key_env)
        .with_context(|| format!("missing LLM API key env {}", config.api_key_env))?;
    let endpoint = chat_completions_endpoint(config)?;

    let body = ChatRequest {
        model: &config.model,
        temperature: config.temperature,
        stream: false,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: user_prompt,
            },
        ],
    };

    let client = llm_client(config)?;
    let response: Value = client
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to call LLM provider")?
        .error_for_status()
        .context("LLM provider returned an error status")?
        .json()
        .context("failed to parse LLM response")?;

    let content = response["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("LLM response did not contain choices[0].message.content"))?;

    Ok(content.trim().to_string())
}

fn llm_client(config: &LlmConfig) -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds.max(1)))
        .build()
        .context("failed to build LLM HTTP client")
}

fn is_retryable_llm_error(err: &anyhow::Error) -> bool {
    let message = err
        .chain()
        .map(|cause| cause.to_string().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" | ");
    message.contains("timed out")
        || message.contains("timeout")
        || message.contains("connection")
        || message.contains("server error")
        || message.contains("body")
}

fn call_chat_streaming<F>(
    config: &LlmConfig,
    system_prompt: &str,
    user_prompt: &str,
    on_delta: &mut F,
) -> Result<String>
where
    F: FnMut(&str) -> Result<()>,
{
    let api_key = env::var(&config.api_key_env)
        .with_context(|| format!("missing LLM API key env {}", config.api_key_env))?;
    let endpoint = chat_completions_endpoint(config)?;

    let body = ChatRequest {
        model: &config.model,
        temperature: config.temperature,
        stream: true,
        messages: vec![
            ChatMessage {
                role: "system",
                content: system_prompt,
            },
            ChatMessage {
                role: "user",
                content: user_prompt,
            },
        ],
    };

    let mut response = llm_client(config)?
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .context("failed to call LLM provider")?
        .error_for_status()
        .context("LLM provider returned an error status")?;

    let mut buffer = [0_u8; 8192];
    let mut pending = Vec::new();
    let mut content = String::new();

    loop {
        let read = response
            .read(&mut buffer)
            .context("failed to read LLM stream")?;
        if read == 0 {
            break;
        }

        pending.extend_from_slice(&buffer[..read]);
        while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=index).collect::<Vec<_>>();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim();
            if line.is_empty() || !line.starts_with("data:") {
                continue;
            }

            let data = line.trim_start_matches("data:").trim();
            if data == "[DONE]" {
                return Ok(content.trim().to_string());
            }

            let value: Value = serde_json::from_str(data).context("failed to parse LLM stream")?;
            if let Some(delta) = value["choices"][0]["delta"]["content"].as_str() {
                content.push_str(delta);
                on_delta(delta)?;
            }
        }
    }

    Ok(content.trim().to_string())
}

fn build_conflict_prompt(request: &ConflictAnalysisRequest, config: &LlmConfig) -> String {
    render_template(
        config
            .prompts
            .conflict_user
            .as_deref()
            .unwrap_or(DEFAULT_CONFLICT_USER_PROMPT),
        &conflict_template_values(request),
        config.max_prompt_bytes,
    )
}

fn build_sync_summary_prompt(report: &SyncReport, config: &LlmConfig) -> String {
    render_template(
        config
            .prompts
            .sync_summary_user
            .as_deref()
            .unwrap_or(DEFAULT_SYNC_SUMMARY_USER_PROMPT),
        &sync_summary_template_values(report),
        config.max_prompt_bytes,
    )
}

fn conflict_template_values(request: &ConflictAnalysisRequest) -> Vec<(&'static str, String)> {
    let sync_context = render_sync_context(request.branch_note.as_deref(), &request.patch_context);
    let combined_diff =
        render_combined_diff_with_context(&sync_context, &request.snapshot.combined_diff);
    vec![
        ("branch", request.branch.clone()),
        ("base", request.base.clone()),
        (
            "branch_note",
            request
                .branch_note
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
        ("sync_context", sync_context),
        ("conflict_files", request.snapshot.files.join("\n")),
        ("git_status", request.snapshot.status.clone()),
        ("combined_diff", combined_diff),
    ]
}

fn auto_resolve_template_values(
    request: &AutoResolveConflictRequest,
) -> Vec<(&'static str, String)> {
    let sync_context = render_sync_context(request.branch_note.as_deref(), &request.patch_context);
    let combined_diff =
        render_combined_diff_with_context(&sync_context, &request.snapshot.combined_diff);
    vec![
        ("branch", request.branch.clone()),
        ("base", request.base.clone()),
        (
            "branch_note",
            request
                .branch_note
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
        ("sync_context", sync_context),
        ("conflict_files", request.snapshot.files.join("\n")),
        ("git_status", request.snapshot.status.clone()),
        ("combined_diff", combined_diff),
        (
            "file_contents",
            render_conflict_file_contents(&request.files),
        ),
    ]
}

fn render_sync_context(branch_note: Option<&str>, patch_context: &SyncPatchContext) -> String {
    let mut context = String::new();
    context.push_str("Branch maintenance note:\n");
    context.push_str(branch_note.unwrap_or("none"));
    context.push_str("\n\nConflict semantics:\n");
    context.push_str(
        "When mode is rebase, HEAD/ours usually means the new upstream-based state, \
and theirs usually means the local patch currently being replayed. Do not invert them.\n",
    );
    context.push_str(
        "Default branch policy: preserve new upstream behavior, then re-apply the \
explicit intent of the local patch when both can coexist. Do not treat behavior that \
only appears in the newer upstream base as something the older local patch intended to remove.\n",
    );
    context.push_str("\nSync mode: ");
    if patch_context.mode.is_empty() {
        context.push_str("unknown");
    } else {
        context.push_str(&patch_context.mode);
    }
    if !patch_context.current_patch.trim().is_empty() {
        context.push_str("\n\nCurrent patch being applied:\n");
        context.push_str(&patch_context.current_patch);
    }
    context
}

fn render_combined_diff_with_context(sync_context: &str, combined_diff: &str) -> String {
    format!("{sync_context}\n\nCombined diff:\n{combined_diff}")
}

fn render_conflict_file_contents(files: &[ConflictFileContent]) -> String {
    files
        .iter()
        .map(|file| {
            format!(
                "===== FILE: {} =====\n{}\n===== END FILE: {} =====",
                file.path, file.content, file.path
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_context_contains_rebase_direction_and_current_patch() {
        let context = render_sync_context(
            Some("个人维护分支"),
            &SyncPatchContext {
                mode: "rebase".to_string(),
                current_patch: "commit abc\n\ndiff --git a/a.py b/a.py".to_string(),
            },
        );

        assert!(context.contains("HEAD/ours usually means the new upstream-based state"));
        assert!(context.contains("Sync mode: rebase"));
        assert!(context.contains("diff --git a/a.py b/a.py"));
    }

    #[test]
    fn auto_resolve_prompt_allows_compatible_functional_conflicts() {
        assert!(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT.contains("功能性冲突不等于高风险"));
        assert!(DEFAULT_AUTO_RESOLVE_SYSTEM_PROMPT.contains("应判定为 low"));
    }
}

fn sync_summary_template_values(report: &SyncReport) -> Vec<(&'static str, String)> {
    vec![("report", report.render_email_text())]
}

fn render_template(template: &str, values: &[(&'static str, String)], max_bytes: usize) -> String {
    let mut prompt = template.to_string();
    for (key, value) in values {
        prompt = prompt.replace(&format!("{{{key}}}"), value);
    }
    if prompt.len() > max_bytes {
        truncate_to_char_boundary(&mut prompt, max_bytes);
        prompt.push_str("\n... prompt truncated by TermiteRS ...\n");
    }
    prompt
}

fn extract_json_object(text: &str) -> Result<&str> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return Ok(trimmed);
    }

    let start = trimmed
        .find('{')
        .ok_or_else(|| anyhow!("auto resolve response did not contain JSON object"))?;
    let end = trimmed
        .rfind('}')
        .ok_or_else(|| anyhow!("auto resolve response did not contain JSON object end"))?;
    if start >= end {
        bail!("auto resolve response contained invalid JSON object bounds");
    }
    Ok(&trimmed[start..=end])
}
