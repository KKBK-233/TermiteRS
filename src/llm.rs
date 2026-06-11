use std::env;
use std::io::Read;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;

use crate::config::{LlmConfig, LlmProvider};
use crate::git::ConflictSnapshot;
use crate::report::SyncReport;

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
    pub snapshot: ConflictSnapshot,
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

    let client = Client::new();
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

    let mut response = Client::new()
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
    vec![
        ("branch", request.branch.clone()),
        ("base", request.base.clone()),
        ("conflict_files", request.snapshot.files.join("\n")),
        ("git_status", request.snapshot.status.clone()),
        ("combined_diff", request.snapshot.combined_diff.clone()),
    ]
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
        prompt.truncate(max_bytes);
        prompt.push_str("\n... prompt truncated by TermiteRS ...\n");
    }
    prompt
}
