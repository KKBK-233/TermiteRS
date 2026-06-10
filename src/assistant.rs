use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result};

use crate::config::Config;
use crate::daemon::Daemon;
use crate::doctor::Doctor;
use crate::llm::LlmService;
use crate::sync::{SyncOptions, SyncRunner};

const MAX_HISTORY_MESSAGES: usize = 12;

pub struct Assistant {
    config_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ConversationMessage {
    role: &'static str,
    content: String,
}

impl Assistant {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    pub fn run(&self) -> Result<()> {
        ensure_owned_config_path(&self.config_path)?;

        println!("TermiteRS assistant");
        println!("===================");
        println!();
        println!("默认进入交互式配置助理。输入自然语言描述需求，或输入 /help 查看命令。");
        println!("配置文件：{}", self.config_path.display());
        println!();
        print_agent_summary(Path::new("agents/termite-config/system.md"))?;
        println!();

        let stdin = io::stdin();
        let mut history = Vec::new();
        loop {
            print!("termite> ");
            io::stdout().flush()?;

            let mut input = String::new();
            if stdin.read_line(&mut input)? == 0 {
                println!();
                return Ok(());
            }

            let input = input.trim();
            if input.is_empty() {
                continue;
            }

            match input {
                "/exit" | "/quit" => return Ok(()),
                "/help" => print_help(),
                "/clear" => {
                    history.clear();
                    println!("已清空当前助理会话上下文。");
                }
                "/check" => self.run_check()?,
                "/doctor" => self.run_doctor()?,
                "/status" => self.run_status()?,
                "/once" => self.run_daemon_once()?,
                "/daemon" => {
                    self.run_daemon()?;
                    return Ok(());
                }
                _ => {
                    if !self.try_handle_local_action(input, &history)? {
                        self.reply_to_user(input, &mut history)?;
                    }
                }
            }
        }
    }

    fn run_doctor(&self) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        println!("{}", Doctor::new(config).run());
        Ok(())
    }

    fn run_status(&self) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        let report = SyncRunner::new(config, SyncOptions::status_only()).status()?;
        println!("{}", report.render_text());
        Ok(())
    }

    fn run_dry_run(&self) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        let options = SyncOptions {
            branch: None,
            dry_run: true,
            notify_on_noop: true,
        };
        let report = SyncRunner::new(config, options).run()?;
        println!("{}", report.render_text());
        Ok(())
    }

    fn run_check(&self) -> Result<()> {
        println!("开始执行 doctor...");
        self.run_doctor()?;
        println!("开始执行 sync --dry-run...");
        self.run_dry_run()
    }

    fn run_daemon_once(&self) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        Daemon::new(config, true, true).run()
    }

    fn run_daemon(&self) -> Result<()> {
        println!("正在启动常驻核心进程。停止请按 Ctrl+C。");
        let config = Config::read_from(&self.config_path)?;
        Daemon::new(config, false, false).run()
    }

    fn reply_to_user(&self, input: &str, history: &mut Vec<ConversationMessage>) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        let system_prompt = read_agent_prompt(Path::new("agents/termite-config/system.md"))?;
        let user_prompt = build_user_prompt(input, &config, history);
        let llm = LlmService::new(config.llm.clone());

        println!("AI 正在回复...");
        io::stdout().flush()?;
        match llm.assistant_reply_streaming(&system_prompt, &user_prompt, |delta| {
            print!("{}", clean_stream_delta(delta));
            io::stdout().flush()?;
            Ok(())
        }) {
            Ok(Some(reply)) => {
                let reply = clean_terminal_reply(&reply);
                println!("\n");
                push_history(history, "user", input.to_string());
                push_history(history, "assistant", reply);
            }
            Ok(None) => {
                println!(
                    "LLM 未启用。请在配置里设置 llm.enabled: true，并确保 API key 环境变量存在。"
                );
            }
            Err(err) => {
                println!("AI 助理调用失败：{err:#}");
            }
        }
        Ok(())
    }

    fn try_handle_local_action(
        &self,
        input: &str,
        history: &[ConversationMessage],
    ) -> Result<bool> {
        if wants_validation(input) {
            self.run_check()?;
            return Ok(true);
        }

        if self.try_remove_branch(input)? {
            return Ok(true);
        }

        if self.try_add_branch(input, history)? {
            return Ok(true);
        }

        Ok(false)
    }

    fn try_remove_branch(&self, input: &str) -> Result<bool> {
        if !(input.contains("停止维护") || input.contains("不再维护")) {
            return Ok(false);
        }
        let config = Config::read_from(&self.config_path)?;
        let Some(branch) = config
            .branches
            .iter()
            .find(|branch| input.contains(&branch.name))
            .map(|branch| branch.name.clone())
        else {
            return Ok(false);
        };

        remove_branch_from_config(&self.config_path, &branch)?;
        println!("已从 TermiteRS 配置中移除分支：{branch}");
        println!("未删除本地 Git 分支，也未删除远端 fork 分支。");
        println!("建议继续执行：/doctor，然后执行 /once 做一次人工检查。");
        Ok(true)
    }

    fn try_add_branch(&self, input: &str, history: &[ConversationMessage]) -> Result<bool> {
        if !(input.contains("维护") || input.contains("新增") || input.contains("加入")) {
            return Ok(false);
        }
        if !(input.contains("直接改") || input.contains("直接修改") || input.contains("搞完"))
        {
            return Ok(false);
        }

        let Some(branch) = extract_branch_name(input).or_else(|| branch_from_history(history))
        else {
            return Ok(false);
        };
        let kind = if input.to_lowercase().contains("pr") {
            "pr"
        } else {
            "product"
        };
        let sync = if input.to_lowercase().contains("merge") {
            "merge"
        } else {
            "rebase"
        };
        let push = if input.contains("本地测试") || input.contains("不推") {
            "none"
        } else if input.contains("推送远端")
            || input.contains("远端历史")
            || input.contains("force-with-lease")
        {
            "force-with-lease"
        } else {
            return Ok(false);
        };
        let note = extract_note(input).unwrap_or_else(|| branch.clone());

        add_or_replace_branch_in_config(&self.config_path, &branch, kind, sync, push, &note)?;
        println!("已更新 TermiteRS 配置，开始维护分支：{branch}");
        println!("kind: {kind}");
        println!("sync: {sync}");
        println!("push: {push}");
        println!("note: {note}");
        println!("建议继续执行：/doctor，然后执行 /once 做一次人工检查。");
        Ok(true)
    }
}

fn print_help() {
    println!("可用命令：");
    println!("  /help    显示帮助");
    println!("  /check   执行 doctor 和 sync --dry-run");
    println!("  /doctor  检查 Git、SSH、远端和推送权限");
    println!("  /status  查看分支状态");
    println!("  /once    运行一次 daemon 同步并退出本次同步");
    println!("  /daemon  启动常驻核心进程");
    println!("  /clear   清空当前助理会话上下文");
    println!("  /exit    退出助理");
    println!();
    println!("自然语言示例：");
    println!("  我只想维护 my/ok-ww，自用分支，允许改远端历史，每小时检查一次。");
}

fn print_agent_summary(path: &Path) -> Result<()> {
    if !path.exists() {
        println!("未找到助理资料：{}", path.display());
        return Ok(());
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read agent prompt {}", path.display()))?;
    println!("助理规则摘要：");
    for line in raw
        .lines()
        .filter(|line| line.starts_with("- ") || line.starts_with("TermiteRS "))
        .take(12)
    {
        println!("{line}");
    }
    Ok(())
}

fn read_agent_prompt(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn build_user_prompt(input: &str, config: &Config, history: &[ConversationMessage]) -> String {
    format!(
        r#"用户需求：
{input}

最近会话上下文：
{}

当前配置摘要：
- repo.path: {}
- upstream_remote: {}
- fork_remote: {}
- base_branch: {}
- daemon.interval_seconds: {}
- daemon.max_consecutive_failures: {}
- branches:
{}

请根据助理规则给出配置建议。
如果用户只回复了“是”、“否”、“B”、“第 2 个”等短回答，必须结合最近会话上下文理解它指向的上一个问题或选项。
请输出纯文本，不要使用 Markdown 标题、加粗、反引号或代码块围栏。
不要直接声称已经修改文件；如果需要修改，请列出建议修改的 YAML 片段和需要用户确认的问题。
"#,
        history_summary(history),
        config.repo.path.display(),
        config.repo.upstream_remote,
        config.repo.fork_remote,
        config.repo.base_branch,
        config.daemon.interval_seconds,
        config.daemon.max_consecutive_failures,
        branch_summary(config)
    )
}

fn push_history(history: &mut Vec<ConversationMessage>, role: &'static str, content: String) {
    history.push(ConversationMessage { role, content });
    if history.len() > MAX_HISTORY_MESSAGES {
        history.remove(0);
    }
}

fn history_summary(history: &[ConversationMessage]) -> String {
    if history.is_empty() {
        return "  none".to_string();
    }

    history
        .iter()
        .map(|message| format!("  {}: {}", message.role, one_line(&message.content)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn one_line(text: &str) -> String {
    let mut line = text.replace('\r', "").replace('\n', " | ");
    if line.chars().count() > 800 {
        line = line.chars().take(800).collect();
        line.push_str("...");
    }
    line
}

fn clean_terminal_reply(reply: &str) -> String {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed == "---" || trimmed.starts_with("```") {
                return None;
            }
            let line = trimmed
                .trim_start_matches('#')
                .trim()
                .replace("**", "")
                .replace('`', "");
            Some(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn clean_stream_delta(delta: &str) -> String {
    delta.replace("**", "").replace('`', "")
}

fn remove_branch_from_config(config_path: &Path, branch_name: &str) -> Result<()> {
    ensure_owned_config_path(config_path)?;
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let lines = raw.lines().collect::<Vec<_>>();
    let target = format!("  - name: {branch_name}");
    let Some(start) = lines.iter().position(|line| line.trim_end() == target) else {
        return Ok(());
    };

    let mut end = lines.len();
    for (index, line) in lines.iter().enumerate().skip(start + 1) {
        if line.starts_with("  - name: ") || (is_top_level_key(line) && !line.trim().is_empty()) {
            end = index;
            break;
        }
    }

    let mut next = Vec::new();
    next.extend_from_slice(&lines[..start]);
    next.extend_from_slice(&lines[end..]);
    let mut output = next.join("\n");
    output.push('\n');
    fs::write(config_path, output)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

fn is_top_level_key(line: &str) -> bool {
    !line.starts_with(' ') && line.ends_with(':')
}

fn add_or_replace_branch_in_config(
    config_path: &Path,
    branch_name: &str,
    kind: &str,
    sync: &str,
    push: &str,
    note: &str,
) -> Result<()> {
    ensure_owned_config_path(config_path)?;
    remove_branch_from_config(config_path, branch_name)?;
    let raw = fs::read_to_string(config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let marker = "\n\ndaemon:";
    let branch_block = format!(
        r#"
  - name: {branch_name}
    kind: {kind}
    note: {note}
    sync: {sync}
    push: {push}
    tests: []
"#
    );

    let output = if let Some(index) = raw.find(marker) {
        let mut next = String::new();
        next.push_str(&raw[..index]);
        next.push_str(&branch_block);
        next.push_str(&raw[index..]);
        next
    } else {
        let mut next = raw;
        next.push_str(&branch_block);
        next
    };

    fs::write(config_path, output)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

fn ensure_owned_config_path(config_path: &Path) -> Result<()> {
    let cwd = env::current_dir().context("failed to get current directory")?;
    let config_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        cwd.join(config_path)
    };
    let parent = config_path
        .parent()
        .with_context(|| format!("invalid config path {}", config_path.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", parent.display()))?;
    let cwd = cwd
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", cwd.display()))?;

    if !parent.starts_with(&cwd) {
        anyhow::bail!(
            "refuse to edit config outside TermiteRS workdir: {}",
            config_path.display()
        );
    }
    Ok(())
}

fn wants_validation(input: &str) -> bool {
    input.contains("跑跑")
        || input.contains("跑一下")
        || input.contains("验证")
        || input.contains("检查")
        || input.contains("看看")
}

fn extract_branch_name(input: &str) -> Option<String> {
    input
        .split_whitespace()
        .find(|part| part.contains('/') || part.contains('-'))
        .map(|part| {
            part.trim_matches(|ch: char| {
                matches!(
                    ch,
                    '，' | ',' | '。' | '.' | '：' | ':' | '；' | ';' | '"' | '\'' | '“' | '”'
                )
            })
            .to_string()
        })
}

fn extract_note(input: &str) -> Option<String> {
    let marker = "备注";
    let index = input.find(marker)?;
    let note = input[index + marker.len()..]
        .trim_start_matches(|ch| ch == '：' || ch == ':' || ch == ' ')
        .trim();
    if note.is_empty() {
        None
    } else {
        Some(note.to_string())
    }
}

fn branch_from_history(history: &[ConversationMessage]) -> Option<String> {
    history
        .iter()
        .rev()
        .filter(|message| message.role == "user")
        .find_map(|message| extract_branch_name(&message.content))
}

fn branch_summary(config: &Config) -> String {
    if config.branches.is_empty() {
        return "  none".to_string();
    }

    config
        .branches
        .iter()
        .map(|branch| {
            format!(
                "  - name: {}, kind: {:?}, sync: {:?}, push: {:?}, note: {}",
                branch.name,
                branch.kind,
                branch.sync,
                branch.push,
                branch.note.as_deref().unwrap_or("none")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}
