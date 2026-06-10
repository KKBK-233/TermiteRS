use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::Config;
use crate::daemon::Daemon;
use crate::doctor::Doctor;
use crate::llm::LlmService;
use crate::sync::{SyncOptions, SyncRunner};

pub struct Assistant {
    config_path: PathBuf,
}

impl Assistant {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    pub fn run(&self) -> Result<()> {
        println!("TermiteRS assistant");
        println!("===================");
        println!();
        println!("默认进入交互式配置助理。输入自然语言描述需求，或输入 /help 查看命令。");
        println!("配置文件：{}", self.config_path.display());
        println!();
        print_agent_summary(Path::new("agents/termite-config/system.md"))?;
        println!();

        let stdin = io::stdin();
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
                "/doctor" => self.run_doctor()?,
                "/status" => self.run_status()?,
                "/once" => self.run_daemon_once()?,
                "/daemon" => {
                    self.run_daemon()?;
                    return Ok(());
                }
                _ => self.reply_to_user(input)?,
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

    fn run_daemon_once(&self) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        Daemon::new(config, true).run()
    }

    fn run_daemon(&self) -> Result<()> {
        println!("正在启动常驻核心进程。停止请按 Ctrl+C。");
        let config = Config::read_from(&self.config_path)?;
        Daemon::new(config, false).run()
    }

    fn reply_to_user(&self, input: &str) -> Result<()> {
        let config = Config::read_from(&self.config_path)?;
        let system_prompt = read_agent_prompt(Path::new("agents/termite-config/system.md"))?;
        let user_prompt = build_user_prompt(input, &config);
        let llm = LlmService::new(config.llm.clone());

        match llm.assistant_reply(&system_prompt, &user_prompt) {
            Ok(Some(reply)) => {
                println!();
                println!("{reply}");
                println!();
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
}

fn print_help() {
    println!("可用命令：");
    println!("  /help    显示帮助");
    println!("  /doctor  检查 Git、SSH、远端和推送权限");
    println!("  /status  查看分支状态");
    println!("  /once    运行一次 daemon 同步并退出本次同步");
    println!("  /daemon  启动常驻核心进程");
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

fn build_user_prompt(input: &str, config: &Config) -> String {
    format!(
        r#"用户需求：
{input}

当前配置摘要：
- repo.path: {}
- upstream_remote: {}
- fork_remote: {}
- base_branch: {}
- daemon.interval_seconds: {}
- daemon.max_consecutive_failures: {}
- branches:
{}

请根据助理规则给出配置建议。不要直接声称已经修改文件；如果需要修改，请列出建议修改的 YAML 片段和需要用户确认的问题。
"#,
        config.repo.path.display(),
        config.repo.upstream_remote,
        config.repo.fork_remote,
        config.repo.base_branch,
        config.daemon.interval_seconds,
        config.daemon.max_consecutive_failures,
        branch_summary(config)
    )
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
