use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "TermiteRS")]
#[command(about = "Maintain long-lived fork branches against upstream updates.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start interactive assistant.
    Assistant {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,
    },

    /// Run the background sync daemon.
    Daemon {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// Run one daemon tick and exit.
        #[arg(long)]
        once: bool,
    },

    /// Sync configured branches against upstream.
    Sync {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// Only sync one branch from the config.
        #[arg(short, long)]
        branch: Option<String>,

        /// Run all checks without pushing changes.
        #[arg(long)]
        dry_run: bool,
    },

    /// Show branch status without changing anything.
    Status {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,
    },

    /// Check Git, SSH, remotes, branches and push permission.
    Doctor {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,
    },

    /// Print an example config.
    ExampleConfig,

    /// Send a test notification using the configured channels.
    NotifyTest {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// Test email subject.
        #[arg(long, default_value = "TermiteRS test notification")]
        subject: String,

        /// Test email body.
        #[arg(long, default_value = "TermiteRS notification channel is working.")]
        body: String,
    },

    /// 启动仅通过 Unix Socket 提供服务的协作控制端。
    Serve {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,
    },

    /// 从标准输入读取密码并生成 Argon2id 哈希。
    HashPassword,
}
