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

    /// Clean old completed, abandoned and failed service jobs.
    Cleanup {
        /// Path to YAML config.
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// Delete terminal jobs updated more than this many days ago.
        #[arg(long, default_value_t = 30)]
        days: u32,
    },

    /// 在执行任何项目代码之前审计受保护项目。
    Protect {
        #[command(subcommand)]
        action: ProtectionCommands,
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
}

#[derive(Debug, Subcommand)]
pub enum ProtectionCommands {
    /// 只读扫描 Cargo 锁文件、清单和构建脚本。
    Scan {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// 扫描目录；未填写时使用 repo.path。
        #[arg(long)]
        path: Option<PathBuf>,

        /// 仅准备该仓库的 Issue 草稿，不会发送。
        #[arg(long)]
        issue_repository: Option<String>,
    },

    /// 使用 DS 对指定 Git 范围逐提交进行结构化安全审计。
    Review {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// Git 仓库目录；未填写时使用 repo.path。
        #[arg(long)]
        path: Option<PathBuf>,

        /// 审计范围起点，不包含该提交。
        #[arg(long)]
        from: String,

        /// 审计范围终点。
        #[arg(long, default_value = "HEAD")]
        to: String,

        /// 临时覆盖 Finding 数据目录，适合本地验收生产配置。
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// 临时补充项目安全意图，不修改配置文件。
        #[arg(long)]
        project_description: Option<String>,
    },

    /// 调查人工提供的安全消息，并按策略在隔离 worktree 中准备候选补丁。
    Investigate {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// 公告或社交媒体消息的简短标题。
        #[arg(long)]
        summary: String,

        /// 仅作为证据保存的引用地址；TermiteRS 不会主动访问。
        #[arg(long)]
        reference: Option<String>,

        /// 已由操作者保存的消息正文，避免任意 URL 抓取带来的 SSRF。
        #[arg(long)]
        content_file: PathBuf,

        /// 选择该配置分支的沙箱测试命令；默认使用首个分支。
        #[arg(long)]
        branch: Option<String>,

        /// 临时覆盖保护数据库与候选 worktree 目录。
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// 显式批准并发布已保存的 GitHub Issue 草稿。
    IssuePublish {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// protection 数据库中的草稿 ID。
        #[arg(long)]
        draft_id: String,

        /// GitHub fine-grained token 的环境变量名。
        #[arg(long, default_value = "GITHUB_TOKEN")]
        token_env: String,

        /// 必须显式提供；缺失时不会进行网络写操作。
        #[arg(long)]
        approve: bool,
    },

    /// 从固定 OSV 官方 API 查询 Cargo.lock 可达版本的已知公告。
    Advisories {
        /// YAML 配置文件路径。
        #[arg(short, long, default_value = "termite.yml")]
        config: PathBuf,

        /// 临时覆盖受保护仓库目录。
        #[arg(long)]
        path: Option<PathBuf>,

        /// 临时覆盖公告去重数据库目录。
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}
