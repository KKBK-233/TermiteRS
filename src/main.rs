use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use clap::Parser;
use rand_core::OsRng;
use std::io::Read;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use TermiteRS::assistant::Assistant;
use TermiteRS::cli::{Cli, Commands};
use TermiteRS::config::Config;
use TermiteRS::daemon::Daemon;
use TermiteRS::doctor::Doctor;
use TermiteRS::notify::Notifier;
use TermiteRS::service;
use TermiteRS::sync::{SyncOptions, SyncRunner};

fn main() -> Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Assistant {
        config: PathBuf::from("termite.yml"),
    }) {
        Commands::Assistant { config } => {
            Assistant::new(config).run()?;
        }
        Commands::Daemon { config, once } => {
            let config = Config::read_from(config)?;
            Daemon::new(config, once, once).run()?;
        }
        Commands::Sync {
            config,
            branch,
            dry_run,
        } => {
            let config = Config::read_from(config)?;
            let options = SyncOptions {
                branch,
                dry_run,
                notify_on_noop: true,
            };
            let report = SyncRunner::new(config, options).run()?;
            println!("{}", report.render_text());
        }
        Commands::Cleanup { config, days } => {
            let report = service::cleanup_old_jobs(config, days)?;
            println!(
                "cleaned cutoff={}, jobs={}, messages={}, events={}, challenges={}, notifications={}, worktrees={}",
                report.cutoff,
                report.jobs,
                report.messages,
                report.events,
                report.challenges,
                report.notifications,
                report.worktrees
            );
        }
        Commands::Status { config } => {
            let config = Config::read_from(config)?;
            let report = SyncRunner::new(config, SyncOptions::status_only()).status()?;
            println!("{}", report.render_text());
        }
        Commands::Doctor { config } => {
            let config = Config::read_from(config)?;
            println!("{}", Doctor::new(config).run());
        }
        Commands::ExampleConfig => {
            println!("{}", Config::example());
        }
        Commands::NotifyTest {
            config,
            subject,
            body,
        } => {
            let config = Config::read_from(config)?;
            let sent = Notifier::new(config.notify).send(&subject, &body)?;
            if sent {
                println!("test notification sent");
            } else {
                println!("no enabled notification channel");
            }
        }
        Commands::Serve { config } => {
            service::run(config)?;
        }
        Commands::HashPassword => {
            let mut password = String::new();
            std::io::stdin().read_to_string(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            anyhow::ensure!(!password.is_empty(), "标准输入中的密码不能为空");
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|err| anyhow::anyhow!("生成密码哈希失败：{err}"))?;
            println!("{hash}");
        }
    }

    Ok(())
}
