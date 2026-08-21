use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use TermiteRS::assistant::Assistant;
use TermiteRS::cli::{Cli, Commands, ProtectionCommands};
use TermiteRS::config::Config;
use TermiteRS::daemon::Daemon;
use TermiteRS::doctor::Doctor;
use TermiteRS::git::Git;
use TermiteRS::notify::Notifier;
use TermiteRS::protection::{
    SecurityDisposition, investigate_security_signal, publish_github_issue,
    run_commit_security_reviews, run_protection_scan,
};
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
        Commands::Protect { action } => match action {
            ProtectionCommands::Scan {
                config,
                path,
                issue_repository,
            } => {
                let config = Config::read_from(config)?;
                let scan_path = path.unwrap_or_else(|| config.repo.path.clone());
                let output = run_protection_scan(&config, scan_path, issue_repository.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.report.build_allowed {
                    std::process::exit(2);
                }
            }
            ProtectionCommands::Review {
                config,
                path,
                from,
                to,
                data_dir,
                project_description,
            } => {
                let mut config = Config::read_from(config)?;
                config.protection.enabled = true;
                if let Some(path) = path {
                    config.repo.path = path;
                }
                if let Some(data_dir) = data_dir {
                    config.service.data_dir = data_dir;
                }
                if let Some(description) = project_description {
                    config.protection.project.description = description;
                }
                let git = Git::new(config.repo.path.clone());
                let output = run_commit_security_reviews(&config, &git, &from, &to)?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if output
                    .as_ref()
                    .is_some_and(|batch| batch.disposition != SecurityDisposition::Allow)
                {
                    std::process::exit(2);
                }
            }
            ProtectionCommands::Investigate {
                config,
                summary,
                reference,
                content_file,
                branch,
                data_dir,
            } => {
                let mut config = Config::read_from(config)?;
                if let Some(data_dir) = data_dir {
                    config.service.data_dir = data_dir;
                }
                let content = std::fs::read_to_string(&content_file)
                    .with_context(|| format!("无法读取安全消息正文：{}", content_file.display()))?;
                let output = investigate_security_signal(
                    &config,
                    &summary,
                    reference.as_deref(),
                    &content,
                    branch.as_deref(),
                )?;
                println!("{}", serde_json::to_string_pretty(&output)?);
                if !output.finding.build_allowed {
                    std::process::exit(2);
                }
            }
            ProtectionCommands::IssuePublish {
                config,
                draft_id,
                token_env,
                approve,
            } => {
                let config = Config::read_from(config)?;
                let receipt =
                    publish_github_issue(&config.service.data_dir, &draft_id, &token_env, approve)?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            }
        },
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
    }

    Ok(())
}
