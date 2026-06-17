mod assistant;
mod cli;
mod command;
mod config;
mod daemon;
mod doctor;
mod git;
mod llm;
mod notify;
mod report;
mod sync;
mod text;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use crate::assistant::Assistant;
use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::daemon::Daemon;
use crate::doctor::Doctor;
use crate::notify::Notifier;
use crate::sync::{SyncOptions, SyncRunner};

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
    }

    Ok(())
}
