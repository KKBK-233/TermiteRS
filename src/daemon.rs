use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::sync::{SyncOptions, SyncRunner};

pub struct Daemon {
    config: Config,
    once: bool,
}

impl Daemon {
    pub fn new(config: Config, once: bool) -> Self {
        Self { config, once }
    }

    pub fn run(&self) -> Result<()> {
        let mut failures = 0;

        if self.config.daemon.run_on_start {
            failures = self.run_tick(failures)?;
            if self.once || self.should_stop(failures) {
                return Ok(());
            }
        }

        loop {
            let sleep_seconds =
                self.config.daemon.interval_seconds + jitter(self.config.daemon.jitter_seconds);
            info!("daemon sleeping for {} seconds", sleep_seconds);
            thread::sleep(Duration::from_secs(sleep_seconds));

            failures = self.run_tick(failures)?;
            if self.once || self.should_stop(failures) {
                return Ok(());
            }
        }
    }

    fn run_tick(&self, failures: u32) -> Result<u32> {
        info!("daemon sync tick started");
        let options = SyncOptions {
            branch: None,
            dry_run: false,
        };
        match SyncRunner::new(self.config.clone(), options).run() {
            Ok(report) => {
                println!("{}", report.render_text());
                info!("daemon sync tick completed");
                Ok(0)
            }
            Err(err) => {
                let next_failures = failures + 1;
                error!("daemon sync tick failed ({next_failures}): {err:#}");
                Ok(next_failures)
            }
        }
    }

    fn should_stop(&self, failures: u32) -> bool {
        if failures < self.config.daemon.max_consecutive_failures {
            return false;
        }

        warn!(
            "daemon stopped after {} consecutive failure(s)",
            self.config.daemon.max_consecutive_failures
        );
        true
    }
}

fn jitter(max_seconds: u64) -> u64 {
    if max_seconds == 0 {
        return 0;
    }

    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    duration.as_secs() % (max_seconds + 1)
}
