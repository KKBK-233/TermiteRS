use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::config::Config;

use super::types::ServiceEvent;

#[derive(Clone)]
pub(crate) struct ServiceState {
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
    pub(crate) database_path: PathBuf,
    pub(crate) events: broadcast::Sender<ServiceEvent>,
    pub(crate) repository_lock: Arc<Mutex<()>>,
}

impl ServiceState {
    pub(crate) fn config(&self) -> Result<Config> {
        Config::read_from(&self.config_path)
    }

    pub(crate) fn open_database(&self) -> Result<Connection> {
        Connection::open(&self.database_path)
            .with_context(|| format!("failed to open {}", self.database_path.display()))
    }
}
