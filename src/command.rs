use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

pub fn run(program: &str, args: &[&str], cwd: impl AsRef<Path>) -> Result<CommandOutput> {
    let cwd = cwd.as_ref();
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {program} in {}", cwd.display()))?;

    Ok(CommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

pub fn run_shell(command: &str, cwd: impl AsRef<Path>) -> Result<CommandOutput> {
    let cwd = cwd.as_ref();
    #[cfg(windows)]
    let mut cmd = {
        let mut command_line = Command::new("powershell");
        command_line.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]);
        command_line
    };

    #[cfg(not(windows))]
    let mut cmd = {
        let mut command_line = Command::new("sh");
        command_line.args(["-lc", command]);
        command_line
    };

    let output = cmd
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run shell command in {}", cwd.display()))?;

    Ok(CommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}
