use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// 普通本机工具的统一上限；拉取、测试或脚本两小时仍未结束时视为异常。
pub const DEFAULT_TOOL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

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
    run_with_timeout(program, args, cwd, DEFAULT_TOOL_TIMEOUT)
}

fn run_with_timeout(
    program: &str,
    args: &[&str],
    cwd: impl AsRef<Path>,
    timeout: Duration,
) -> Result<CommandOutput> {
    let mut command = Command::new(program);
    command.args(args);
    run_prepared(&mut command, program, cwd.as_ref(), timeout)
}

pub fn run_shell(command: &str, cwd: impl AsRef<Path>) -> Result<CommandOutput> {
    let cwd = cwd.as_ref();
    #[cfg(windows)]
    let mut command_line = {
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
    let mut command_line = {
        let mut command_line = Command::new("sh");
        command_line.args(["-lc", command]);
        command_line
    };

    run_prepared(&mut command_line, "shell", cwd, DEFAULT_TOOL_TIMEOUT)
}

/// 启动工具后并行读取输出、轮询截止时间，并在超时时终止整棵进程树。
fn run_prepared(
    command: &mut Command,
    label: &str,
    cwd: &Path,
    timeout: Duration,
) -> Result<CommandOutput> {
    configure_process_group(command);
    let mut child = command
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {label} in {}", cwd.display()))?;
    let stdout = child.stdout.take().context("无法捕获工具 stdout")?;
    let stderr = child.stderr.take().context("无法捕获工具 stderr")?;
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(PROCESS_POLL_INTERVAL),
            Ok(None) => {
                timed_out = true;
                terminate_process_tree(&mut child);
                break child.wait().context("等待超时工具退出失败")?;
            }
            Err(error) => {
                terminate_process_tree(&mut child);
                let _ = child.wait();
                return Err(error).context("等待工具退出失败");
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("读取工具 stdout 的线程异常退出"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("读取工具 stderr 的线程异常退出"))??;
    if timed_out {
        bail!("工具 {label} 运行超过 {} 秒，已终止", timeout.as_secs());
    }

    Ok(CommandOutput {
        status: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
    })
}

fn read_all(mut reader: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }

    // 子进程以自己的进程组启动，负 PID 可一次终止 shell 及其后代。
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe {
            let _ = kill(-pid, 9);
        }
    }
    let _ = child.kill();
}

#[cfg(windows)]
fn terminate_process_tree(child: &mut Child) {
    // taskkill /T 会连同 PowerShell 或 Git 派生的后代一起清理。
    let pid = child.id().to_string();
    let _ = Command::new("taskkill")
        .args(["/PID", &pid, "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_tool_is_stopped_at_deadline() {
        #[cfg(windows)]
        let (program, args) = (
            "powershell",
            vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 10"],
        );
        #[cfg(not(windows))]
        let (program, args) = ("sh", vec!["-c", "sleep 10"]);

        let started = Instant::now();
        let error = run_with_timeout(
            program,
            &args,
            std::env::current_dir().unwrap(),
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(error.to_string().contains("已终止"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
