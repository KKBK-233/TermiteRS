use std::path::Path;

#[cfg(unix)]
use std::{
    ffi::OsString,
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};

use crate::command::CommandOutput;

#[cfg(unix)]
const SANDBOX_TIMEOUT: Duration = Duration::from_secs(30 * 60);
#[cfg(unix)]
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// 在不继承宿主凭证、网络和根文件系统的 Bubblewrap 沙箱中执行项目命令。
#[cfg(unix)]
pub fn run_sandboxed(command: &str, worktree: impl AsRef<Path>) -> Result<CommandOutput> {
    let worktree = worktree.as_ref();
    anyhow::ensure!(
        worktree.is_dir(),
        "沙箱 worktree 不存在：{}",
        worktree.display()
    );
    ensure_bubblewrap_available()?;
    let args = bubblewrap_args(worktree, command);
    let mut child = Command::new("bwrap")
        .args(&args)
        .current_dir(worktree)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("启动 Bubblewrap 项目沙箱失败")?;
    let stdout = child.stdout.take().context("无法捕获沙箱 stdout")?;
    let stderr = child.stderr.take().context("无法捕获沙箱 stderr")?;
    let stdout_reader = thread::spawn(move || read_capped(stdout));
    let stderr_reader = thread::spawn(move || read_capped(stderr));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= SANDBOX_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("沙箱命令超过 {} 秒，已终止", SANDBOX_TIMEOUT.as_secs());
        }
        thread::sleep(Duration::from_millis(100));
    };
    let (stdout, stdout_exceeded) = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("读取沙箱 stdout 的线程异常退出"))??;
    let (stderr, stderr_exceeded) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("读取沙箱 stderr 的线程异常退出"))??;
    anyhow::ensure!(
        !stdout_exceeded && !stderr_exceeded,
        "沙箱命令输出超过 {} 字节，已拒绝继续",
        MAX_OUTPUT_BYTES
    );
    Ok(CommandOutput {
        status: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
    })
}

#[cfg(windows)]
pub fn run_sandboxed(_command: &str, worktree: impl AsRef<Path>) -> Result<CommandOutput> {
    bail!(
        "Windows 主机没有启用 TermiteRS 项目沙箱，已拒绝执行 {} 中的项目命令；请在 WSL/Linux Bubblewrap 环境运行",
        worktree.as_ref().display()
    )
}

/// 运行不读取项目文件的固定自检，确认沙箱基础能力可用。
pub fn verify_sandbox(worktree: impl AsRef<Path>) -> Result<()> {
    let output = run_sandboxed(
        "test ! -e /etc/termiters/termiters.env && test -z \"${DEEPSEEK_API_KEY+x}\"",
        worktree,
    )?;
    anyhow::ensure!(
        output.success(),
        "项目沙箱自检失败：{}",
        output.stderr.trim()
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_bubblewrap_available() -> Result<()> {
    let status = Command::new("bwrap")
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("未安装 Bubblewrap，项目保护必须失败关闭")?;
    anyhow::ensure!(
        status.success(),
        "Bubblewrap 自检失败，项目保护必须失败关闭"
    );
    Ok(())
}

#[cfg(unix)]
fn bubblewrap_args(worktree: &Path, command: &str) -> Vec<OsString> {
    let mut args = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "TERM",
        "dumb",
        "--bind",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    args.push(worktree.as_os_str().to_os_string());
    args.push(OsString::from("/workspace"));
    args.extend(
        ["--chdir", "/workspace", "/usr/bin/sh", "-lc"]
            .into_iter()
            .map(OsString::from),
    );
    args.push(OsString::from(command));
    args
}

#[cfg(unix)]
fn read_capped(mut reader: impl Read) -> Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut limited = reader.by_ref().take((MAX_OUTPUT_BYTES + 1) as u64);
    limited.read_to_end(&mut output)?;
    let exceeded = output.len() > MAX_OUTPUT_BYTES;
    if exceeded {
        output.truncate(MAX_OUTPUT_BYTES);
    }
    Ok((output, exceeded))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn bubblewrap_never_binds_host_root_or_credentials() {
        let args = bubblewrap_args(Path::new("/tmp/worktree"), "python3 -m pytest");
        let text = args
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("--unshare-all"));
        assert!(text.contains("--clearenv"));
        assert!(text.contains("--cap-drop ALL"));
        assert!(text.contains("--bind /tmp/worktree /workspace"));
        assert!(!text.contains("/.ssh"));
        assert!(!text.contains("/etc/termiters"));
        assert!(!text.contains("--bind / /"));
    }

    #[test]
    #[ignore = "需要 Linux Bubblewrap，用于发布前真实沙箱回放"]
    fn live_sandbox_blocks_network_credentials_and_host_paths() {
        let root = std::env::temp_dir().join(format!("termiters-sandbox-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let command = r#"
set -eu
printf sandboxed > sandbox-write.txt
test ! -e /root/.ssh
test ! -e /etc/termiters/termiters.env
test -z "${DEEPSEEK_API_KEY+x}"
! python3 -c "import socket; socket.create_connection(('1.1.1.1', 53), 1)"
"#;
        let output = run_sandboxed(command, &root).unwrap();
        assert!(output.success(), "{}", output.stderr);
        assert_eq!(
            std::fs::read_to_string(root.join("sandbox-write.txt")).unwrap(),
            "sandboxed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
