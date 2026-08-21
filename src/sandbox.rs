use std::path::Path;

#[cfg(unix)]
use std::{
    env,
    ffi::OsString,
    fs,
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
    let args = bubblewrap_args(worktree, command)?;
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
fn bubblewrap_args(worktree: &Path, command: &str) -> Result<Vec<OsString>> {
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
        "--dir",
        "/sandbox-bin",
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
        "/sandbox-bin:/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "TERM",
        "dumb",
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    append_rust_toolchain_mounts(&mut args)?;
    args.push(OsString::from("--bind"));
    args.push(worktree.as_os_str().to_os_string());
    args.push(OsString::from("/workspace"));
    args.extend(
        ["--chdir", "/workspace", "/usr/bin/sh", "-lc"]
            .into_iter()
            .map(OsString::from),
    );
    args.push(OsString::from(command));
    Ok(args)
}

/// Rustup 工具链和 registry 代码只读进入沙箱；Cargo 凭证与全局 config 永不挂载。
#[cfg(unix)]
fn append_rust_toolchain_mounts(args: &mut Vec<OsString>) -> Result<()> {
    let Some(rustup_proxy) = find_executable("rustup") else {
        return Ok(());
    };
    let rustup_proxy = rustup_proxy.canonicalize()?;
    anyhow::ensure!(rustup_proxy.is_file(), "rustup 代理不是普通文件");
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".rustup")));
    let Some(rustup_home) = rustup_home.filter(|path| path.is_dir()) else {
        return Ok(());
    };
    let rustup_home = rustup_home.canonicalize()?;
    let metadata = fs::symlink_metadata(&rustup_home)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "RUSTUP_HOME 不能是符号链接"
    );
    push_args(args, &["--ro-bind"]);
    args.push(rustup_proxy.into_os_string());
    args.push(OsString::from("/sandbox-bin/rustup"));
    for tool in ["cargo", "rustc", "rustdoc", "rustfmt", "clippy-driver"] {
        push_args(args, &["--symlink", "rustup"]);
        args.push(OsString::from(format!("/sandbox-bin/{tool}")));
    }
    if Path::new("/usr/bin/gcc").is_file() {
        push_args(args, &["--symlink", "/usr/bin/gcc", "/sandbox-bin/cc"]);
    }
    push_args(args, &["--ro-bind"]);
    args.push(rustup_home.into_os_string());
    args.push(OsString::from("/sandbox-rustup"));
    push_args(
        args,
        &[
            "--setenv",
            "RUSTUP_HOME",
            "/sandbox-rustup",
            "--setenv",
            "CARGO_HOME",
            "/tmp/cargo-home",
            "--setenv",
            "CARGO_NET_OFFLINE",
            "true",
            "--setenv",
            "CC",
            "gcc",
            "--setenv",
            "CXX",
            "g++",
            "--dir",
            "/tmp/cargo-home",
        ],
    );

    let cargo_home = env::var_os("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo")));
    if let Some(registry) = cargo_home
        .map(|home| home.join("registry"))
        .filter(|path| path.is_dir())
    {
        let registry = registry.canonicalize()?;
        let metadata = fs::symlink_metadata(&registry)?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Cargo registry 缓存不能是符号链接"
        );
        push_args(args, &["--ro-bind"]);
        args.push(registry.into_os_string());
        args.push(OsString::from("/tmp/cargo-home/registry"));
    }
    Ok(())
}

#[cfg(unix)]
fn find_executable(name: &str) -> Option<std::path::PathBuf> {
    let from_path = env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    });
    from_path.or_else(|| {
        env::var_os("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
            })
            .map(|home| home.join("bin").join(name))
            .filter(|candidate| candidate.is_file())
    })
}

#[cfg(unix)]
fn push_args(args: &mut Vec<OsString>, values: &[&str]) {
    args.extend(values.iter().map(OsString::from));
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
        let args = bubblewrap_args(Path::new("/tmp/worktree"), "python3 -m pytest").unwrap();
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

    #[test]
    #[ignore = "需要 Linux Bubblewrap 和 Rustup，用于发布前离线 Rust 工具链回放"]
    fn live_sandbox_runs_cargo_without_host_credentials() {
        let root = std::env::temp_dir().join(format!("termiters-cargo-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"sandbox-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn answer() -> u8 { 42 }\n#[test]\nfn works() { assert_eq!(answer(), 42); }\n",
        )
        .unwrap();
        let output = run_sandboxed(
            "cargo test --offline && test ! -e /tmp/cargo-home/credentials.toml",
            &root,
        )
        .unwrap();
        assert!(output.success(), "{}", output.stderr);
        std::fs::remove_dir_all(root).unwrap();
    }
}
