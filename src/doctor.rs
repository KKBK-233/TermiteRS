use std::path::Path;

use crate::command::{CommandOutput, run};
use crate::config::{Config, PushStrategy};
use crate::git::Git;
use crate::text::truncate_to_char_boundary;

pub struct Doctor {
    config: Config,
}

impl Doctor {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn run(&self) -> String {
        let mut report = DoctorReport::default();
        report.title();

        let cwd = if self.config.repo.path.exists() {
            self.config.repo.path.as_path()
        } else {
            Path::new(".")
        };

        self.check_git(&mut report, cwd);
        self.check_github_ssh(&mut report, cwd);
        self.check_repo(&mut report);
        self.check_remotes(&mut report);
        self.check_fetch(&mut report);
        self.check_branches(&mut report);
        self.check_push_permission(&mut report);
        report.finish()
    }

    fn check_git(&self, report: &mut DoctorReport, cwd: &Path) {
        match run("git", &["--version"], cwd) {
            Ok(output) if output.success() => {
                let version = output.stdout.trim();
                if git_version_is_old(version) {
                    report.warn(format!(
                        "Git 可用，但版本偏旧：{version}；建议使用 Git 2.20 或更新版本"
                    ));
                } else {
                    report.ok(format!("Git 可用：{version}"));
                }
            }
            Ok(output) => report.fail(format!("Git 不可用：{}", one_line_output(&output))),
            Err(err) => report.fail(format!("找不到 Git：{err:#}")),
        }
    }

    fn check_github_ssh(&self, report: &mut DoctorReport, cwd: &Path) {
        let output = run(
            "ssh",
            &[
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "git@github.com",
            ],
            cwd,
        );

        match output {
            Ok(output) => {
                let text = format!("{}{}", output.stdout, output.stderr);
                if text.contains("successfully authenticated") {
                    report.ok("GitHub SSH 授权可用");
                } else {
                    report.warn(format!(
                        "GitHub SSH 未确认可用：{}",
                        one_line_output(&output)
                    ));
                }
            }
            Err(err) => report.warn(format!("无法运行 ssh 授权检查：{err:#}")),
        }
    }

    fn check_repo(&self, report: &mut DoctorReport) {
        if !self.config.repo.path.exists() {
            report.fail(format!(
                "仓库路径不存在：{}",
                self.config.repo.path.display()
            ));
            return;
        }

        let git = Git::new(self.config.repo.path.clone());
        match git.ensure_repo() {
            Ok(()) => report.ok(format!("仓库路径有效：{}", self.config.repo.path.display())),
            Err(err) => report.fail(format!("仓库路径不是 Git 仓库：{err:#}")),
        }
    }

    fn check_remotes(&self, report: &mut DoctorReport) {
        let git = Git::new(self.config.repo.path.clone());
        check_remote(
            report,
            &git,
            &self.config.repo.upstream_remote,
            &self.config.repo.upstream,
            "上游 remote",
        );
        check_remote(
            report,
            &git,
            &self.config.repo.fork_remote,
            &self.config.repo.fork,
            "fork remote",
        );
    }

    fn check_fetch(&self, report: &mut DoctorReport) {
        let git = Git::new(self.config.repo.path.clone());
        match git.fetch_all(&self.config.repo) {
            Ok(()) => report.ok("fetch 上游和 fork 成功"),
            Err(err) => report.fail(format!("fetch 失败：{err:#}")),
        }
    }

    fn check_branches(&self, report: &mut DoctorReport) {
        let git = Git::new(self.config.repo.path.clone());
        let base = format!(
            "{}/{}",
            self.config.repo.upstream_remote, self.config.repo.base_branch
        );

        match git.ref_exists(&base) {
            Ok(true) => report.ok(format!("上游基线存在：{base}")),
            Ok(false) => report.fail(format!("上游基线不存在：{base}")),
            Err(err) => report.fail(format!("检查上游基线失败：{err:#}")),
        }

        for branch in &self.config.branches {
            match git.local_branch_exists(&branch.name) {
                Ok(true) => report.ok(format!("本地分支存在：{}", branch.name)),
                Ok(false) => report.fail(format!("本地分支不存在：{}", branch.name)),
                Err(err) => report.fail(format!("检查本地分支失败 {}：{err:#}", branch.name)),
            }

            match git.remote_branch_exists(&self.config.repo.fork_remote, &branch.name) {
                Ok(true) => report.ok(format!(
                    "fork 远端分支存在：{}/{}",
                    self.config.repo.fork_remote, branch.name
                )),
                Ok(false) => report.warn(format!(
                    "fork 远端分支不存在：{}/{}；首次 push 后会出现",
                    self.config.repo.fork_remote, branch.name
                )),
                Err(err) => report.warn(format!("检查 fork 分支失败 {}：{err:#}", branch.name)),
            }
        }
    }

    fn check_push_permission(&self, report: &mut DoctorReport) {
        let git = Git::new(self.config.repo.path.clone());
        for branch in &self.config.branches {
            if matches!(branch.push, PushStrategy::None) {
                continue;
            }
            match git.local_branch_exists(&branch.name) {
                Ok(true) => {}
                _ => continue,
            }

            match git.push_dry_run(&self.config.repo.fork_remote, &branch.name) {
                Ok(output) if output.success() => {
                    report.ok(format!("fork 推送权限可用：{}", branch.name));
                }
                Ok(output) => {
                    report.fail(format!(
                        "fork 推送权限检查失败 {}：{}",
                        branch.name,
                        one_line_output(&output)
                    ));
                }
                Err(err) => report.fail(format!("fork 推送权限检查失败 {}：{err:#}", branch.name)),
            }
        }
    }
}

#[derive(Default)]
struct DoctorReport {
    lines: Vec<String>,
    failed: usize,
    warned: usize,
}

impl DoctorReport {
    fn title(&mut self) {
        self.lines.push("TermiteRS doctor report".to_string());
        self.lines.push("=======================".to_string());
        self.lines.push(String::new());
    }

    fn ok(&mut self, message: impl Into<String>) {
        self.lines.push(format!("[OK] {}", message.into()));
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warned += 1;
        self.lines.push(format!("[WARN] {}", message.into()));
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.failed += 1;
        self.lines.push(format!("[FAIL] {}", message.into()));
    }

    fn finish(mut self) -> String {
        self.lines.push(String::new());
        if self.failed == 0 && self.warned == 0 {
            self.lines.push("结果：可以运行 sync。".to_string());
        } else if self.failed == 0 {
            self.lines.push(format!(
                "结果：可以尝试运行 sync，但有 {} 个警告。",
                self.warned
            ));
        } else {
            self.lines.push(format!(
                "结果：暂不建议运行 sync；需要先处理 {} 个失败项。",
                self.failed
            ));
        }
        self.lines.join("\n")
    }
}

fn check_remote(report: &mut DoctorReport, git: &Git, name: &str, expected: &str, label: &str) {
    match git.remote_url(name) {
        Ok(Some(current)) if current == expected => {
            report.ok(format!("{label} 正确：{name} -> {current}"));
        }
        Ok(Some(current)) => {
            report.warn(format!(
                "{label} 地址不一致：{name} 当前是 {current}，配置是 {expected}"
            ));
        }
        Ok(None) => {
            report.fail(format!("{label} 不存在：{name}"));
        }
        Err(err) => {
            report.fail(format!("检查 {label} 失败：{err:#}"));
        }
    }
}

fn one_line_output(output: &CommandOutput) -> String {
    let mut text = format!("{} {}", output.stdout.trim(), output.stderr.trim())
        .replace('\r', "")
        .replace('\n', " | ");
    if text.len() > 500 {
        truncate_to_char_boundary(&mut text, 500);
        text.push_str("...");
    }
    text.trim().to_string()
}

fn git_version_is_old(version: &str) -> bool {
    let Some(raw) = version.split_whitespace().nth(2) else {
        return false;
    };
    let mut parts = raw.split('.');
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), _) if major < 2 => true,
        (Some(2), Some(minor)) if minor < 20 => true,
        _ => false,
    }
}
