use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::command::{CommandOutput, run};
use crate::config::RepoConfig;
use crate::text::truncate_to_char_boundary;

#[derive(Debug, Clone)]
pub struct Git {
    root: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictSnapshot {
    pub status: String,
    pub files: Vec<String>,
    pub combined_diff: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictFileContent {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy)]
pub struct AheadBehind {
    pub ahead: u32,
    pub behind: u32,
}

impl Git {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn ensure_repo(&self) -> Result<()> {
        let output = self.git(&["rev-parse", "--show-toplevel"])?;
        if !output.success() {
            bail!("not a git repository: {}", self.root.display());
        }
        Ok(())
    }

    pub fn ensure_remotes(&self, repo: &RepoConfig) -> Result<()> {
        self.ensure_remote(&repo.upstream_remote, &repo.upstream)?;
        self.ensure_remote(&repo.fork_remote, &repo.fork)?;
        Ok(())
    }

    pub fn fetch_all(&self, repo: &RepoConfig) -> Result<()> {
        self.git_checked(&["fetch", "--prune", &repo.upstream_remote])?;
        self.git_checked(&["fetch", "--prune", &repo.fork_remote])?;
        Ok(())
    }

    pub fn checkout(&self, branch: &str) -> Result<()> {
        self.git_checked(&["checkout", branch])
            .with_context(|| format!("failed to checkout {branch}"))?;
        Ok(())
    }

    pub fn rebase(&self, target: &str) -> Result<CommandOutput> {
        self.git(&["rebase", target])
    }

    pub fn merge(&self, target: &str) -> Result<CommandOutput> {
        self.git(&["merge", "--no-edit", target])
    }

    pub fn abort_rebase_or_merge(&self) {
        let _ = self.git(&["rebase", "--abort"]);
        let _ = self.git(&["merge", "--abort"]);
    }

    pub fn continue_sync(&self, strategy: crate::config::SyncStrategy) -> Result<CommandOutput> {
        match strategy {
            crate::config::SyncStrategy::Rebase => {
                self.git(&["-c", "core.editor=true", "rebase", "--continue"])
            }
            crate::config::SyncStrategy::Merge => self.git(&["commit", "--no-edit"]),
        }
    }

    pub fn push(
        &self,
        remote: &str,
        branch: &str,
        force_with_lease: bool,
    ) -> Result<CommandOutput> {
        if force_with_lease {
            self.git(&["push", "--force-with-lease", remote, branch])
        } else {
            self.git(&["push", remote, branch])
        }
    }

    pub fn push_with_lease(
        &self,
        remote: &str,
        branch: &str,
        expected_remote_head: &str,
    ) -> Result<CommandOutput> {
        let lease = format!("--force-with-lease=refs/heads/{branch}:{expected_remote_head}");
        let refspec = format!("HEAD:refs/heads/{branch}");
        self.git(&["push", &lease, remote, &refspec])
    }

    pub fn remote_head(&self, remote: &str, branch: &str) -> Result<Option<String>> {
        let reference = format!("refs/heads/{branch}");
        let output = self.git(&["ls-remote", "--heads", remote, &reference])?;
        if !output.success() {
            bail!("failed to read remote head for {remote}/{branch}");
        }
        Ok(output
            .stdout
            .split_whitespace()
            .next()
            .map(ToOwned::to_owned))
    }

    pub fn run_git(&self, args: &[&str]) -> Result<CommandOutput> {
        self.git(args)
    }

    pub fn push_dry_run(&self, remote: &str, branch: &str) -> Result<CommandOutput> {
        let refspec = format!("{branch}:{branch}");
        self.git(&["push", "--dry-run", remote, &refspec])
    }

    pub fn run_test(&self, command: &str) -> Result<CommandOutput> {
        crate::command::run_shell(command, &self.root)
    }

    pub fn add_file(&self, path: &str) -> Result<()> {
        self.git_checked(&["add", path])?;
        Ok(())
    }

    pub fn write_file(&self, path: &str, content: &str) -> Result<()> {
        ensure_relative_repo_path(path)?;
        let full_path = self.root.join(path);
        fs::write(&full_path, content)
            .with_context(|| format!("failed to write {}", full_path.display()))?;
        Ok(())
    }

    pub fn head(&self) -> Result<String> {
        Ok(self
            .git_checked(&["rev-parse", "--short", "HEAD"])?
            .stdout
            .trim()
            .to_string())
    }

    pub fn short_ref(&self, reference: &str) -> Result<String> {
        Ok(self
            .git_checked(&["rev-parse", "--short", reference])?
            .stdout
            .trim()
            .to_string())
    }

    pub fn local_branch_exists(&self, branch: &str) -> Result<bool> {
        let reference = format!("refs/heads/{branch}");
        Ok(self
            .git(&["rev-parse", "--verify", "--quiet", &reference])?
            .success())
    }

    pub fn remote_branch_exists(&self, remote: &str, branch: &str) -> Result<bool> {
        let reference = format!("refs/remotes/{remote}/{branch}");
        Ok(self
            .git(&["rev-parse", "--verify", "--quiet", &reference])?
            .success())
    }

    pub fn ref_exists(&self, reference: &str) -> Result<bool> {
        Ok(self
            .git(&["rev-parse", "--verify", "--quiet", reference])?
            .success())
    }

    pub fn ahead_behind(&self, left: &str, right: &str) -> Result<AheadBehind> {
        let range = format!("{left}...{right}");
        let output = self.git_checked(&["rev-list", "--left-right", "--count", &range])?;
        let mut parts = output.stdout.split_whitespace();
        let ahead = parts
            .next()
            .context("missing ahead count")?
            .parse()
            .context("failed to parse ahead count")?;
        let behind = parts
            .next()
            .context("missing behind count")?
            .parse()
            .context("failed to parse behind count")?;
        Ok(AheadBehind { ahead, behind })
    }

    pub fn merge_base(&self, left: &str, right: &str) -> Result<Option<String>> {
        let output = self.git(&["merge-base", left, right])?;
        if output.success() {
            Ok(Some(output.stdout.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    pub fn log_oneline(&self, range: &str, limit: usize) -> Result<Vec<String>> {
        let limit = format!("-n{limit}");
        Ok(self
            .git_checked(&["log", "--oneline", "--no-decorate", &limit, range])?
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    pub fn changed_files(&self, range: &str, limit: usize) -> Result<Vec<String>> {
        let mut files = self
            .git_checked(&["diff", "--name-status", range])?
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if files.len() > limit {
            files.truncate(limit);
            files.push("... file list truncated by TermiteRS ...".to_string());
        }
        Ok(files)
    }

    pub fn remote_url(&self, name: &str) -> Result<Option<String>> {
        let output = self.git(&["remote", "get-url", name])?;
        if output.success() {
            Ok(Some(output.stdout.trim().to_string()))
        } else {
            Ok(None)
        }
    }

    pub fn conflict_snapshot(&self, max_diff_bytes: usize) -> Result<ConflictSnapshot> {
        let status = self.git(&["status", "--porcelain=v1"])?.stdout;
        let files = self
            .git(&["diff", "--name-only", "--diff-filter=U"])?
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        let mut combined_diff = self.git(&["diff", "--cc"])?.stdout;
        if combined_diff.len() > max_diff_bytes {
            truncate_to_char_boundary(&mut combined_diff, max_diff_bytes);
            combined_diff.push_str("\n... diff truncated ...\n");
        }
        Ok(ConflictSnapshot {
            status,
            files,
            combined_diff,
        })
    }

    pub fn conflict_file_contents(
        &self,
        files: &[String],
        max_file_bytes: usize,
    ) -> Result<Vec<ConflictFileContent>> {
        files
            .iter()
            .map(|path| {
                ensure_relative_repo_path(path)?;
                let full_path = self.root.join(path);
                let mut content = fs::read_to_string(&full_path)
                    .with_context(|| format!("failed to read {}", full_path.display()))?;
                if content.len() > max_file_bytes {
                    truncate_to_char_boundary(&mut content, max_file_bytes);
                    content.push_str("\n... file truncated by TermiteRS ...\n");
                }
                Ok(ConflictFileContent {
                    path: path.clone(),
                    content,
                })
            })
            .collect()
    }

    fn ensure_remote(&self, name: &str, url: &str) -> Result<()> {
        let output = self.git(&["remote", "get-url", name])?;
        if output.success() {
            let current = output.stdout.trim();
            if current != url {
                self.git_checked(&["remote", "set-url", name, url])?;
            }
        } else {
            self.git_checked(&["remote", "add", name, url])?;
        }
        Ok(())
    }

    fn git(&self, args: &[&str]) -> Result<CommandOutput> {
        run("git", args, &self.root)
    }

    fn git_checked(&self, args: &[&str]) -> Result<CommandOutput> {
        let output = self.git(args)?;
        if !output.success() {
            bail!(
                "git {:?} failed with code {}\nstdout:\n{}\nstderr:\n{}",
                args,
                output.status,
                output.stdout,
                output.stderr
            );
        }
        Ok(output)
    }
}

fn ensure_relative_repo_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("unsafe repository path: {}", path.display());
    }
    Ok(())
}
