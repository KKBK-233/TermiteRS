use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::{config::ReleaseConfig, git::Git};

const MAX_TAG_PUSH_ATTEMPTS: usize = 3;

/// 确保当前提交拥有指定前缀的远端发布标签。
pub fn ensure_release_tag(
    git: &Git,
    remote: &str,
    config: &ReleaseConfig,
) -> Result<Option<String>> {
    if !config.enabled {
        return Ok(None);
    }

    let prefix = config.tag_prefix.trim();
    validate_tag_prefix(git, prefix)?;
    let head = git
        .run_git(&["rev-parse", "HEAD"])?
        .stdout
        .trim()
        .to_string();

    for _ in 0..MAX_TAG_PUSH_ATTEMPTS {
        let tags = remote_release_tags(git, remote, prefix)?;
        if tags.values().any(|commit| commit == &head) {
            return Ok(None);
        }

        let tag = next_release_tag(prefix, tags.keys().map(String::as_str));
        let refspec = format!("HEAD:refs/tags/{tag}");
        let output = git.run_git(&["push", remote, &refspec])?;
        if output.success() {
            return Ok(Some(tag));
        }

        let refreshed = remote_release_tags(git, remote, prefix)?;
        if !refreshed.contains_key(&tag) {
            bail!("发布标签 {tag} 失败：{}", output.stderr.trim());
        }
    }

    bail!("发布标签失败：远端标签在重试期间持续变化")
}

pub fn validate_tag_prefix(git: &Git, prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        bail!("release.tag_prefix 不能为空");
    }
    let reference = format!("refs/tags/{prefix}0");
    let output = git.run_git(&["check-ref-format", &reference])?;
    if !output.success() {
        bail!("release.tag_prefix 不是有效的 Git 标签前缀：{prefix}");
    }
    Ok(())
}

fn remote_release_tags(git: &Git, remote: &str, prefix: &str) -> Result<BTreeMap<String, String>> {
    let pattern = format!("refs/tags/{prefix}*");
    let output = git.run_git(&["ls-remote", "--tags", remote, &pattern])?;
    if !output.success() {
        bail!("读取远端发布标签失败：{}", output.stderr.trim());
    }

    let mut tags = BTreeMap::new();
    for line in output.stdout.lines() {
        let mut fields = line.split_whitespace();
        let Some(commit) = fields.next() else {
            continue;
        };
        let Some(reference) = fields.next() else {
            continue;
        };
        let reference = reference.strip_prefix("refs/tags/").unwrap_or(reference);
        let (tag, peeled) = match reference.strip_suffix("^{}") {
            Some(tag) => (tag, true),
            None => (reference, false),
        };
        if tag
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.parse::<u64>().is_ok())
            && (peeled || !tags.contains_key(tag))
        {
            tags.insert(tag.to_string(), commit.to_string());
        }
    }
    Ok(tags)
}

fn next_release_tag<'a>(prefix: &str, tags: impl Iterator<Item = &'a str>) -> String {
    let next = tags
        .filter_map(|tag| tag.strip_prefix(prefix))
        .filter_map(|suffix| suffix.parse::<u64>().ok())
        .max()
        .map_or(0, |value| value.saturating_add(1));
    format!("{prefix}{next}")
}

#[cfg(test)]
mod tests {
    use super::next_release_tag;

    #[test]
    fn increments_numeric_release_tags() {
        let tags = ["v99.0.0", "v99.0.2", "v99.0.beta"];
        assert_eq!(next_release_tag("v99.0.", tags.into_iter()), "v99.0.3");
    }

    #[test]
    fn starts_from_zero_without_existing_tags() {
        assert_eq!(
            next_release_tag("preview-", std::iter::empty()),
            "preview-0"
        );
    }
}
