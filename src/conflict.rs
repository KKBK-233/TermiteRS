use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

use crate::git::ConflictFileContent;

/// 提供给模型的单个冲突块，只包含冲突内容和少量相邻上下文。
#[derive(Debug, Clone, Serialize)]
pub struct ConflictBlock {
    pub path: String,
    pub id: String,
    pub expected_sha256: String,
    pub before_context: String,
    pub ours: String,
    pub base: Option<String>,
    pub theirs: String,
    pub after_context: String,
}

/// 模型只返回局部替换，不允许重新生成整个文件。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConflictResolution {
    pub path: String,
    pub conflict_id: String,
    pub expected_sha256: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResolvedFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug)]
struct ParsedBlock {
    block: ConflictBlock,
    start: usize,
    end: usize,
    raw_ends_with_newline: bool,
    uses_crlf: bool,
}

/// 解析所有冲突文件，生成可直接序列化给模型的局部冲突块。
pub fn extract_conflict_blocks(
    files: &[ConflictFileContent],
    context_lines: usize,
) -> Result<Vec<ConflictBlock>> {
    let mut blocks = Vec::new();
    for file in files {
        blocks.extend(
            parse_file(&file.path, &file.content, context_lines)?
                .into_iter()
                .map(|parsed| parsed.block),
        );
    }
    if blocks.is_empty() {
        bail!("冲突文件中没有可解析的 Git 冲突块");
    }
    Ok(blocks)
}

/// 根据模型返回的局部替换重建文件，未冲突区域始终由 TermiteRS 原样保留。
pub fn resolve_conflict_files(
    files: &[ConflictFileContent],
    resolutions: &[ConflictResolution],
) -> Result<Vec<ResolvedFile>> {
    if resolutions.is_empty() {
        bail!("模型没有返回冲突块替换");
    }

    let mut resolution_map = HashMap::new();
    for resolution in resolutions {
        let key = (resolution.path.clone(), resolution.conflict_id.clone());
        if resolution_map.insert(key, resolution).is_some() {
            bail!(
                "冲突块重复返回：{} {}",
                resolution.path,
                resolution.conflict_id
            );
        }
        if contains_conflict_marker(&resolution.replacement) {
            bail!(
                "冲突块替换仍包含 Git 标记：{} {}",
                resolution.path,
                resolution.conflict_id
            );
        }
    }

    let mut resolved_files = Vec::new();
    let mut consumed = HashSet::new();
    for file in files {
        let parsed = parse_file(&file.path, &file.content, 0)?;
        if parsed.is_empty() {
            bail!("文件不包含 Git 冲突块：{}", file.path);
        }

        let mut output = String::with_capacity(file.content.len());
        let mut cursor = 0;
        for block in parsed {
            output.push_str(&file.content[cursor..block.start]);
            let key = (file.path.clone(), block.block.id.clone());
            let resolution = resolution_map
                .get(&key)
                .with_context(|| format!("模型遗漏冲突块：{} {}", file.path, block.block.id))?;
            if resolution.expected_sha256 != block.block.expected_sha256 {
                bail!("冲突块哈希不匹配：{} {}", file.path, block.block.id);
            }

            let replacement = normalize_line_endings(&resolution.replacement, block.uses_crlf);
            output.push_str(&replacement);
            if block.raw_ends_with_newline
                && !replacement.is_empty()
                && !replacement.ends_with('\n')
            {
                output.push_str(if block.uses_crlf { "\r\n" } else { "\n" });
            }
            consumed.insert(key);
            cursor = block.end;
        }
        output.push_str(&file.content[cursor..]);
        resolved_files.push(ResolvedFile {
            path: file.path.clone(),
            content: output,
        });
    }

    if consumed.len() != resolution_map.len() {
        let unknown = resolution_map
            .keys()
            .find(|key| !consumed.contains(*key))
            .context("存在未知冲突块替换")?;
        bail!("模型返回了未知冲突块：{} {}", unknown.0, unknown.1);
    }
    Ok(resolved_files)
}

fn parse_file(path: &str, content: &str, context_lines: usize) -> Result<Vec<ParsedBlock>> {
    let lines = content.split_inclusive('\n').collect::<Vec<_>>();
    let mut offsets = Vec::with_capacity(lines.len() + 1);
    let mut offset = 0;
    for line in &lines {
        offsets.push(offset);
        offset += line.len();
    }
    offsets.push(offset);

    let mut blocks = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !marker(lines[index], "<<<<<<<") {
            index += 1;
            continue;
        }

        let start_line = index;
        let ours_start = index + 1;
        index += 1;
        while index < lines.len()
            && !marker(lines[index], "|||||||")
            && !marker(lines[index], "=======")
        {
            index += 1;
        }
        if index >= lines.len() {
            bail!("Git 冲突块缺少分隔符：{path}");
        }

        let ours_end = index;
        let mut base = None;
        if marker(lines[index], "|||||||") {
            let base_start = index + 1;
            index += 1;
            while index < lines.len() && !marker(lines[index], "=======") {
                index += 1;
            }
            if index >= lines.len() {
                bail!("Git diff3 冲突块缺少分隔符：{path}");
            }
            base = Some(lines[base_start..index].concat());
        }

        let theirs_start = index + 1;
        index += 1;
        while index < lines.len() && !marker(lines[index], ">>>>>>>") {
            index += 1;
        }
        if index >= lines.len() {
            bail!("Git 冲突块缺少结束标记：{path}");
        }

        let end_line = index;
        let start = offsets[start_line];
        let end = offsets[end_line + 1];
        let raw = &content[start..end];
        let id = format!("conflict-{}", blocks.len() + 1);
        blocks.push(ParsedBlock {
            block: ConflictBlock {
                path: path.to_string(),
                id,
                expected_sha256: sha256(raw),
                before_context: lines[start_line.saturating_sub(context_lines)..start_line]
                    .concat(),
                ours: lines[ours_start..ours_end].concat(),
                base,
                theirs: lines[theirs_start..end_line].concat(),
                after_context: lines[end_line + 1..(end_line + 1 + context_lines).min(lines.len())]
                    .concat(),
            },
            start,
            end,
            raw_ends_with_newline: raw.ends_with('\n'),
            uses_crlf: raw.contains("\r\n"),
        });
        index = end_line + 1;
    }
    Ok(blocks)
}

fn marker(line: &str, prefix: &str) -> bool {
    line.trim_end_matches(['\r', '\n']).starts_with(prefix)
}

fn contains_conflict_marker(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("<<<<<<<")
            || line.starts_with("|||||||")
            || line.starts_with("=======")
            || line.starts_with(">>>>>>>")
    })
}

fn normalize_line_endings(content: &str, use_crlf: bool) -> String {
    let normalized = content.replace("\r\n", "\n");
    if use_crlf {
        normalized.replace('\n', "\r\n")
    } else {
        normalized
    }
}

fn sha256(content: &str) -> String {
    digest(&SHA256, content.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conflict_file() -> ConflictFileContent {
        ConflictFileContent {
            path: "src/example.py".to_string(),
            content: concat!(
                "before = 1\n",
                "<<<<<<< HEAD\n",
                "upstream()\n",
                "||||||| parent\n",
                "old()\n",
                "=======\n",
                "personal_patch()\n",
                ">>>>>>> patch\n",
                "after = 2\n"
            )
            .to_string(),
        }
    }

    #[test]
    fn extracts_small_conflict_block_from_large_file() {
        let mut file = conflict_file();
        file.content = format!("{}{}", "header = 0\n".repeat(10_000), file.content);
        let blocks = extract_conflict_blocks(&[file], 3).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].ours, "upstream()\n");
        assert_eq!(blocks[0].base.as_deref(), Some("old()\n"));
        assert_eq!(blocks[0].theirs, "personal_patch()\n");
        assert!(blocks[0].before_context.len() < 100);
    }

    #[test]
    fn rebuild_preserves_non_conflict_content() {
        let file = conflict_file();
        let block = extract_conflict_blocks(std::slice::from_ref(&file), 3)
            .unwrap()
            .remove(0);
        let resolved = resolve_conflict_files(
            &[file],
            &[ConflictResolution {
                path: block.path,
                conflict_id: block.id,
                expected_sha256: block.expected_sha256,
                replacement: "upstream()\npersonal_patch()".to_string(),
            }],
        )
        .unwrap();
        assert_eq!(
            resolved[0].content,
            "before = 1\nupstream()\npersonal_patch()\nafter = 2\n"
        );
    }

    #[test]
    fn rejects_stale_hash_and_unknown_block() {
        let file = conflict_file();
        let block = extract_conflict_blocks(std::slice::from_ref(&file), 2)
            .unwrap()
            .remove(0);
        let error = resolve_conflict_files(
            &[file],
            &[ConflictResolution {
                path: block.path,
                conflict_id: block.id,
                expected_sha256: "stale".to_string(),
                replacement: "resolved()\n".to_string(),
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("哈希不匹配"));
    }

    #[test]
    fn replacement_follows_conflict_line_endings() {
        let mut file = conflict_file();
        file.content = file.content.replace('\n', "\r\n");
        let block = extract_conflict_blocks(std::slice::from_ref(&file), 2)
            .unwrap()
            .remove(0);
        let resolved = resolve_conflict_files(
            &[file],
            &[ConflictResolution {
                path: block.path,
                conflict_id: block.id,
                expected_sha256: block.expected_sha256,
                replacement: "upstream()\npersonal_patch()".to_string(),
            }],
        )
        .unwrap();
        assert!(!resolved[0].content.replace("\r\n", "").contains('\n'));
    }
}
