use std::fs;
use std::path::Path;
use std::process::Command;

use TermiteRS::conflict::{ConflictResolution, extract_conflict_blocks, resolve_conflict_files};
use TermiteRS::git::Git;
use uuid::Uuid;

/// 使用真实 rebase 冲突验证局部替换可以继续同步，且文件首尾不会被模型覆盖。
#[test]
fn block_resolution_continues_real_git_rebase() {
    let root = std::env::temp_dir().join(format!("termiters-conflict-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    run(&root, &["init"]);
    run(&root, &["config", "user.name", "TermiteRS Test"]);
    run(&root, &["config", "user.email", "termite@example.com"]);
    run(&root, &["config", "core.autocrlf", "false"]);
    fs::write(root.join("sample.txt"), "header\nvalue=base\nfooter\n").unwrap();
    run(&root, &["add", "sample.txt"]);
    run(&root, &["commit", "-m", "base"]);
    run(&root, &["branch", "-M", "main"]);

    run(&root, &["checkout", "-b", "personal"]);
    fs::write(root.join("sample.txt"), "header\nvalue=personal\nfooter\n").unwrap();
    run(&root, &["commit", "-am", "personal"]);

    run(&root, &["checkout", "main"]);
    fs::write(root.join("sample.txt"), "header\nvalue=upstream\nfooter\n").unwrap();
    run(&root, &["commit", "-am", "upstream"]);
    run(&root, &["checkout", "personal"]);
    assert!(!run_output(&root, &["rebase", "main"]).status.success());

    let git = Git::new(&root);
    let snapshot = git.conflict_snapshot(64 * 1024).unwrap();
    let files = git
        .conflict_file_contents(&snapshot.files, 40 * 1024)
        .unwrap();
    let block = extract_conflict_blocks(&files, 4).unwrap().remove(0);
    let resolved = resolve_conflict_files(
        &files,
        &[ConflictResolution {
            path: block.path,
            conflict_id: block.id,
            expected_sha256: block.expected_sha256,
            replacement: "value=upstream\nvalue=personal\n".to_string(),
        }],
    )
    .unwrap();
    git.write_file(&resolved[0].path, &resolved[0].content)
        .unwrap();
    git.add_file(&resolved[0].path).unwrap();
    assert!(
        git.continue_sync(TermiteRS::config::SyncStrategy::Rebase)
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::read_to_string(root.join("sample.txt")).unwrap(),
        "header\nvalue=upstream\nvalue=personal\nfooter\n"
    );

    fs::remove_dir_all(root).unwrap();
}

fn run(root: &Path, args: &[&str]) {
    let output = run_output(root, args);
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_output(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}
