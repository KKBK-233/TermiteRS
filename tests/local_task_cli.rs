//! 用本机模拟 LLM 验证交互入口、动作循环与权限范围，不访问真实提供商。

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn natural_language_runs_scoped_read_only_loop() {
    let root = std::env::temp_dir().join(format!("termiters-cli-task-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&root)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        Command::new("git")
            .args(["add", "src/main.rs"])
            .current_dir(&root)
            .output()
            .unwrap()
            .status
            .success()
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        for answer in [
            r#"{"action":"inspect"}"#,
            r#"{"action":"finish","summary":"已检查，未修改"}"#,
        ] {
            let started = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < Duration::from_secs(10) =>
                    {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(err) => panic!("模拟 LLM 未收到请求：{err}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut received = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let size = stream.read(&mut buffer).unwrap();
                assert!(size > 0);
                received.extend_from_slice(&buffer[..size]);
                if received.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&received).contains("POST /chat/completions"));
            let body = serde_json::json!({"choices":[{"message":{"content":answer}}]}).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            stream.flush().unwrap();
        }
    });

    let path = root.to_string_lossy().replace('\\', "/");
    let config = format!(
        "repo:\n  path: '{path}'\n  upstream: unused\n  fork: unused\nautonomy:\n  enabled: true\n  reports:\n    enabled: true\n    data_dir: .termite/reports\n  scope:\n    local_repositories: ['{path}']\n  permissions:\n    local_read: allow\nllm:\n  enabled: true\n  provider: open-ai-compatible\n  model: mock\n  api_key_env: TERMITERS_TEST_API_KEY\n  base_url: http://127.0.0.1:{port}\n  max_retries: 0\nwatch:\n  enabled: false\n"
    );
    fs::write(root.join("termite.yml"), config).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_TermiteRS"))
        .current_dir(&root)
        .env("TERMITERS_TEST_API_KEY", "mock-key")
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all("检查当前仓库\n/exit\n".as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("已读取 Git 状态和跟踪文件名"), "{stdout}");
    assert!(stdout.contains("已检查，未修改"), "{stdout}");
    assert!(stdout.contains("任务报告已保存"), "{stdout}");
    assert!(!stdout.contains("开始执行 doctor"), "{stdout}");

    let report_path = fs::read_dir(root.join(".termite/reports"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    let report_id = report["id"].as_str().unwrap();
    assert_eq!(report["outcome"], "finished");
    assert_eq!(report["summary"], "已检查，未修改");
    assert!(
        !fs::read_to_string(&report_path)
            .unwrap()
            .contains("mock-key")
    );

    let mut report_child = Command::new(env!("CARGO_BIN_EXE_TermiteRS"))
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    report_child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("/reports\n/report {}\n/exit\n", &report_id[..8]).as_bytes())
        .unwrap();
    let report_output = report_child.wait_with_output().unwrap();
    let report_stdout = String::from_utf8_lossy(&report_output.stdout);
    assert!(report_output.status.success());
    assert!(report_stdout.contains(&report_id[..8]), "{report_stdout}");
    assert!(
        report_stdout.contains("模型结论：\n已检查，未修改"),
        "{report_stdout}"
    );
    fs::remove_dir_all(root).unwrap();
}
