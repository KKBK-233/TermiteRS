//! 用本机模型桩验证研究协议、JSON 输出与已有 LLM 配置的衔接。

use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn research_calls_existing_provider_and_returns_machine_readable_json() {
    let root =
        std::env::temp_dir().join(format!("termiters-research-cli-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_secs(10) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("未收到研究模型请求：{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = Vec::new();
        let mut buffer = [0u8; 4096];
        let (header_end, content_length) = loop {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0);
            received.extend_from_slice(&buffer[..count]);
            if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&received[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                break (end + 4, length);
            }
        };
        while received.len() < header_end + content_length {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0);
            received.extend_from_slice(&buffer[..count]);
        }
        let request: serde_json::Value =
            serde_json::from_slice(&received[header_end..header_end + content_length]).unwrap();
        assert_eq!(request["model"], "research-mock");
        assert!(
            request["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("原创逆向报告")
        );
        assert!(
            request["messages"][1]["content"]
                .as_str()
                .unwrap()
                .contains("untrusted_research")
        );
        let answer = serde_json::json!({"accepted": false, "reason": "不是逆向报告", "code_paths": [], "findings": []});
        let body = serde_json::json!({"choices": [{"message": {"content": answer.to_string()}}]})
            .to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    let config = format!(
        "repo:\n  path: .\n  upstream: unused\n  fork: unused\nllm:\n  enabled: true\n  provider: open-ai-compatible\n  model: research-mock\n  api_key_env: TERMITERS_RESEARCH_TEST_KEY\n  base_url: http://127.0.0.1:{port}\n  timeout_seconds: 5\n  max_retries: 0\n"
    );
    fs::write(root.join("llm.yml"), config).unwrap();
    fs::write(
        root.join("input.json"),
        r#"{"phase":"classify","evidence":{"article":"public fixture"}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_TermiteRS"))
        .args([
            "research",
            "analyze",
            "--config",
            "llm.yml",
            "--input",
            "input.json",
        ])
        .current_dir(&root)
        .env("TERMITERS_RESEARCH_TEST_KEY", "synthetic-test-key")
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["accepted"], false);
    assert_eq!(result["reason"], "不是逆向报告");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn research_help_exposes_one_shot_and_preview() {
    let output = Command::new(env!("CARGO_BIN_EXE_TermiteRS"))
        .args(["research", "run-once", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("--preview"));
    assert!(output.contains("--config"));
}

#[test]
fn embedded_runner_refuses_disabled_config_before_network_or_model_calls() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    if Command::new(python).arg("--version").output().is_err() {
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "termiters-research-disabled-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&root).unwrap();
    let config = root.join("research.json");
    fs::write(&config, r#"{"enabled":false}"#).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_TermiteRS"))
        .args(["research", "run-once", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("显式启用"));
    assert!(!root.join(".termite").exists());
    fs::remove_dir_all(root).unwrap();
}
