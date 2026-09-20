//! 本机 Linear 只读客户端：固定 GraphQL 查询，仅返回令牌持有者本人分配的事项。

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, time::Duration};

use crate::{config::LinearConfig, http::client_builder_for};

const LINEAR_ENDPOINT: &str = "https://api.linear.app/graphql";
const ASSIGNED_ISSUES_QUERY: &str = r#"query TermiteAssignedIssues($first: Int!) {
  viewer {
    id
    assignedIssues(first: $first, orderBy: updatedAt) {
      nodes {
        id
        identifier
        title
        url
        updatedAt
        state { name }
        assignee { id }
        team { key }
      }
    }
  }
}"#;

#[derive(Debug, Clone, Serialize)]
pub struct LinearIssueSummary {
    pub identifier: String,
    pub title: String,
    pub status: String,
    pub team: String,
    pub updated_at: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct GraphQlEnvelope {
    data: Option<GraphQlData>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Debug, Deserialize)]
struct GraphQlError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct GraphQlData {
    viewer: Viewer,
}

#[derive(Debug, Deserialize)]
struct Viewer {
    id: String,
    #[serde(rename = "assignedIssues")]
    assigned_issues: IssueConnection,
}

#[derive(Debug, Deserialize)]
struct IssueConnection {
    nodes: Vec<IssueNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueNode {
    identifier: String,
    title: String,
    url: String,
    updated_at: String,
    state: IssueState,
    assignee: Option<IssueAssignee>,
    team: IssueTeam,
}

#[derive(Debug, Deserialize)]
struct IssueState {
    name: String,
}

#[derive(Debug, Deserialize)]
struct IssueAssignee {
    id: String,
}

#[derive(Debug, Deserialize)]
struct IssueTeam {
    key: String,
}

pub struct LinearClient<'a> {
    config: &'a LinearConfig,
    endpoint: &'a str,
}

impl<'a> LinearClient<'a> {
    pub fn new(config: &'a LinearConfig) -> Self {
        Self {
            config,
            endpoint: LINEAR_ENDPOINT,
        }
    }

    /// 查询前后的负责人双重校验，避免凭据与配置中的个人范围不一致。
    pub fn assigned_issues(&self, expected_assignee_id: &str) -> Result<Vec<LinearIssueSummary>> {
        ensure!(self.config.enabled, "Linear 本地读取未启用");
        ensure!(
            !expected_assignee_id.trim().is_empty(),
            "Linear 个人负责人范围未配置"
        );
        ensure!(
            (1..=50).contains(&self.config.max_issues),
            "Linear max_issues 必须在 1 到 50 之间"
        );
        let api_key = env::var(&self.config.api_key_env)
            .with_context(|| format!("缺少 Linear API key 环境变量 {}", self.config.api_key_env))?;
        self.assigned_issues_with_key(expected_assignee_id, &api_key)
    }

    fn assigned_issues_with_key(
        &self,
        expected_assignee_id: &str,
        api_key: &str,
    ) -> Result<Vec<LinearIssueSummary>> {
        ensure!(!api_key.trim().is_empty(), "Linear API key 为空");
        let client = client_builder_for(self.endpoint)
            .timeout(Duration::from_secs(20))
            .build()
            .context("无法初始化 Linear HTTP 客户端")?;
        let response = client
            .post(self.endpoint)
            .header(reqwest::header::AUTHORIZATION, api_key)
            .json(&json!({
                "query": ASSIGNED_ISSUES_QUERY,
                "variables": { "first": self.config.max_issues }
            }))
            .send()
            .context("Linear 只读请求失败")?
            .error_for_status()
            .context("Linear 返回非成功状态")?;
        let envelope: GraphQlEnvelope = response.json().context("Linear 响应格式无效")?;
        if let Some(error) = envelope.errors.first() {
            bail!(
                "Linear GraphQL 返回错误：{}",
                sanitized(&error.message, 200)
            );
        }
        let viewer = envelope.data.context("Linear 响应缺少 data")?.viewer;
        ensure!(
            viewer.id == expected_assignee_id,
            "Linear 授权身份与 scope.linear_assignee 不一致"
        );
        viewer
            .assigned_issues
            .nodes
            .into_iter()
            .map(|issue| {
                ensure!(
                    issue
                        .assignee
                        .as_ref()
                        .is_some_and(|assignee| assignee.id == viewer.id),
                    "Linear 返回了不属于当前授权用户的事项"
                );
                Ok(LinearIssueSummary {
                    identifier: sanitized(&issue.identifier, 64),
                    title: sanitized(&issue.title, 500),
                    status: sanitized(&issue.state.name, 100),
                    team: sanitized(&issue.team.key, 40),
                    updated_at: issue.updated_at,
                    url: issue.url,
                })
            })
            .collect()
    }
}

fn sanitized(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    use super::*;

    fn mock_response(body: &str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let body = body.to_string();
        let server = thread::spawn(move || {
            let started = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < Duration::from_secs(5) =>
                    {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("模拟 Linear 请求未到达：{err}"),
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
                if received.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&received);
            assert!(request.contains("POST /graphql"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: mock-key")
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            stream.flush().unwrap();
        });
        (endpoint, server)
    }

    fn test_config() -> LinearConfig {
        serde_yaml::from_str("enabled: true\nmax_issues: 5\n").unwrap()
    }

    #[test]
    fn only_returns_issues_assigned_to_the_expected_viewer() {
        let (endpoint, server) = mock_response(
            r#"{"data":{"viewer":{"id":"person-1","assignedIssues":{"nodes":[{"identifier":"D9-1","title":"标题","url":"https://linear.app/d9/issue/D9-1","updatedAt":"2026-09-18T00:00:00Z","state":{"name":"Todo"},"assignee":{"id":"person-1"},"team":{"key":"D9"}}]}}}}"#,
        );
        let config = test_config();
        let client = LinearClient {
            config: &config,
            endpoint: &endpoint,
        };
        let issues = client
            .assigned_issues_with_key("person-1", "mock-key")
            .unwrap();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].identifier, "D9-1");
        server.join().unwrap();
    }

    #[test]
    fn rejects_mismatched_viewer_even_with_valid_response() {
        let (endpoint, server) =
            mock_response(r#"{"data":{"viewer":{"id":"other","assignedIssues":{"nodes":[]}}}}"#);
        let config = test_config();
        let client = LinearClient {
            config: &config,
            endpoint: &endpoint,
        };
        assert!(
            client
                .assigned_issues_with_key("person-1", "mock-key")
                .is_err()
        );
        server.join().unwrap();
    }

    #[test]
    fn rejects_issue_assigned_to_someone_else() {
        let (endpoint, server) = mock_response(
            r#"{"data":{"viewer":{"id":"person-1","assignedIssues":{"nodes":[{"identifier":"D9-2","title":"其他人的事项","url":"https://linear.app/d9/issue/D9-2","updatedAt":"2026-09-18T00:00:00Z","state":{"name":"Todo"},"assignee":{"id":"person-2"},"team":{"key":"D9"}}]}}}}"#,
        );
        let config = test_config();
        let client = LinearClient {
            config: &config,
            endpoint: &endpoint,
        };
        assert!(
            client
                .assigned_issues_with_key("person-1", "mock-key")
                .is_err()
        );
        server.join().unwrap();
    }

    #[test]
    fn graphql_errors_fail_closed() {
        let (endpoint, server) = mock_response(r#"{"errors":[{"message":"Forbidden"}]}"#);
        let config = test_config();
        let client = LinearClient {
            config: &config,
            endpoint: &endpoint,
        };
        assert!(
            client
                .assigned_issues_with_key("person-1", "mock-key")
                .is_err()
        );
        server.join().unwrap();
    }
}
