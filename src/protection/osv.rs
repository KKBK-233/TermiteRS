use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Read,
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};

use crate::config::Config;

use super::{OsvAdvisoryCursor, OsvAdvisorySignal, ProtectionStore, cargo_reachability_snapshot};

const OSV_API_BASE: &str = "https://api.osv.dev";
const QUERY_BATCH_SIZE: usize = 128;
const MAX_BATCH_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DETAIL_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_PAGINATION_ROUNDS: usize = 10;
const MAX_ADVISORY_CONTENT_BYTES: usize = 60 * 1024;

#[derive(Debug, Clone, Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: &'static str,
}

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvReference>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    id: String,
    modified: String,
}

/// 使用固定 OSV 官方端点批量查询 Cargo.lock 可达版本；公告 URL 和正文都不会控制网络目标。
pub fn scan_osv_advisories(config: &Config) -> Result<Vec<OsvAdvisorySignal>> {
    scan_osv_advisories_at(config, OSV_API_BASE)
}

fn scan_osv_advisories_at(config: &Config, api_base: &str) -> Result<Vec<OsvAdvisorySignal>> {
    if !config.protection.enabled
        || !config
            .protection
            .profiles
            .iter()
            .any(|profile| profile == "osv")
    {
        return Ok(Vec::new());
    }
    let Some(snapshot) = cargo_reachability_snapshot(&config.repo.path)? else {
        return Ok(Vec::new());
    };
    let mut seen = HashSet::new();
    let queries = snapshot
        .reachable_packages
        .into_iter()
        .filter(|package| is_crates_io_source(&package.source))
        .filter(|package| seen.insert((package.name.clone(), package.version.clone())))
        .map(|package| OsvQuery {
            version: package.version,
            package: OsvPackage {
                name: package.name,
                ecosystem: "crates.io",
            },
            page_token: None,
        })
        .collect::<Vec<_>>();
    if queries.is_empty() {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&config.service.data_dir)?;
    let store = ProtectionStore::open(config.service.data_dir.join("termite.db"))?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(Policy::none())
        .user_agent("TermiteRS-OSV-monitor/1")
        .build()?;
    let mut references = BTreeMap::new();
    for chunk in queries.chunks(QUERY_BATCH_SIZE) {
        collect_query_pages(&client, api_base, chunk.to_vec(), &mut references)?;
    }
    let mut advisories = Vec::new();
    let mut grouped_ids = HashSet::new();
    for (id, modified) in &references {
        if grouped_ids.contains(id) {
            continue;
        }
        validate_osv_id(&id)?;
        if !store.osv_advisory_needs_processing(id, modified)? {
            continue;
        }
        let detail = get_bounded_json(
            &client,
            &format!("{}/v1/vulns/{id}", api_base.trim_end_matches('/')),
            MAX_DETAIL_RESPONSE_BYTES,
        )?;
        let mut related_ids = vec![OsvAdvisoryCursor {
            id: id.clone(),
            modified: modified.clone(),
        }];
        for alias in detail
            .get("aliases")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            if let Some(alias_modified) = references.get(alias) {
                validate_osv_id(alias)?;
                related_ids.push(OsvAdvisoryCursor {
                    id: alias.to_string(),
                    modified: alias_modified.clone(),
                });
            }
        }
        related_ids.sort_by(|left, right| left.id.cmp(&right.id));
        related_ids.dedup_by(|left, right| left.id == right.id);
        grouped_ids.extend(related_ids.iter().map(|cursor| cursor.id.clone()));
        let summary = detail
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("OSV 公告未提供摘要")
            .to_string();
        let content = bounded_advisory_content(&detail)?;
        advisories.push(OsvAdvisorySignal {
            id: id.clone(),
            modified: modified.clone(),
            related_ids,
            summary: format!("{id}: {summary}"),
            reference: format!("https://osv.dev/vulnerability/{id}"),
            content,
        });
    }
    Ok(advisories)
}

fn collect_query_pages(
    client: &Client,
    api_base: &str,
    mut queries: Vec<OsvQuery>,
    references: &mut BTreeMap<String, String>,
) -> Result<()> {
    for _ in 0..MAX_PAGINATION_ROUNDS {
        let response = post_bounded_json(
            client,
            &format!("{}/v1/querybatch", api_base.trim_end_matches('/')),
            &OsvBatchRequest {
                queries: queries.clone(),
            },
            MAX_BATCH_RESPONSE_BYTES,
        )?;
        let response: OsvBatchResponse = serde_json::from_value(response)?;
        anyhow::ensure!(
            response.results.len() == queries.len(),
            "OSV querybatch 响应数量与请求不一致"
        );
        let mut next = Vec::new();
        for (query, result) in queries.into_iter().zip(response.results) {
            for vulnerability in result.vulns {
                references
                    .entry(vulnerability.id)
                    .and_modify(|modified| {
                        if vulnerability.modified > *modified {
                            *modified = vulnerability.modified.clone();
                        }
                    })
                    .or_insert(vulnerability.modified);
            }
            if let Some(page_token) = result.next_page_token {
                next.push(OsvQuery {
                    page_token: Some(page_token),
                    ..query
                });
            }
        }
        if next.is_empty() {
            return Ok(());
        }
        queries = next;
    }
    anyhow::bail!(
        "OSV querybatch 分页超过 {} 轮，已失败关闭",
        MAX_PAGINATION_ROUNDS
    )
}

fn bounded_advisory_content(detail: &serde_json::Value) -> Result<String> {
    let selected = serde_json::json!({
        "id": detail.get("id"),
        "summary": detail.get("summary"),
        "details": detail.get("details"),
        "aliases": detail.get("aliases"),
        "severity": detail.get("severity"),
        "affected": detail.get("affected"),
        "database_specific": detail.get("database_specific"),
        "references": detail.get("references"),
        "published": detail.get("published"),
        "modified": detail.get("modified"),
    });
    let content = serde_json::to_string_pretty(&selected)?;
    anyhow::ensure!(
        content.len() <= MAX_ADVISORY_CONTENT_BYTES,
        "OSV 公告证据超过 60 KiB，拒绝截断后自动判断"
    );
    Ok(content)
}

fn post_bounded_json(
    client: &Client,
    url: &str,
    body: &impl Serialize,
    max_bytes: u64,
) -> Result<serde_json::Value> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .context("查询 OSV 失败")?;
    read_bounded_json(response, max_bytes)
}

fn get_bounded_json(client: &Client, url: &str, max_bytes: u64) -> Result<serde_json::Value> {
    let response = client.get(url).send().context("读取 OSV 公告失败")?;
    read_bounded_json(response, max_bytes)
}

fn read_bounded_json(
    mut response: reqwest::blocking::Response,
    max_bytes: u64,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "OSV 返回 HTTP {}",
        response.status()
    );
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        anyhow::bail!("OSV 响应超过 {} 字节", max_bytes);
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= max_bytes,
        "OSV 响应超过 {} 字节",
        max_bytes
    );
    serde_json::from_slice(&bytes).context("解析 OSV JSON 失败")
}

fn is_crates_io_source(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source == "sparse+https://index.crates.io/"
}

fn validate_osv_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') }),
        "OSV ID 非法：{id}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use uuid::Uuid;

    use super::*;

    #[test]
    fn osv_scan_uses_locked_version_and_fixed_detail_path() {
        let root = std::env::temp_dir().join(format!("termiters-osv-{}", Uuid::new_v4()));
        let project = root.join("project");
        let data = root.join("data");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("Cargo.lock"),
            r#"version = 4

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = ["affected 1.2.3"]

[[package]]
name = "affected"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
        )
        .unwrap();
        let yaml = format!(
            r#"repo:
  path: '{}'
  upstream: unused
  fork: unused
service:
  data_dir: '{}'
protection:
  enabled: true
  profiles: [baseline, rust, osv]
"#,
            project.display().to_string().replace('\\', "/"),
            data.display().to_string().replace('\\', "/")
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut batch, _) = listener.accept().unwrap();
            let batch_request = read_http_request(&mut batch);
            assert!(batch_request.starts_with("POST /v1/querybatch HTTP/1.1"));
            assert!(batch_request.contains("\"name\":\"affected\""));
            assert!(batch_request.contains("\"version\":\"1.2.3\""));
            write_json_response(
                &mut batch,
                r#"{"results":[{"vulns":[{"id":"RUSTSEC-TEST-1","modified":"2026-01-01T00:00:00Z"}]}]}"#,
            );

            let (mut detail, _) = listener.accept().unwrap();
            let detail_request = read_http_request(&mut detail);
            assert!(detail_request.starts_with("GET /v1/vulns/RUSTSEC-TEST-1 HTTP/1.1"));
            write_json_response(
                &mut detail,
                r#"{"id":"RUSTSEC-TEST-1","summary":"fixture vulnerability","details":"fixed detail","modified":"2026-01-01T00:00:00Z","affected":[]}"#,
            );
        });
        let advisories = scan_osv_advisories_at(&config, &format!("http://{address}")).unwrap();
        server.join().unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "RUSTSEC-TEST-1");
        assert!(advisories[0].content.contains("fixed detail"));
        fs::remove_dir_all(root).unwrap();
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = value.trim().parse().unwrap();
            }
            request.push_str(&line);
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).unwrap();
        request.push_str(std::str::from_utf8(&body).unwrap());
        request
    }

    fn write_json_response(stream: &mut TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }
}
