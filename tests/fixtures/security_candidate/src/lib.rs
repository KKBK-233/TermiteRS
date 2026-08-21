/// 演示项目当前错误地允许请求任意 HTTP 地址，包括云元数据和环回地址。
pub fn webhook_url_allowed(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_https_is_allowed() {
        assert!(webhook_url_allowed("https://hooks.example.com/hook"));
    }
}
