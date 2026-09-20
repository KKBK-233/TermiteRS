use std::net::IpAddr;

use reqwest::{
    Url,
    blocking::{Client, ClientBuilder},
};

/// 为 HTTP 目标创建客户端；仅回环地址绕过环境代理，保证本机测试与本机服务不被代理劫持。
pub fn client_builder_for(url: &str) -> ClientBuilder {
    let builder = Client::builder();
    if is_loopback_url(url) {
        builder.no_proxy()
    } else {
        builder
    }
}

fn is_loopback_url(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::is_loopback_url;

    #[test]
    fn identifies_only_loopback_http_targets() {
        assert!(is_loopback_url("http://127.0.0.1:8080/v1"));
        assert!(is_loopback_url("http://[::1]:8080/v1"));
        assert!(is_loopback_url("http://localhost/v1"));
        assert!(!is_loopback_url("https://api.github.com"));
        assert!(!is_loopback_url("not-a-url"));
    }
}
