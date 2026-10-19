"""一次性研究执行器：搜索、证据核验、代码判断、首页发布；仅依赖 Python 标准库。"""

import argparse
import contextlib
from datetime import date, datetime
from difflib import get_close_matches
import hashlib
import html
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET


START = "<!-- termiters:research:start -->"
END = "<!-- termiters:research:end -->"
RESEARCH_PROTOCOL = 5
MODEL_PROTOCOL = 6
REPORT_BASELINE = {
    "mode": "report_baseline",
    "assumption": "假设云端 CLI 为指定上游本轮选中的报告版本，并按报告描述运行；这是评估前提，不是实际部署版本检测结果。",
    "scope": "以报告中的机制与触发条件为依据，只判断目标网关的过滤、透传及触发条件控制；不自行逆向 CLI，不要求动态提取或验证报告中的 CLI 内部实现。",
}
DEFAULT_PROFILE = {
    "name": "Unbundle 默认配置",
    "policy": "按目标仓库的默认部署及 engine.mjs 中的固定 CLI 参数、环境白名单评估，不假定用户额外启用远程控制、OTel、插件或测试上游。不读取个人部署的凭据或自定义覆盖。先核对默认配置是否满足报告触发条件，再判断实际可能发送的信号是否过滤。",
}
STATUSES = {"filtered": "已过滤", "unfiltered": "未过滤", "partial": "部分过滤", "not_triggered": "当前配置不触发", "unknown": "待核实"}
SUFFIXES = {".rs", ".go", ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".java", ".kt"}


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def alarm_timeout(signum, frame):
    raise TimeoutError("达到本轮研究总时限")


def text(value, label, limit=1500):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{label} 缺失或过长")
    return value.strip()


def normalized_url(value):
    value = text(value, "URL", 4096)
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.port not in (None, 443):
        raise ValueError("研究网页仅接受无认证信息的标准 HTTPS URL")
    if any(ord(c) < 32 for c in value):
        raise ValueError("URL 含控制字符")
    return urlunsplit(("https", url.netloc.lower(), url.path or "/", url.query, ""))


def safe_path(value):
    path = PurePosixPath(text(value, "仓库文件路径", 500))
    if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value or str(path) != value:
        raise ValueError("文件必须是仓库内规范相对路径")
    return value


class Budget:
    """所有子步骤共享截止时间，避免每日任务无限挂起。"""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def timeout(self, maximum):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("达到本轮研究总时限")
        return max(0.01, min(maximum, remaining))


class PageText(HTMLParser):
    """仅提取可见文本，网页脚本与样式不进入模型证据。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden += 1
        elif tag in {"p", "div", "br", "li", "pre", "h1", "h2", "h3", "tr"} and not self.hidden:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden = max(0, self.hidden - 1)
        elif not self.hidden:
            self.parts.append("\n" if tag in {"p", "div", "li", "pre", "tr"} else "")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def publication_day(value):
    """只规范化来源明确给出的日期，不把研究日期、更新日期或抓取时间补成首发。"""
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).date().isoformat()
    except (ValueError, TypeError):
        months = "January February March April May June July August September October November December".split()
        match = re.fullmatch(r"([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})", value.strip())
        if match and match[1].title() in months:
            try:
                return date(int(match[3]), months.index(match[1].title()) + 1, int(match[2])).isoformat()
            except ValueError:
                pass
    return None


class Publication(PageText):
    """读取首发元数据及标题前的独立日期；忽略正文研究日期、修订时间和评论日期。"""

    def __init__(self):
        super().__init__()
        self.candidates, self.prefix, self.structured = [], None, None

    def add(self, value, quote, kind):
        day = publication_day(value) if isinstance(value, str) else None
        if day:
            self.candidates.append({"value": day, "quote": quote[:1000], "kind": kind})

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if not self.hidden:
            if tag == "h1" and self.prefix is None:
                self.prefix = "".join(self.parts)
            if tag == "meta" and (attributes.get("property") or attributes.get("name", "")).lower() in {
                "article:published_time", "datepublished", "pubdate", "dc.date.issued", "dcterms.issued"
            }:
                self.add(attributes.get("content"), self.get_starttag_text(), "首发元数据")
            if tag == "time" and (attributes.get("itemprop") == "datePublished" or "published" in attributes.get("class", "").split()):
                self.add(attributes.get("datetime"), self.get_starttag_text(), "首发时间标签")
            if tag == "script" and attributes.get("type", "").lower() == "application/ld+json":
                self.structured = []
        super().handle_starttag(tag, attrs)

    def handle_data(self, data):
        if self.structured is not None:
            self.structured.append(data)
        super().handle_data(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.structured is not None:
            raw = "".join(self.structured)
            self.structured = None
            try:
                data = json.loads(raw)
                nodes = data if isinstance(data, list) else [data]
                for node in list(nodes):
                    if isinstance(node, dict) and isinstance(node.get("@graph"), list):
                        nodes += node["@graph"]
                for node in nodes:
                    if not isinstance(node, dict):
                        continue
                    types = node.get("@type", [])
                    types = [types] if isinstance(types, str) else types
                    if isinstance(types, list) and any(kind in types for kind in ("Article", "BlogPosting", "NewsArticle", "TechArticle", "DiscussionForumPosting")):
                        value = node.get("datePublished")
                        if isinstance(value, str) and value in raw:
                            self.add(value, value, "结构化首发时间")
            except (ValueError, RecursionError):
                pass
        super().handle_endtag(tag)

    def result(self):
        if not self.candidates and self.prefix is not None:
            # 有些博客未提供元数据，但在文章标题前单列首发日期。只读标题前，不扫正文样例。
            for line in self.prefix.splitlines():
                value = line.strip()
                if re.fullmatch(r"[A-Za-z]+\s+\d{1,2},\s+\d{4}|\d{4}-\d{2}-\d{2}", value):
                    self.add(value, value, "文章标题日期")
        days = {item["value"] for item in self.candidates}
        return self.candidates[0] if len(days) == 1 else None


class GoogleLinks(HTMLParser):
    """读取普通 Google 网页结果链接，忽略站内导航与验证页。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.current = None
        self.parts = []
        self.results = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.current = dict(attrs).get("href", "")
            self.parts = []

    def handle_data(self, data):
        if self.current is not None:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag != "a" or self.current is None:
            return
        href = self.current
        self.current = None
        if href.startswith("/url?"):
            values = parse_qs(urlsplit(href).query)
            href = (values.get("q") or values.get("url") or [""])[0]
        try:
            href = normalized_url(href)
        except ValueError:
            return
        host = urlsplit(href).hostname
        if host == "google.com" or host.endswith(".google.com") or host.endswith(".google.com.hk"):
            return
        title = " ".join(self.parts).strip()
        if title:
            self.results.append((href, title))


def google_results(body):
    parser = GoogleLinks()
    parser.feed(body)
    if not parser.results and not any(marker in body.lower() for marker in ("did not match any documents", "no results found")):
        raise ValueError("Google 未提供可解析的网页结果，可能要求 JavaScript 或验证码")
    return parser.results


class Web:
    """逐跳核对公网地址并固定连接 IP，阻止重定向和 DNS 重绑定读取内网。"""

    def __init__(self, budget, timeout=30, max_bytes=1048576):
        self.budget, self.seconds, self.max_bytes = budget, timeout, max_bytes
        self.upstream_sources = {}
        self.max_report_bytes = 48000
        self.article_cache = {}
        self.publication_cache = {}

    def get(self, url, headers=None):
        url = normalized_url(url)
        initial_host = urlsplit(url).hostname
        for _ in range(5):
            parsed = urlsplit(url)
            host = parsed.hostname.encode("idna").decode("ascii")
            addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
                raise ValueError("网页解析到非公网地址，已拒绝")
            connection = http.client.HTTPSConnection(host, timeout=self.budget.timeout(self.seconds))
            try:
                raw = socket.create_connection(addresses[0][4][:2], self.budget.timeout(self.seconds))
                try:
                    connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                except BaseException:
                    raw.close()
                    raise
                request_headers = {"User-Agent": "TermiteRS-Research/1.0", "Accept-Encoding": "identity"}
                if headers and parsed.hostname == initial_host:
                    request_headers.update(headers)
                target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                connection.request("GET", target, headers=request_headers)
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    url = normalized_url(urljoin(url, response.getheader("Location", "")))
                    continue
                if response.status != 200:
                    raise ValueError(f"网页 HTTP {response.status}")
                if response.getheader("Content-Encoding", "identity") != "identity":
                    raise ValueError("网页返回未支持的压缩格式")
                body = bytearray()
                while True:
                    # HTTPResponse 在对端关闭 keep-alive 时仍持有独立文件对象。
                    chunk = response.read1(min(65536, self.max_bytes + 1 - len(body)))
                    self.budget.timeout(self.seconds)
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        raise ValueError("网页超过大小上限")
                    if not chunk:
                        break
                content_type = response.getheader("Content-Type", "")
                return url, bytes(body).decode("utf-8", errors="replace"), content_type
            finally:
                connection.close()
        raise ValueError("网页重定向过多")

    def upstream(self, config):
        """只读取指定 GitHub 上游的版本目录与 Markdown，不下载或执行 CLI bundle。"""
        repository = config["repository"].rstrip("/").removesuffix(".git")
        slug = repository.removeprefix("https://github.com/")
        api = "https://api.github.com/repos/" + slug
        def read_json(path):
            return json.loads(self.get(api + path, {"Accept": "application/vnd.github+json"})[1])
        reference = read_json("/git/ref/heads/" + quote(config.get("branch", "main"), safe=""))
        commit = reference.get("object", {}).get("sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or reference.get("object", {}).get("type") != "commit":
            raise ValueError("上游分支未指向有效 Git 提交")
        directory = config.get("versions_dir", "versions")
        entries = read_json("/contents/" + quote(directory, safe="/") + "?ref=" + commit)
        versions = [entry["name"] for entry in entries
                    if entry.get("type") == "dir" and re.fullmatch(r"\d+\.\d+\.\d+", entry.get("name", ""))]
        versions.sort(key=version_rank, reverse=True)
        versions = versions[:config.get("latest_versions", 1)]
        if not versions:
            raise ValueError("指定上游未公开可识别的版本报告目录")
        sources = {}
        selected = config.get("report_files", [])
        for version in versions:
            prefix = directory + "/" + version
            files = read_json("/contents/" + quote(prefix, safe="/") + "?ref=" + commit)
            for item in files:
                name = item.get("name", "")
                if item.get("type") != "file" or not name.endswith(".md"):
                    continue
                path = safe_path(item.get("path", ""))
                if path != prefix + "/" + name or "target" in item:
                    raise ValueError("上游报告路径与版本目录不一致")
                blob = item.get("sha", "")
                if not re.fullmatch(r"[0-9a-f]{40}", blob):
                    raise ValueError("上游报告未提供有效内容指纹")
                canonical = "https://raw.githubusercontent.com/" + slug + "/" + quote(config.get("branch", "main"), safe="/") + "/" + quote(path, safe="/")
                sources[canonical] = {"repository": repository, "commit": commit, "path": path,
                                      "version": version, "blob_sha": blob,
                                      "raw_url": "https://raw.githubusercontent.com/" + slug + "/" + commit + "/" + quote(path, safe="/"),
                                      "url": repository + "/blob/" + commit + "/" + quote(path, safe="/")}
        if not sources:
            raise ValueError("上游最新版本目录中没有匹配的 Markdown 报告")
        self.upstream_sources = sources
        self.max_report_bytes = config.get("max_report_bytes", 192000)
        # 优先处理指纹与遥测，其余报告按用户配置顺序；不以 API 返回顺序决定优先级。
        priority = selected or ["device-fingerprinting.md", "telemetry.md", "api-endpoints.md", "system-prompt.md"]
        candidates = [url for url in sources if not selected or Path(sources[url]["path"]).name in selected]
        if not candidates:
            raise ValueError("上游最新版本目录中没有匹配的 Markdown 报告")
        urls = sorted(candidates, key=lambda url: (tuple(-p for p in version_rank(sources[url]["version"])),
                      priority.index(Path(sources[url]["path"]).name) if Path(sources[url]["path"]).name in priority else len(priority), sources[url]["path"]))
        return urls, {"repository": repository, "branch": config.get("branch", "main"), "commit": commit,
                      "versions": versions, "report_paths": [sources[url]["path"] for url in urls]}

    def upstream_publication(self, source):
        """发现日期按报告文件最早可查提交记账，不要求确认机制的真实发现时间。"""
        key = source["repository"] + ":" + source["path"]
        if key in self.publication_cache:
            return self.publication_cache[key]
        slug = source["repository"].removeprefix("https://github.com/")
        oldest = None
        try:
            for page in range(1, 6):
                url = "https://api.github.com/repos/" + slug + "/commits?" + urlencode({
                    "sha": source["commit"], "path": source["path"], "per_page": 100, "page": page})
                history = json.loads(self.get(url, {"Accept": "application/vnd.github+json"})[1])
                if not isinstance(history, list):
                    raise ValueError("上游提交列表格式非法")
                if history:
                    oldest = history[-1]
                if len(history) < 100:
                    break
            if not isinstance(oldest, dict) or not re.fullmatch(r"[0-9a-f]{40}", oldest.get("sha", "")):
                return None
            stamp = (oldest.get("commit", {}).get("committer") or {}).get("date")
            day = publication_day(stamp) if isinstance(stamp, str) else None
            if day:
                result = {"value": day, "kind": "上游报告提交日期", "quote": "报告文件最早可查提交日期：" + stamp,
                          "url": source["repository"] + "/commit/" + oldest["sha"]}
                self.publication_cache[key] = result
                return result
        except (ValueError, OSError, TimeoutError, http.client.HTTPException):
            # 日期获取失败不阻塞机制评估，下轮仍可补全。
            return None
        return None

    def article(self, url, include_publication=True):
        source = self.upstream_sources.get(url)
        cached = self.article_cache.get(url)
        if cached is None:
            final_url, body, content_type = self.get(source["raw_url"] if source else url)
            if source:
                raw = body.encode("utf-8")
                actual = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
                if actual != source["blob_sha"]:
                    raise ValueError("上游原文与固定提交的 Git 内容指纹不一致")
            published = None
            if "html" in content_type:
                publication = Publication()
                publication.feed(body)
                published = publication.result()
                parser = PageText()
                parser.feed(body)
                body = "".join(parser.parts)
            elif not any(t in content_type for t in ("text/", "json", "xml")):
                raise ValueError("不支持的报告内容格式")
            body = re.sub(r"[ \t]+", " ", body)
            body = re.sub(r"\n\s*\n+", "\n\n", body).strip()
            if len(body.encode("utf-8")) > self.max_report_bytes:
                raise ValueError(f"报告正文超过 {self.max_report_bytes} 字节，需分段处理；本轮不做截断判断")
            if len(body) < 80:
                raise ValueError("报告正文为空或不足")
            cached = {"url": source["url"] if source else final_url, "body": body, "hash": digest(body), "published": published}
            if source:
                cached["tracked_upstream"] = source
            self.article_cache[url] = cached
        article = dict(cached)
        if source and include_publication:
            article["published"] = self.upstream_publication(source)
        return article

    def add_context(self, article, config):
        """补齐同版本、同提交的公共控制报告；关联正文也参与去重和证据校验。"""
        source = article.get("tracked_upstream")
        if not source:
            return article
        reports, missing, used = [], [], 0
        for name in config.get("context_reports", []):
            if name == PurePosixPath(source["path"]).name:
                continue
            match = next((url for url, entry in self.upstream_sources.items()
                          if entry["repository"] == source["repository"] and entry["commit"] == source["commit"]
                          and entry["version"] == source["version"] and PurePosixPath(entry["path"]).name == name), None)
            if match is None:
                missing.append(name)
                continue
            context = self.article(match, include_publication=False)
            used += len(context["body"].encode("utf-8"))
            if used > config.get("max_context_bytes", 128000):
                raise ValueError("关联报告总正文超过上限，不能截断后作判断")
            reports.append(context)
        return {**article, "context_reports": reports, "missing_context_reports": missing}

    def google(self, query, config):
        endpoint = "https://www.google.com/search?" + urlencode({"q": query, "num": config.get("max_results", 10), "hl": "en", "udm": 14})
        _, body, _ = self.get(endpoint)
        try:
            return google_results(body)
        except ValueError:
            if not config.get("browser_enabled", False):
                raise
        # 正常渲染 Google 的 JavaScript 页面；不处理或绕过验证码。
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser_env = {key: value for key, value in os.environ.items()
                           if key in {"PATH", "HOME", "LANG", "TMPDIR", "TEMP", "TMP", "PLAYWRIGHT_BROWSERS_PATH", "SystemRoot", "WINDIR"}}
            browser = playwright.chromium.launch(headless=True, env=browser_env)
            try:
                page = browser.new_page()
                def route_request(route):
                    host = urlsplit(route.request.url).hostname or ""
                    allowed = any(host == domain or host.endswith("." + domain)
                                  for domain in ("google.com", "google.com.hk", "gstatic.com", "googleusercontent.com"))
                    if allowed and route.request.resource_type not in {"image", "font", "media"}:
                        route.continue_()
                    else:
                        route.abort()
                page.route("**/*", route_request)
                page.goto(endpoint, wait_until="domcontentloaded", timeout=int(self.budget.timeout(45) * 1000))
                page.wait_for_function("document.querySelector('a h3') || location.pathname.startsWith('/sorry/')", timeout=int(self.budget.timeout(20) * 1000))
                if "/sorry/" in page.url:
                    raise ValueError("Google 返回验证码，未继续搜索")
                return google_results(page.content())
            finally:
                browser.close()

    def search(self, config):
        if not config.get("enabled", True):
            return [], []
        links, errors = [], []
        for query in config["queries"]:
            try:
                if config.get("provider", "bing_rss") == "google":
                    results = self.google(query, config)
                elif config.get("provider", "bing_rss") == "brave":
                    key = os.environ[config.get("api_key_env", "BRAVE_SEARCH_API_KEY")]
                    endpoint = "https://api.search.brave.com/res/v1/web/search?" + urlencode({"q": query, "count": config.get("max_results", 10)})
                    _, body, _ = self.get(endpoint, {"X-Subscription-Token": key})
                    results = [(item["url"], item.get("title", "") + " " + item.get("description", ""))
                               for item in json.loads(body).get("web", {}).get("results", [])]
                else:
                    endpoint = "https://www.bing.com/search?" + urlencode({"format": "rss", "q": query})
                    _, body, _ = self.get(endpoint)
                    root = ET.fromstring(body)
                    if root.tag != "rss" or root.find("channel") is None:
                        raise ValueError("搜索未返回 RSS，可能需要验证码或接口已变化")
                    results = [(item.findtext("link", ""), item.findtext("title", "") + " " + item.findtext("description", ""))
                               for item in root.findall("./channel/item")]
                for value, description in results[:config.get("max_results", 10)]:
                    keywords = config.get("required_keywords", [])
                    if keywords and not any(term.casefold() in (value + " " + description).casefold() for term in keywords):
                        continue
                    try:
                        links.append(normalized_url(value))
                    except ValueError:
                        continue
            except Exception as error:
                errors.append(f"搜索 {query}: {type(error).__name__}: {str(error)[:180]}")
        return list(dict.fromkeys(links)), errors


class ToolFailure(RuntimeError):
    """工具失败默认只暴露退出码，由模型入口单独脱敏处理诊断。"""

    def __init__(self, program, code, stderr):
        super().__init__(f"{Path(program).name} 退出码 {code}")
        self.stderr = stderr


def run_command(args, budget, timeout=120, data=None, env=None):
    options = {"stdin": subprocess.PIPE if data is not None else subprocess.DEVNULL,
               "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": env}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    process = subprocess.Popen([str(arg) for arg in args], **options)
    try:
        stdout, stderr = process.communicate(data, timeout=budget.timeout(timeout))
    except BaseException:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
        else:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        process.kill()
        process.communicate()
        raise
    if process.returncode:
        # 工具输出可能含凭证，错误只保留程序名和退出码。
        raise ToolFailure(args[0], process.returncode, stderr)
    return stdout.decode("utf-8")


class Repository:
    """独立裸仓库读代码并通过 Git 对象更新单个文件，不接触用户工作区。"""

    def __init__(self, config, state_dir, budget):
        self.config, self.budget = config, budget
        self.path = state_dir / "repository.git"
        self.remote = config["remote"]
        self.branch = config.get("branch", "main")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", self.branch) or ".." in self.branch:
            raise ValueError("目标分支格式非法")
        self.homepage = safe_path(config.get("homepage", "README.md"))

    def git(self, *args, data=None, env=None):
        return run_command(["git", "-C", str(self.path), *args], self.budget, data=data, env=env)

    def refresh(self):
        if not self.path.exists():
            run_command(["git", "init", "--bare", str(self.path)], self.budget)
            self.git("remote", "add", "origin", self.remote)
        if self.git("remote", "get-url", "origin").strip() != self.remote:
            raise ValueError("研究副本 remote 不匹配")
        self.git("fetch", "--no-tags", "origin", f"+refs/heads/{self.branch}:refs/remotes/origin/{self.branch}")
        self.commit = self.git("rev-parse", f"refs/remotes/origin/{self.branch}").strip()
        entries = self.git("ls-tree", "-r", "-z", self.commit).split("\0")
        self.entries = {}
        for entry in filter(None, entries):
            meta, path = entry.split("\t", 1)
            mode, kind, oid = meta.split()
            if kind == "blob" and mode in {"100644", "100755"}:
                self.entries[path] = (mode, oid)
        prefixes = self.config.get("source_prefixes", ["src/"])
        self.sources = sorted(path for path in self.entries if any(path.startswith(p) for p in prefixes)
                              and PurePosixPath(path).suffix in SUFFIXES
                              and not any(token in path.lower() for token in ("secret", "credential", "private", ".env")))
        self.code_hash = digest(json.dumps([(path, self.entries[path][1]) for path in self.sources]))
        return self

    def read(self, path):
        if path not in self.entries:
            raise ValueError("目标文件不存在或不是普通跟踪文件")
        if int(self.git("cat-file", "-s", self.entries[path][1])) > 200000:
            raise ValueError("源文件过大")
        return self.git("cat-file", "blob", self.entries[path][1])

    def code(self, paths, maximum=None):
        maximum = maximum or self.config.get("max_code_bytes", 96000)
        if not isinstance(paths, list) or len(paths) > 12:
            raise ValueError("代码选择超过上限")
        files, unavailable, used = {}, [], 0
        required = self.config.get("required_code_paths", [])
        combined = list(dict.fromkeys(required + paths))
        if len(combined) > 20:
            raise ValueError("必读代码与所选文件合计超过20项")
        # 配置指定的关键实现优先，随后实现文件优先于测试文件。
        ordered = required + sorted([p for p in combined if p not in required], key=lambda p: (bool(re.search(r"(?:[./_-])(?:test|tests|spec)(?:[./_-])", p)), combined.index(p)))
        for path in dict.fromkeys(ordered):
            if path not in self.sources:
                raise ValueError("模型选择了未授权代码文件")
            content = self.read(path)
            size = len(content.encode("utf-8"))
            if used + size > maximum:
                unavailable.append(path)
            else:
                files[path] = content
                used += size
        return files, unavailable

    def publish(self, original, updated, config):
        if original == updated:
            return None
        if self.read(self.homepage) != original:
            raise ValueError("首页快照不匹配")
        version = config.get("commit_version", "")
        if not version and "package.json" in self.entries:
            version = json.loads(self.read("package.json")).get("version", "")
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("请配置有效 commit_version")
        author = config["author"]
        env = os.environ.copy()
        for role in ("AUTHOR", "COMMITTER"):
            env[f"GIT_{role}_NAME"] = text(author["name"], "提交作者", 100)
            env[f"GIT_{role}_EMAIL"] = text(author["email"], "提交邮箱", 200)
        with tempfile.TemporaryDirectory(prefix="termiters-index-") as temporary:
            env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
            self.git("read-tree", self.commit, env=env)
            blob = self.git("hash-object", "-w", "--stdin", data=updated.encode()).strip()
            self.git("update-index", "--add", "--cacheinfo", self.entries[self.homepage][0], blob, self.homepage, env=env)
            tree = self.git("write-tree", env=env).strip()
            commit = self.git("commit-tree", tree, "-p", self.commit, "-m", f"{version} 更新隐写记录", env=env).strip()
            # 普通快进推送：远端有并发提交时失败，下轮重新基于最新代码判断。
            self.git("push", "origin", f"{commit}:refs/heads/{self.branch}")
            return commit


class Model:
    """复用 TermiteRS 的模型配置，凭证不经过网页抓取器或研究状态库。"""

    def __init__(self, executable, config, budget, timeout=600, cache_dir=None):
        self.executable, self.config, self.budget, self.timeout = executable, config, budget, timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(mode=0o700, exist_ok=True)

    def __call__(self, phase, evidence):
        cached = None
        if self.cache_dir:
            fingerprint = digest(json.dumps({"protocol": MODEL_PROTOCOL, "phase": phase, "evidence": evidence,
                                             "llm_config": Path(self.config).read_text(encoding="utf-8")}, sort_keys=True, ensure_ascii=False))
            cached = self.cache_dir / (fingerprint + '.json')
            if cached.exists():
                print(f"研究阶段 {phase}：复用本机缓存", flush=True)
                return json.loads(cached.read_text(encoding="utf-8"))
        print(f"研究阶段 {phase}：请求模型", flush=True)
        with tempfile.TemporaryDirectory(prefix="termiters-evidence-") as temporary:
            input_path = Path(temporary) / "input.json"
            with input_path.open("x", encoding="utf-8") as output:
                json.dump({"phase": phase, "evidence": evidence}, output, ensure_ascii=False)
            if os.name != "nt":
                input_path.chmod(0o600)
            try:
                result = run_command([self.executable, "research", "analyze", "--config", self.config,
                                      "--input", input_path], self.budget, self.timeout)
            except ToolFailure as error:
                detail = error.stderr.decode('utf-8', errors='replace')
                for key, value in os.environ.items():
                    if any(word in key.upper() for word in ('KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL')) and len(value) >= 8:
                        detail = detail.replace(value, '[REDACTED]')
                raise RuntimeError('模型调用失败：' + detail.strip()[-1800:]) from None
            parsed = json.loads(result)
            if cached:
                with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.cache_dir, prefix='.stage-', delete=False) as output:
                    json.dump(parsed, output, ensure_ascii=False)
                    output.flush()
                    os.fsync(output.fileno())
                    temporary_cache = output.name
                os.chmod(temporary_cache, 0o600)
                os.replace(temporary_cache, cached)
            return parsed


def claim(value, body, required=True):
    if not required and isinstance(value, dict) and value == {"value": None, "quote": None}:
        return None
    if value is None and not required:
        return None
    if not isinstance(value, dict) or set(value) != {"value", "quote"}:
        raise ValueError("报告声明格式非法")
    result = {"value": text(value["value"], "报告声明", 800), "quote": text(value["quote"], "报告引用", 1000)}
    if result["quote"] not in body:
        raise ValueError("报告引用未在原文中找到")
    return result


def classify_result(result, article):
    if not isinstance(result, dict) or type(result.get("accepted")) is not bool:
        raise ValueError("报告核验格式非法")
    text(result.get("reason"), "核验理由")
    if not result["accepted"]:
        return []
    findings = result.get("findings")
    if not isinstance(findings, list) or not 1 <= len(findings) <= 12:
        raise ValueError("报告机制数量非法")
    validated, ids = [], set()
    for item in findings:
        identifier = text(item.get("id"), "机制ID", 100)
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", identifier) or identifier in ids:
            raise ValueError("机制ID非法或重复")
        ids.add(identifier)
        entry = {"id": identifier, **{key: claim(item.get(key), article["body"], key in {"mechanism", "trigger"})
                                      for key in ("mechanism", "trigger", "version")}}
        # 简表摘要同样进入独立复核；旧状态没有摘要时仍可完整展示证据。
        # 英文标识符按字符计数容易超出中文摘要目标；存储保留全文，展示仍按原宽度压缩。
        for key, limit in (("label", 72), ("trigger_summary", 240)):
            if key in item:
                entry[key] = text(item[key], key, limit)
        if "category" in item:
            if item["category"] not in {"隐写", "环境标记", "协议指纹", "模型水印"}:
                raise ValueError("机制分类非法")
            entry["category"] = item["category"]
        validated.append(entry)
    return validated


def assess_result(result, findings, files, unavailable, report_sources=None):
    assessments = result.get("assessments") if isinstance(result, dict) else None
    ids = {item["id"] for item in findings}
    if not isinstance(assessments, list) or len(assessments) != len(ids) or {a.get("id") for a in assessments} != ids:
        raise ValueError("代码判断未完整对应机制清单")
    validated = {}
    report_errors = []
    for item in assessments:
        status = item.get("status")
        if status not in STATUSES:
            raise ValueError("过滤状态非法")
        reason = text(item.get("reason"), "代码判断理由")
        evidence = item.get("code_evidence")
        if not isinstance(evidence, list) or len(evidence) > 12:
            raise ValueError("代码证据格式非法")
        verified = []
        for entry in evidence:
            path = entry.get("path")
            snippet = text(entry.get("quote"), "代码引用", 2000)
            if path not in files or snippet not in files[path]:
                raise ValueError("代码引用未在指定文件中找到")
            line = files[path][:files[path].index(snippet)].count("\n") + 1
            verified.append({"path": path, "line": line, "quote": snippet})
        if status != "unknown" and (not verified or unavailable):
            status, reason = "unknown", "代码证据不完整，尚不能确定过滤状态。"
        report_evidence = []
        references = item.get("report_evidence", [])
        if not isinstance(references, list) or len(references) > 8 or any(not isinstance(entry, dict) for entry in references):
            raise ValueError("报告控制引用必须为最多8项的列表")
        for entry in references:
            path = entry.get("path")
            snippet = text(entry.get("quote"), "报告控制证据", 2000)
            # 模型偶尔填写报告链接；仅接受本轮证据中唯一匹配的精确链接。
            if report_sources is not None and path not in report_sources:
                matches = [key for key, source in report_sources.items() if source["url"] == path]
                if len(matches) == 1:
                    path = matches[0]
            if report_sources is None or path not in report_sources:
                report_errors.append(f"报告控制引用路径无效：{item['id']}；允许路径：{list(report_sources or {})}")
                continue
            if snippet not in report_sources[path]["body"]:
                # 相近行只帮助定位，仍拒绝当前引用，必须由模型重读并逐字修正。
                nearby = get_close_matches(snippet, report_sources[path]["body"].splitlines(), n=2, cutoff=0.5)
                report_errors.append(f"报告控制引用不匹配：{item['id']}，{path}，引用={snippet!r}；须逐字连续引用，不能添加反引号或改写空白；相近原文行（仅供定位，须核对语义）：{nearby!r}")
                continue
            report_evidence.append({"path": path, "quote": snippet, "url": report_sources[path]["url"]})
        if status == "not_triggered" and report_sources is not None and not report_evidence:
            report_errors.append(f"不触发结论必须引用报告的触发条件或禁用控制依据：{item['id']}")
        summary = text(item.get("summary", reason), "结论简述", 1500)
        validated[item["id"]] = {"status": status, "reason": reason, "summary": summary,
                                 "code_evidence": verified, "report_evidence": report_evidence}
    # 一次反馈全部报告引用错误，避免模型修好第一项后才看到下一项。
    if report_errors:
        raise ValueError("\n".join(report_errors))
    return validated


class ReportEvidenceFailure(ValueError):
    """复核否定报告声明时必须重提机制，不能只让复核改口。"""


def apply_verification(result, assessments):
    verdicts = result.get("verdicts") if isinstance(result, dict) else None
    if not isinstance(verdicts, list) or len(verdicts) != len(assessments) or {v.get("id") for v in verdicts} != set(assessments):
        raise ValueError("复核未完整对应机制清单")
    for verdict in verdicts:
        if type(verdict.get("supported")) is not bool or type(verdict.get("report_supported")) is not bool:
            raise ValueError("复核结果格式非法")
        reason = text(verdict.get("reason"), "复核理由")
        if not verdict["report_supported"]:
            raise ReportEvidenceFailure("报告机制或日期复核未通过：" + reason)
        assessments[verdict["id"]].update(review_supported=verdict["supported"], review_reason=reason)
        if not verdict["supported"]:
            assessments[verdict["id"]].update(status="unknown", reason="复核未通过：" + reason, summary="证据尚不足，详见复核说明。")
    return assessments


def escape(value):
    value = "".join(c if ord(c) >= 32 else " " for c in value)
    value = html.escape(value, quote=False)
    for character in "|`[]*_\\":
        value = value.replace(character, f"&#{ord(character)};")
    return value


def report_link(url):
    return quote(normalized_url(url), safe="/:?=&%+~-._")


def version_rank(value):
    """按报告版本数值倒序；范围取上界，未说明版本统一置后。"""
    versions = re.findall(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", value or "")
    return max((tuple(map(int, version)) for version in versions), default=(-1, -1, -1))


def compact(value, maximum):
    """只缩短展示，不改证据；省略部分可在对应折叠项查看。"""
    value = " ".join(value.split())
    return escape(value if len(value) <= maximum else value[:maximum - 1] + "…")


def render(ledger, current_hash, remote="", upstream=None, evaluation_profile=None):
    lines = [START, "## 隐写与指纹跟踪", "",
             "按报告分析版本新→旧排列。过滤仅对折叠证据列明的路径成立，不是端到端保证；未经真实流量验证，旧版标记不推定新版仍有。发现时间以原报告首发时间为准，不推断引入时间。", "",
             "| 报告版本 | 机制 | 过滤 | 触发条件（摘要） | 发现时间 |", "| --- | --- | --- | --- | --- |"]
    if upstream:
        lines[5:5] = [f"固定研究上游：[{escape(upstream['repository'].removeprefix('https://github.com/'))}]({report_link(upstream['repository'])})；本轮读取提交 [`{upstream['commit'][:12]}`]({upstream['repository']}/commit/{upstream['commit']})。报告目录版本：{escape('、'.join(upstream['versions']))}（不代表官方最新发布版本）。历史来源保留供查证。", ""]
    if upstream:
        lines[3] = "评估前提：假设云端 CLI 为指定上游本轮选中的报告版本，并按报告描述运行。依据报告与网关源码判断过滤效果，不自行逆向 CLI，也不代表已检测部署版本或完成动态验证。历史条目仍按各自报告版本解释。发现时间以原报告首发时间为准。"
        lines[5:5] = ["已过滤＝相关路径移除信号；未过滤＝保留信号或 CLI 自发请求不经网关过滤；当前配置不触发＝有证据表明必要触发条件被禁用，不等于已过滤；待核实＝报告或网关证据仍不足。", ""]
    if evaluation_profile == "unbundle_defaults":
        lines[3] = "评估基准：Unbundle 默认配置；假设云端 CLI 使用下列报告版本，并接受报告描述的行为。结合同版本关联报告判断是否发送及是否过滤，不自行逆向 CLI。发现日期按上游报告文件最早可查提交日期记账，不代表确认或机制引入时间。"
        lines = [line.replace("| 过滤 | 触发条件（摘要） |", "| 默认配置结论 | 原因（简述） |") for line in lines]
    rows = [(identifier, url, item) for identifier, records in ledger.items() for url, item in records.items()]
    rows.sort(key=lambda row: (tuple(-part for part in version_rank((row[2]["finding"].get("version") or {}).get("value"))), row[0], row[1]))
    details = []
    github = re.fullmatch(r"(?:git@github\.com:|https://github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?", remote)
    for number, (identifier, url, item) in enumerate(rows, 1):
        finding, assessment = item["finding"], item["assessment"]
        url = item.get("tracked_upstream", {}).get("url", url)
        stale = item["code_hash"] != current_hash
        status = "待核实（代码已变化）" if stale else STATUSES[assessment["status"]]
        if upstream and item.get("tracked_upstream") and not item.get("evaluation_basis") and not stale:
            status = "待重评（旧评估口径）"
        if evaluation_profile and item.get("evaluation_profile") != evaluation_profile and not stale:
            status = "待重评（默认配置）"
        if item.get("revised"):
            status = "待核实（来源已修订）"
        published = item.get("published")
        discovered = published["value"] if published else "未说明"
        version = finding.get("version")
        label = finding.get("label", finding["mechanism"]["value"])
        category = finding.get("category")
        name = (escape(category) + " · " if category else "") + compact(label, 36)
        trigger = compact(finding.get("trigger_summary", finding["trigger"]["value"]), 90)
        full_version = version["value"] if version else "未说明"
        # 简表只展示版本号；架构、包名等附注留在证据区，不推造版本区间。
        numbers = list(dict.fromkeys(re.findall(r"(?<!\d)\d+\.\d+\.\d+(?!\d)", full_version)))
        version_text = " / ".join(numbers) if numbers else compact(full_version, 24)
        anchor = f"termiters-evidence-{number}"
        active = not upstream or (item.get("tracked_upstream", {}).get("repository") == upstream["repository"]
                                  and item.get("tracked_upstream", {}).get("version") in upstream["versions"])
        if evaluation_profile == "unbundle_defaults":
            if status == STATUSES["not_triggered"]:
                status = "默认关闭／不触发"
            trigger = "条件或配置已变化，等待重新评估。" if status.startswith(("待重评", "待核实（")) else compact(assessment.get("summary", assessment["reason"]), 65)
        if active:
            lines.append(f"| {escape(version_text)} | {name} [↗]({report_link(url)}) | {status} | {trigger} [详情](#{anchor}) | {escape(discovered)} |")
        evidence = []
        for entry in assessment["code_evidence"]:
            location = escape(entry["path"]) + ":" + str(entry["line"])
            if github and re.fullmatch(r"[0-9a-f]{40,64}", item["commit"]):
                location = f"[{location}](https://github.com/{github[1]}/blob/{item['commit']}/{quote(entry['path'], safe='/')}#L{entry['line']})"
            evidence.append(location)
        report_evidence = list(dict.fromkeys("[" + escape(entry["path"]) + "](" + report_link(entry["url"]) + ")"
                           for entry in assessment.get("report_evidence", [])))
        date_basis = published.get("kind", "来源首发日期") if published else "上游未提供可用日期"
        details += [f'<a id="{anchor}"></a>', f"**{number}. {compact(label, 36)}** · {escape(full_version)} · [原报告]({report_link(url)})", "",
                    "评估基准：" + ("假设云端使用报告版本，并接受报告描述的 CLI 行为。" if item.get("evaluation_basis") else "历史记录，尚未按报告版本假设重新评估。"), "",
                    f"机制：{escape(finding['mechanism']['value'])}", "",
                    f"完整触发条件：{escape(finding['trigger']['value'])}", "",
                    f"{status}：{escape(assessment['reason'])}", "",
                    "关联报告依据：" + ("；".join(report_evidence) or "见主报告与代码说明"), "",
                    f"代码：{'、'.join(evidence) or '证据不足'}；审阅提交 {escape(item['commit'][:12])}。发现时间：{escape(discovered)}（{escape(date_basis)}）。", ""]
    lines += ["", "<details>", "<summary>展开完整条件与代码证据</summary>", "", *details, "</details>", "",
              "此追踪由 [TermiteRS](https://github.com/KKBK-233/TermiteRS) 进行在线追踪更新。", "", END]
    return "\n".join(lines)


def update_homepage(original, section):
    if original.count(START) != original.count(END) or original.count(START) > 1:
        raise ValueError("首页研究区标记不完整或重复，停止更新")
    if START in original:
        begin, end = original.index(START), original.index(END)
        if begin >= end:
            raise ValueError("首页研究区标记顺序错误")
        return original[:begin] + section + original[end + len(END):]
    return original.rstrip() + "\n\n" + section + "\n"


def validated_model(model, phase, evidence, validator):
    """引用纠错有界重试；评估最多两次，复核否定机制时仍回到原研究流程。"""
    result = model(phase, evidence)
    limit = 2 if phase == "evaluate" else 1
    for attempt in range(limit + 1):
        try:
            return validator(result)
        except ReportEvidenceFailure:
            raise
        except ValueError as error:
            if attempt == limit:
                raise
            result = model(phase, {**evidence, "correction": {
                "validation_error": str(error), "previous_response": result,
                "instruction": "原文引用必须是原文中逐字连续片段，不要去掉引用中的符号或把多处内容拼接。未说明的版本输出 null。发现时间由执行器读取来源首发时间，不需要提取发现或引入日期。请修正有错误的字段，仍按本阶段原定 JSON 协议返回完整结果，不要为了通过校验改变事实。"}})


def investigate(article, repository, model, ledger, topic, evaluation_profile=None):
    known = [{"id": key, "mechanisms": [r["finding"]["mechanism"]["value"] for r in rows.values()]} for key, rows in ledger.items()]
    upstream_evidence = {"tracked_upstream": article.get("tracked_upstream"),
                         "upstream_policy": "tracked_upstream 是用户明确指定的研究报告上游，不是 Claude 官方上游。只据该文件原文和目标网关源码核验，不把仓库身份当作结论正确的保证，不推断报告目录版本就是官方最新版本。"}
    if article.get("tracked_upstream"):
        upstream_evidence["evaluation_basis"] = {**REPORT_BASELINE, "version": article["tracked_upstream"].get("version")}
        upstream_evidence["upstream_policy"] = "tracked_upstream 是用户明确指定的研究基准，不是 Claude 官方仓库。接受报告所述 CLI 行为作为本次条件评估前提，仍须忠实提取原文机制和完整触发条件；无需再次证明报告的逆向过程，不推断报告版本就是官方最新发布版本。"
    if evaluation_profile == "unbundle_defaults":
        upstream_evidence["deployment_profile"] = DEFAULT_PROFILE
    primary_article = {key: value for key, value in article.items() if key not in {"context_reports", "missing_context_reports"}}
    classification_evidence = {**upstream_evidence, "topic": topic, "article": primary_article, "files": repository.sources, "known_mechanisms": known,
                              "date_policy": "指定上游的发现日期按报告文件最早可查提交日期记录，无需模型确认真实发现或引入时间。"}
    def validate_classification(result):
        return result, classify_result(result, article)
    # 语义复核失败后最多回到提取阶段一次，重读原文、重评代码并再次独立复核。
    for attempt in range(2):
        classification, findings = validated_model(model, "classify", classification_evidence, validate_classification)
        if not findings:
            return {"status": "rejected", "reason": classification["reason"], "findings": []}
        files, unavailable = repository.code(classification.get("code_paths", []))
        evidence = {**upstream_evidence, "article": article, "findings": findings, "files": files, "unavailable_files": unavailable, "commit": repository.commit}
        report_sources = {entry["tracked_upstream"]["path"]: entry
                          for entry in [article, *article.get("context_reports", [])] if entry.get("tracked_upstream")}
        assessments = validated_model(model, "evaluate", evidence,
                                      lambda result: assess_result(result, findings, files, unavailable, report_sources or None))
        try:
            assessments = validated_model(model, "verify", {**evidence, "article": article, "assessments": assessments},
                                          lambda result: apply_verification(result, json.loads(json.dumps(assessments))))
        except ReportEvidenceFailure as error:
            if attempt:
                raise
            classification_evidence = {**classification_evidence, "review_feedback": {
                "reason": str(error), "previous_findings": findings,
                "instruction": "重新核对原报告，修正错误的机制、版本或触发条件，再给出完整提取结果。未知开关不得自行补成确定前置条件。不得只要求复核改口，也不能为了通过而补造证据。"}}
            continue
        records = [{"finding": finding, "assessment": assessments[finding["id"]], "code_hash": repository.code_hash,
                    "commit": repository.commit, "checked_at": now(), "published": article.get("published"),
                    "tracked_upstream": article.get("tracked_upstream") or {},
                    "evaluation_basis": upstream_evidence.get("evaluation_basis"), "evaluation_profile": evaluation_profile,
                    "context_sources": [entry["tracked_upstream"] for entry in article.get("context_reports", [])]} for finding in findings]
        return {"status": "accepted", "reason": classification["reason"], "findings": records}


def cycle(config, state, repository, web, model, state_dir, preview=False):
    """失败逐项保留并在下轮重试；成功结果按正文与代码指纹去重。"""
    run = {"started_at": now(), "errors": [], "processed": 0, "skipped": 0, "published_commit": None}
    state.setdefault("articles", {})
    state.setdefault("ledger", {})
    web.publication_cache = state.setdefault("publication_cache", {})
    if config.get("tracked_upstream"):
        candidates, upstream = web.upstream(config["tracked_upstream"])
        run["tracked_upstream"] = state["tracked_upstream"] = upstream
        # 固定上游模式只调度本轮选定报告，旧来源的历史证据保留但不继续抓取。
        carried = [url for url in state.get("queue", []) if url in candidates]
    else:
        candidates, errors = web.search(config["search"])
        run["errors"].extend(errors)
        candidates = config["search"].get("seed_urls", []) + candidates
        candidates += [url for url, value in state["articles"].items() if value.get("status") in {"accepted", "pending"}]
        carried = state.get("queue", [])
    candidates = list(dict.fromkeys(candidates))
    # 超过每日上限的候选落盘排队，下一轮优先处理，避免后续条目长期饥饿。
    queue = list(dict.fromkeys(carried + candidates))
    queue.sort(key=lambda url: state["articles"].get(url, {}).get("last_attempt", ""))
    if len(queue) > config.get("max_queue", 1000):
        run["errors"].append("候选队列达到上限，请收窄关键词或调整 max_queue")
        queue = queue[:config.get("max_queue", 1000)]
    remaining = []
    for url in queue:
        if run["processed"] >= config.get("max_reports", 6):
            remaining.append(url)
            continue
        try:
            article = web.article(url)
            if config.get("tracked_upstream", {}).get("context_reports"):
                article = web.add_context(article, config["tracked_upstream"])
            previous = state["articles"].get(url, {})
            context_hash = digest(json.dumps({"reports": [(entry["tracked_upstream"]["path"], entry["hash"])
                for entry in article.get("context_reports", [])], "missing": article.get("missing_context_reports", []),
                "profile": config.get("evaluation_profile")}, sort_keys=True))
            report_fingerprint = digest(str(RESEARCH_PROTOCOL) + article["hash"] + config["topic"] + context_hash)
            fingerprint = digest(report_fingerprint + repository.code_hash)
            same_rejected = previous.get("status") == "rejected" and previous.get("report_fingerprint") == report_fingerprint
            if same_rejected or (previous.get("fingerprint") == fingerprint and previous.get("status") == "accepted"):
                # 日期口径独立迁移，不重跑已经核验的机制与代码结论，不沿用旧的研究日期。
                for records in state["ledger"].values():
                    if url in records:
                        records[url]["published"] = article.get("published")
                run["skipped"] += 1
                continue
            run["processed"] += 1
            decision = investigate(article, repository, model, state["ledger"], config["topic"], config.get("evaluation_profile"))
            state["articles"][url] = {"status": decision["status"], "reason": decision["reason"], "fingerprint": fingerprint,
                                      "report_fingerprint": report_fingerprint, "last_attempt": now(), "final_url": article["url"]}
            # 来源修订不静默覆盖其他报告；同一机制的不同来源保留各自版本和日期。
            for records in state["ledger"].values():
                if url in records:
                    records[url]["revised"] = True
            for record in decision["findings"]:
                state["ledger"].setdefault(record["finding"]["id"], {})[url] = record
        except Exception as error:
            detail = f"{type(error).__name__}: {str(error)[:240]}"
            state["articles"][url] = {**state["articles"].get(url, {}), "status": "pending", "last_attempt": now(), "last_error": detail}
            run["errors"].append(f"报告 {url}: {detail}")
            remaining.append(url)
    state["queue"] = list(dict.fromkeys(remaining))
    if state["ledger"]:
        original = repository.read(repository.homepage)
        updated = update_homepage(original, render(state["ledger"], repository.code_hash, config.get("target", {}).get("remote", ""), state.get("tracked_upstream"), config.get("evaluation_profile")))
        (state_dir / "README.preview.md").write_text(updated, encoding="utf-8")
        if config.get("publish", False) and not preview:
            try:
                run["published_commit"] = repository.publish(original, updated, config)
            except Exception as error:
                run["errors"].append("首页发布失败，下轮重新生成：" + type(error).__name__)
    run["finished_at"] = now()
    run["mechanisms"] = len(state["ledger"])
    run["pending"] = len(state["queue"])
    state["last_run"] = run
    return run


def load_config(path):
    path = path.resolve()
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    if config.get("enabled") is not True:
        raise ValueError("请显式启用 research.enabled")
    text(config.get("topic"), "研究主题", 2000)
    search = config.get("search", {})
    if type(search.get("enabled", True)) is not bool:
        raise ValueError("search.enabled 必须为布尔值")
    if search.get("provider", "bing_rss") not in {"google", "bing_rss", "brave"}:
        raise ValueError("不支持的搜索提供方")
    if type(search.get("browser_enabled", False)) is not bool:
        raise ValueError("browser_enabled 必须为布尔值")
    queries = search.get("queries")
    if not isinstance(queries, list) or not 1 <= len(queries) <= 12:
        raise ValueError("需要配置 1 至 12 个关键词查询")
    for query in queries:
        text(query, "搜索词", 500)
    keywords = search.get("required_keywords", [])
    if not isinstance(keywords, list) or len(keywords) > 30:
        raise ValueError("required_keywords 必须为最多30项的列表")
    for keyword in keywords:
        text(keyword, "预筛选关键词", 100)
    if type(search.get("max_results", 10)) is not int or not 1 <= search.get("max_results", 10) <= 20:
        raise ValueError("搜索结果数量应在 1 至 20 之间")
    for url in search.get("seed_urls", []):
        normalized_url(url)
    upstream = config.get("tracked_upstream")
    if upstream is not None:
        if not isinstance(upstream, dict) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", upstream.get("repository", "")):
            raise ValueError("tracked_upstream.repository 必须是明确的 GitHub 仓库")
        if search.get("enabled", True) or search.get("seed_urls"):
            raise ValueError("固定上游模式须关闭搜索并清空 seed_urls，避免混入其他来源")
        branch = text(upstream.get("branch", "main"), "上游分支", 200)
        if any(c in branch for c in "?#\\"):
            raise ValueError("上游分支含非法字符")
        safe_path(upstream.get("versions_dir", "versions"))
        count = upstream.get("latest_versions", 1)
        if type(count) is not int or not 1 <= count <= 3:
            raise ValueError("latest_versions 应在 1 至 3 之间")
        files = upstream.get("report_files", [])
        if not isinstance(files, list) or len(files) > 20:
            raise ValueError("report_files 必须为最多20项的 Markdown 文件名列表")
        for filename in files:
            if safe_path(filename) != PurePosixPath(filename).name or not filename.endswith(".md"):
                raise ValueError("上游报告须为版本目录下的 Markdown 文件")
        context_files = upstream.get("context_reports", [])
        if not isinstance(context_files, list) or len(context_files) > 4 or any(not isinstance(name, str) for name in context_files) or len(set(context_files)) != len(context_files):
            raise ValueError("context_reports 必须为最多4项且不重复的报告文件名列表")
        for filename in context_files:
            if safe_path(filename) != PurePosixPath(filename).name or not filename.endswith(".md"):
                raise ValueError("关联报告须为同版本目录下的 Markdown 文件")
        context_limit = upstream.get("max_context_bytes", 128000)
        if type(context_limit) is not int or not 1024 <= context_limit <= 256000:
            raise ValueError("max_context_bytes 应在 1024 至 256000 之间")
        limit = upstream.get("max_report_bytes", 192000)
        if type(limit) is not int or not 48000 <= limit <= 256000:
            raise ValueError("max_report_bytes 应在 48000 至 256000 之间")
    if config.get("evaluation_profile") not in (None, "unbundle_defaults"):
        raise ValueError("evaluation_profile 仅支持 unbundle_defaults")
    target = config.get("target", {})
    for boolean in ("publish",):
        if type(config.get(boolean, False)) is not bool:
            raise ValueError(f"{boolean} 必须为布尔值")
    remote = text(target.get("remote"), "目标仓库", 1000)
    if not (re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?", remote)
            or re.fullmatch(r"git@github\.com:[\w.-]+/[\w.-]+(?:\.git)?", remote)):
        raise ValueError("自动发布目标须为明确的 GitHub 仓库")
    prefixes = target.get("source_prefixes", ["src/"])
    if not isinstance(prefixes, list) or not prefixes or len(prefixes) > 20:
        raise ValueError("source_prefixes 必须为非空目录列表")
    for prefix in prefixes:
        safe_path(prefix.rstrip("/"))
    required = target.get("required_code_paths", [])
    if not isinstance(required, list) or len(required) > 8:
        raise ValueError("required_code_paths 必须为最多8项的列表")
    for required_path in required:
        safe_path(required_path)
    code_limit = target.get("max_code_bytes", 96000)
    if type(code_limit) is not int or not 1024 <= code_limit <= 128000:
        raise ValueError("max_code_bytes 超出允许范围")
    for key, default, ceiling in (("max_reports", 6, 30), ("timeout_seconds", 7200, 7200),
                                  ("http_timeout_seconds", 30, 120), ("model_timeout_seconds", 600, 1800),
                                  ("max_queue", 1000, 10000)):
        value = config.get(key, default)
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValueError(f"{key} 超出允许范围")
        config[key] = value
    for key, default in (("state_dir", ".termite/research"), ("llm_config", "termite.yml")):
        config[key] = str((path.parent / config.get(key, default)).resolve())
    if config.get("publish"):
        text(config.get("author", {}).get("name"), "提交作者", 100)
        text(config.get("author", {}).get("email"), "提交邮箱", 200)
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--termiters", required=True)
    parser.add_argument("--preview", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    state_dir = Path(config["state_dir"])
    state_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        state_dir.chmod(0o700)
    # SQLite 事务锁随进程退出自动释放，避免掉电遗留锁文件阻断后续调度。
    connection = sqlite3.connect(state_dir / "state.sqlite3", timeout=0, isolation_level=None)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS research_state (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT payload FROM research_state WHERE id=1").fetchone()
        state = json.loads(row[0]) if row else {}
        identity = json.dumps(config["target"], sort_keys=True)
        if state.get("target", identity) != identity:
            raise ValueError("状态目录属于其他研究目标，请选择新目录")
        state["target"] = identity
        budget = Budget(config["timeout_seconds"])
        # Unix 先中断 Python 的阻塞操作，让子工具清理分支执行；外层与 systemd 仍有硬超时。
        if os.name != "nt":
            signal.signal(signal.SIGALRM, alarm_timeout)
            signal.setitimer(signal.ITIMER_REAL, max(0.1, config["timeout_seconds"] - 1))
        try:
            repository = Repository(config["target"], state_dir, budget).refresh()
            web = Web(budget, config["http_timeout_seconds"])
            model = Model(args.termiters, config["llm_config"], budget, config["model_timeout_seconds"], state_dir / "model-cache")
            result = cycle(config, state, repository, web, model, state_dir, args.preview)
        except Exception as error:
            result = {"finished_at": now(), "errors": [type(error).__name__ + ": " + str(error)]}
            state["last_run"] = result
        connection.execute("INSERT OR REPLACE INTO research_state VALUES (1, ?)", (json.dumps(state, ensure_ascii=False),))
        connection.commit()
        (state_dir / "last-run.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result["errors"] else 0
    finally:
        if os.name != "nt":
            signal.setitimer(signal.ITIMER_REAL, 0)
        connection.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"研究未执行：{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
