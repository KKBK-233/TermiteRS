"""每日研究的行为回归：去重、证据边界、持续重试与最小首页发布。"""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("research_watch", ROOT / "scripts/research_watch.py")
research = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(research)
URL = "https://research.example/report"
BODY = "Original reverse engineering. Version 2.1.196. Discovered June 30, 2026. The date marks the custom endpoint. The request keeps its punctuation."
CODE = "export function relay(input) { return input; }\n"


def finding():
    return {"id": "date-mark", "mechanism": {"value": "日期标记", "quote": "The date marks the custom endpoint."},
            "trigger": {"value": "使用自定义端点", "quote": "custom endpoint"},
            "version": {"value": "2.1.196", "quote": "Version 2.1.196"},
            "discovered": {"value": "2026-06-30", "quote": "Discovered June 30, 2026"}, "introduced": None}


class FakeModel:
    def __init__(self):
        self.calls = []
        self.accepted = True
        self.supported = True
        self.report_supported = True
        self.forged = False

    def __call__(self, phase, evidence):
        self.calls.append(phase)
        if phase == "classify":
            item = finding()
            if self.forged:
                item["introduced"] = {"value": "2026-01-01", "quote": "invented introduction date"}
            return {"accepted": self.accepted, "reason": "存在原创技术分析", "code_paths": ["src/relay.mjs"], "findings": [item]}
        if phase == "evaluate":
            return {"assessments": [{"id": "date-mark", "status": "unfiltered", "reason": "实现直接返回输入。",
                                      "code_evidence": [{"path": "src/relay.mjs", "quote": "return input;"}]}]}
        return {"verdicts": [{"id": "date-mark", "report_supported": self.report_supported,
                              "supported": self.supported, "reason": "逐字核对实现路径"}]}


class FakeWeb:
    def __init__(self):
        self.body = BODY
        self.links = [URL]
        self.fail = False

    def search(self, config):
        return self.links, []

    def article(self, url):
        if self.fail:
            raise OSError("测试抓取失败")
        return {"url": url, "body": self.body, "hash": research.digest(self.body)}


class FakeRepository:
    def __init__(self):
        self.sources = ["src/relay.mjs"]
        self.code_hash = "code-v1"
        self.commit = "a" * 40
        self.homepage = "README.md"
        self.original = "# 项目\n\n原有首页内容。\n"
        self.published = []

    def code(self, paths):
        return {"src/relay.mjs": CODE}, []

    def read(self, path):
        return self.original

    def publish(self, original, updated, config):
        if original == updated:
            return None
        self.published.append(updated)
        self.original = updated
        return "b" * 40


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.web, self.model = FakeRepository(), FakeWeb(), FakeModel()
        self.state = {}
        self.config = {"topic": "CLI 隐写", "search": {"queries": ["CLI 隐写"]}, "publish": True, "max_reports": 6}

    def cycle(self, preview=False):
        return research.cycle(self.config, self.state, self.repo, self.web, self.model, self.root, preview)

    def test_publish_four_fields_and_unchanged_cycle_does_not_call_model(self):
        result = self.cycle()
        self.assertFalse(result["errors"])
        self.assertEqual(self.model.calls, ["classify", "evaluate", "verify"])
        self.assertIn("| 隐写机制 | 过滤状态 | 触发条件 | 发现／引入时间", self.repo.original)
        self.assertIn("未过滤", self.repo.original)
        self.assertIn("引入：报告未说明", self.repo.original)
        self.assertTrue(self.repo.original.startswith("# 项目\n\n原有首页内容。"))
        self.cycle()
        self.assertEqual(len(self.model.calls), 3)
        self.assertEqual(len(self.repo.published), 1)

    def test_changed_code_rechecks_known_report_even_when_search_no_longer_returns_it(self):
        self.cycle()
        self.web.links = []
        self.repo.code_hash = "code-v2"
        self.repo.commit = "c" * 40
        self.cycle()
        self.assertEqual(len(self.model.calls), 6)

    def test_changed_report_is_rechecked(self):
        self.cycle()
        self.web.body += " Report updated."
        self.cycle()
        self.assertEqual(len(self.model.calls), 6)

    def test_revised_report_does_not_leave_old_claim_as_current(self):
        self.cycle()
        self.web.body += " This analysis has been withdrawn."
        self.model.accepted = False
        self.cycle()
        self.assertIn("来源已修订", self.repo.original)

    def test_report_verification_failure_prevents_publication(self):
        self.model.report_supported = False
        self.assertTrue(self.cycle()["errors"])
        self.assertFalse(self.repo.published)

    def test_untrusted_prose_cannot_inject_markdown_links(self):
        self.assertNotIn("[click]", research.escape("[click](https://example.org)"))

    def test_irrelevant_report_is_cached_without_evaluation_or_publication(self):
        self.model.accepted = False
        self.cycle()
        self.cycle()
        self.assertEqual(self.model.calls, ["classify"])
        self.assertFalse(self.repo.published)

    def test_code_change_does_not_reanalyze_rejected_article(self):
        self.model.accepted = False
        self.cycle()
        self.repo.code_hash = "changed-code"
        self.cycle()
        self.assertEqual(self.model.calls, ["classify"])

    def test_pending_report_does_not_starve_unseen_candidates(self):
        self.config["max_reports"] = 1
        self.model.forged = True
        self.cycle()
        self.web.links.append(URL + "-new")
        self.model.forged = False
        self.cycle()
        self.assertEqual(self.state["articles"][URL + "-new"]["status"], "accepted")

    def test_fabricated_date_does_not_publish_and_is_retried(self):
        self.model.forged = True
        self.assertTrue(self.cycle()["errors"])
        self.assertFalse(self.repo.published)
        self.assertEqual(self.state["articles"][URL]["status"], "pending")
        self.model.forged = False
        self.assertFalse(self.cycle()["errors"])
        self.assertTrue(self.repo.published)

    def test_failed_fetch_does_not_count_as_completed(self):
        self.web.fail = True
        self.assertTrue(self.cycle()["errors"])
        self.assertFalse(self.model.calls)
        self.web.fail = False
        self.assertFalse(self.cycle()["errors"])

    def test_verifier_disagreement_is_not_published_as_unfiltered(self):
        self.model.supported = False
        self.cycle()
        self.assertIn("待核实", self.repo.original)
        self.assertNotIn("未过滤", self.repo.original)

    def test_preview_produces_document_without_pushing(self):
        self.cycle(preview=True)
        self.assertTrue((self.root / "README.preview.md").exists())
        self.assertFalse(self.repo.published)
        self.cycle()
        self.assertTrue(self.repo.published)

    def test_budgeted_candidates_survive_to_next_cycle(self):
        self.config["max_reports"] = 1
        self.web.links = [URL, URL + "-second"]
        self.cycle()
        self.assertIn(URL + "-second", self.state["queue"])
        self.cycle()
        self.assertEqual(len(self.model.calls), 6)

    def test_unknown_and_missing_code_never_become_definite(self):
        result = {"assessments": [{"id": "date-mark", "status": "filtered", "reason": "候选判断", "code_evidence": []}]}
        checked = research.assess_result(result, [finding()], {}, [])
        self.assertEqual(checked["date-mark"]["status"], "unknown")

    def test_code_quote_must_match_selected_file(self):
        result = {"assessments": [{"id": "date-mark", "status": "filtered", "reason": "候选判断",
                                    "code_evidence": [{"path": "src/relay.mjs", "quote": "removeAllMarkers()"}]}]}
        with self.assertRaises(ValueError):
            research.assess_result(result, [finding()], {"src/relay.mjs": CODE}, [])

    def test_duplicate_or_broken_document_markers_stop_writing(self):
        for original in (research.START, research.END + research.START, research.START + research.START + research.END + research.END):
            with self.assertRaises(ValueError):
                research.update_homepage(original, "new section")

    def test_render_marks_old_code_as_pending(self):
        self.cycle()
        self.assertIn("代码已变化", research.render(self.state["ledger"], "another-hash"))

    def test_private_dns_and_non_https_targets_are_blocked(self):
        for url in ("http://example.org", "https://user:pass@example.org", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                research.normalized_url(url)
        with patch.object(research.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                research.Web(research.Budget(5)).get("https://example.org")

    def test_html_script_does_not_enter_evidence(self):
        parser = research.PageText()
        parser.feed("<h1>Report</h1><script>secretInstructions()</script><p>Actual evidence</p>")
        self.assertIn("Actual evidence", "".join(parser.parts))
        self.assertNotIn("secretInstructions", "".join(parser.parts))

    def test_deadline_is_enforced(self):
        budget = research.Budget(1)
        budget.deadline = 0
        with self.assertRaises(TimeoutError):
            budget.timeout(30)

    def test_search_parses_indexed_urls_and_reports_invalid_response(self):
        web = research.Web(research.Budget(10))
        rss = '<rss><channel><item><link>https://research.example/new</link></item></channel></rss>'
        with patch.object(web, "get", return_value=("https://www.bing.com/", rss, "application/rss+xml")):
            links, errors = web.search({"queries": ["CLI reverse engineering"]})
        self.assertEqual(links, ["https://research.example/new"])
        self.assertFalse(errors)
        with patch.object(web, "get", return_value=("https://www.bing.com/", "<html>captcha</html>", "text/html")):
            links, errors = web.search({"queries": ["CLI reverse engineering"]})
        self.assertFalse(links)
        self.assertTrue(errors)

    def test_search_keyword_gate_excludes_generic_product_pages(self):
        web = research.Web(research.Budget(10))
        rss = ('<rss><channel><item><title>Claude download</title><link>https://example.org/product</link></item>'
               '<item><title>Claude prompt steganography</title><link>https://example.org/report</link></item></channel></rss>')
        with patch.object(web, "get", return_value=("https://www.bing.com/", rss, "application/rss+xml")):
            links, errors = web.search({"queries": ["CLI"], "required_keywords": ["stegan", "隐写"]})
        self.assertEqual(links, ["https://example.org/report"])
        self.assertFalse(errors)

    def test_google_extracts_direct_and_redirected_results(self):
        body = ('<a href="https://support.google.com/websearch">Help</a>'
                '<a href="/url?q=https%3A%2F%2Fresearch.example%2Fpost&amp;sa=U"><h3>Hidden markers</h3></a>'
                '<a href="https://another.example/post"><h3>Original reverse engineering</h3></a>')
        self.assertEqual([url for url, _ in research.google_results(body)], ["https://research.example/post", "https://another.example/post"])

    def test_google_javascript_gate_is_not_reported_as_no_results(self):
        web = research.Web(research.Budget(10))
        with patch.object(web, "get", return_value=("https://www.google.com/", "<html>Please enable JavaScript</html>", "text/html")):
            links, errors = web.search({"provider": "google", "queries": ["reverse engineering"]})
        self.assertFalse(links)
        self.assertIn("JavaScript", errors[0])

    def test_known_original_is_processed_before_generic_search_hits(self):
        self.config["max_reports"] = 1
        self.config["search"]["seed_urls"] = [URL + "-original"]
        self.cycle()
        self.assertEqual(self.state["articles"][URL + "-original"]["status"], "accepted")
        self.assertNotIn(URL, self.state["articles"])

    def test_example_remains_opt_in_and_active_config_resolves_paths(self):
        config = json.loads((ROOT / "examples/research.json").read_text(encoding="utf-8"))
        path = self.root / "research.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        with self.assertRaises(ValueError):
            research.load_config(path)
        config["enabled"] = True
        config["target"]["remote"] = "https://github.com/example/project.git"
        path.write_text(json.dumps(config), encoding="utf-8")
        loaded = research.load_config(path)
        self.assertEqual(loaded["state_dir"], str((self.root / ".termite/research").resolve()))
        self.assertFalse(loaded["publish"])


class GitPublishTests(unittest.TestCase):
    """使用本机临时 bare remote 验证真实 Git 发布，不访问网络或调用模型。"""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.work = self.root / "work"
        self.git("init", "--bare", str(self.remote))
        self.git("init", "-b", "main", str(self.work))
        self.git("-C", str(self.work), "config", "user.name", "Research Test")
        self.git("-C", str(self.work), "config", "user.email", "test@example.invalid")
        (self.work / "README.md").write_text("# Fixture\n", encoding="utf-8")
        (self.work / "package.json").write_text('{"version":"1.0.0"}', encoding="utf-8")
        (self.work / "src").mkdir()
        (self.work / "src/relay.mjs").write_text(CODE, encoding="utf-8")
        self.git("-C", str(self.work), "add", ".")
        self.git("-C", str(self.work), "commit", "-m", "1.0.0 fixture")
        self.git("-C", str(self.work), "remote", "add", "origin", str(self.remote))
        self.git("-C", str(self.work), "push", "origin", "main")
        state = self.root / "state"
        state.mkdir()
        self.repo = research.Repository({"remote": str(self.remote), "branch": "main", "source_prefixes": ["src/"]}, state, research.Budget(30)).refresh()
        self.publish_config = {"author": {"name": "Research Test", "email": "test@example.invalid"}}

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.PIPE).decode().strip()

    def test_publication_changes_only_readme_and_preserves_working_tree(self):
        (self.work / "src/relay.mjs").write_text("user uncommitted work", encoding="utf-8")
        original = self.repo.read("README.md")
        commit = self.repo.publish(original, original + "\nResearch\n", self.publish_config)
        changed = self.git("-C", str(self.remote), "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
        self.assertEqual(changed, "README.md")
        self.assertEqual((self.work / "src/relay.mjs").read_text(), "user uncommitted work")
        self.assertIn("src/relay.mjs", self.repo.sources)
        self.assertEqual(self.repo.code(["src/relay.mjs"])[0]["src/relay.mjs"], CODE)

    def test_concurrent_remote_commit_is_not_overwritten(self):
        (self.work / "other.txt").write_text("other work")
        self.git("-C", str(self.work), "add", "other.txt")
        self.git("-C", str(self.work), "commit", "-m", "1.0.1 other")
        self.git("-C", str(self.work), "push", "origin", "main")
        newer = self.git("-C", str(self.remote), "rev-parse", "refs/heads/main")
        with self.assertRaises(RuntimeError):
            self.repo.publish(self.repo.read("README.md"), "# New\n", self.publish_config)
        self.assertEqual(self.git("-C", str(self.remote), "rev-parse", "refs/heads/main"), newer)


if __name__ == "__main__":
    unittest.main()
