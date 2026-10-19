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
                item["version"] = {"value": "2.0.0", "quote": "invented version"}
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


class UpstreamTests(unittest.TestCase):
    """固定报告上游的版本发现、提交锁定和模型来源边界。"""

    def setUp(self):
        self.config = {"repository": "https://github.com/wtfwhs/tengu-decoded", "branch": "main"}
        self.commit = "a" * 40
        self.path = "versions/2.1.300/device-fingerprinting.md"
        raw = BODY.encode("utf-8")
        self.blob = research.hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.requests = []
        self.web = research.Web(research.Budget(20))

    def get(self, url, headers=None):
        self.requests.append(url)
        if "/git/ref/heads/" in url:
            data = {"object": {"sha": self.commit, "type": "commit"}}
        elif "/contents/versions?" in url:
            data = [{"type": "dir", "name": value} for value in ["2.1.32", "2.1.300", "2.1.197"]]
        elif "/contents/versions/2.1.300?" in url:
            data = [{"type": "file", "name": "device-fingerprinting.md", "path": self.path, "sha": self.blob},
                    {"type": "file", "name": "bundle.js", "path": "versions/2.1.300/bundle.js", "sha": self.blob}]
        elif "raw.githubusercontent.com/" in url:
            return url, BODY, "text/plain"
        else:
            raise AssertionError("unexpected request: " + url)
        return url, json.dumps(data), "application/json"

    def test_discovers_numeric_latest_and_fetches_verified_pinned_markdown(self):
        with patch.object(self.web, "get", side_effect=self.get):
            urls, upstream = self.web.upstream(self.config)
            article = self.web.article(urls[0])
        self.assertEqual(upstream["versions"], ["2.1.300"])
        self.assertEqual(len(urls), 1)
        self.assertEqual(article["body"], BODY)
        self.assertEqual(article["tracked_upstream"]["commit"], self.commit)
        self.assertIn("/" + self.commit + "/" + self.path, self.requests[-1])
        self.assertIsNone(article["published"])

    def test_large_markdown_is_retained_whole_under_upstream_specific_limit(self):
        with patch.object(self.web, "get", side_effect=self.get):
            urls, _ = self.web.upstream(self.config)
        body = "feature flags\n" + "x" * 132500 + "\nfinal evidence"
        raw = body.encode("utf-8")
        source = self.web.upstream_sources[urls[0]]
        source["blob_sha"] = research.hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        with patch.object(self.web, "get", return_value=(source["raw_url"], body, "text/plain")):
            article = self.web.article(urls[0])
        self.assertEqual(article["body"], body)
        self.assertTrue(article["body"].endswith("final evidence"))

    def test_rejects_raw_content_not_matching_upstream_git_blob(self):
        with patch.object(self.web, "get", side_effect=self.get):
            urls, _ = self.web.upstream(self.config)
        with patch.object(self.web, "get", return_value=(urls[0], BODY + " tampered", "text/plain")):
            with self.assertRaisesRegex(ValueError, "内容指纹"):
                self.web.article(urls[0])

    def test_every_model_phase_receives_explicit_upstream_identity(self):
        source = {"repository": self.config["repository"], "commit": self.commit, "path": self.path, "version": "2.1.300"}
        article = {"url": URL, "body": BODY, "hash": research.digest(BODY), "tracked_upstream": source}
        received = []
        model = FakeModel()
        def capture(phase, evidence):
            received.append((phase, evidence))
            return model(phase, evidence)
        result = research.investigate(article, FakeRepository(), capture, {}, "指纹研究")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual([phase for phase, _ in received], ["classify", "evaluate", "verify"])
        for _, evidence in received:
            self.assertEqual(evidence["tracked_upstream"], source)
            self.assertIn("用户明确指定", evidence["upstream_policy"])
        self.assertEqual(result["findings"][0]["tracked_upstream"], source)
        for _, evidence in received:
            self.assertEqual(evidence["evaluation_basis"]["mode"], "report_baseline")
            self.assertEqual(evidence["evaluation_basis"]["version"], "2.1.300")
            self.assertEqual(evidence["article"]["body"], BODY)
        self.assertEqual(result["findings"][0]["evaluation_basis"], received[0][1]["evaluation_basis"])

    def test_report_baseline_is_not_applied_to_unrelated_sources(self):
        received = []
        model = FakeModel()
        def capture(phase, evidence):
            received.append(evidence)
            return model(phase, evidence)
        research.investigate({"url": URL, "body": BODY}, FakeRepository(), capture, {}, "研究")
        self.assertTrue(all("evaluation_basis" not in evidence for evidence in received))

    def test_not_triggered_requires_code_evidence_and_survives_review(self):
        result = {"assessments": [{"id": "date-mark", "status": "not_triggered", "reason": "报告必要条件被代码关闭",
                                  "code_evidence": [{"path": "src/relay.mjs", "quote": "return input;"}]}]}
        checked = research.assess_result(result, [finding()], {"src/relay.mjs": CODE}, [])
        reviewed = research.apply_verification({"verdicts": [{"id": "date-mark", "report_supported": True,
            "supported": True, "reason": "条件与代码对应"}]}, checked)
        self.assertEqual(reviewed["date-mark"]["status"], "not_triggered")
        self.assertTrue(reviewed["date-mark"]["review_supported"])
        result["assessments"][0]["code_evidence"] = []
        self.assertEqual(research.assess_result(result, [finding()], {}, [])["date-mark"]["status"], "unknown")

    def test_render_distinguishes_baseline_results_from_unmigrated_records(self):
        article = {"url": URL, "body": BODY, "tracked_upstream": {"version": "2.1.300"}}
        result = research.investigate(article, FakeRepository(), FakeModel(), {}, "研究")
        record = result["findings"][0]
        ledger = {"date-mark": {URL: record}}
        upstream = {"repository": self.config["repository"], "commit": self.commit, "versions": ["2.1.300"]}
        rendered = research.render(ledger, "code-v1", upstream=upstream)
        self.assertIn("假设云端 CLI", rendered)
        self.assertIn("| 未过滤 |", rendered)
        self.assertNotIn("旧版标记不推定新版仍有", rendered)
        record.pop("evaluation_basis")
        self.assertIn("待重评（旧评估口径）", research.render(ledger, "code-v1", upstream=upstream))

    def test_fixed_source_cycle_does_not_search_or_requeue_old_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            web, repo, model = FakeWeb(), FakeRepository(), FakeModel()
            source = {"repository": self.config["repository"], "commit": self.commit, "versions": ["2.1.300"]}
            web.upstream = lambda config: ([URL], source)
            web.search = lambda config: self.fail("固定上游不得执行关键词搜索")
            state = {"queue": ["https://old.example/report"]}
            config = {"tracked_upstream": self.config, "topic": "指纹研究", "publish": True, "max_reports": 1}
            result = research.cycle(config, state, repo, web, model, root)
            self.assertFalse(result["errors"])
            self.assertEqual(result["processed"], 1)
            self.assertFalse(state["queue"])
            self.assertIn("固定研究上游", repo.original)
            self.assertIn("wtfwhs/tengu-decoded", repo.original)
            # 相同报告和源码再次轮询不会重复调用模型。
            research.cycle(config, state, repo, web, model, root)
            self.assertEqual(len(model.calls), 3)

    def test_upstream_configuration_requires_exclusive_source_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "research.json"
            config = json.loads((ROOT / "examples/research.json").read_text(encoding="utf-8"))
            config.update(enabled=True, tracked_upstream=self.config)
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "关闭搜索"):
                research.load_config(path)
            config["search"].update(enabled=False, seed_urls=[])
            path.write_text(json.dumps(config), encoding="utf-8")
            self.assertEqual(research.load_config(path)["tracked_upstream"], self.config)
            config["tracked_upstream"] = {**self.config, "report_files": ["../secret.md"]}
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                research.load_config(path)


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
        self.assertIn("| 报告版本 | 机制 | 过滤 | 触发条件（摘要） | 发现时间 |", self.repo.original)
        self.assertIn("未过滤", self.repo.original)
        self.assertIn("发现时间：未说明", self.repo.original)
        self.assertNotIn("引入：", self.repo.original)
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
        self.assertEqual(self.model.calls.count("classify"), 2)
        self.assertEqual(self.model.calls.count("verify"), 2)
        self.assertFalse(self.repo.published)

    def test_semantic_review_returns_feedback_to_extraction_before_rechecking(self):
        original_model = self.model
        requests = []
        def model(phase, evidence):
            requests.append((phase, evidence))
            result = original_model(phase, evidence)
            if phase == "verify" and original_model.calls.count("verify") == 1:
                result['verdicts'][0].update(report_supported=False, reason='触发条件错误，需要重新提取')
            return result
        self.model = model
        result = self.cycle()
        self.assertFalse(result['errors'])
        self.assertEqual([phase for phase, _ in requests], ['classify', 'evaluate', 'verify'] * 2)
        feedback = requests[3][1]['review_feedback']
        self.assertIn('触发条件错误', feedback['reason'])
        self.assertEqual(feedback['previous_findings'][0]['id'], 'date-mark')
        self.assertEqual(len(self.repo.published), 1)

    def test_unspecified_report_dates_are_published_without_inventing_them(self):
        original = self.model.__call__
        def model(phase, evidence):
            result = original(phase, evidence)
            if phase == 'classify':
                result['findings'][0]['discovered'] = None
                result['findings'][0]['introduced'] = None
            return result
        self.model = model
        self.assertFalse(self.cycle()['errors'])
        self.assertIn('发现时间：未说明（以来源首发时间为准）', self.repo.original)

    def test_publication_updates_without_reanalyzing_mechanisms(self):
        self.cycle()
        article = self.web.article
        self.web.article = lambda url: {**article(url), 'published': {'value': '2026-07-01', 'quote': '2026-07-01', 'kind': '首发元数据'}}
        self.cycle()
        self.assertEqual(len(self.model.calls), 3)
        self.assertIn('| 2026-07-01 |', self.repo.original)
        self.assertNotIn('2026-06-30', self.repo.original)
        self.assertNotIn('引入：', self.repo.original)

    def test_readme_instructions_can_change_without_reanalysis_or_overwrite(self):
        self.cycle()
        self.repo.original = '# New deployment guide\n\n' + self.repo.original + '\nManual installation notes\n'
        before = self.repo.original
        self.cycle()
        self.assertEqual(self.repo.original, before)
        self.assertEqual(len(self.model.calls), 3)

    def test_publication_uses_explicit_first_publication_not_update_or_research(self):
        parser = research.Publication()
        parser.feed('<meta property="article:published_time" content="2026-06-30T23:00:00-07:00"><meta property="article:modified_time" content="2026-10-16"><h1>Research</h1><p>Research was done in February 2026.</p>')
        self.assertEqual(parser.result()['value'], '2026-06-30')
        self.assertEqual(parser.result()['kind'], '首发元数据')

    def test_publication_jsonld_ignores_comment_dates(self):
        parser = research.Publication()
        parser.feed('<script type="application/ld+json">' + json.dumps({'@type': 'DiscussionForumPosting', 'datePublished': '2026-06-10T17:25:06Z', 'dateModified': '2026-10-16', 'comment': [{'@type': 'Comment', 'datePublished': '2026-07-02'}]}) + '</script><h1>Issue</h1>')
        self.assertEqual(parser.result()['value'], '2026-06-10')

    def test_title_date_is_allowed_but_dates_in_body_are_not_publication(self):
        parser = research.Publication()
        parser.feed('<div>June 30, 2026</div><h1>Report</h1><p>Research done February 2026; date example 2026-06-29.</p>')
        self.assertEqual(parser.result()['value'], '2026-06-30')
        parser = research.Publication()
        parser.feed('<h1>Report</h1><p>June 30, 2026</p>')
        self.assertIsNone(parser.result())

    def test_conflicting_or_invalid_publication_dates_remain_unknown(self):
        parser = research.Publication()
        parser.feed('<meta property="article:published_time" content="2026-06-30"><meta name="datePublished" content="2026-07-01"><h1>Report</h1>')
        self.assertIsNone(parser.result())
        for value in ('2026-02-30', 'June 31, 2026', 'not a date'):
            self.assertIsNone(research.publication_day(value))

    def test_required_implementation_is_read_before_large_tests(self):
        repo = research.Repository.__new__(research.Repository)
        repo.config = {'required_code_paths': ['src/engine.mjs'], 'max_code_bytes': 40}
        repo.sources = ['src/engine.mjs', 'src/engine.test.mjs', 'src/context.mjs']
        files = {'src/engine.mjs': 'entry' * 4, 'src/engine.test.mjs': 'test' * 10, 'src/context.mjs': 'context'}
        repo.read = files.__getitem__
        selected, unavailable = repo.code(['src/engine.test.mjs', 'src/context.mjs'])
        self.assertEqual(list(selected), ['src/engine.mjs', 'src/context.mjs'])
        self.assertEqual(unavailable, ['src/engine.test.mjs'])

    def test_required_path_cannot_escape_authorized_source_files(self):
        repo = research.Repository.__new__(research.Repository)
        repo.config = {'required_code_paths': ['secret.env']}
        repo.sources = ['src/engine.mjs']
        with self.assertRaises(ValueError):
            repo.code([])

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

    def test_fabricated_quote_does_not_publish_and_is_retried(self):
        self.model.forged = True
        self.assertTrue(self.cycle()["errors"])
        self.assertFalse(self.repo.published)
        self.assertEqual(self.state["articles"][URL]["status"], "pending")
        self.model.forged = False
        self.assertFalse(self.cycle()["errors"])
        self.assertTrue(self.repo.published)

    def test_long_identifier_summary_is_preserved_for_semantic_verification(self):
        entry = finding()
        entry["label"] = "protocol-environment-device-identity-marker"
        entry["trigger_summary"] = "Only if remoteControlMachineId is set, include machine_id in POST /v1/environments/bridge metadata."
        checked = research.classify_result({"accepted": True, "reason": "原文支持", "findings": [entry]}, {"body": BODY})
        self.assertEqual(checked[0]["trigger_summary"], entry["trigger_summary"])
        self.assertGreater(len(checked[0]["trigger_summary"]), 90)

    def test_null_optional_object_is_treated_as_unspecified(self):
        self.assertIsNone(research.claim({'value': None, 'quote': None}, BODY, required=False))
        with self.assertRaises(ValueError):
            research.claim({'value': 'invented', 'quote': None}, BODY, required=False)

    def test_invalid_quote_is_sent_back_for_one_bounded_correction(self):
        calls = []
        def model(phase, evidence):
            calls.append(evidence)
            return {'value': 'exact' if 'correction' in evidence else 'invented'}
        def validate(result):
            if result['value'] != 'exact':
                raise ValueError('引用不在原文')
            return result
        self.assertEqual(research.validated_model(model, 'classify', {'article': BODY}, validate), {'value': 'exact'})
        self.assertEqual(len(calls), 2)
        self.assertIn('引用不在原文', calls[1]['correction']['validation_error'])

    def test_correction_stops_after_second_invalid_result(self):
        calls = []
        def model(phase, evidence):
            calls.append(phase)
            return {}
        def validate(result):
            raise ValueError('原文不支持')
        with self.assertRaises(ValueError):
            research.validated_model(model, 'classify', {}, validate)
        self.assertEqual(len(calls), 2)

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

    def test_policy_change_rechecks_unchanged_reports_then_deduplicates(self):
        self.cycle()
        self.assertEqual(len(self.model.calls), 3)
        with patch.object(research, "RESEARCH_PROTOCOL", research.RESEARCH_PROTOCOL + 1):
            self.cycle()
            self.assertEqual(len(self.model.calls), 6)
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

    def test_render_orders_versions_numerically_and_unknown_last(self):
        self.cycle()
        template = self.state["ledger"]["date-mark"][URL]
        ledger = {}
        for identifier, version in (("a", "2.1.9"), ("b", "2.1.10"), ("c", None), ("d", "2.1.90 / 2.1.92")):
            record = json.loads(json.dumps(template))
            record["finding"].update(label="机制" + identifier, version={"value": version, "quote": ""} if version else None)
            ledger[identifier] = {URL: record}
        rendered = research.render(ledger, self.repo.code_hash)
        table = rendered.split("<details>")[0]
        self.assertLess(table.index("机制d"), table.index("机制b"))
        self.assertLess(table.index("机制b"), table.index("机制a"))
        self.assertLess(table.index("机制a"), table.index("机制c"))

    def test_render_keeps_version_annotations_out_of_compact_table(self):
        self.cycle()
        record = self.state['ledger']['date-mark'][URL]
        record['finding']['version']['value'] = 'v2.1.169（npm 包，native win32-x64）'
        rendered = research.render(self.state['ledger'], self.repo.code_hash)
        self.assertIn('| 2.1.169 |', rendered.split('<details>')[0])
        self.assertNotIn('win32', rendered.split('<details>')[0])
        self.assertIn('native win32-x64', rendered.split('<details>')[1])

    def test_render_keeps_full_evidence_folded_and_links_fixed_commit(self):
        self.cycle()
        record = self.state["ledger"]["date-mark"][URL]
        full = "前置条件" * 40 + "且只有自定义端点才触发"
        record["finding"]["trigger"]["value"] = full
        rendered = research.render(self.state["ledger"], self.repo.code_hash, "git@github.com:example/adapter.git")
        self.assertNotIn(full, rendered.split("<details>")[0])
        self.assertIn(full, rendered.split("<details>")[1])
        self.assertIn("https://github.com/example/adapter/blob/" + self.repo.commit + "/src/relay.mjs#L1", rendered)
        self.assertIn("[详情](#termiters-evidence-1)", rendered)
        self.assertIn('id="termiters-evidence-1"', rendered)
        self.assertTrue(rendered.endswith("此追踪由 [TermiteRS](https://github.com/KKBK-233/TermiteRS) 进行在线追踪更新。\n\n" + research.END))

    def test_classification_validates_compact_labels_and_categories(self):
        item = finding()
        item.update(category="协议指纹", label="版本指纹", trigger_summary="使用自定义端点")
        result = {"accepted": True, "reason": "原始报告", "findings": [item]}
        self.assertEqual(research.classify_result(result, {"body": BODY})[0]["category"], "协议指纹")
        item["label"] = "长" * 73
        with self.assertRaises(ValueError):
            research.classify_result(result, {"body": BODY})
        item["label"], item["category"] = "短名", "未经许可的分类"
        with self.assertRaises(ValueError):
            research.classify_result(result, {"body": BODY})

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

    def test_search_can_be_disabled_for_seed_report_acceptance(self):
        web = research.Web(research.Budget(10))
        with patch.object(web, "get", side_effect=AssertionError("不应请求搜索引擎")):
            self.assertEqual(web.search({"enabled": False}), ([], []))

    def test_model_stage_cache_avoids_repeated_provider_requests(self):
        config = self.root / "llm.yml"
        config.write_text("llm: test", encoding="utf-8")
        model = research.Model("mock", str(config), research.Budget(10), cache_dir=self.root / "cache")
        with patch.object(research, "run_command", return_value='{"accepted":false}') as command:
            self.assertEqual(model("classify", {"article": "one"}), {"accepted": False})
            self.assertEqual(model("classify", {"article": "one"}), {"accepted": False})
            self.assertEqual(command.call_count, 1)
            model("classify", {"article": "changed"})
            self.assertEqual(command.call_count, 2)

    def test_model_diagnostic_redacts_environment_credentials(self):
        model = research.Model('mock', 'mock.yml', research.Budget(10))
        error = research.ToolFailure('mock', 1, b'HTTP failed: synthetic-secret-key')
        with patch.dict(research.os.environ, {'DS_API_KEY': 'synthetic-secret-key'}), patch.object(research, 'run_command', side_effect=error):
            with self.assertRaises(RuntimeError) as raised:
                model('classify', {})
        self.assertNotIn('synthetic-secret-key', str(raised.exception))
        self.assertIn('[REDACTED]', str(raised.exception))

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

    def test_concurrent_readme_deployment_edit_survives_refresh_and_retry(self):
        original = self.repo.read('README.md')
        manual = '# Deploy guide\n\nNew installation instructions.\n'
        (self.work / 'README.md').write_text(manual, encoding='utf-8')
        self.git('-C', str(self.work), 'add', 'README.md')
        self.git('-C', str(self.work), 'commit', '-m', '1.0.1 deployment guide')
        self.git('-C', str(self.work), 'push', 'origin', 'main')
        with self.assertRaises(RuntimeError):
            self.repo.publish(original, research.update_homepage(original, research.START + '\nOld research\n' + research.END), self.publish_config)
        self.repo.refresh()
        updated = research.update_homepage(self.repo.read('README.md'), research.START + '\nNew research\n' + research.END)
        commit = self.repo.publish(manual, updated, self.publish_config)
        published = self.git('-C', str(self.remote), 'show', commit + ':README.md')
        self.assertTrue(published.startswith(manual))
        self.assertEqual((self.work / 'README.md').read_text(encoding='utf-8'), manual)


if __name__ == "__main__":
    unittest.main()
