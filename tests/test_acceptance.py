"""Acceptance coverage for the code quality auditor.

Requirement IDs in the docstrings are the traceability evidence. A requirement
is verified only when the assertion below it passes.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".cursor" / "skills" / "code-quality-auditor"
SCRIPT = SKILL / "scripts" / "auditor.py"
sys.path.insert(0, str(SKILL / "scripts"))

spec = importlib.util.spec_from_file_location("auditor", SCRIPT)
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)

from cqa.catalog import load  # noqa: E402
from cqa.executor import TransientFailure, execute  # noqa: E402
from cqa.security import ExecutionLog, install_analyzer, install_skill, run_contained, runtime_probe  # noqa: E402
from cqa.project import init_repository, manage_profile  # noqa: E402
from cqa.reporting import compare_history, render_html, trends  # noqa: E402
from cqa import checks as check_module  # noqa: E402


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def repo(self, name="repo"):
        path = self.tmp / name
        path.mkdir()
        return path

    def out(self):
        path = self.tmp / "out"
        path.mkdir(exist_ok=True)
        return path

    def audit(self, repo, **kwargs):
        kwargs.setdefault("skill_root", SKILL)
        kwargs.setdefault("output_dir", self.out() / kwargs.get("profile", "run"))
        Path(kwargs["output_dir"]).mkdir(parents=True, exist_ok=True)
        return auditor.audit(repo, **kwargs)

    def test_skill_contract(self):
        """Requirements: 1.1, 1.3, 1.4, 13.1, 13.5."""
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: code-quality-auditor", text)
        self.assertIn("/code-quality-auditor", text)
        self.assertIn("full", text)
        self.assertIn("natural-language", text.lower())
        self.assertTrue((SKILL / "scripts" / "auditor.py").is_file())
        for name in ("metrics.yaml", "checks.yaml", "tools.yaml", "policy.yaml", "schema.yaml"):
            self.assertTrue((SKILL / "config" / name).is_file())
        self.assertEqual(load(SKILL / "quality-auditor.yaml")["default_profile"], "full")

    def test_catalog_contract(self):
        """Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.11, 4.1, 4.2, 4.5, 4.7, 13.2, 13.6."""
        metrics = load(SKILL / "config" / "metrics.yaml")["metrics"]
        checks = load(SKILL / "config" / "checks.yaml")["checks"]
        tools = load(SKILL / "config" / "tools.yaml")
        self.assertEqual(len(metrics), 112)
        self.assertFalse(auditor.catalog_validation(metrics, checks))
        self.assertTrue(all(item["default_enabled"] is True for item in checks.values()))
        kinds = {item["kind"] for item in metrics}
        self.assertEqual(kinds, {"defect_counter", "quality_measure"})
        reference = (SKILL / "references" / "checks.md").read_text(encoding="utf-8")
        tool_reference = (SKILL / "references" / "tools.md").read_text(encoding="utf-8")
        for check_id in checks:
            self.assertIn(f"## {check_id}", reference)
        for tool_id in tools["tools"]:
            self.assertIn(f"## {tool_id}", tool_reference)
        from cqa.catalog import render_checks_reference
        from cqa.reporting import dedupe_findings

        generated = render_checks_reference(load(SKILL / "config" / "checks.yaml"))
        for check_id in checks:
            self.assertIn(f"## {check_id}", generated)
        duplicated = dedupe_findings(
            [
                {"file": "a.py", "line": 1, "metric_ids": ["SEC-001"], "observation": "confirmed aws_access_key", "tool": {"name": "cqa-builtin"}},
                {"file": "a.py", "line": 1, "metric_ids": ["SEC-001"], "observation": "confirmed aws_access_key", "tool": {"name": "gitleaks"}},
            ]
        )
        self.assertEqual(len(duplicated), 1)
        self.assertEqual(duplicated[0]["corroboration"][0]["name"], "gitleaks")
        self.assertIn("registry_version", tools)
        for path in (SKILL / "config").glob("*"):
            self.assertIn(path.suffix, {".yaml", ".yml"})
        with self.assertRaises(ValueError):
            load(self.tmp / "bad.json") if False else auditor.load(self._json_path())

    def _json_path(self):
        path = self.tmp / "bad.json"
        path.write_text("{}", encoding="utf-8")
        return path

    def test_profile_rules(self):
        """Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.12, 13.3, 14.2."""
        checks = load(SKILL / "config" / "checks.yaml")["checks"]
        conf = load(SKILL / "quality-auditor.yaml")
        for name in ("full", "fast", "expensive", "pr-review", "security"):
            self.assertIn(name, conf["profiles"])
        selected, _trace = auditor.resolve_profile("full", conf, checks)
        self.assertEqual(selected, set(checks))
        self.assertEqual(conf.get("check_overrides"), {})
        absent = {"profiles": {"full": {}}}
        self.assertEqual(auditor.resolve_profile("full", absent, checks)[0], set(checks))
        custom = {
            "profiles": {
                "pre-release": {"extends": "fast", "include": ["mutation_testing"]},
                "deep-quant": {"extends": "security", "include": ["quantitative"]},
                "loop-a": {"extends": "loop-b"},
                "loop-b": {"extends": "loop-a"},
            }
        }
        pre, _trace = auditor.resolve_profile("pre-release", custom, checks)
        self.assertIn("mutation_testing", pre)
        deep, _trace = auditor.resolve_profile("deep-quant", custom, checks)
        self.assertIn("quantitative", deep)
        self.assertIn("secrets", deep)
        child_exclude = {"profiles": {"child": {"extends": "full", "include": ["secrets"], "exclude": ["secrets"]}}}
        self.assertNotIn("secrets", auditor.resolve_profile("child", child_exclude, checks)[0])
        with self.assertRaises(ValueError):
            auditor.resolve_profile("missing", conf, checks)
        with self.assertRaises(ValueError):
            auditor.resolve_profile("loop-a", custom, checks)
        explanation = auditor.explain_profile("fast", conf, checks)
        self.assertIn("exclude wins", explanation)
        self.assertIn("child include", explanation.lower())
        listed = manage_profile(SKILL / "quality-auditor.yaml", "list", checks)
        self.assertIn("full", listed["profiles"])

    def test_user_profile_crud_and_security_lock(self):
        """Requirements: 3.10, 3.11, 3.13, 3.14, 9.7, 10.11."""
        checks = load(SKILL / "config" / "checks.yaml")["checks"]
        path = self.tmp / "quality-auditor.yaml"
        path.write_text("version: 1\ndefault_profile: full\nprofiles:\n  full: {}\n", encoding="utf-8")
        blocked = manage_profile(path, "create", checks, name="pre-release", body={"extends": "full"}, approve_write=False)
        self.assertEqual(blocked["status"], "approval_required")
        self.assertNotIn("pre-release", path.read_text(encoding="utf-8"))
        created = manage_profile(path, "create", checks, name="pre-release", body={"extends": "full", "scope": "changed"}, approve_write=True)
        self.assertTrue(created["written"])
        self.assertIn("changed", auditor.explain_profile("pre-release", auditor.load(path), checks))
        manage_profile(path, "delete", checks, name="pre-release", approve_write=True)
        self.assertNotIn("pre-release", path.read_text(encoding="utf-8"))
        repo = self.repo()
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: full
        allow_repo_execution: true
        policy:
          zero_confirmed_violations: false
        profiles:
          full: {}
        """)
        with self.assertRaises(ValueError):
            self.audit(repo)
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: full
        allow_repo_execution: true
        thresholds:
          SEC-001: 5
        profiles:
          full: {}
        """)
        _write(repo / "app.py", "def main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n")
        report = self.audit(repo, profile="security")
        self.assertIn("allow_repo_execution", report["execution"]["ignored_security_overrides"])
        self.assertFalse(report["execution"]["commands"] and any("pytest" in " ".join(item["command"]) for item in report["execution"]["commands"]))
        self.assertEqual(report["effective_policy"]["thresholds"]["SEC-001"]["value"], 5)
        self.assertEqual(report["effective_policy"]["zero_confirmed_violations"], True)
        self.assertEqual(report["configuration_precedence"][0], "explicit invocation overrides")

    def test_dag_runtime(self):
        """Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.11, 5.12, 14.3."""
        registry = {
            "symbol_index": {"id": "symbol_index", "depends_on": []},
            "dead_code": {"id": "dead_code", "depends_on": ["symbol_index"]},
            "left": {"id": "left", "depends_on": []},
            "right": {"id": "right", "depends_on": []},
        }
        with self.assertRaises(ValueError):
            auditor.dag({"dead_code"}, {"dead_code": {"id": "dead_code", "depends_on": ["dead_code"]}})
        evidence = {"builds": 0}
        arrived = self.tmp / "parallel-arrived"

        def symbol(_task, store):
            store["builds"] += 1
            store["graph"] = {"ready": True}
            return {"ok": True}

        def dead(_task, store):
            self.assertTrue(store["graph"]["ready"])
            return {"used": True}

        def parallel(task, _store):
            with arrived.open("a", encoding="utf-8") as handle:
                handle.write(task + "\n")
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                text = arrived.read_text(encoding="utf-8") if arrived.exists() else ""
                if "left" in text and "right" in text:
                    return {"task": task}
                time.sleep(0.01)
            raise TimeoutError("peer did not start")

        plan = execute(
            {"dead_code"},
            registry,
            {"symbol_index": symbol, "dead_code": dead},
            evidence,
            {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(plan["ok"])
        self.assertEqual(evidence["builds"], 1)
        self.assertEqual(plan["order"][0], "symbol_index")
        parallel_result = execute(
            {"left", "right"},
            registry,
            {"left": parallel, "right": parallel},
            {},
            {"concurrency": 2, "max_retries": 1, "task_timeout_seconds": 2},
        )
        self.assertTrue(parallel_result["ok"])
        self.assertEqual(len(parallel_result["layers"][0]), 2)

        counter = self.tmp / "flaky-count"
        counter.write_text("0", encoding="utf-8")

        def flaky(_task, _store):
            count = int(counter.read_text(encoding="utf-8")) + 1
            counter.write_text(str(count), encoding="utf-8")
            if count < 2:
                raise TransientFailure("temporary")
            return {"done": True}

        retried = execute(
            {"left"},
            registry,
            {"left": flaky},
            {},
            {"concurrency": 1, "max_retries": 2, "retry_backoff_seconds": 0, "task_timeout_seconds": 2},
        )
        self.assertTrue(retried["ok"])
        self.assertGreaterEqual(len(retried["tasks"][0]["attempts"]), 2)

        def broken(_task, _store):
            raise ValueError("deterministic")

        failed = execute(
            {"dead_code"},
            registry,
            {"symbol_index": broken, "dead_code": dead},
            {},
            {"concurrency": 1, "max_retries": 3, "task_timeout_seconds": 2},
        )
        self.assertFalse(failed["ok"])
        symbol_attempts = next(task for task in failed["tasks"] if task["task_id"] == "symbol_index")
        self.assertEqual(len(symbol_attempts["attempts"]), 1)
        self.assertFalse(symbol_attempts["attempts"][0]["transient"])
        dependent = next(task for task in failed["tasks"] if task["task_id"] == "dead_code")
        self.assertIn("dependency failed", dependent["error"])

        def sleepy(_task, _store):
            time.sleep(0.4)
            return {"late": True}

        timed = execute(
            {"left"},
            registry,
            {"left": sleepy},
            {},
            {"concurrency": 1, "max_retries": 1, "task_timeout_seconds": 0.1},
        )
        self.assertFalse(timed["ok"])
        self.assertEqual(timed["tasks"][0]["attempts"][0]["outcome"], "timeout")

        calls = {"n": 0}
        cache = self.tmp / "cache"

        def counted(_task, _store):
            calls["n"] += 1
            return {"value": calls["n"]}

        options = {
            "concurrency": 1,
            "max_retries": 1,
            "task_timeout_seconds": 2,
            "cache_dir": cache,
            "fingerprint": lambda task: "same-" + task,
        }
        execute({"left"}, registry, {"left": counted}, {}, options)
        execute({"left"}, registry, {"left": counted}, {}, options)
        self.assertEqual(calls["n"], 1)
        options["fingerprint"] = lambda task: "changed-" + task
        execute({"left"}, registry, {"left": counted}, {}, options)
        self.assertEqual(calls["n"], 2)

    def test_graph_duplication_and_architecture(self):
        """Requirements: 5.10, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.10, 6.11, 6.12, 6.13, 6.14, 8.1, 8.2, 14.4, 14.5."""
        repo = self.repo()
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: focused
        architecture:
          layers:
            - name: domain
              paths: [src/domain]
              allowed_dependencies: []
            - name: api
              paths: [src/api]
              allowed_dependencies: []
        profiles:
          focused:
            include: [syntax_static, symbol_index, dead_code, duplication, semantic_duplication, architecture, clean_code]
        """)
        _write(repo / "app.py", """
        def route(path):
            def deco(fn):
                return fn
            return deco

        @route('/health')
        def health():
            return 'ok'

        def unused():
            return 1

        def main():
            if False:
                return 2
            return health()

        if __name__ == '__main__':
            main()
        """)
        _write(repo / "src" / "domain" / "model.py", """
        def price(units, rate):
            total = units * rate
            if total > 0:
                return total
            return 0
        """)
        _write(repo / "src" / "api" / "server.py", """
        from src.domain.model import price

        def quote(units, rate):
            total = units * rate
            if total > 0:
                return total
            return 0
        """)
        _write(repo / "left.py", """
        def shared_block(value):
            step = value + 1
            step = step + 2
            step = step + 3
            step = step + 4
            step = step + 5
            step = step + 6
            return step
        """)
        _write(repo / "right.py", """
        def shared_block(value):
            step = value + 1
            step = step + 2
            step = step + 3
            step = step + 4
            step = step + 5
            step = step + 6
            return step
        """)
        report = self.audit(repo, profile="focused")
        by_id = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(by_id["GRAPH-001"]["status"], "FAIL")
        self.assertGreater(report["graph_completeness"]["symbols"], 0)
        self.assertIn("indexed_files", report["graph_completeness"])
        health = [item for item in report["findings"] if "health" in item["observation"] and item["confidence"] == "confirmed"]
        self.assertFalse(health)
        self.assertTrue(any(item["metric_ids"] == ["GRAPH-004"] and item["confidence"] == "confirmed" for item in report["findings"]))
        self.assertEqual(by_id["ARCH-011"]["status"], "FAIL")
        self.assertEqual(by_id["DUP-001"]["status"], "FAIL")
        self.assertIn(by_id["DUP-004"]["status"], {"PASS", "WARNING", "NOT_APPLICABLE", "INCONCLUSIVE"})
        semantic = [item for item in report["findings"] if "DUP-004" in item["metric_ids"] or "DUP-005" in item["metric_ids"]]
        for item in semantic:
            self.assertNotEqual(item["confidence"], "confirmed")
            self.assertTrue(item["rationale"])
            self.assertTrue(item["uncertainty"])
            self.assertFalse(item["confirmed_by_tests"])
        dynamic = self.repo("dynamic")
        _write(dynamic / "quality-auditor.yaml", """
        version: 1
        default_profile: focused
        profiles:
          focused:
            include: [syntax_static, symbol_index, dead_code]
        """)
        _write(dynamic / "app.py", """
        import importlib
        name = 'plugin'
        importlib.import_module(name)

        def unused():
            return 1

        def main():
            return 0

        if __name__ == '__main__':
            main()
        """)
        dynamic_report = self.audit(dynamic, profile="focused")
        self.assertTrue(all(item["confidence"] != "confirmed" for item in dynamic_report["findings"] if "GRAPH-001" in item["metric_ids"]))
        self.assertEqual({item["metric_id"]: item["status"] for item in dynamic_report["metrics"]}["GRAPH-001"], "INCONCLUSIVE")

    def test_requirements_and_quantitative(self):
        """Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 7.9, 8.8."""
        repo = self.repo()
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The system SHALL add two numbers.
        Acceptance: test_add returns 3 for 1 and 2.

        # REQ-100 Other
        The system SHALL subtract two numbers.

        # REQ-200 Out
        Widget is out of scope.
        """)
        _write(repo / "src" / "add.py", """
        def add(left, right):
            return left + right
        """)
        report = self.audit(repo, profile="full")
        by_id = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(by_id["REQ-003"]["status"], "FAIL")
        self.assertEqual(by_id["REQ-006"]["status"], "FAIL")
        self.assertEqual(report["decision"], "FAIL")
        verified = self.repo("verified")
        _write(verified / "docs" / "requirements.md", """
        # REQ-100 Adder
        The system SHALL add two numbers.
        Acceptance: test_add returns 2 for 1 and 1.
        """)
        _write(verified / "src" / "add.py", """
        # REQ-100
        def add(left, right):
            return left + right
        """)
        _write(verified / "tests" / "test_add.py", """
        from src.add import add

        def test_add():
            # REQ-100
            assert add(1, 1) == 2
        """)
        verified_report = self.audit(verified, profile="full")
        verified_by_id = {item["metric_id"]: item for item in verified_report["metrics"]}
        self.assertEqual(verified_by_id["REQ-003"]["status"], "PASS")
        self.assertIn(verified_by_id["TEST-005"]["status"], {"PASS", "WARNING", "FAIL", "NOT_APPLICABLE"})
        quant = self.repo("risk-book")
        _write(quant / "model" / "risk.py", """
        def value_at_risk(losses):
            return losses[0]

        def snapshot_view(snapshot):
            return snapshot
        """)
        _write(quant / "ui" / "panel.py", """
        def show():
            VaR = 10
            return VaR
        """)
        _write(quant / "model" / "book.py", """
        def mutate(snapshot):
            snapshot['price'] = 1
            return snapshot
        """)
        quant_report = self.audit(quant, profile="full")
        quant_by_id = {item["metric_id"]: item for item in quant_report["metrics"]}
        self.assertEqual(quant_by_id["QUANT-003"]["status"], "FAIL")
        self.assertEqual(quant_by_id["QUANT-004"]["status"], "FAIL")
        self.assertEqual(quant_by_id["QUANT-006"]["status"], "FAIL")
        plain = self.repo("plain")
        _write(plain / "app.py", "def main():\n    return 1\n")
        plain_report = self.audit(plain, profile="full")
        self.assertEqual({item["metric_id"]: item["status"] for item in plain_report["metrics"]}["QUANT-003"], "NOT_APPLICABLE")

    def test_authorized_line_coverage(self):
        """Requirements: 8.3."""
        repo = self.repo("covered")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: lines
        profiles:
          lines:
            include: [coverage]
        """)
        _write(repo / "app.py", """
        def add(left, right):
            return left + right

        def unused(value):
            return value
        """)
        _write(repo / "tests" / "test_add.py", """
        import unittest
        from app import add

        class AddTests(unittest.TestCase):
            def test_add(self):
                self.assertEqual(add(1, 1), 2)
        """)
        denied = self.audit(repo, profile="lines")
        denied_line = {item["metric_id"]: item for item in denied["metrics"]}["TEST-002"]
        self.assertEqual(denied_line["status"], "UNAVAILABLE")
        self.assertIn("not approved", denied_line["reason"])
        before = (repo / "app.py").read_text(encoding="utf-8")
        approved = self.audit(repo, profile="lines", allow_repo_execution=True, sandbox_confirmed=True)
        metrics = {item["metric_id"]: item for item in approved["metrics"]}
        self.assertEqual(metrics["TEST-003"]["status"], "NOT_APPLICABLE")
        self.assertIsInstance(metrics["TEST-002"]["measured_value"], float)
        self.assertGreater(metrics["TEST-002"]["measured_value"], 0)
        self.assertLess(metrics["TEST-002"]["measured_value"], 100)
        self.assertIn(metrics["TEST-002"]["status"], {"PASS", "FAIL"})
        self.assertTrue(metrics["TEST-002"]["evidence_refs"])
        self.assertEqual((repo / "app.py").read_text(encoding="utf-8"), before)

    def test_catalog_heuristics_are_measured(self):
        """Requirements: 8.2, 8.4, 8.7."""
        repo = self.repo("signals")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: signals
        profiles:
          signals:
            include: [architecture, security_sast, reliability, observability]
        """)
        _write(repo / "service.py", """
        class Parent:
            def draw(self):
                return self.left_side

        class Child(Parent):
            def draw(self, extra):
                return extra

        class Split:
            def left(self):
                return self.left_side

            def right(self):
                return self.right_side

        def create(app):
            @app.post("/items")
            def create_item():
                requests.get("http://example.invalid/items")
                return input()
        """)
        report = self.audit(repo, profile="signals")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertGreaterEqual(metrics["ARCH-003"]["measured_value"], 1)
        self.assertEqual(metrics["ARCH-003"]["status"], "WARNING")
        self.assertGreaterEqual(metrics["ARCH-009"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["SEC-004"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["SEC-005"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["REL-002"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["OBS-001"]["measured_value"], 1)
        self.assertEqual(metrics["OBS-001"]["status"], "WARNING")

    def test_catalog_counts_match_source(self):
        """Requirements: 8.1, 8.2, 8.3, 8.4, 8.8, 7.8."""
        repo = self.repo("catalog-counts")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: counts
        profiles:
          counts:
            include: [clean_code, architecture, testing, security_sast, ai_evaluation, quantitative]
        """)
        _write(repo / "docs" / "requirements.md", """
        # IDENT-9 Conservation
        Identity IDENT-9 must hold for VaR.
        # UNIT-3 Tolerance
        Tolerance UNIT-3 is one basis point.
        """)
        _write(repo / "app.py", """
        def value_at_risk(losses):
            return losses[0]

        def gate(flag):
            return flag and flag and flag and flag and flag and flag

        class Wrapper:
            def run(self, value):
                return self.inner.run(value)

        def read_path():
            return open(sys.argv[1])

        def page():
            return "<p>" + request.args.get("name") + "</p>"

        def test_inside():
            assert True
        """)
        _write(repo / "tests" / "test_empty.py", """
        def test_nothing():
            assert True
        """)
        report = self.audit(repo, profile="counts")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertGreaterEqual(metrics["CC-012"]["measured_value"], 5)
        self.assertEqual(metrics["CC-012"]["status"], "WARNING")
        self.assertGreaterEqual(metrics["ARCH-010"]["measured_value"], 1)
        self.assertEqual(metrics["TEST-012"]["measured_value"], 100)
        self.assertGreaterEqual(metrics["SEC-009"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["SEC-010"]["measured_value"], 1)
        self.assertEqual(metrics["AI-004"]["measured_value"], 100)
        self.assertGreaterEqual(metrics["QUANT-001"]["measured_value"], 1)
        self.assertEqual(metrics["QUANT-001"]["status"], "FAIL")
        self.assertGreaterEqual(metrics["QUANT-002"]["measured_value"], 1)

    def test_history_interfaces_and_candidates(self):
        """Requirements: 8.2, 8.5, 8.6, 8.8, 7.2."""
        repo = self.repo("history")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: history
        profiles:
          history:
            include: [architecture, performance_benchmarks, maintainability, ai_evaluation, requirements_trace]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-1 Deferred
        draw is deferred.

        # REQ-2 Limit
        Widget is out of scope.
        """)
        _write(repo / "app.py", """
        class Port:
            def send(self, value):
                return value

            def recv(self):
                return 1

        class Adapter(Port):
            def send(self, value):
                return value

        def load(paths):
            for path in paths:
                open(path).read()

        def widget():
            return 1

        def extra():
            return 2
        """)
        _write(repo / "pair.py", "VALUE = 1\n")
        _write(repo / "twin.py", "VALUE = 1\n")
        env = os.environ.copy()
        env.update({"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@example.com"})
        subprocess.check_call(["git", "init"], cwd=repo, env=env, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "add", "."], cwd=repo, env=env)
        subprocess.check_call(["git", "commit", "-m", "start"], cwd=repo, env=env, stdout=subprocess.DEVNULL)
        for index in range(4):
            with (repo / "pair.py").open("a", encoding="utf-8") as handle:
                handle.write(f"MARK_{index} = {index}\n")
            with (repo / "twin.py").open("a", encoding="utf-8") as handle:
                handle.write(f"MARK_{index} = {index}\n")
            subprocess.check_call(["git", "add", "pair.py", "twin.py"], cwd=repo, env=env)
            subprocess.check_call(["git", "commit", "-m", f"pair {index}"], cwd=repo, env=env, stdout=subprocess.DEVNULL)
        report = self.audit(repo, profile="history")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-004"]["measured_value"], 2)
        self.assertGreaterEqual(metrics["PERF-007"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["PERF-008"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["MAINT-003"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["MAINT-004"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["AI-007"]["measured_value"], 1)
        self.assertGreaterEqual(metrics["REQ-005"]["measured_value"], 1)
        self.assertEqual(metrics["REQ-005"]["status"], "WARNING")
        self.assertGreaterEqual(metrics["AI-002"]["measured_value"], 1)
        self.assertEqual(metrics["AI-002"]["status"], "WARNING")

    def test_measurements_and_export_baseline(self):
        """Requirements: 8.5, 8.6."""
        repo = self.repo("budgets")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: budgets
        export_baseline:
          - kept
          - removed_api
        profiles:
          budgets:
            include: [performance_benchmarks, maintainability]
        """)
        _write(repo / "bench-results.yaml", """
        latency: 50
        latency_target: 40
        throughput: 100
        throughput_target: 80
        memory: 10
        memory_budget: 20
        cpu: 0.2
        cpu_budget: 1
        """)
        _write(repo / "app.py", """
        def kept():
            return 1

        def added():
            return 2

        def _nest():
            for _left in range(1):
                for _right in range(1):
                    return _left
        """)
        report = self.audit(repo, profile="budgets")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["PERF-001"]["measured_value"], 1.25)
        self.assertEqual(metrics["PERF-001"]["status"], "FAIL")
        self.assertEqual(metrics["PERF-002"]["measured_value"], 0.8)
        self.assertEqual(metrics["PERF-003"]["measured_value"], 0.5)
        self.assertEqual(metrics["PERF-004"]["measured_value"], 0.2)
        self.assertEqual(metrics["PERF-006"]["measured_value"], 2)
        self.assertEqual(metrics["MAINT-005"]["measured_value"], 1)
        self.assertEqual(metrics["MAINT-005"]["status"], "FAIL")
        self.assertEqual(metrics["MAINT-008"]["measured_value"], 1)
        self.assertEqual(metrics["MAINT-008"]["status"], "WARNING")

    def test_extension_points_and_freshness(self):
        """Requirements: 8.2, 8.6."""
        repo = self.repo("fresh")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: fresh
        freshness_snapshot:
          requests: "2.32.0"
        architecture:
          extension_points:
            - protected: core.py
              allow:
                - plugins/
                - core.py
        profiles:
          fresh:
            include: [architecture, maintainability]
        """)
        _write(repo / "requirements.txt", "requests==2.31.0\n")
        _write(repo / "core.py", """
        def price():
            return 1
        """)
        _write(repo / "app.py", """
        from core import price

        def main():
            return price()
        """)
        _write(repo / "plugins" / "extra.py", """
        from core import price

        def extra():
            return price()
        """)
        report = self.audit(repo, profile="fresh")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertGreaterEqual(metrics["ARCH-002"]["measured_value"], 1)
        self.assertEqual(metrics["ARCH-002"]["status"], "WARNING")
        self.assertEqual(metrics["MAINT-007"]["measured_value"], 1)
        self.assertEqual(metrics["MAINT-007"]["status"], "WARNING")
        self.assertIn("requests", metrics["MAINT-007"]["evidence_refs"])

    def test_unused_locals_and_local_advisories(self):
        """Requirements: 8.1, 8.4."""
        repo = self.repo("advisories")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: local
        advisory_database:
          requests:
            - id: CVE-TEST-1
              versions: ["2.31.0"]
        profiles:
          local:
            include: [clean_code, dependency_audit]
        """)
        _write(repo / "requirements.txt", "requests==2.31.0\nurllib3==2.0.0\n")
        _write(repo / "app.py", """
        def main():
            leftover = 1
            return 2
        """)
        report = self.audit(repo, profile="local")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-010"]["measured_value"], 1)
        self.assertEqual(metrics["CC-010"]["status"], "WARNING")
        self.assertEqual(metrics["SEC-002"]["measured_value"], 1)
        self.assertEqual(metrics["SEC-002"]["status"], "FAIL")
        self.assertEqual(metrics["SEC-002"]["evidence_refs"], ["requests"])
        self.assertEqual(report["decision"], "FAIL")
        self.assertTrue(any("CVE-TEST-1" in item["observation"] for item in report["findings"]))
        self.assertTrue(any("leftover" in item["observation"] for item in report["findings"]))

    def test_empty_handlers_across_languages(self):
        """Requirements: 6.1, 8.7."""
        repo = self.repo("handlers")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: handlers
        profiles:
          handlers:
            include: [reliability]
        """)
        _write(repo / "app.py", """
        def run():
            try:
                return 1
            except:
                pass
            try:
                return 2
            except Exception:
                ...
            try:
                return 3
            except Exception as exc:
                return exc
        """)
        _write(repo / "app.js", """
        function run() {
          try {
            return 1;
          } catch (err) {
          }
          try {
            return 2;
          } catch (err) {
            return err;
          }
        }
        """)
        _write(repo / "app.cpp", """
        int run() {
          try {
            return 1;
          } catch (...) {
          }
          try {
            return 2;
          } catch (...) {
            return 2;
          }
        }
        """)
        report = self.audit(repo, profile="handlers")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REL-001"]["measured_value"], 4)
        self.assertEqual(metrics["REL-001"]["status"], "FAIL")
        self.assertEqual(report["decision"], "FAIL")
        files = {item["file"] for item in report["findings"] if "REL-001" in item["metric_ids"]}
        self.assertEqual(files, {"app.py", "app.js", "app.cpp"})

    def test_clang_syntax_requires_tool_approval(self):
        """Requirements: 4.4, 8.7."""
        self.assertIsNotNone(shutil.which("clang"))
        repo = self.repo("clang-syntax")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: syntax
        profiles:
          syntax:
            include: [syntax_static]
        """)
        _write(repo / "broken.cpp", """
        int run() {
          return 1
        }
        """)
        denied = self.audit(repo, profile="syntax")
        denied_metrics = {item["metric_id"]: item for item in denied["metrics"]}
        self.assertEqual(denied_metrics["REL-004"]["measured_value"], 0)
        self.assertEqual(denied["decision"], "PASS")
        approved = self.audit(repo, profile="syntax", allow_tools=True)
        approved_metrics = {item["metric_id"]: item for item in approved["metrics"]}
        self.assertEqual(approved_metrics["REL-004"]["measured_value"], 1)
        self.assertEqual(approved_metrics["REL-004"]["status"], "FAIL")
        self.assertEqual(approved["decision"], "FAIL")
        self.assertTrue(any("clang:" in item["observation"] for item in approved["findings"]))
        semantic = self.repo("clang-semantic")
        _write(semantic / "quality-auditor.yaml", """
        version: 1
        default_profile: syntax
        profiles:
          syntax:
            include: [syntax_static]
        """)
        _write(semantic / "name.cpp", """
        int run() {
          return missing;
        }
        """)
        semantic_report = self.audit(semantic, profile="syntax", allow_tools=True)
        semantic_metrics = {item["metric_id"]: item for item in semantic_report["metrics"]}
        self.assertEqual(semantic_metrics["REL-004"]["measured_value"], 0)
        self.assertEqual(semantic_report["decision"], "PASS")

    def test_concurrency_primitives_need_a_concurrency_test(self):
        """Requirements: 8.3."""
        repo = self.repo("workers")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: workers
        profiles:
          workers:
            include: [concurrency]
        """)
        _write(repo / "app.py", """
        import threading
        from concurrent.futures import ThreadPoolExecutor

        def work():
            threading.Thread(target=lambda: None).start()
            ThreadPoolExecutor(max_workers=2)
        """)
        _write(repo / "app.js", """
        const { Worker } = require("worker_threads");

        function start() {
          return new Worker("./task.js");
        }
        """)
        _write(repo / "app.cpp", """
        #include <thread>
        void run();
        void start() {
          std::thread worker(run);
        }
        """)
        _write(repo / "tests" / "test_app.py", """
        from app import work

        def test_work():
            assert work is not None
        """)
        report = self.audit(repo, profile="workers")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["TEST-010"]["measured_value"], 4)
        self.assertEqual(metrics["TEST-010"]["status"], "WARNING")
        self.assertEqual(report["counts"]["confirmed_violations"], 0)
        files = {item["file"] for item in report["findings"] if "TEST-010" in item["metric_ids"]}
        self.assertEqual(files, {"app.py", "app.js", "app.cpp"})

    def test_script_complexity_counts_decisions(self):
        """Requirements: 6.1, 8.1."""
        repo = self.repo("complexity")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: complexity
        profiles:
          complexity:
            include: [clean_code]
        """)
        _write(repo / "choose.js", """
        function choose(a, b, c) {
          if (a) {
            if (b) {
              if (c) {
                if (a && b) {
                  if (c || a) {
                    return 1;
                  }
                }
              }
            }
          }
          return 0;
        }
        """)
        _write(repo / "choose.cpp", """
        int choose(int a, int b) {
          if (a) {
            if (b) {
              return a;
            }
          }
          return b;
        }
        """)
        report = self.audit(repo, profile="complexity")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-004"]["measured_value"], 8)
        self.assertEqual(metrics["CC-004"]["status"], "PASS")
        self.assertEqual(metrics["CC-005"]["measured_value"], 13)
        self.assertEqual(metrics["CC-006"]["measured_value"], 5)
        self.assertEqual(metrics["CC-006"]["status"], "WARNING")
        self.assertEqual(metrics["CC-007"]["measured_value"], 3)

    def test_commented_out_code_blocks(self):
        """Requirements: 8.1."""
        repo = self.repo("comments")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: comments
        profiles:
          comments:
            include: [clean_code]
        """)
        _write(repo / "app.py", """
        # This module loads prices.
        # It stays small on purpose.
        # Callers pass integers.

        def live(value):
            return value

        # def retired(value):
        #     return value + 1
        #     print(value)
        """)
        _write(repo / "old.js", """
        function live(value) {
          return value;
        }

        /*
        const old = 1;
        function retired() {
          return old;
        }
        */
        """)
        report = self.audit(repo, profile="comments")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-014"]["measured_value"], 2)
        self.assertEqual(metrics["CC-014"]["status"], "WARNING")
        files = {item["file"] for item in report["findings"] if "CC-014" in item["metric_ids"]}
        self.assertEqual(files, {"app.py", "old.js"})

    def test_boolean_chain_in_script_conditions(self):
        """Requirements: 8.1."""
        repo = self.repo("booleans")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: booleans
        profiles:
          booleans:
            include: [clean_code]
        """)
        _write(repo / "gate.js", """
        function gate(a, b, c, d, e, f) {
          const note = "a && b && c && d && e && f && g";
          return a && b && c && d && e && f;
        }
        """)
        _write(repo / "gate.cpp", """
        bool gate(bool a, bool b, bool c) {
          return a || b || c;
        }
        """)
        report = self.audit(repo, profile="booleans")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-012"]["measured_value"], 5)
        self.assertEqual(metrics["CC-012"]["status"], "WARNING")

    def test_script_types_count_methods(self):
        """Requirements: 6.1, 8.2."""
        repo = self.repo("types")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: types
        profiles:
          types:
            include: [architecture]
        """)
        methods = "\n".join(f"  step{index}() {{ return {index}; }}" for index in range(21))
        _write(repo / "bucket.js", f"class Bucket {{\n{methods}\n}}\n")
        _write(repo / "pair.cpp", """
        struct Pair {
          int left() { return 1; }
          int right() { return 2; }
        };
        """)
        report = self.audit(repo, profile="types")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-001"]["measured_value"], 21)
        self.assertEqual(metrics["ARCH-001"]["status"], "WARNING")

    def test_naming_conventions_follow_the_language(self):
        """Requirements: 6.1, 8.1."""
        repo = self.repo("names")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: names
        profiles:
          names:
            include: [clean_code]
        """)
        _write(repo / "app.py", """
        def good_name():
            return 1

        class Bad_Type:
            def _hidden(self):
                return 1
        """)
        _write(repo / "app.js", """
        function bad_name() {
          return 1;
        }
        function goodName() {
          return 1;
        }
        class bad_type {
          fine() { return 1; }
        }
        """)
        _write(repo / "app.cpp", """
        int Bad_Name() { return 1; }
        struct bad_type {
          int fine_name() { return 2; }
        };
        """)
        report = self.audit(repo, profile="names")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-001"]["measured_value"], 5)
        self.assertEqual(metrics["CC-001"]["status"], "WARNING")
        files = {item["file"] for item in report["findings"] if "CC-001" in item["metric_ids"]}
        self.assertEqual(files, {"app.py", "app.js", "app.cpp"})

    def test_unused_imports_compare_names_with_references(self):
        """Requirements: 6.1, 8.1."""
        repo = self.repo("imports")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: imports
        profiles:
          imports:
            include: [clean_code]
        """)
        _write(repo / "app.py", """
        import json
        import sys

        def live():
            return sys.version
        """)
        _write(repo / "app.js", """
        import { read, write as save } from "./io";
        import fs from "fs";
        import "side-effect";
        const extra = require("extra");

        function live() {
          return fs.ok() + read();
        }
        """)
        report = self.audit(repo, profile="imports")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-009"]["measured_value"], 3)
        self.assertEqual(metrics["CC-009"]["status"], "WARNING")
        observations = [item["observation"] for item in report["findings"] if "CC-009" in item["metric_ids"]]
        self.assertTrue(any("json" in item for item in observations))
        self.assertTrue(any("save" in item for item in observations))
        self.assertTrue(any("extra" in item for item in observations))
        self.assertFalse(any("read" in item or "fs" in item or "sys" in item for item in observations))

    def test_public_functions_count_leading_comments(self):
        """Requirements: 8.6."""
        repo = self.repo("docs")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: docs
        profiles:
          docs:
            include: [maintainability]
        """)
        _write(repo / "app.py", """
        def documented():
            \"\"\"Return one.\"\"\"
            return 1

        def _skip():
            return 0
        """)
        _write(repo / "app.js", """
        // Counts the items.
        function documented() {
          return 1;
        }
        """)
        _write(repo / "app.cpp", """
        #include <thread>
        int bare() {
          return 2;
        }
        """)
        report = self.audit(repo, profile="docs")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["MAINT-006"]["measured_value"], 200 / 3)
        self.assertEqual(metrics["MAINT-006"]["status"], "PASS")

    def test_constant_branches_in_script_languages(self):
        """Requirements: 6.4, 8.1."""
        repo = self.repo("branches")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: branches
        profiles:
          branches:
            include: [dead_code]
        """)
        _write(repo / "app.js", """
        function live(flag) {
          if (false) {
            return 1;
          }
          if (true) {
            return 2;
          } else {
            return 3;
          }
          if (false && flag) {
            return 4;
          }
          return 0;
        }
        """)
        _write(repo / "app.cpp", """
        int live(bool flag) {
          if (false) {
            return 1;
          }
          if (true) {
            return 2;
          } else {
            return 3;
          }
          if (false && flag) {
            return 4;
          }
          return 0;
        }
        """)
        report = self.audit(repo, profile="branches")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["GRAPH-004"]["measured_value"], 4)
        self.assertEqual(metrics["GRAPH-004"]["status"], "FAIL")
        self.assertEqual(report["decision"], "FAIL")

    def test_script_import_cycles_count_modules(self):
        """Requirements: 6.2, 8.2."""
        repo = self.repo("cycles")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: cycles
        profiles:
          cycles:
            include: [architecture]
        """)
        _write(repo / "a.js", """
        import { b } from "./b.js";
        import { util } from "./util.js";
        export function a() {
          return b() + util();
        }
        """)
        _write(repo / "b.js", """
        import { a } from "./a.js";
        export function b() {
          return a();
        }
        """)
        _write(repo / "util.js", """
        export function util() {
          return 1;
        }
        """)
        _write(repo / "left.h", """
        #include "right.h"
        int left();
        """)
        _write(repo / "right.h", """
        #include "left.h"
        int right();
        """)
        report = self.audit(repo, profile="cycles")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-012"]["measured_value"], 4)
        self.assertEqual(metrics["ARCH-012"]["status"], "FAIL")
        files = {item["file"] for item in report["findings"] if "ARCH-012" in item["metric_ids"]}
        self.assertEqual(files, {"a.js", "b.js", "left.h", "right.h"})

    def test_debt_markers_come_from_comments(self):
        """Requirements: 8.6."""
        repo = self.repo("debt")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: debt
        profiles:
          debt:
            include: [maintainability]
        """)
        _write(repo / "app.py", """
        def live():
            note = "TODO"
            return note

        # FIXME the caller
        """)
        _write(repo / "app.js", """
        function live() {
          const note = "HACK";
          return note;
        }
        // TODO the export
        """)
        _write(repo / "app.cpp", """
        int live() {
          return 1;
        }
        /* HACK the buffer */
        """)
        report = self.audit(repo, profile="debt")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["MAINT-002"]["measured_value"], 3)
        self.assertEqual(metrics["MAINT-002"]["status"], "WARNING")
        self.assertEqual(set(metrics["MAINT-002"]["evidence_refs"]), {"app.py:5:FIXME", "app.js:5:TODO", "app.cpp:4:HACK"})

    def test_winnowing_detects_token_duplicates(self):
        """Requirements: 6.8, 8.1."""
        repo = self.repo("clones")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: clones
        profiles:
          clones:
            include: [duplication]
        """)
        body = "function copy(alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa) { return alpha+beta+gamma+delta+epsilon+zeta+eta+theta+iota+kappa; }\n"
        _write(repo / "left.js", body)
        _write(repo / "right.js", body)
        report = self.audit(repo, profile="clones")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertGreaterEqual(metrics["DUP-002"]["measured_value"], 1)
        self.assertEqual(metrics["DUP-002"]["status"], "FAIL")
        self.assertEqual(metrics["DUP-001"]["measured_value"], 0)

    def test_token_duplicate_uses_the_source_line(self):
        """Requirements: 6.9, 11.3."""
        repo = self.repo("clone-lines")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: clones
        profiles:
          clones:
            include: [duplication]
        """)
        body = "\n\nfunction copy(alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa) { return alpha+beta+gamma+delta+epsilon+zeta+eta+theta+iota+kappa; }\n"
        # _write lstrips the body, which would put the clone on line 1.
        (repo / "left.js").write_text(body, encoding="utf-8")
        (repo / "right.js").write_text(body, encoding="utf-8")
        report = self.audit(repo, profile="clones")
        findings = [item for item in report["findings"] if "DUP-002" in item["metric_ids"]]
        self.assertTrue(findings)
        self.assertTrue(any(item["line"] == 3 for item in findings))
        self.assertFalse(any(item["line"] == 1 for item in findings))

    def test_script_functions_share_structure_hashes(self):
        """Requirements: 6.9, 8.1."""
        repo = self.repo("shapes")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: shapes
        profiles:
          shapes:
            include: [duplication]
        """)
        _write(repo / "left.js", """
        function left(value) {
          if (value) {
            return value + 1;
          }
          return 0;
        }
        """)
        _write(repo / "right.cpp", """
        int right(int other) {
          if (other) {
            return other + 1;
          }
          return 0;
        }
        """)
        report = self.audit(repo, profile="shapes")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertGreaterEqual(metrics["DUP-003"]["measured_value"], 1)
        self.assertEqual(metrics["DUP-003"]["status"], "FAIL")
        self.assertEqual(metrics["DUP-001"]["measured_value"], 0)

    def test_magic_literals_skip_declarations_and_tests(self):
        """Requirements: 8.1."""
        repo = self.repo("literals")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: literals
        profiles:
          literals:
            include: [clean_code]
        """)
        _write(repo / "app.py", """
        LIMIT = 99

        def run(value):
            return value + 40
        """)
        _write(repo / "tests/test_app.py", """
        def test_run():
            assert run(1) == 40
        """)
        _write(repo / "app.js", """
        const LIMIT = 99;
        function run(value) { return value + 40; }
        """)
        report = self.audit(repo, profile="literals")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-011"]["measured_value"], 2)
        self.assertEqual(set(metrics["CC-011"]["evidence_refs"]), {"app.py:4:40", "app.js:2:40"})

    def test_unexported_script_function_can_be_dead(self):
        """Requirements: 6.4, 6.5, 6.8."""
        repo = self.repo("exports")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: dead
        profiles:
          dead:
            include: [dead_code]
        """)
        _write(repo / "main.js", """
        import { used } from "./util.js";
        function main() { return used(); }
        """)
        _write(repo / "util.js", """
        export function used() { return 1; }
        function spare() { return 2; }
        """)
        _write(repo / "main.cpp", """
        #include "util.h"
        int main() { return used(); }
        """)
        _write(repo / "util.h", """
        int used() { return 1; }
        int spare() { return 2; }
        """)
        report = self.audit(repo, profile="dead")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        confirmed = [item for item in report["findings"] if "GRAPH-001" in item["metric_ids"] and item["confidence"] == "confirmed"]
        self.assertTrue(any(item["file"] == "util.js" and item["line"] == 2 for item in confirmed))
        self.assertFalse(any(item["file"] == "util.h" for item in confirmed))
        self.assertGreaterEqual(metrics["GRAPH-001"]["measured_value"], 1)

    def test_unimported_modules_are_dead_when_an_entry_exists(self):
        """Requirements: 6.4, 8.1."""
        repo = self.repo("orphans")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: orphans
        profiles:
          orphans:
            include: [dead_code]
        """)
        _write(repo / "main.js", """
        import { used } from "./util.js";
        function main() { return used(); }
        """)
        _write(repo / "util.js", """
        function used() { return 1; }
        """)
        _write(repo / "leftover.js", """
        function helper() { return 2; }
        """)
        _write(repo / "main.cpp", """
        #include "util.h"
        int main() { return used(); }
        """)
        _write(repo / "util.h", """
        int used() { return 1; }
        """)
        _write(repo / "orphan.cpp", """
        int helper() { return 2; }
        """)
        report = self.audit(repo, profile="orphans")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["GRAPH-003"]["measured_value"], 2)
        self.assertEqual(metrics["GRAPH-003"]["status"], "FAIL")
        self.assertEqual(set(metrics["GRAPH-003"]["evidence_refs"]), {"leftover.js", "orphan.cpp"})
        uncertain = self.repo("no-entry")
        _write(uncertain / "quality-auditor.yaml", """
        version: 1
        default_profile: orphans
        profiles:
          orphans:
            include: [dead_code]
        """)
        _write(uncertain / "leftover.js", """
        function helper() { return 2; }
        """)
        _write(uncertain / "other.js", """
        function other() { return 3; }
        """)
        report = self.audit(uncertain, profile="orphans")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["GRAPH-003"]["status"], "INCONCLUSIVE")
        self.assertEqual(metrics["GRAPH-003"]["measured_value"], 0)

    def test_script_routes_are_service_entry_points(self):
        """Requirements: 6.1, 8.4, 8.5."""
        repo = self.repo("routes")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: routes
        profiles:
          routes:
            include: [security_sast, observability]
        """)
        _write(repo / "server.js", """
        const app = express();
        app.get("/items", (req, res) => { res.send("ok"); });
        app.post("/items", (req, res) => { res.send("created"); });
        app.put("/items", authorize, (req, res) => { res.send("updated"); });
        cache.get("user");
        """)
        report = self.audit(repo, profile="routes")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-005"]["measured_value"], 1)
        self.assertEqual(metrics["SEC-005"]["status"], "WARNING")
        self.assertEqual(metrics["OBS-001"]["measured_value"], 1)
        self.assertEqual(metrics["OBS-005"]["measured_value"], 1)
        self.assertEqual(metrics["OBS-001"]["status"], "WARNING")

    def test_script_input_boundaries_need_validation(self):
        """Requirements: 6.1, 8.4."""
        repo = self.repo("inputs")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: inputs
        profiles:
          inputs:
            include: [security_sast]
        """)
        _write(repo / "app.js", """
        function create(req, res) {
          const name = req.body.name;
          res.send(name);
        }
        function update(req, res) {
          const name = schema.parse(req.body.name);
          return name;
        }
        function main() {
          const args = process.argv.slice(2);
          return args;
        }
        """)
        _write(repo / "app.cpp", """
        int main(int argc, char** argv) {
          return 0;
        }
        int parsed(int argc, char** argv) {
          return stoi(argv[1]);
        }
        """)
        report = self.audit(repo, profile="inputs")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-004"]["measured_value"], 3)
        self.assertEqual(metrics["SEC-004"]["status"], "WARNING")

    def test_script_calls_need_a_timeout(self):
        """Requirements: 6.1, 8.7."""
        repo = self.repo("timeouts")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: timeouts
        profiles:
          timeouts:
            include: [reliability]
        """)
        _write(repo / "app.js", """
        function load() {
          fetch("http://example.invalid/items");
          axios.get("http://example.invalid/other", { timeout: 5 });
          spawn("tool");
        }
        """)
        _write(repo / "app.cpp", """
        int load() {
          popen("tool", "r");
          std::system("tool");
          return 0;
        }
        """)
        report = self.audit(repo, profile="timeouts")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REL-002"]["measured_value"], 4)
        self.assertEqual(metrics["REL-002"]["status"], "WARNING")

    def test_script_paths_and_markup_use_the_same_function(self):
        """Requirements: 6.1, 8.4."""
        repo = self.repo("paths")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: paths
        profiles:
          paths:
            include: [security_sast]
        """)
        _write(repo / "app.js", """
        function read(req) {
          return fs.readFileSync(path.join("data", req.query.file));
        }
        function page(req) {
          return "<div>" + req.query.name;
        }
        function safe(req) {
          return req.query.file;
        }
        function fixed() {
          return fs.readFileSync("fixed");
        }
        """)
        _write(repo / "app.cpp", """
        int read(int argc, char** argv) {
          return fopen(argv[1], "r");
        }
        int page(int argc, char** argv) {
          printf("<div>%s", argv[1]);
          return 0;
        }
        """)
        report = self.audit(repo, profile="paths")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-009"]["measured_value"], 2)
        self.assertEqual(metrics["SEC-009"]["status"], "WARNING")
        self.assertEqual(metrics["SEC-010"]["measured_value"], 2)
        self.assertEqual(metrics["SEC-010"]["status"], "WARNING")
        split = self.repo("split-paths")
        _write(split / "quality-auditor.yaml", """
        version: 1
        default_profile: paths
        profiles:
          paths:
            include: [security_sast]
        """)
        _write(split / "app.js", """
        function take(req) { return req.query.file; }
        function load() { return fs.readFileSync("fixed"); }
        """)
        report = self.audit(split, profile="paths")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-009"]["status"], "INCONCLUSIVE")

    def test_broken_crypto_includes_script_apis_and_static_ivs(self):
        """Requirements: 6.1, 8.4."""
        repo = self.repo("crypto")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: crypto
        profiles:
          crypto:
            include: [security_sast]
        """)
        _write(repo / "app.js", """
        function digest(value) {
          return crypto.createHash("md5").update(value);
        }
        function seal(key) {
          return crypto.createCipheriv("aes-256-cbc", key, "0123456789abcdef");
        }
        function strong(value) {
          return crypto.createHash("sha256").update(value);
        }
        """)
        _write(repo / "app.cpp", """
        const EVP_MD* broken() { return EVP_sha1(); }
        """)
        _write(repo / "app.py", """
        def seal(key):
            return AES.new(key, AES.MODE_CBC, iv=b"0123456789012345")
        """)
        report = self.audit(repo, profile="crypto")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-011"]["measured_value"], 4)
        self.assertEqual(metrics["SEC-011"]["status"], "FAIL")

    def test_data_reads_inside_script_loops(self):
        """Requirements: 6.1, 8.8."""
        repo = self.repo("loops")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: loops
        profiles:
          loops:
            include: [performance_benchmarks]
        """)
        _write(repo / "app.js", """
        function load(names) {
          for (const name of names) {
            fs.readFileSync(name);
            fetch(name);
          }
          fs.readFileSync("once");
        }
        """)
        _write(repo / "app.cpp", """
        int load(int n) {
          for (int i = 0; i < n; i++) {
            query();
          }
          read();
          while (n) query();
          return 0;
        }
        """)
        report = self.audit(repo, profile="loops")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["PERF-007"]["measured_value"], 4)
        self.assertEqual(metrics["PERF-007"]["status"], "WARNING")

    def test_traceability_links_open_their_targets(self):
        """Requirements: 7.4, 8.8."""
        repo = self.repo("links")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: links
        profiles:
          links:
            include: [requirements_trace]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        implementation: src/present.py, src/missing.py
        """)
        _write(repo / "src" / "present.py", """
        def present():
            return 1
        """)
        _write(repo / "src" / "add.py", """
        def add():
            # REQ-999
            return 1
        """)
        report = self.audit(repo, profile="links")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REQ-004"]["measured_value"], 2)
        self.assertEqual(metrics["REQ-004"]["status"], "FAIL")
        self.assertEqual(set(metrics["REQ-004"]["evidence_refs"]), {"src/missing.py", "REQ-999"})
        cited = self.repo("citation-only")
        _write(cited / "quality-auditor.yaml", """
        version: 1
        default_profile: links
        profiles:
          links:
            include: [requirements_trace]
        """)
        _write(cited / "app.py", """
        def add():
            # REQ-50
            return 1
        """)
        report = self.audit(cited, profile="links")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REQ-004"]["measured_value"], 1)
        self.assertEqual(metrics["REQ-004"]["status"], "FAIL")

    def test_authorized_acceptance_failures_count(self):
        """Requirements: 7.8, 8.8."""
        repo = self.repo("accept")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: accept
        profiles:
          accept:
            include: [requirements_trace]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        Acceptance: test_add returns 2.

        # REQ-200 Missing
        The widget is covered.
        Acceptance: a test cites this requirement.
        """)
        _write(repo / "tests" / "test_add.py", """
        import unittest

        class AddTests(unittest.TestCase):
            def test_add(self):
                \"\"\"REQ-100\"\"\"
                self.assertEqual(1 + 1, 3)

            def test_other(self):
                self.assertEqual(1, 0)
        """)
        denied = self.audit(repo, profile="accept")
        denied_metrics = {item["metric_id"]: item for item in denied["metrics"]}
        self.assertEqual(denied_metrics["REQ-008"]["measured_value"], 1)
        self.assertEqual(denied_metrics["REQ-008"]["status"], "FAIL")
        approved = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
        metrics = {item["metric_id"]: item for item in approved["metrics"]}
        self.assertEqual(metrics["REQ-008"]["measured_value"], 2)
        self.assertEqual(metrics["REQ-008"]["status"], "FAIL")
        self.assertIn("tests/test_add.py:test_add", metrics["REQ-008"]["evidence_refs"])
        self.assertNotIn("tests/test_add.py:test_other", metrics["REQ-008"]["evidence_refs"])

    def test_pytest_project_uses_its_runner(self):
        """Requirements: 4.4, 7.6, 8.3."""
        repo = self.repo("pyrunner")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: accept
        profiles:
          accept:
            include: [requirements_trace, coverage]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        Acceptance: test_add returns 2.
        """)
        _write(repo / "app.py", """
        def add(left, right):
            return left + right
        """)
        _write(repo / "tests" / "test_add.py", """
        import pytest

        def test_add():
            \"\"\"REQ-100\"\"\"
            assert 1 + 1 == 3
        """)
        runner = repo / ".venv" / "bin" / "pytest"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'FAILED tests/test_add.py::test_add - AssertionError'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        report = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
        commands = [" ".join(item["command"]) for item in report["execution"]["commands"]]
        blob = "\n".join(commands)
        self.assertIn(".venv/bin/pytest", blob)
        self.assertNotIn("cqa_accept_driver", blob)
        self.assertNotIn("cqa_trace_driver", blob)
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertIn("tests/test_add.py:test_add", metrics["REQ-008"]["evidence_refs"])
        self.assertEqual(metrics["TEST-002"]["status"], "UNAVAILABLE")
        self.assertIn("coverage.py", metrics["TEST-002"]["reason"])

    def test_pytest_collection_error_stays_unavailable(self):
        """Requirements: 4.4, 7.6, 8.3."""
        repo = self.repo("pycollect")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: accept
        profiles:
          accept:
            include: [requirements_trace, coverage]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        Acceptance: test_add returns 2.
        """)
        _write(repo / "app.py", """
        def add(left, right):
            return left + right
        """)
        _write(repo / "tests" / "test_add.py", """
        import pytest

        def test_add():
            \"\"\"REQ-100\"\"\"
            assert 1 + 1 == 3
        """)
        runner = repo / ".venv" / "bin" / "pytest"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'ERROR collecting tests'\n"
            "exit 2\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        report = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
        commands = [" ".join(item["command"]) for item in report["execution"]["commands"]]
        blob = "\n".join(commands)
        self.assertIn(".venv/bin/pytest", blob)
        self.assertNotIn("cqa_accept_driver", blob)
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REQ-008"]["status"], "UNAVAILABLE")

    def test_pytest_failure_with_error_line_stays_unavailable(self):
        """Requirements: 4.4, 7.6, 8.3."""
        repo = self.repo("pyerror")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: accept
        profiles:
          accept:
            include: [requirements_trace, coverage]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        Acceptance: test_add returns 2.
        """)
        _write(repo / "app.py", """
        def add(left, right):
            return left + right
        """)
        _write(repo / "tests" / "test_add.py", """
        import pytest

        def test_add():
            \"\"\"REQ-100\"\"\"
            assert 1 + 1 == 3
        """)
        runner = repo / ".venv" / "bin" / "pytest"
        runner.parent.mkdir(parents=True)
        runner.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'FAILED tests/test_add.py::test_add - AssertionError'\n"
            "printf '%s\\n' 'ERROR tests/test_missing.py'\n"
            "exit 1\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        report = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REQ-008"]["status"], "UNAVAILABLE")

    def test_unittest_import_error_stays_unavailable(self):
        """Requirements: 7.8, 8.8."""
        repo = self.repo("accept-broken")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: accept
        profiles:
          accept:
            include: [requirements_trace]
        """)
        _write(repo / "docs" / "requirements.md", """
        # REQ-100 Adder
        The adder works.
        Acceptance: test_add returns 2.

        # REQ-200 Missing
        The widget is covered.
        Acceptance: a test cites this requirement.
        """)
        _write(repo / "tests" / "test_add.py", """
        import unittest

        class AddTests(unittest.TestCase):
            def test_add(self):
                \"\"\"REQ-100\"\"\"
                self.assertEqual(1 + 1, 3)

            def test_other(self):
                self.assertEqual(1, 0)
        """)
        _write(repo / "tests" / "test_broken.py", "import does_not_exist\n")
        report = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REQ-008"]["status"], "UNAVAILABLE")

    def test_script_loop_nesting_ignores_conditionals(self):
        """Requirements: 6.1, 8.8."""
        repo = self.repo("depth")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: depth
        profiles:
          depth:
            include: [performance_benchmarks]
        """)
        _write(repo / "app.js", """
        function load(rows) {
          for (const row of rows) {
            for (const cell of row) {
              for (const item of cell) {
                while (item) {
                  item = item.next;
                }
              }
            }
          }
          if (rows) {
            if (rows) {
              if (rows) {
                if (rows) {
                  return 1;
                }
              }
            }
          }
        }
        """)
        _write(repo / "app.cpp", """
        int load(int n) {
          for (int i = 0; i < n; i++) {
            while (n) {
              n--;
            }
          }
          return 0;
        }
        """)
        report = self.audit(repo, profile="depth")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["PERF-006"]["measured_value"], 4)
        self.assertEqual(metrics["PERF-006"]["status"], "WARNING")

    def test_eval_like_loaders_are_unsafe_deserialization(self):
        """Requirements: 6.1, 8.4."""
        repo = self.repo("loaders")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: loaders
        profiles:
          loaders:
            include: [security_sast]
        """)
        _write(repo / "app.py", """
        def load(payload):
            return marshal.loads(payload)

        def read(payload):
            return yaml.unsafe_load(payload)
        """)
        _write(repo / "app.js", """
        function load(payload) {
          return serialize.unserialize(payload);
        }
        function read(payload) {
          return JSON.parse(payload);
        }
        """)
        report = self.audit(repo, profile="loaders")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-008"]["measured_value"], 3)
        self.assertEqual(metrics["SEC-008"]["status"], "FAIL")

    def test_config_files_disable_tls_and_open_hosts(self):
        """Requirements: 8.4, 8.5."""
        repo = self.repo("config")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: config
        profiles:
          config:
            include: [insecure_config]
        """)
        _write(repo / "deploy" / "server.yaml", """
        verify: false
        allowed_hosts:
          - "*"
        """)
        _write(repo / "app.js", """
        function agent() {
          return { rejectUnauthorized: false };
        }
        """)
        _write(repo / "production.yaml", """
        debug: true
        """)
        report = self.audit(repo, profile="config")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-006"]["measured_value"], 3)
        self.assertEqual(metrics["SEC-006"]["status"], "FAIL")
        self.assertEqual(metrics["SEC-012"]["measured_value"], 1)
        self.assertEqual(metrics["SEC-012"]["status"], "FAIL")

    def test_credential_assignments_allow_object_syntax(self):
        """Requirements: 6.1, 8.4."""
        repo = self.repo("secrets")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: secrets
        profiles:
          secrets:
            include: [secrets]
        """)
        _write(repo / "app.js", """
        function settings() {
          return { api_key: "supersecretvalue", token: "example-token-ok" };
        }
        const password = "changeme";
        """)
        _write(repo / "app.cpp", """
        const char* secret = "anothersecret1";
        """)
        report = self.audit(repo, profile="secrets")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["SEC-007"]["measured_value"], 2)
        self.assertEqual(metrics["SEC-007"]["status"], "FAIL")

    def test_script_interfaces_count_stateless_methods(self):
        """Requirements: 6.1, 8.2."""
        repo = self.repo("interfaces")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: interfaces
        profiles:
          interfaces:
            include: [architecture]
        """)
        _write(repo / "app.js", """
        class Port {
          send(value) { return value; }
          recv() { return 1; }
        }
        class Adapter extends Port {
          send(value) { return value; }
        }
        class Stateful {
          send(value) { return this.value; }
          recv() { return this.value; }
        }
        class Child extends Stateful {
          send(value) { return value; }
        }
        """)
        _write(repo / "app.cpp", """
        struct Port {
          int send(int value) { return value; }
          int recv() { return 1; }
          int peek() { return 0; }
        };
        struct Adapter : public Port {
          int send(int value) { return value; }
        };
        """)
        report = self.audit(repo, profile="interfaces")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-004"]["measured_value"], 3)
        self.assertEqual(metrics["ARCH-004"]["status"], "PASS")

    def test_script_overrides_cannot_require_more_arguments(self):
        """Requirements: 6.1, 8.2."""
        repo = self.repo("liskov")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: liskov
        profiles:
          liskov:
            include: [architecture]
        """)
        _write(repo / "app.js", """
        class Port {
          send(value) { return value; }
        }
        class Adapter extends Port {
          send(value, extra) { return value + extra; }
        }
        class Ok extends Port {
          send(value, extra = 1) { return value + extra; }
        }
        """)
        _write(repo / "app.cpp", """
        struct Port {
          int send(int value) { return value; }
        };
        struct Adapter : public Port {
          int send(int value, int extra) { return value; }
        };
        """)
        report = self.audit(repo, profile="liskov")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-003"]["measured_value"], 2)
        self.assertEqual(metrics["ARCH-003"]["status"], "WARNING")

    def test_one_method_script_classes_that_forward(self):
        """Requirements: 6.1, 8.2."""
        repo = self.repo("wrappers")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: wrappers
        profiles:
          wrappers:
            include: [architecture]
        """)
        _write(repo / "app.js", """
        class Wrap {
          send(value) { return inner(value); }
        }
        class Plain {
          send(value) { return value; }
        }
        class Pair {
          send(value) { return inner(value); }
          recv() { return 1; }
        }
        """)
        _write(repo / "app.cpp", """
        struct Wrap {
          int send(int value) { return inner(value); }
        };
        """)
        report = self.audit(repo, profile="wrappers")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["ARCH-010"]["measured_value"], 2)
        self.assertEqual(metrics["ARCH-010"]["status"], "WARNING")

    def test_style_majority_includes_quotes_and_trailing_space(self):
        """Requirements: 8.1."""
        repo = self.repo("style")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: style
        profiles:
          style:
            include: [clean_code]
        """)
        _write(repo / "app.py", """
        def run():
            return "ok"
        """)
        _write(repo / "quotes.py", """
        def run():
            return 'ok'
        """)
        _write(repo / "trailing.py", """
        def run():
            return "ok"  
        """)
        _write(repo / "tabs.py", """
        def run():
        \treturn "ok"
        """)
        report = self.audit(repo, profile="style")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["CC-008"]["measured_value"], 3)
        self.assertEqual(metrics["CC-008"]["status"], "WARNING")
        self.assertEqual(set(metrics["CC-008"]["evidence_refs"]), {"quotes.py", "trailing.py", "tabs.py"})

    def test_spec_and_test_suffixes_are_tests(self):
        """Requirements: 6.1, 8.3."""
        repo = self.repo("specs")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: specs
        profiles:
          specs:
            include: [testing]
        """)
        _write(repo / "app.js", """
        function add(left, right) { return left + right; }
        """)
        _write(repo / "app.spec.js", """
        function testAdd() { return add(0, 1); }
        """)
        _write(repo / "widget.test.ts", """
        function testWidget() { return 1; }
        """)
        _write(repo / "calc.cpp", """
        int calc() { return 1; }
        """)
        _write(repo / "calc_test.cpp", """
        int test_calc() { return calc(); }
        """)
        _write(repo / "orphan.js", """
        function orphan() { return 1; }
        """)
        report = self.audit(repo, profile="specs")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        files = {item["file"] for item in report["findings"] if "TEST-001" in item["metric_ids"]}
        self.assertEqual(metrics["TEST-001"]["measured_value"], 1)
        self.assertEqual(metrics["TEST-001"]["status"], "FAIL")
        self.assertEqual(files, {"orphan.js"})

    def test_unseeded_random_covers_script_calls_and_determinism_claims(self):
        """Requirements: 6.1, 8.7."""
        repo = self.repo("random")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: random
        profiles:
          random:
            include: [reliability]
        """)
        _write(repo / "app.py", """
        def price():
            \"\"\"value_at_risk\"\"\"
            return random.random()
        """)
        _write(repo / "seeded.py", """
        def price():
            \"\"\"value_at_risk\"\"\"
            random.seed(1)
            return random.random()
        """)
        _write(repo / "roll.js", """
        function loss() { // Expected Shortfall
            return Math.random();
        }
        """)
        _write(repo / "draw.cpp", """
        double draw() { // DV01
            return rand();
        }
        """)
        report = self.audit(repo, profile="random")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["REL-003"]["measured_value"], 3)
        self.assertEqual(metrics["REL-003"]["status"], "FAIL")
        self.assertEqual(set(metrics["REL-003"]["evidence_refs"]), {"app.py:3", "roll.js:2", "draw.cpp:2"})

        claimed = self.repo("claimed")
        _write(claimed / "quality-auditor.yaml", """
        version: 1
        default_profile: random
        profiles:
          random:
            include: [reliability]
        """)
        _write(claimed / "tests" / "test_roll.py", """
        def test_roll():
            \"\"\"deterministic\"\"\"
            assert random.random() >= 0
        """)
        claimed_report = self.audit(claimed, profile="random")
        claimed_metrics = {item["metric_id"]: item for item in claimed_report["metrics"]}
        self.assertEqual(claimed_metrics["REL-003"]["measured_value"], 1)
        self.assertEqual(claimed_metrics["REL-003"]["status"], "FAIL")

        advisory = self.repo("advisory-random")
        _write(advisory / "quality-auditor.yaml", """
        version: 1
        default_profile: random
        profiles:
          random:
            include: [reliability]
        """)
        _write(advisory / "app.js", """
        function id() { return Math.random(); }
        """)
        advisory_report = self.audit(advisory, profile="random")
        advisory_metrics = {item["metric_id"]: item for item in advisory_report["metrics"]}
        self.assertEqual(advisory_metrics["REL-003"]["measured_value"], 1)
        self.assertEqual(advisory_metrics["REL-003"]["status"], "WARNING")
        self.assertEqual(advisory_report["decision"], "PASS")

    def test_script_tests_that_skip_production_are_gaps(self):
        """Requirements: 6.1, 8.6."""
        repo = self.repo("self-test")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: gap
        profiles:
          gap:
            include: [ai_evaluation]
        """)
        _write(repo / "app.js", """
        function add(left, right) { return left + right; }
        """)
        _write(repo / "app.spec.js", """
        function testAdd() { return add(1, 2); }
        function testGap() { return 1; }
        """)
        _write(repo / "calc.cpp", """
        int calc() { return 1; }
        """)
        _write(repo / "calc_test.cpp", """
        int test_calc() { return calc(); }
        int test_gap() { return 1; }
        """)
        report = self.audit(repo, profile="gap")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["AI-004"]["measured_value"], 50.0)
        self.assertEqual(metrics["AI-004"]["status"], "WARNING")

    def test_integration_names_count_across_packages(self):
        """Requirements: 8.3."""
        repo = self.repo("packages")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: tests
        profiles:
          tests:
            include: [testing]
        """)
        _write(repo / "packages" / "web" / "package.json", "{}")
        _write(repo / "packages" / "web" / "app.js", """
        function serve() { return 1; }
        """)
        _write(repo / "packages" / "api" / "package.json", "{}")
        _write(repo / "packages" / "api" / "app.js", """
        function query() { return 1; }
        """)
        _write(repo / "packages" / "web" / "checkout.spec.js", """
        function testEndToEnd() { return serve(); }
        """)
        _write(repo / "packages" / "api" / "flow.e2e.spec.js", """
        function check() { return query(); }
        """)
        _write(repo / "packages" / "api" / "end-to-end" / "pay.spec.js", """
        function pay() { return 1; }
        """)
        report = self.audit(repo, profile="tests")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["TEST-008"]["measured_value"], 3)
        self.assertEqual(metrics["TEST-008"]["status"], "PASS")

        single = self.repo("single-package")
        _write(single / "quality-auditor.yaml", """
        version: 1
        default_profile: tests
        profiles:
          tests:
            include: [testing]
        """)
        _write(single / "src" / "app.js", """
        function serve() { return 1; }
        """)
        _write(single / "src" / "app.spec.js", """
        function testEndToEnd() { return serve(); }
        """)
        single_report = self.audit(single, profile="tests")
        single_metrics = {item["metric_id"]: item for item in single_report["metrics"]}
        self.assertEqual(single_metrics["TEST-008"]["status"], "NOT_APPLICABLE")

    def test_property_cases_are_counted(self):
        """Requirements: 8.3."""
        repo = self.repo("property")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: tests
        profiles:
          tests:
            include: [testing]
        """)
        _write(repo / "package.json", """
        {"devDependencies": {"fast-check": "3.0.0"}}
        """)
        _write(repo / "tests" / "test_price.py", """
        from hypothesis import given
        @given(st.integers())
        def test_positive(value):
            assert value == value
        """)
        _write(repo / "price.spec.js", """
        function testPrice() { return fc.assert(fc.property(fc.integer(), function (n) { return n === n; })); }
        """)
        _write(repo / "price_test.cpp", """
        int test_price() { return RC_PROPERTY(gen, 1); }
        """)
        report = self.audit(repo, profile="tests")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["TEST-006"]["measured_value"], 3)
        self.assertEqual(metrics["TEST-006"]["status"], "PASS")

        declared = self.repo("property-missing")
        _write(declared / "quality-auditor.yaml", """
        version: 1
        default_profile: tests
        profiles:
          tests:
            include: [testing]
        """)
        _write(declared / "requirements.txt", "hypothesis==6.0.0\n")
        _write(declared / "tests" / "test_price.py", """
        import hypothesis
        def test_price():
            assert hypothesis is not None
        """)
        missing = self.audit(declared, profile="tests")
        missing_metrics = {item["metric_id"]: item for item in missing["metrics"]}
        self.assertEqual(missing_metrics["TEST-006"]["measured_value"], 0)
        self.assertEqual(missing_metrics["TEST-006"]["status"], "WARNING")

    def test_javascript_regex_literals_are_not_delimiters(self):
        """Requirements: 6.1, 8.7."""
        repo = self.repo("regex")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: syntax
        profiles:
          syntax:
            include: [syntax_static]
        """)
        _write(repo / "app.js", """
        const HELP_TAG = /<BlockHelp\\s+id="([^"]+)"\\s*\\/>/g
        function find(text) {
            return /^[a-z]+/.test(text)
        }
        function ratio(left, right) {
            return left / right
        }
        """)
        _write(repo / "card.jsx", """
        export default function MetricCard(label, value) {
            return <Nav onSelect={() => {}} /><div className="card"><strong>{value}</strong> / {label}</div>
        }
        """)
        _write(repo / "broken.js", """
        function bad() { return [1, 2 }
        """)
        report = self.audit(repo, profile="syntax")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        files = {item["file"] for item in report["findings"] if "REL-004" in item["metric_ids"]}
        self.assertEqual(metrics["REL-004"]["measured_value"], 1)
        self.assertEqual(metrics["REL-004"]["status"], "FAIL")
        self.assertEqual(files, {"broken.js"})

    def test_assertion_percent_counts_script_tests(self):
        """Requirements: 6.1, 8.3."""
        repo = self.repo("asserts")
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: tests
        profiles:
          tests:
            include: [testing]
        """)
        _write(repo / "app.spec.js", """
        function testAdd() { expect(add(1, 1)).toBe(2); }
        function testEmpty() { return 1; }
        function testTautology() { assert(true); }
        it("checks", () => { expect(1).toBe(1); })
        it("blank", () => { return 1 })
        """)
        _write(repo / "calc_test.cpp", """
        int test_calc() { ASSERT_EQ(calc(), 1); return 1; }
        int test_gap() { return 1; }
        """)
        report = self.audit(repo, profile="tests")
        metrics = {item["metric_id"]: item for item in report["metrics"]}
        self.assertEqual(metrics["TEST-011"]["measured_value"], 42.9)
        self.assertEqual(metrics["TEST-011"]["status"], "FAIL")
        self.assertEqual(
            set(metrics["TEST-011"]["evidence_refs"]),
            {"app.spec.js:testEmpty", "app.spec.js:testTautology", "app.spec.js:it:5", "calc_test.cpp:test_gap"},
        )

    def test_policy_reports_and_history(self):
        """Requirements: 2.10, 8.3, 8.4, 8.5, 8.6, 8.7, 8.9, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.8, 9.9, 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8, 12.1, 12.2, 12.3, 12.4, 12.5, 14.1, 14.7, 14.8, 14.9."""
        clean = self.repo("clean")
        _write(clean / "app.py", "def main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n")
        first = self.audit(clean, profile="security", history_path=self.tmp / "history.csv")
        self.assertEqual(first["decision"], "PASS")
        self.assertIn("selected checks passed", first["profile_scope_note"])
        self.assertIn("does not mean all 112 metrics were evaluated", first["profile_scope_note"])
        self.assertTrue(first["profile_scope_note"].startswith("PASS means the selected checks passed"))
        self.assertEqual(len(first["metrics"]), 112)
        for item in first["metrics"]:
            self.assertIn(item["status"], {"PASS", "FAIL", "WARNING", "SKIPPED", "UNAVAILABLE", "NOT_APPLICABLE", "ERROR", "INCONCLUSIVE"})
            self.assertIn("threshold", item)
            self.assertIn("applicability", item)
        self.assertTrue(Path(first["reports"]["json"]).is_file())
        self.assertTrue(Path(first["reports"]["markdown"]).is_file())
        self.assertTrue(Path(first["reports"]["html"]).is_file())
        self.assertIn("Confirmed violations", Path(first["reports"]["markdown"]).read_text(encoding="utf-8"))
        skipped = {item["id"]: item["reason"] for item in first["skipped_checks"]}
        self.assertEqual(skipped["mutation_testing"], "profile exclusion")
        secret = self.repo("secret")
        _write(secret / "app.py", 'TOKEN = "AKIAIOSFODNN7EXAMPLE"\n\ndef main():\n    return TOKEN\n')
        second = self.audit(secret, profile="security", history_path=self.tmp / "history.csv")
        self.assertEqual(second["decision"], "FAIL")
        breach = next(item for item in second["findings"] if item["confidence"] == "confirmed")
        for field in ("repository", "revision", "location", "check_id", "metric_ids", "tool", "profile", "configuration_hash", "observation", "evidence_pointer"):
            self.assertTrue(breach["provenance"].get(field) not in (None, "", []))
        self.assertIn("not applied", Path(second["reports"]["markdown"]).read_text(encoding="utf-8").lower())
        comparison = compare_history(self.tmp / "history.csv", first["run_id"], second["run_id"], load(SKILL / "config" / "metrics.yaml")["metrics"])
        sec = next(item for item in comparison["comparisons"] if item["metric_id"] == "SEC-001")
        self.assertTrue(sec["regression"])
        unavailable = next(item for item in comparison["comparisons"] if item["metric_id"] == "TEST-002")
        self.assertEqual(unavailable["comparison"], "not_comparable")
        self.assertFalse(unavailable["regression"])
        self.assertTrue(trends(self.tmp / "history.csv", "SEC-001"))
        header = (self.tmp / "history.csv").read_text(encoding="utf-8").splitlines()[0]
        for column in ("schema_version", "timestamp", "repository", "commit_sha", "profile", "metric_id", "status", "measured_value", "threshold", "run_id", "report_path"):
            self.assertIn(column, header)
        excused = self.repo("excused")
        _write(excused / "quality-auditor.yaml", """
        version: 1
        default_profile: security
        exceptions:
          - id: EX-1
            metric_id: SEC-001
            file: app.py
            justification: Rotated example retained for the fixture only.
            scope: file
        profiles:
          security:
            include: [secrets, security_sast, dependency_audit, insecure_config]
        """)
        _write(excused / "app.py", 'TOKEN = "AKIAIOSFODNN7EXAMPLE"\n')
        excused_report = self.audit(excused, profile="security")
        self.assertTrue(any(item["confidence"] == "accepted_exception" for item in excused_report["findings"]))
        self.assertEqual({item["metric_id"]: item["status"] for item in excused_report["metrics"]}["SEC-001"], "PASS")
        self.assertGreater(excused_report["counts"]["exceptions"], 0)
        incomplete = self.repo("incomplete")
        _write(incomplete / "requirements.txt", "requests==2.31.0\n")
        _write(incomplete / "app.py", "def main():\n    return 1\n")
        incomplete_report = self.audit(incomplete, profile="security")
        self.assertEqual(incomplete_report["decision"], "INCOMPLETE")
        self.assertEqual({item["metric_id"]: item["status"] for item in incomplete_report["metrics"]}["SEC-002"], "UNAVAILABLE")
        full = self.repo("fullmetrics")
        _write(full / "app.py", "def add(a, b):\n    return a + b\n")
        _write(full / "tests" / "test_add.py", "from app import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
        full_report = self.audit(full, profile="full")
        self.assertEqual({item["metric_id"] for item in full_report["metrics"]}, {item["id"] for item in load(SKILL / "config" / "metrics.yaml")["metrics"]})
        self.assertEqual(full_report["decision"], "INCOMPLETE")
        self.assertEqual({item["metric_id"]: item["status"] for item in full_report["metrics"]}["MAINT-001"], "NOT_APPLICABLE")
        html = render_html({"decision": "PASS", "decision_rationale": "<script>", "profile_scope_note": "", "profile": "full", "repository": {"revision": "abc"}, "counts": {key: 0 for key in ("confirmed_violations", "unresolved_candidates", "exceptions", "failed_checks", "skipped_checks", "unavailable_checks")}, "metrics": [], "findings": [{"id": "F-0001", "confidence": "confirmed", "observation": "<b>", "suggested_fix": "no"}]})
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_security_and_init(self):
        """Requirements: 4.3, 4.4, 4.5, 4.6, 4.8, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10, 10.12, 14.6, 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9, 15.10."""
        self.assertNotIn("pip install", SCRIPT.read_text(encoding="utf-8"))
        runtime = load(SKILL / "config" / "policy.yaml")
        self.assertTrue(runtime["zero_confirmed_violations"])
        probe = runtime_probe(lambda _name: None)
        self.assertTrue(probe["approval_required"])
        self.assertTrue(probe["limited_checks_offered"])
        repo = self.repo()
        _write(repo / "setup.py", "open('PWNED','w').write('x')\n")
        _write(repo / "package.json", '{"dependencies":{"left":"1.0.0"}}\n')
        _write(repo / "src" / "app.py", "def main():\n    return 1\n")
        _write(repo / "web" / "app.ts", "export function main(){ return 1 }\n")
        _write(repo / "native" / "main.cpp", "int main(){ return 0; }\n")
        discovery = init_repository(repo, load(SKILL / "quality-auditor.yaml"), approve_write=False)
        self.assertFalse(discovery["written"])
        self.assertFalse((repo / "PWNED").exists())
        self.assertIn("python", discovery["discovery"]["languages"])
        self.assertIn("typescript", discovery["discovery"]["languages"])
        self.assertIn("cpp", discovery["discovery"]["languages"])
        self.assertIn("package.json", discovery["discovery"]["analyzer_configs"])
        self.assertEqual(discovery["installations"], [])
        written = init_repository(repo, load(SKILL / "quality-auditor.yaml"), approve_write=True, languages=["python"], directories=["src"])
        self.assertTrue(written["written"])
        text = (repo / "quality-auditor.yaml").read_text(encoding="utf-8")
        self.assertNotIn("metrics:", text)
        document = auditor.load(repo / "quality-auditor.yaml")
        document["profiles"]["custom"] = {"include": ["secrets"]}
        (repo / "quality-auditor.yaml").write_text(__import__("yaml").safe_dump(document), encoding="utf-8")
        init_repository(repo, load(SKILL / "quality-auditor.yaml"), approve_write=True)
        self.assertIn("custom", auditor.load(repo / "quality-auditor.yaml")["profiles"])
        self.assertFalse((repo / "PWNED").exists())
        target = self.tmp / "agent-home"
        denied = install_skill(target, SKILL, approve=False)
        self.assertEqual(denied["status"], "approval_required")
        self.assertFalse((target / ".cursor" / "skills" / "code-quality-auditor" / "SKILL.md").exists())
        installed = install_skill(target, SKILL, approve=True)
        self.assertTrue(installed["installed"])
        self.assertTrue((Path(installed["path"]) / "config" / "metrics.yaml").is_file())
        tools = load(SKILL / "config" / "tools.yaml")["tools"]
        with mock.patch("cqa.security.subprocess.run") as runner:
            blocked = install_analyzer(tools["ruff"], approve=False)
            self.assertEqual(blocked["status"], "approval_required")
            runner.assert_not_called()
            verified = install_analyzer(tools["ruff"], approve=True)
            self.assertEqual(verified["status"], "blocked")
            runner.assert_not_called()
        log = ExecutionLog()
        with self.assertRaises(PermissionError):
            run_contained(["/usr/bin/true"], repo, log)
        self.assertTrue(log.denied)
        before = {path.relative_to(repo).as_posix() for path in repo.rglob("*") if path.is_file()}
        report = self.audit(repo, profile="security")
        after = {path.relative_to(repo).as_posix() for path in repo.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertTrue(report["execution"]["denied"] or report["decision"] in {"PASS", "FAIL", "INCOMPLETE"})
        with self.assertRaises(ValueError):
            auditor.audit(repo, skill_root=SKILL, output_dir=repo / "inside")
        contained = ExecutionLog(allow_repo_execution=True, sandbox_confirmed=True)
        with mock.patch("cqa.security.probe_sandbox", return_value=(False, "containment unavailable")):
            with self.assertRaises(PermissionError):
                run_contained(["/usr/bin/true"], repo, contained)
        self.assertTrue(any(item["operation"] == "containment" for item in contained.denied))

    def test_scope_languages_and_adapters(self):
        """Requirements: 1.2, 1.5, 1.6, 1.7, 1.8, 1.9, 13.4."""
        from cqa.adapters import ADAPTERS, LanguageAdapter, register_adapter

        self.assertEqual({adapter.language for adapter in ADAPTERS}, {"python", "javascript", "typescript", "cpp"})

        class RubyAdapter(LanguageAdapter):
            language = "ruby"
            extensions = (".rb",)

            def analyze(self, root, path):
                return {"path": "demo.rb", "language": "ruby", "syntax_errors": [], "symbols": [], "limits": []}

        register_adapter(RubyAdapter())
        repo = self.repo()
        _write(repo / "demo.rb", "def ruby_only\n  1\nend\n")
        _write(repo / "app.py", "def main():\n    return 1\n")
        files, langs = auditor.discover(repo)
        self.assertIn("ruby", langs)
        skill_sources = "\n".join(path.read_text(encoding="utf-8") for path in (SKILL / "scripts").rglob("*.py"))
        self.assertNotIn("QuantLineage", skill_sources)
        self.assertNotIn("quantlineage", skill_sources)
        report = self.audit(repo, profile="security")
        self.assertIn("platform_limitations", report["execution"])
        self.assertIn(report["decision"], {"PASS", "FAIL", "INCOMPLETE"})
        git = self.repo("gitrepo")
        _write(git / "app.py", "def main():\n    return 1\n")
        env = os.environ.copy()
        env.update({"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@example.com"})
        subprocess.check_call(["git", "init"], cwd=git, env=env, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "add", "app.py"], cwd=git, env=env)
        subprocess.check_call(["git", "commit", "-m", "first"], cwd=git, env=env, stdout=subprocess.DEVNULL)
        _write(git / "app.py", "def main():\n    return 2\n")
        changed = self.audit(git, profile="security", scope="changed")
        self.assertIn(changed["decision"], {"PASS", "FAIL", "INCOMPLETE"})
        subprocess.check_call(["git", "add", "app.py"], cwd=git, env=env)
        subprocess.check_call(["git", "commit", "-m", "second"], cwd=git, env=env, stdout=subprocess.DEVNULL)
        first_commit = subprocess.check_output(["git", "rev-list", "--max-parents=0", "HEAD"], cwd=git, text=True).strip()
        original = (git / "app.py").read_text(encoding="utf-8")
        committed = self.audit(git, profile="security", commit=first_commit)
        self.assertEqual((git / "app.py").read_text(encoding="utf-8"), original)
        self.assertEqual(committed["repository"]["revision"], first_commit)
        missing_pr = self.audit(git, profile="security", scope="pull-request")
        self.assertEqual(missing_pr["decision"], "INCOMPLETE")
        self.assertIn("network", missing_pr["decision_rationale"])

    def test_directory_override_and_examples_are_yaml(self):
        """Requirements: 15.5, 3.13."""
        repo = self.repo()
        _write(repo / "quality-auditor.yaml", """
        version: 1
        default_profile: full
        thresholds:
          SEC-001: 1
        profiles:
          full: {}
        """)
        _write(repo / "services" / "quality-auditor.yaml", """
        version: 1
        thresholds:
          SEC-001: 3
        profiles: {}
        """)
        _write(repo / "services" / "app.py", "def main():\n    return 1\n")
        report = self.audit(repo, directories=["services"])
        self.assertEqual(report["effective_policy"]["thresholds"]["SEC-001"]["value"], 3)
        for path in (SKILL / "examples").glob("*.yaml"):
            auditor.load(path)


if __name__ == "__main__":
    unittest.main()
