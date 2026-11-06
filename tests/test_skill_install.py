"""Layout tests for multi-agent skill install, update, and uninstall.

These tests check directories, copies, and symlinks. They do not show that
Cursor, Claude Code, or Codex loaded the skill. Native CLI checks live in
test_agent_cli_smoke.py.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".agents" / "skills" / "code-quality-auditor"
SCRIPT = SKILL / "scripts" / "auditor.py"
sys.path.insert(0, str(SKILL / "scripts"))

spec = importlib.util.spec_from_file_location("auditor_skill_install", SCRIPT)
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)

from cqa.security import ExecutionLog, install_skill  # noqa: E402
from cqa.skill_install import install_agents, plan_slots  # noqa: E402

NAME = "code-quality-auditor"


def _git(repo, *args):
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        }
    )
    subprocess.check_call(["git", *args], cwd=repo, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class SkillInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-skill-install-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = self.tmp / "project"
        self.root.mkdir()

    def run_cli(self, *args, cwd=None, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=cwd or self.tmp,
            env=env,
            capture_output=True,
            text=True,
        )

    def slot(self, agent, root=None):
        root = self.root if root is None else root
        relative = {"cursor": Path(".cursor"), "claude": Path(".claude"), "codex": Path(".agents")}[agent]
        return root / relative / "skills" / NAME

    def snapshot(self, root=None):
        root = self.root if root is None else root
        found = {}
        if not root.exists():
            return found
        for path in root.rglob("*"):
            if path.is_symlink():
                found[path.relative_to(root).as_posix()] = ("symlink", os.readlink(path))
            elif path.is_file():
                found[path.relative_to(root).as_posix()] = ("file", path.read_bytes())
        return found

    def parse(self, completed):
        lines = completed.stdout.splitlines()
        self.assertGreaterEqual(len(lines), 1, completed.stderr)
        rows = []
        for line in lines[1:]:
            agent, scope, method, status, path = line.split("\t")
            rows.append({"agent": agent, "scope": scope, "method": method, "status": status, "path": path})
        return lines[0], rows

    def write_siblings(self, root=None):
        root = self.root if root is None else root
        files = {
            root / ".cursor" / "skills" / "other" / "SKILL.md": b"cursor-sibling\n",
            root / ".claude" / "settings.json": b'{"kept": true}\n',
            root / ".agents" / "skills" / "other" / "SKILL.md": b"agents-sibling\n",
        }
        for path, payload in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        return files

    def assert_siblings(self, files):
        for path, payload in files.items():
            self.assertEqual(path.read_bytes(), payload)

    def test_plan_slots_do_not_touch_the_filesystem(self):
        missing = self.tmp / "missing root"
        slots = plan_slots(missing, agent="all", scope="global")
        self.assertFalse(missing.exists())
        self.assertEqual([slot["agent"] for slot in slots], ["codex", "cursor", "claude"])
        self.assertEqual([slot["scope"] for slot in slots], ["global", "global", "global"])
        self.assertEqual([slot["link"] for slot in slots], [False, False, True])
        project = plan_slots(missing, agent="claude", scope="project")
        home = plan_slots(missing, agent="claude", scope="global")
        self.assertEqual(project[0]["path"], home[0]["path"])
        self.assertEqual(project[0]["path"], missing / ".claude" / "skills" / NAME)
        with self.assertRaises(ValueError):
            plan_slots(missing, agent="all", destination=missing / NAME)
        with self.assertRaises(ValueError):
            plan_slots(missing, agent="claude", destination=missing / "other-skill")

    def test_unapproved_install_writes_nothing(self):
        siblings = self.write_siblings()
        existing = self.slot("cursor")
        existing.parent.mkdir(parents=True, exist_ok=True)
        existing.mkdir()
        (existing / "keep.txt").write_text("stay", encoding="utf-8")
        before = self.snapshot()
        denied = install_skill(self.root, SKILL, approve=False)
        self.assertEqual(denied["status"], "approval_required")
        self.assertFalse(denied["installed"])
        self.assertIsNone(denied["path"])
        completed = self.run_cli("install", "--target", str(self.root), "--agent", "all")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "approval_required")
        self.assertTrue(all(row["method"] == "none" and row["status"] == "approval_required" for row in rows))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((existing / "keep.txt").read_text(encoding="utf-8"), "stay")
        self.assert_siblings(siblings)
        log = ExecutionLog()
        install_agents(self.root, SKILL, approve=False, log=log)
        self.assertEqual(log.denied[0]["detail"], "skill installation needs explicit approval")
        self.assertFalse(log.allow_tools)
        self.assertFalse(log.allow_repo_execution)
        self.assertFalse(log.sandbox_confirmed)

    def test_default_install_is_cursor_project_copy(self):
        completed = self.run_cli("install", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "installed")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["agent"], "cursor")
        self.assertEqual(rows[0]["scope"], "project")
        self.assertEqual(rows[0]["method"], "copy")
        self.assertEqual(rows[0]["status"], "installed")
        self.assertTrue(Path(rows[0]["path"]).is_absolute())
        metrics = self.slot("cursor") / "config" / "metrics.yaml"
        self.assertTrue(metrics.is_file())
        self.assertEqual(metrics.read_bytes(), (SKILL / "config" / "metrics.yaml").read_bytes())
        self.assertFalse(self.slot("claude").exists())
        self.assertFalse(self.slot("codex").exists())
        self.assertNotIn("--allow-tools", completed.stdout)
        self.assertNotIn("--allow-repo-execution", completed.stdout)
        self.assertNotIn("--sandbox-confirmed", completed.stdout)

    def test_repeated_install_is_unchanged_and_refreshes_our_skill(self):
        first = install_skill(self.root, SKILL, approve=True)
        self.assertTrue(first["installed"])
        self.assertEqual(first["status"], "installed")
        second = install_skill(self.root, SKILL, approve=True)
        self.assertTrue(second["installed"])
        self.assertEqual(second["status"], "unchanged")
        slot = self.slot("cursor")
        (slot / "MARKER.txt").write_text("local edit", encoding="utf-8")
        text = (slot / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: code-quality-auditor", text)
        third = self.run_cli("install", "--target", str(self.root), "--approve")
        self.assertEqual(third.returncode, 0, third.stderr)
        status, _rows = self.parse(third)
        self.assertEqual(status, "updated")
        self.assertFalse((slot / "MARKER.txt").exists())
        self.assertEqual((slot / "SKILL.md").read_bytes(), (SKILL / "SKILL.md").read_bytes())
        fourth = self.run_cli("install", "--target", str(self.root), "--approve")
        self.assertEqual(self.parse(fourth)[0], "unchanged")

    def test_foreign_occupant_is_refused_with_no_partial_writes(self):
        siblings = self.write_siblings()
        empty = self.slot("cursor")
        empty.mkdir(parents=True)
        other = self.tmp / "other-agent" / ".cursor" / "skills" / NAME
        other.mkdir(parents=True)
        (other / "SKILL.md").write_text("---\nname: other-skill\n---\n", encoding="utf-8")
        (other / "scripts").mkdir()
        (other / "scripts" / "auditor.py").write_text("print(1)\n", encoding="utf-8")
        file_root = self.tmp / "file-agent"
        file_slot = file_root / ".cursor" / "skills" / NAME
        file_slot.parent.mkdir(parents=True)
        file_slot.write_text("not a skill", encoding="utf-8")
        link_root = self.tmp / "link-agent"
        outside = self.tmp / "outside-tree"
        outside.mkdir()
        (outside / "keep.txt").write_text("kept", encoding="utf-8")
        link_slot = link_root / ".cursor" / "skills" / NAME
        link_slot.parent.mkdir(parents=True)
        os.symlink(outside, link_slot)

        before_empty = self.snapshot(self.root)
        refused = self.run_cli("install", "--target", str(self.root), "--agent", "all", "--approve")
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertEqual(self.parse(refused)[0], "refused")
        self.assertEqual(self.snapshot(self.root), before_empty)
        self.assertFalse(self.slot("codex").exists())
        self.assertFalse(self.slot("claude").exists())
        self.assertEqual(list(empty.iterdir()), [])
        self.assert_siblings(siblings)

        other_root = other.parents[2]
        before_other = (other / "SKILL.md").read_bytes()
        other_run = self.run_cli("install", "--target", str(other_root), "--approve")
        self.assertEqual(other_run.returncode, 1)
        self.assertEqual((other / "SKILL.md").read_bytes(), before_other)
        self.assertFalse((other_root / ".claude").exists())
        self.assertFalse((other_root / ".agents").exists())

        before_file = file_slot.read_bytes()
        file_run = self.run_cli("install", "--target", str(file_root), "--agent", "all", "--approve")
        self.assertEqual(file_run.returncode, 1)
        self.assertEqual(file_slot.read_bytes(), before_file)
        self.assertFalse((file_root / ".agents").exists())
        self.assertFalse((file_root / ".claude").exists())

        link_run = self.run_cli("install", "--target", str(link_root), "--approve")
        self.assertEqual(link_run.returncode, 1)
        self.assertTrue(link_slot.is_symlink())
        self.assertEqual((outside / "keep.txt").read_text(encoding="utf-8"), "kept")
        legacy = install_skill(file_root, SKILL, approve=True)
        self.assertFalse(legacy["installed"])
        self.assertEqual(legacy["status"], "refused")
        self.assertEqual(file_slot.read_bytes(), before_file)

    def test_paths_with_spaces_for_target_repo_and_out(self):
        target = self.tmp / "agent home"
        repo = self.tmp / "host project"
        out = self.tmp / "report out"
        repo.mkdir()
        (repo / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        _git(repo, "init")
        _git(repo, "add", "app.py")
        _git(repo, "commit", "-m", "first")
        installed = self.run_cli("install", "--target", str(target), "--approve")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assertTrue((target / ".cursor" / "skills" / NAME / "config" / "metrics.yaml").is_file())
        neither = self.tmp / "neither"
        neither.mkdir()
        audited = self.run_cli(
            "audit",
            "--repo",
            str(repo),
            "--profile",
            "fast",
            "--out",
            str(out),
            cwd=self.tmp / "neither",
        )
        self.assertIn(audited.returncode, {0, 1}, audited.stderr)
        decision, report_path = audited.stdout.strip().split(" ", 1)
        self.assertIn(decision, {"PASS", "FAIL", "INCOMPLETE"})
        report = Path(report_path)
        self.assertTrue(report.is_file())
        self.assertTrue(str(out) in str(report.resolve()))
        self.assertNotIn(report.resolve(), [repo.resolve(), *repo.resolve().parents])
        self.assertTrue(repo.resolve() not in report.resolve().parents)

    def test_siblings_survive_install_update_and_uninstall(self):
        siblings = self.write_siblings()
        installed = self.run_cli("install", "--agent", "all", "--scope", "project", "--target", str(self.root), "--approve")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        self.assert_siblings(siblings)
        updated = self.run_cli("update", "--agent", "all", "--scope", "global", "--target", str(self.root), "--approve")
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertEqual(self.parse(updated)[0], "unchanged")
        self.assert_siblings(siblings)
        removed = self.run_cli("uninstall", "--agent", "all", "--target", str(self.root), "--approve")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertEqual(self.parse(removed)[0], "removed")
        self.assertFalse(self.slot("cursor").exists())
        self.assertFalse(self.slot("claude").exists() or self.slot("claude").is_symlink())
        self.assertFalse(self.slot("codex").exists())
        self.assert_siblings(siblings)

    def test_agent_all_links_claude_and_falls_back_to_copy(self):
        completed = self.run_cli("install", "--agent", "all", "--scope", "project", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "installed")
        self.assertEqual([row["agent"] for row in rows], ["codex", "cursor", "claude"])
        self.assertEqual(rows[0]["method"], "copy")
        self.assertEqual(rows[1]["method"], "copy")
        self.assertEqual(rows[2]["method"], "symlink")
        link = self.slot("claude")
        self.assertTrue(link.is_symlink())
        self.assertFalse(os.path.isabs(os.readlink(link)))
        self.assertEqual(link.resolve(), self.slot("codex").resolve())
        self.assertTrue((self.slot("cursor") / "config" / "metrics.yaml").is_file())
        self.assertTrue((link / "config" / "metrics.yaml").is_file())

        fallback_root = self.tmp / "fallback"
        with mock.patch("cqa.skill_install.os.symlink", side_effect=OSError("symlinks are unavailable")):
            result = install_agents(fallback_root, SKILL, agent="all", approve=True)
        self.assertEqual(result["status"], "installed")
        claude = next(item for item in result["destinations"] if item["agent"] == "claude")
        self.assertEqual(claude["method"], "copy")
        copied = fallback_root / ".claude" / "skills" / NAME
        self.assertFalse(copied.is_symlink())
        self.assertTrue((copied / "scripts" / "auditor.py").is_file())
        self.assertTrue((fallback_root / ".agents" / "skills" / NAME / "config" / "metrics.yaml").is_file())

    def test_source_cursor_slot_is_copied_before_it_could_be_replaced(self):
        cursor = self.slot("cursor")
        shutil.copytree(SKILL, cursor, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (cursor / "CANARY.txt").write_text("from-cursor\n", encoding="utf-8")
        script = cursor / "scripts" / "auditor.py"
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        completed = subprocess.run(
            [sys.executable, str(script), "install", "--agent", "all", "--target", str(self.root), "--approve"],
            cwd=elsewhere,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual((cursor / "CANARY.txt").read_text(encoding="utf-8"), "from-cursor\n")
        self.assertEqual((self.slot("codex") / "CANARY.txt").read_text(encoding="utf-8"), "from-cursor\n")
        self.assertTrue((cursor / "scripts" / "auditor.py").is_file())
        self.assertTrue((self.slot("codex") / "config" / "metrics.yaml").is_file())
        self.assertTrue(self.slot("claude").is_symlink())
        self.assertEqual(self.slot("claude").resolve(), self.slot("codex").resolve())

    def test_update_absent_and_uninstall_absent(self):
        missing = self.run_cli("update", "--target", str(self.root), "--agent", "codex", "--approve")
        self.assertEqual(missing.returncode, 1, missing.stdout)
        self.assertEqual(self.parse(missing)[0], "absent")
        self.assertFalse(self.slot("codex").exists())
        self.assertFalse((self.root / ".agents").exists())
        gone = self.run_cli("uninstall", "--target", str(self.root), "--agent", "codex", "--approve")
        self.assertEqual(gone.returncode, 0, gone.stderr)
        self.assertEqual(self.parse(gone)[0], "absent")
        self.assertFalse(self.root.exists() and self.slot("codex").exists())
        for command in ("update", "uninstall"):
            fresh = self.tmp / f"fresh-{command}"
            blocked = self.run_cli(command, "--target", str(fresh))
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            self.assertEqual(self.parse(blocked)[0], "approval_required")
            self.assertFalse(fresh.exists())

    def test_uninstall_unlinks_symlink_and_keeps_the_target(self):
        target = self.tmp / "real-skill"
        shutil.copytree(SKILL, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        slot = self.slot("cursor")
        slot.parent.mkdir(parents=True)
        os.symlink(target, slot)
        marker = target / "config" / "metrics.yaml"
        before = marker.read_bytes()
        completed = self.run_cli("uninstall", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "removed")
        self.assertEqual(rows[0]["method"], "symlink")
        self.assertFalse(slot.exists())
        self.assertFalse(slot.is_symlink())
        self.assertEqual(marker.read_bytes(), before)

    def test_destination_override_and_rejections(self):
        destination = self.tmp / "custom place" / NAME
        blocked = self.run_cli(
            "install",
            "--agent",
            "claude",
            "--target",
            str(self.root),
            "--destination",
            str(destination),
        )
        self.assertEqual(blocked.returncode, 0, blocked.stderr)
        self.assertEqual(self.parse(blocked)[0], "approval_required")
        self.assertFalse(destination.exists())
        installed = self.run_cli(
            "install",
            "--agent",
            "claude",
            "--scope",
            "global",
            "--target",
            str(self.root),
            "--destination",
            str(destination),
            "--approve",
        )
        self.assertEqual(installed.returncode, 0, installed.stderr)
        status, rows = self.parse(installed)
        self.assertEqual(status, "installed")
        self.assertEqual(rows[0]["agent"], "claude")
        self.assertEqual(rows[0]["scope"], "global")
        self.assertEqual(Path(rows[0]["path"]), destination)
        self.assertTrue((destination / "scripts" / "auditor.py").is_file())
        self.assertFalse(self.slot("claude").exists())
        self.assertFalse((self.root / ".claude").exists())
        rejected = self.run_cli(
            "install",
            "--agent",
            "all",
            "--target",
            str(self.root),
            "--destination",
            str(destination),
            "--approve",
        )
        self.assertEqual(rejected.returncode, 2, rejected.stdout)
        self.assertIn("destination cannot be combined with --agent all", rejected.stderr)
        bad = self.tmp / "custom place" / "not-the-skill"
        named = self.run_cli("install", "--agent", "codex", "--target", str(self.root), "--destination", str(bad), "--approve")
        self.assertEqual(named.returncode, 2)
        self.assertIn("the last path component must be code-quality-auditor", named.stderr)
        self.assertFalse(bad.exists())

    def test_install_ignores_home_and_claude_config_dir(self):
        home = self.tmp / "real-home"
        config = self.tmp / "claude-config"
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["CLAUDE_CONFIG_DIR"] = str(config)
        completed = self.run_cli("install", "--agent", "claude", "--target", str(self.root), "--approve", env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(self.slot("claude").is_dir())
        self.assertFalse(home.exists())
        self.assertFalse(config.exists())

    def test_install_does_not_download_or_approve_execution(self):
        log = ExecutionLog()
        with mock.patch("subprocess.run") as runner, mock.patch("urllib.request.urlopen") as opener:
            result = install_agents(self.root, SKILL, agent="cursor", approve=True, log=log)
        runner.assert_not_called()
        opener.assert_not_called()
        self.assertEqual(result["status"], "installed")
        self.assertFalse(log.allow_tools)
        self.assertFalse(log.allow_repo_execution)
        self.assertFalse(log.sandbox_confirmed)
        self.assertFalse(log.allow_install)
        self.assertFalse(log.allow_network)
        self.assertTrue(any(item["action"] == "install-skill" for item in log.approvals))
        self.assertNotIn("pip", json.dumps(log.commands))
        legacy = install_skill(self.tmp / "legacy", SKILL, approve=True)
        self.assertTrue(legacy["installed"])
        self.assertTrue((Path(legacy["path"]) / "config" / "metrics.yaml").is_file())

    def test_cross_agent_fast_findings_match_outside_the_fixture(self):
        work = self.tmp / "work dir"
        work.mkdir()
        (work / "quality-auditor.yaml").write_text("version: 1\ndefault_profile: fast\nprofiles:\n  fast:\n    include: [secrets]\n", encoding="utf-8")
        (work / "config").mkdir()
        (work / "config" / "metrics.yaml").write_text("metrics: []\n", encoding="utf-8")
        repo = self.tmp / "fixture"
        repo.mkdir()
        (repo / "app.py").write_text("def add(a, b):\n    return a + b\n\ndef unused():\n    return 1\n", encoding="utf-8")
        _git(repo, "init")
        _git(repo, "add", "app.py")
        _git(repo, "commit", "-m", "first")
        (repo / "app.py").write_text("def add(a, b):\n    return a + b\n\ndef unused():\n    return 1\n\n", encoding="utf-8")
        installed = self.run_cli("install", "--agent", "all", "--target", str(self.root), "--approve")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        normalized = []
        for agent in ("cursor", "claude", "codex"):
            out = self.tmp / f"out {agent}"
            script = self.slot(agent) / "scripts" / "auditor.py"
            completed = subprocess.run(
                [sys.executable, str(script), "audit", "--repo", str(repo), "--profile", "fast", "--out", str(out)],
                cwd=work,
                capture_output=True,
                text=True,
            )
            self.assertIn(completed.returncode, {0, 1}, completed.stderr)
            _decision, report_path = completed.stdout.strip().split(" ", 1)
            report_file = Path(report_path)
            self.assertTrue(repo.resolve() not in report_file.resolve().parents)
            self.assertNotEqual(report_file.resolve(), repo.resolve())
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(len(report["metrics"]), 112)
            self.assertNotIn("mutation_testing", report["selected_checks"])
            normalized.append(_normalize(report))
        self.assertEqual(normalized[0], normalized[1])
        self.assertEqual(normalized[1], normalized[2])

    def test_skill_directory_audit_is_refused_without_the_flag(self):
        home = self.tmp / "home"
        env = os.environ.copy()
        env["HOME"] = str(home)
        refused = self.run_cli("audit", "--repo", str(SKILL), "--profile", "fast", env=env)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("refusing to audit the skill package; pass the host project as --repo", refused.stdout)
        nested = self.run_cli("audit", "--repo", str(SKILL / "config"), "--profile", "fast", env=env)
        self.assertEqual(nested.returncode, 2)
        self.assertFalse(home.exists())
        allowed = self.run_cli(
            "audit",
            "--repo",
            str(SKILL),
            "--profile",
            "fast",
            "--allow-skill-target",
            "--out",
            str(self.tmp / "skill-out"),
            env=env,
        )
        self.assertIn(allowed.returncode, {0, 1}, allowed.stderr)
        self.assertNotIn("refusing to audit the skill package", allowed.stdout)
        host = self.run_cli(
            "audit",
            "--repo",
            str(ROOT),
            "--profile",
            "fast",
            "--out",
            str(self.tmp / "repo-out"),
            env=env,
        )
        self.assertIn(host.returncode, {0, 1}, host.stderr)
        self.assertNotIn("refusing to audit the skill package", host.stdout)

    def test_default_report_stays_outside_the_repo(self):
        repo = self.tmp / "plain"
        repo.mkdir()
        (repo / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        home = self.tmp / "home"
        env = os.environ.copy()
        env["HOME"] = str(home)
        completed = self.run_cli("audit", "--repo", str(repo), "--profile", "fast", env=env, cwd=self.tmp)
        self.assertIn(completed.returncode, {0, 1}, completed.stderr)
        _decision, report_path = completed.stdout.strip().split(" ", 1)
        report = Path(report_path)
        expected_root = home / ".code-quality-auditor" / "reports" / repo.name
        self.assertTrue(str(report.resolve()).startswith(str(expected_root.resolve())))
        self.assertTrue(repo.resolve() not in report.resolve().parents)
        with self.assertRaises(ValueError):
            auditor.audit(repo, skill_root=SKILL, output_dir=repo / "inside")

    def test_ancestor_symlink_refuses_missing_slot(self):
        outside = self.tmp / "outside-tree"
        outside.mkdir()
        (outside / "marker.txt").write_text("keep", encoding="utf-8")
        for agent, link in {
            "cursor": self.root / ".cursor",
            "claude": self.root / ".claude",
            "codex": self.root / ".agents",
        }.items():
            link.symlink_to(outside, target_is_directory=True)
            completed = self.run_cli("install", "--agent", agent, "--target", str(self.root), "--approve")
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertEqual(self.parse(completed)[0], "refused")
            self.assertEqual((outside / "marker.txt").read_text(encoding="utf-8"), "keep")
            self.assertFalse((outside / "skills").exists())
            link.unlink()
        (self.root / ".cursor").mkdir()
        (self.root / ".cursor" / "skills").symlink_to(outside, target_is_directory=True)
        completed = self.run_cli("install", "--agent", "all", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertEqual(self.parse(completed)[0], "refused")
        self.assertFalse((outside / NAME).exists())
        self.assertFalse((self.root / ".agents").exists())
        self.assertFalse((self.root / ".claude").exists())
        self.assertEqual((outside / "marker.txt").read_text(encoding="utf-8"), "keep")

    def test_ancestor_symlink_refuses_existing_skill(self):
        outside = self.tmp / "outside-home"
        real = outside / "skills" / NAME
        shutil.copytree(SKILL, real, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        marker = real / "config" / "metrics.yaml"
        before = marker.read_bytes()
        (self.root / ".cursor").symlink_to(outside, target_is_directory=True)
        for command in ("install", "update", "uninstall"):
            completed = self.run_cli(command, "--target", str(self.root), "--approve")
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertEqual(self.parse(completed)[0], "refused")
            self.assertEqual(marker.read_bytes(), before)
            self.assertTrue((real / "scripts" / "auditor.py").is_file())
        (self.root / ".cursor").unlink()
        (self.root / ".cursor").mkdir()
        skills = self.tmp / "real-skills"
        skills.mkdir()
        moved = skills / NAME
        real.rename(moved)
        (self.root / ".cursor" / "skills").symlink_to(skills, target_is_directory=True)
        for command in ("install", "update", "uninstall"):
            completed = self.run_cli(command, "--target", str(self.root), "--approve")
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertEqual(self.parse(completed)[0], "refused")
            self.assertEqual((moved / "config" / "metrics.yaml").read_bytes(), before)
            self.assertTrue((moved / "SKILL.md").is_file())

    def test_operator_root_symlink_prefix_is_resolved(self):
        real = self.tmp / "private-tmp"
        real.mkdir()
        alias = self.tmp / "tmp-alias"
        alias.symlink_to(real, target_is_directory=True)
        target = alias / "proj"
        completed = self.run_cli("install", "--target", str(target), "--approve")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        slot = real / "proj" / ".cursor" / "skills" / NAME
        self.assertTrue((slot / "config" / "metrics.yaml").is_file())
        self.assertTrue((target / ".cursor" / "skills" / NAME / "scripts" / "auditor.py").is_file())

    def test_destination_parent_symlink_is_refused(self):
        outside = self.tmp / "outside-dest"
        outside.mkdir()
        (outside / "secret.txt").write_text("keep", encoding="utf-8")
        parent = self.root / "custom"
        parent.symlink_to(outside, target_is_directory=True)
        destination = parent / NAME
        for command in ("install", "update", "uninstall"):
            completed = self.run_cli(
                command,
                "--agent",
                "claude",
                "--target",
                str(self.root),
                "--destination",
                str(destination),
                "--approve",
            )
            self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
            self.assertEqual(self.parse(completed)[0], "refused")
            self.assertFalse((outside / NAME).exists())
            self.assertEqual((outside / "secret.txt").read_text(encoding="utf-8"), "keep")
            self.assertFalse((self.root / ".claude").exists())

    def test_multi_agent_failure_rolls_back_existing_installations(self):
        from cqa import skill_install

        first = install_agents(self.root, SKILL, agent="all", approve=True)
        self.assertTrue(first["installed"], first)
        before = self.snapshot()
        updated_source = self.tmp / "new-source"
        shutil.copytree(SKILL, updated_source)
        (updated_source / "SKILL.md").write_text(
            (updated_source / "SKILL.md").read_text(encoding="utf-8") + "\\n# update\\n",
            encoding="utf-8",
        )
        with mock.patch.object(skill_install, "_install_link", side_effect=RuntimeError("simulated link failure")):
            with self.assertRaises(RuntimeError):
                install_agents(self.root, updated_source, agent="all", approve=True)
        self.assertEqual(self.snapshot(), before)

    def test_absolute_source_symlink_is_refused_without_modifying_slot(self):
        source = self.tmp / "absolute-source"
        shutil.copytree(SKILL, source)
        (source / "absolute.link").symlink_to(source / "SKILL.md")
        result = install_agents(self.root, source, approve=True)
        self.assertEqual(result["status"], "refused")
        self.assertFalse(self.slot("cursor").exists())

    def test_source_symlink_is_not_followed(self):
        outside = self.tmp / "outside-secret.txt"
        outside.write_text("SECRET-BYTES", encoding="utf-8")
        source = self.tmp / "source-skill"
        shutil.copytree(SKILL, source, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (source / "leak.txt").symlink_to(outside)
        refused = install_agents(self.root, source, approve=True)
        self.assertEqual(refused["status"], "refused")
        self.assertFalse(refused["installed"])
        self.assertFalse(self.slot("cursor").exists())
        leaked = [
            path
            for path in self.root.rglob("*")
            if path.is_file() and not path.is_symlink() and b"SECRET-BYTES" in path.read_bytes()
        ]
        self.assertEqual(leaked, [])

        source_dir = self.tmp / "source-dirlink"
        shutil.copytree(SKILL, source_dir, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        outside_dir = self.tmp / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "hidden.txt").write_text("HIDDEN-DIR", encoding="utf-8")
        (source_dir / "sub").symlink_to(outside_dir, target_is_directory=True)
        refused_dir = install_agents(self.root, source_dir, approve=True)
        self.assertEqual(refused_dir["status"], "refused")
        self.assertFalse(self.slot("cursor").exists())
        self.assertFalse(any(path.name == "hidden.txt" for path in self.root.rglob("*")))
        self.assertEqual((outside_dir / "hidden.txt").read_text(encoding="utf-8"), "HIDDEN-DIR")

        inside = self.tmp / "source-inside"
        shutil.copytree(SKILL, inside, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        (inside / "README.link").symlink_to("SKILL.md")
        installed = install_agents(self.root, inside, approve=True)
        self.assertEqual(installed["status"], "installed")
        link = self.slot("cursor") / "README.link"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "SKILL.md")
        self.assertEqual(link.resolve(), (self.slot("cursor") / "SKILL.md").resolve())

    def test_reinstall_replaces_extra_directory_symlink(self):
        installed = install_skill(self.root, SKILL, approve=True)
        self.assertTrue(installed["installed"])
        slot = self.slot("cursor")
        outside = self.tmp / "linked-outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("keep-secret", encoding="utf-8")
        (slot / "linked-dir").symlink_to(outside, target_is_directory=True)
        completed = self.run_cli("install", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.parse(completed)[0], "updated")
        self.assertFalse(os.path.lexists(slot / "linked-dir"))
        self.assertEqual((outside / "secret.txt").read_text(encoding="utf-8"), "keep-secret")
        self.assertEqual((slot / "SKILL.md").read_bytes(), (SKILL / "SKILL.md").read_bytes())

    def test_uninstall_refused_on_foreign_occupant(self):
        slot = self.slot("cursor")
        slot.mkdir(parents=True)
        kept = slot / "keep.txt"
        kept.write_bytes(b"foreign-bytes")
        completed = self.run_cli("uninstall", "--target", str(self.root), "--approve")
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "refused")
        self.assertEqual(rows[0]["status"], "refused")
        self.assertEqual(rows[0]["method"], "none")
        self.assertEqual(kept.read_bytes(), b"foreign-bytes")

    def test_blocked_rows_are_skipped(self):
        installed = self.run_cli("install", "--target", str(self.root), "--approve")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        metrics = (self.slot("cursor") / "config" / "metrics.yaml").read_bytes()
        updated = self.run_cli("update", "--agent", "all", "--target", str(self.root), "--approve")
        self.assertEqual(updated.returncode, 1, updated.stdout + updated.stderr)
        status, rows = self.parse(updated)
        self.assertEqual(status, "absent")
        by_agent = {row["agent"]: row for row in rows}
        self.assertEqual(by_agent["cursor"]["status"], "skipped")
        self.assertEqual(by_agent["cursor"]["method"], "none")
        self.assertEqual(by_agent["codex"]["status"], "absent")
        self.assertEqual(by_agent["claude"]["status"], "absent")
        self.assertFalse(self.slot("codex").exists())
        self.assertEqual((self.slot("cursor") / "config" / "metrics.yaml").read_bytes(), metrics)

        foreign = self.slot("claude")
        foreign.parent.mkdir(parents=True)
        foreign.write_text("not-the-skill", encoding="utf-8")
        refused = self.run_cli("install", "--agent", "all", "--target", str(self.root), "--approve")
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        status, rows = self.parse(refused)
        self.assertEqual(status, "refused")
        by_agent = {row["agent"]: row for row in rows}
        self.assertEqual(by_agent["claude"]["status"], "refused")
        self.assertEqual(by_agent["cursor"]["status"], "skipped")
        self.assertEqual(by_agent["codex"]["status"], "absent")
        self.assertEqual(foreign.read_text(encoding="utf-8"), "not-the-skill")
        self.assertEqual((self.slot("cursor") / "config" / "metrics.yaml").read_bytes(), metrics)
        self.assertFalse(self.slot("codex").exists())

    def test_global_scope_installs_under_the_given_target(self):
        home = self.tmp / "fake-home"
        completed = self.run_cli(
            "install",
            "--scope",
            "global",
            "--target",
            str(home),
            "--agent",
            "cursor",
            "--approve",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        status, rows = self.parse(completed)
        self.assertEqual(status, "installed")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scope"], "global")
        self.assertEqual(rows[0]["agent"], "cursor")
        slot = home / ".cursor" / "skills" / NAME
        self.assertEqual(Path(rows[0]["path"]), slot)
        self.assertTrue((slot / "config" / "metrics.yaml").is_file())
        self.assertTrue(str(Path(rows[0]["path"]).resolve()).startswith(str(home.resolve())))
        self.assertFalse((home / ".claude").exists())
        self.assertFalse((home / ".agents").exists())


def _normalize(report):
    findings = []
    for item in report["findings"]:
        cloned = json.loads(json.dumps(item))
        cloned.pop("id", None)
        provenance = cloned.get("provenance")
        if isinstance(provenance, dict):
            provenance.pop("evidence_pointer", None)
        findings.append(cloned)
    findings.sort(key=lambda item: json.dumps(item, sort_keys=True, default=str))
    metrics = [
        {
            "metric_id": item["metric_id"],
            "status": item["status"],
            "measured_value": item["measured_value"],
            "applicable": item["applicable"],
        }
        for item in report["metrics"]
    ]
    return {
        "decision": report["decision"],
        "selected_checks": report["selected_checks"],
        "metrics": metrics,
        "findings": findings,
    }


if __name__ == "__main__":
    unittest.main()
