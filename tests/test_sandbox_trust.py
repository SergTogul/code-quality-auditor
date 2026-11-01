"""Adversarial coverage for sandbox trust and untrusted analyzer configuration.

These tests exercise the execution policy directly. They are not a full external
audit, and they do not mark requirements verified in the traceability checklist.
They run on any POSIX host. A fake sandbox command stands in for sandbox-exec
through a mocked `_trusted_sandbox()`, so they check the policy text, the probe
decision logic, and the launch path. They do not show that seatbelt enforces
the profile natively.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".cursor" / "skills" / "code-quality-auditor"
sys.path.insert(0, str(SKILL / "scripts"))

spec = importlib.util.spec_from_file_location("auditor", SKILL / "scripts" / "auditor.py")
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)

from cqa import security  # noqa: E402
from cqa.project import discover_repository, init_repository  # noqa: E402
from cqa.security import _SECRET_DIRS, ExecutionLog, _profile, _trusted_sandbox, probe_sandbox, run_contained, run_tool  # noqa: E402

PASSTHROUGH = """#!/bin/sh
[ "$1" = "-p" ] || exit 64
shift 2
[ "$1" = "--" ] || exit 64
shift
exec "$@"
"""


def _write_executable(path, text):
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class SandboxTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-sandbox-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self._saved = os.environ.copy()
        os.environ.pop("CQA_SANDBOX_CMD", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def _log(self, **kwargs):
        defaults = {"allow_repo_execution": True, "sandbox_confirmed": True, "allow_tools": True}
        defaults.update(kwargs)
        return ExecutionLog(**defaults)

    def _fake_sandbox(self, name="sandbox-exec"):
        path = self.tmp / "trusted-bin" / name
        path.parent.mkdir(exist_ok=True)
        _write_executable(path, PASSTHROUGH)
        return path

    def _patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def _select_sandbox(self, path):
        self._patch("cqa.security._trusted_sandbox", return_value=Path(path))

    def _accept_fake_sandbox(self):
        """A passthrough fake that the probe is told to accept. It checks the launch path, not enforcement."""
        fake = self._fake_sandbox()
        self._select_sandbox(fake)
        self._patch("cqa.security.probe_sandbox", return_value=(True, str(fake)))
        return fake

    def test_passthrough_custom_sandbox_is_rejected_before_the_command(self):
        wrapper = self.tmp / "passthrough"
        _write_executable(wrapper, "#!/bin/sh\nexec \"$@\"\n")
        marker = self.tmp / "ran"
        payload = self.tmp / "payload"
        _write_executable(payload, f"#!/bin/sh\n: > {marker}\n")
        os.environ["CQA_SANDBOX_CMD"] = str(wrapper)
        available, detail = probe_sandbox(self.repo)
        self.assertFalse(available)
        self.assertIn("allowlisted", detail)
        with self.assertRaises(PermissionError):
            run_contained([str(payload)], self.repo, self._log())
        self.assertFalse(marker.exists())

    def test_custom_sandbox_differing_from_the_trusted_command_is_never_executed(self):
        self._select_sandbox(self._fake_sandbox())
        log_path = self.tmp / "custom.log"
        wrapper = self.tmp / "custom-wrapper"
        _write_executable(wrapper, f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log_path}\nexec \"$@\"\n")
        marker = self.tmp / "ran"
        payload = self.tmp / "payload"
        _write_executable(payload, f"#!/bin/sh\n: > {marker}\n")
        os.environ["CQA_SANDBOX_CMD"] = str(wrapper)
        with mock.patch("cqa.security._run_process") as runner:
            available, detail = probe_sandbox(self.repo)
            self.assertFalse(available)
            self.assertIn("allowlisted", detail)
            log = self._log()
            with self.assertRaises(PermissionError):
                run_contained([str(payload)], self.repo, log)
            with self.assertRaises(PermissionError):
                run_tool([str(payload)], self.repo, log)
            runner.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertFalse(log_path.exists())
        self.assertTrue(any(item["operation"] == "containment" for item in log.denied))

    def test_custom_sandbox_inside_the_repository_is_rejected(self):
        wrapper = self.repo / "sandbox-wrapper"
        _write_executable(wrapper, "#!/bin/sh\necho ran > ran.txt\nexit 0\n")
        os.environ["CQA_SANDBOX_CMD"] = str(wrapper)
        available, _detail = probe_sandbox(self.repo)
        self.assertFalse(available)
        with self.assertRaises(PermissionError):
            run_contained(["/usr/bin/true"], self.repo, self._log())
        self.assertFalse((self.repo / "ran.txt").exists())

    def test_shell_and_relative_custom_commands_are_rejected(self):
        for value in ("env", "bash -c", "sandbox-exec"):
            os.environ["CQA_SANDBOX_CMD"] = value
            available, _detail = probe_sandbox(self.repo)
            self.assertFalse(available, value)
            with self.assertRaises(PermissionError):
                run_contained(["/usr/bin/true"], self.repo, self._log())

    def test_sandbox_apply_failure_is_not_rerun(self):
        fake = self._accept_fake_sandbox()
        marker = self.tmp / "payload-ran"
        payload = self.tmp / "payload"
        _write_executable(payload, f"#!/bin/sh\n: > {marker}\n")
        work = self.tmp / "work"
        work.mkdir(mode=0o700)
        failures = {
            "status 71": (71, "", ""),
            "sandbox_apply": (1, "", "sandbox-exec: sandbox_apply: Operation not permitted"),
            "silent signal": (-6, "", ""),
        }
        launchers = {
            "run_contained": lambda log: run_contained([str(payload)], self.repo, log, write_path=work),
            "run_tool": lambda log: run_tool([str(payload)], self.repo, log),
        }
        for failure, (code, stdout, stderr) in failures.items():
            for name, launch in launchers.items():
                with self.subTest(failure=failure, launcher=name):
                    calls = []

                    def fail(command, cwd, env, timeout):
                        calls.append(list(command))
                        return subprocess.CompletedProcess(command, code, stdout, stderr)

                    log = self._log()
                    with mock.patch("cqa.security._run_process", side_effect=fail):
                        with self.assertRaises(PermissionError) as caught:
                            launch(log)
                    self.assertIn("not rerun", str(caught.exception))
                    self.assertFalse(marker.exists())
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0][0], str(fake))
                    self.assertEqual(calls[0][1], "-p")
                    self.assertTrue(any(item["operation"] == "containment" for item in log.denied))

    def test_ordinary_analyzer_failure_is_not_a_containment_failure(self):
        self._accept_fake_sandbox()
        for code, stdout, stderr in ((1, "", "broken.cpp:1:1: error: expected ';'"), (-11, "", "Segmentation fault")):
            with self.subTest(code=code):
                log = self._log()
                with mock.patch("cqa.security._run_process", return_value=subprocess.CompletedProcess([], code, stdout, stderr)):
                    completed = run_tool(["/usr/bin/true"], self.repo, log)
                self.assertEqual(completed.returncode, code)
                self.assertFalse(log.denied)

    def test_repository_executable_is_not_a_trusted_analyzer(self):
        marker = self.repo / "pwned"
        tool = self.repo / "evil-analyzer"
        _write_executable(tool, f"#!/bin/sh\n: > {marker}\n")
        with self.assertRaises(PermissionError):
            run_tool([str(tool)], self.repo, self._log())
        self.assertFalse(marker.exists())

    def test_tool_timeout_kills_the_grandchild(self):
        fake = self._accept_fake_sandbox()
        pid_file = self.tmp / "grandchild"
        tool = self.tmp / "parent-tool"
        _write_executable(
            tool,
            f"""#!/bin/sh
            sleep 30 &
            echo $! > {pid_file}
            wait
            """,
        )
        log = self._log()
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            run_tool([str(tool)], self.repo, log, timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        grandchild = int(pid_file.read_text(encoding="utf-8").strip())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and _alive(grandchild):
            time.sleep(0.05)
        self.assertFalse(_alive(grandchild))
        self.assertTrue(any(item["outcome"] == "timeout" and item["command"][0] == str(fake) for item in log.commands))

    def test_analyzer_configuration_is_not_executed(self):
        marker = self.repo / "config-executed"
        (self.repo / "eslint.config.js").write_text(
            f"require('fs').writeFileSync({str(marker)!r}, 'x')\n",
            encoding="utf-8",
        )
        (self.repo / ".pre-commit-config.yaml").write_text(
            f"repos:\n- repo: local\n  hooks:\n  - id: x\n    entry: touch {marker}\n",
            encoding="utf-8",
        )
        discovery = discover_repository(self.repo)
        self.assertIn("eslint.config.js", discovery["analyzer_configs"])
        self.assertIn(".pre-commit-config.yaml", discovery["analyzer_configs"])
        self.assertFalse(marker.exists())
        init_repository(self.repo, {"default_profile": "full", "profiles": {}}, approve_write=False)
        self.assertFalse(marker.exists())
        with self.assertRaises(PermissionError):
            run_tool([str(self.repo / "eslint.config.js")], self.repo, self._log())
        self.assertFalse(marker.exists())

    def test_tool_environment_drops_startup_hooks_and_uses_private_scratch(self):
        fake = self._accept_fake_sandbox()
        os.environ["PYTHONSTARTUP"] = str(self.tmp / "startup.py")
        os.environ["LD_PRELOAD"] = str(self.tmp / "preload.so")
        os.environ["NODE_OPTIONS"] = "--require " + str(self.tmp / "hook.js")
        os.environ["TMPDIR"] = tempfile.gettempdir()
        log = self._log()
        completed = run_tool(["/usr/bin/env"], self.repo, log, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout
        self.assertNotIn("PYTHONSTARTUP", output)
        self.assertNotIn("LD_PRELOAD", output)
        self.assertNotIn("NODE_OPTIONS", output)
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        scratch = Path(values["TMPDIR"])
        self.assertEqual(values["TMP"], str(scratch))
        self.assertEqual(values["TEMP"], str(scratch))
        self.assertNotEqual(scratch, Path(tempfile.gettempdir()).resolve())
        self.assertTrue(scratch.name.startswith("cqa-tool-"))
        self.assertFalse(scratch.exists())
        wrapped = next(item["command"] for item in log.commands if item["outcome"] == "started")
        self.assertEqual(wrapped[0], str(fake))
        profile = wrapped[2]
        writes = _write_roots(profile)
        self.assertEqual(writes, [scratch])
        self.assertTrue(_read_allowed(profile, scratch / "work.o"))
        self.assertFalse(_allowed(profile, "file-write-data", Path(tempfile.gettempdir()) / "cqa-shared-file"))

    def test_contained_temporary_variables_point_at_the_write_path(self):
        self._accept_fake_sandbox()
        work = self.tmp / "work"
        work.mkdir(mode=0o700)
        os.environ["TMPDIR"] = tempfile.gettempdir()
        completed = run_contained(["/usr/bin/env"], self.repo, self._log(), timeout=10, write_path=work, env={"TMPDIR": "/tmp", "EXTRA": "1"})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        values = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
        for key in ("TMPDIR", "TMP", "TEMP"):
            self.assertEqual(values[key], str(work), key)
        self.assertEqual(values["EXTRA"], "1")

    def test_profile_closes_reads_outside_the_command_allowlist(self):
        home = self.tmp / "home"
        repo = home / "cqa-allowlist-repo"
        repo.mkdir(parents=True)
        repo_file = repo / "visible.txt"
        repo_file.write_text("visible", encoding="utf-8")
        sibling = home / "cqa-allowlist-sibling.txt"
        sibling.write_text("outside", encoding="utf-8")
        with mock.patch.object(Path, "home", return_value=home):
            profile = _profile([str(repo)], str(repo), repo)
        self.assertNotIn("(allow default)", profile)
        self.assertEqual(_unfiltered_file_allows(profile), [])
        self.assertFalse(_read_allowed(profile, "/etc/passwd"))
        self.assertFalse(_read_allowed(profile, "/var/lib/cqa-not-allowed"))
        self.assertFalse(_read_allowed(profile, "/opt/cqa-not-allowed"))
        self.assertFalse(_read_allowed(profile, "/Library/Keychains/login.keychain-db"))
        self.assertFalse(_read_allowed(profile, sibling))
        self.assertFalse(_read_allowed(profile, home))
        self.assertTrue(_read_allowed(profile, repo_file))
        self.assertTrue(_read_allowed(profile, Path("/usr/bin/true").resolve()))
        for name in _SECRET_DIRS:
            self.assertFalse(_read_allowed(profile, home / name / "credentials"), name)
        self.assertNotIn('(allow file-read* (subpath "/"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/etc"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/opt"))', profile)

    def test_profile_denies_home_secrets_even_when_they_are_requested(self):
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".config" / "gh").mkdir(parents=True)
        private = home / "private-note"
        private.write_text("private", encoding="utf-8")
        with mock.patch.object(Path, "home", return_value=home):
            profile = _profile([str(home), str(home / ".ssh"), str(home / ".config" / "gh")], str(home / ".ssh"), self.repo)
        self.assertFalse(_read_allowed(profile, private))
        self.assertFalse(_read_allowed(profile, home / ".ssh" / "id_ed25519"))
        self.assertFalse(_read_allowed(profile, home / ".config" / "gh" / "hosts.yml"))
        self.assertFalse(_allowed(profile, "file-write-data", home / ".ssh" / "authorized_keys"))
        for name in _SECRET_DIRS:
            self.assertFalse(_read_allowed(profile, home / name / "x"), name)
            self.assertFalse(_allowed(profile, "file-map-executable", home / name / "x"), name)

    def test_profile_has_no_unfiltered_file_rules_and_scopes_writes(self):
        work = self.tmp / "work"
        work.mkdir(mode=0o700)
        profile = _profile([str(self.repo)], str(work), self.repo)
        self.assertEqual(_unfiltered_file_allows(profile), [])
        self.assertEqual(_write_roots(profile), [work])
        self.assertTrue(_allowed(profile, "file-write-data", work / "out.txt"))
        self.assertTrue(_read_allowed(profile, work / "out.txt"))
        self.assertFalse(_allowed(profile, "file-write-data", self.repo / "app.py"))
        self.assertFalse(_allowed(profile, "file-write-data", self.tmp / "sibling.txt"))
        self.assertFalse(_allowed(profile, "file-write-data", "/dev/null"))
        no_write = _profile([str(self.repo)], None, self.repo)
        self.assertEqual(_write_roots(no_write), [])
        self.assertEqual(_unfiltered_file_allows(no_write), [])

    def test_profile_denies_network_and_limits_process_rules(self):
        profile = _profile([str(self.repo)], str(self.repo), self.repo)
        lines = [line.strip() for line in profile.splitlines() if line.strip()]
        self.assertIn("(deny network*)", lines)
        self.assertFalse([line for line in lines if line.startswith("(allow network")])
        self.assertFalse(_allowed(profile, "network-outbound", "/"))
        self.assertNotIn("(allow process*)", lines)
        self.assertFalse([line for line in lines if line.startswith("(allow signal")])
        self.assertEqual(sorted(line for line in lines if line.startswith("(allow process")), ["(allow process-exec)", "(allow process-fork)"])
        self.assertFalse([line for line in lines if line.startswith("(allow system-socket")])

    def test_profile_uses_literal_device_rules_and_reviewed_roots(self):
        self.assertEqual(security._SYSTEM_READ_ROOTS, ("/usr", "/bin", "/sbin", "/System/Library", "/Library/Developer", "/opt/homebrew"))
        profile = _profile([str(self.repo)], None, self.repo)
        for device in ("/dev/null", "/dev/random", "/dev/urandom"):
            self.assertIn(f'(allow file-read* (literal "{device}"))', profile)
            self.assertTrue(_read_allowed(profile, device))
        self.assertNotIn('(subpath "/dev")', profile)
        self.assertFalse(_read_allowed(profile, "/dev/disk0"))
        self.assertFalse(_read_allowed(profile, "/dev/tty"))
        self.assertNotIn('(subpath "/Library")', profile)
        for root in ("/usr", "/bin", "/sbin"):
            if Path(root).exists():
                self.assertTrue(_read_allowed(profile, Path(root).resolve() / "cqa-tool"), root)

    def test_profile_never_opens_the_macos_data_volume(self):
        """/System/Volumes/Data is a second path to every user home and to /private on modern macOS."""
        data = Path("/System/Volumes/Data")
        for raw in security._SYSTEM_READ_ROOTS:
            root = Path(raw)
            self.assertFalse(root == data or root in data.parents, raw)
        protected = security._protected_roots()
        for broad in (data, data.parent, Path("/System"), Path("/")):
            self.assertTrue(security._too_broad(broad, protected), broad)
        repo = data / "Projects" / "cqa-repo"
        self.assertFalse(security._too_broad(repo, protected))
        requested = [str(data), str(data.parent), "/System", str(repo)]
        with mock.patch("cqa.security._existing_reads", return_value=requested):
            profile = _profile(requested, None, self.repo)
        self.assertEqual(_unfiltered_file_allows(profile), [])
        self.assertTrue(_read_allowed(profile, repo / "app.cpp"))
        for raw in ("Users/someone/.ssh/id_ed25519", "private/etc/master.passwd", "private/var/folders/ab/T/cqa-unrelated", "Projects/cqa-sibling/secret.txt"):
            self.assertFalse(_read_allowed(profile, data / raw), raw)
        self.assertNotIn('(subpath "/System")', profile)
        self.assertNotIn(f'(subpath "{data}")', profile)

    def test_profile_denies_shared_temporary_storage(self):
        work = Path(tempfile.mkdtemp(prefix="cqa-scratch-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, work, True)
        shared = Path(tempfile.gettempdir()).resolve()
        profile = _profile([str(self.repo), str(shared), "/tmp", "/var/tmp"], str(work), self.repo)
        self.assertTrue(_read_allowed(profile, work / "scratch.txt"))
        self.assertFalse(_read_allowed(profile, shared / "cqa-unrelated-file"))
        for raw in ("/tmp/cqa-unrelated", "/private/tmp/cqa-unrelated", "/var/tmp/cqa-unrelated", "/private/var/folders/ab/T/cqa-unrelated"):
            self.assertFalse(_read_allowed(profile, raw), raw)
            self.assertFalse(_allowed(profile, "file-write-data", raw), raw)

    def test_tool_without_containment_does_not_run(self):
        marker = self.tmp / "side-effect"
        tool = self.tmp / "host-tool"
        _write_executable(tool, f"#!/bin/sh\n: > {marker}\n")
        with mock.patch("cqa.security.probe_sandbox", return_value=(False, "containment is unavailable")):
            with self.assertRaises(PermissionError):
                run_tool([str(tool)], self.repo, self._log())
        self.assertFalse(marker.exists())

    def test_tool_never_falls_back_when_no_trusted_sandbox_exists(self):
        marker = self.tmp / "side-effect"
        tool = self.tmp / "host-tool"
        _write_executable(tool, f"#!/bin/sh\n: > {marker}\n")
        self._patch("cqa.security._trusted_sandbox", return_value=None)
        with mock.patch("cqa.security._run_process") as runner:
            for launch in (lambda log: run_tool([str(tool)], self.repo, log), lambda log: run_contained([str(tool)], self.repo, log)):
                log = self._log()
                with self.assertRaises(PermissionError):
                    launch(log)
                self.assertTrue(any(item["operation"] == "containment" for item in log.denied))
            runner.assert_not_called()
        self.assertFalse(marker.exists())

    def test_wrapper_that_blocks_the_probe_but_allows_other_commands_is_not_trusted(self):
        log_path = self.tmp / "wrapper.log"
        marker = self.tmp / "network-payload"
        wrapper = self.tmp / "selective-wrapper"
        python = sys.executable
        _write_executable(
            wrapper,
            f"""#!/bin/sh
            printf '%s\\n' "$*" >> {log_path}
            if [ "$1" = {python} ] || [ "$1" = /usr/bin/touch ] || [ "$1" = /bin/cat ]; then
              exit 1
            fi
            exec "$@"
            """,
        )
        payload = self.tmp / "payload"
        _write_executable(payload, f"#!/bin/sh\n: > {marker}\n")
        os.environ["CQA_SANDBOX_CMD"] = str(wrapper)
        available, detail = probe_sandbox(self.repo)
        self.assertFalse(available)
        self.assertIn("allowlisted", detail)
        with self.assertRaises(PermissionError):
            run_contained([str(payload)], self.repo, self._log())
        self.assertFalse(marker.exists())
        self.assertFalse(log_path.exists())

    def test_path_sandbox_exec_is_never_executed(self):
        fake_dir = self.repo / ".venv" / "bin"
        fake_dir.mkdir(parents=True)
        log_path = self.tmp / "fake-sandbox.log"
        marker = self.tmp / "fake-ran"
        _write_executable(
            fake_dir / "sandbox-exec",
            f"""#!/bin/sh
            printf '%s\\n' "$*" >> {log_path}
            : > {marker}
            exit 0
            """,
        )
        os.environ["PATH"] = str(fake_dir) + os.pathsep + os.environ.get("PATH", "")
        self.assertIn(_trusted_sandbox(), (None, Path("/usr/bin/sandbox-exec")))
        with mock.patch.dict(security._PLATFORM_SANDBOX, {sys.platform: str(fake_dir / "sandbox-exec")}):
            if os.geteuid() != 0:
                self.assertIsNone(_trusted_sandbox())
        fake = self._accept_fake_sandbox()
        log = self._log()
        completed = run_tool(["/usr/bin/true"], self.repo, log, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(log_path.exists())
        self.assertFalse(marker.exists())
        self.assertTrue(any(item["command"] and item["command"][0] == str(fake) for item in log.commands))

    def _chdir(self, path):
        previous = os.getcwd()
        os.chdir(path)
        self.addCleanup(os.chdir, previous)

    def _wrapped_profile(self, command, write_path=None):
        self._select_sandbox(self._fake_sandbox())
        wrapped = security._contained_command(command, self.repo, write_path)
        self.assertEqual(wrapped[1], "-p")
        return wrapped[2]

    def test_command_arguments_do_not_widen_reads(self):
        elsewhere = self.tmp / "elsewhere"
        (elsewhere / "leak").mkdir(parents=True)
        (elsewhere / "leak" / "secret.txt").write_text("outside", encoding="utf-8")
        self._chdir(elsewhere)
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("outside", encoding="utf-8")
        (self.repo / "link.txt").symlink_to(outside / "secret.txt")
        (self.repo / "dirlink").symlink_to(outside, target_is_directory=True)
        (self.repo / "visible.txt").write_text("visible", encoding="utf-8")
        command = [
            "/usr/bin/true",
            "leak/secret.txt",
            "leak",
            "/etc/passwd",
            "/etc",
            str(self.repo / "link.txt"),
            "dirlink",
            str(Path.home()),
            tempfile.gettempdir(),
        ]
        profile = self._wrapped_profile(command)
        self.assertTrue(_read_allowed(profile, self.repo / "visible.txt"))
        for denied in (elsewhere / "leak" / "secret.txt", elsewhere / "other", Path("/etc/passwd"), Path("/etc/hosts"), outside / "secret.txt", outside / "other", Path(tempfile.gettempdir()).resolve() / "cqa-unrelated"):
            self.assertFalse(_read_allowed(profile, denied), denied)
        for root in (elsewhere, elsewhere / "leak", Path("/etc"), outside, Path.home().resolve(), Path(tempfile.gettempdir()).resolve()):
            self.assertNotIn(f'(subpath "{root}")', profile.replace(f'(subpath "{self.repo}")', ""), root)

    def test_relative_command_is_resolved_against_the_audit_root(self):
        self._select_sandbox(self._fake_sandbox())
        elsewhere = self.tmp / "elsewhere"
        (elsewhere / "bin").mkdir(parents=True)
        _write_executable(elsewhere / "bin" / "tool", "#!/bin/sh\nexit 0\n")
        (self.repo / "bin").mkdir()
        _write_executable(self.repo / "bin" / "tool", "#!/bin/sh\nexit 0\n")
        self._chdir(elsewhere)
        wrapped = security._contained_command(["bin/tool"], self.repo, None)
        self.assertEqual(wrapped[4], str((self.repo / "bin" / "tool").resolve()))

    def test_containment_denial_does_not_store_child_output(self):
        self._accept_fake_sandbox()
        secret = "cqa-child-secret-" + os.urandom(6).hex()
        cases = (
            (1, f"{secret} out", f"{secret} sandbox_apply: Operation not permitted"),
            (71, f"{secret} out", f"{secret}"),
        )
        for code, stdout, stderr in cases:
            with self.subTest(code=code):
                log = self._log()
                with mock.patch("cqa.security._run_process", return_value=subprocess.CompletedProcess([], code, stdout, stderr)):
                    with self.assertRaises(PermissionError) as caught:
                        run_tool(["/usr/bin/true"], self.repo, log)
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn(secret, json.dumps({"denied": log.denied, "commands": log.commands}))
                denial = next(item for item in log.denied if item["operation"] == "containment")
                self.assertIn(f"exit {code}", denial["detail"])

    def test_timeout_record_does_not_store_child_output(self):
        self._accept_fake_sandbox()
        secret = "cqa-child-secret-" + os.urandom(6).hex()
        tool = self.tmp / "chatty-tool"
        _write_executable(tool, f"#!/bin/sh\necho {secret}\necho {secret} >&2\nsleep 30\n")
        log = self._log()
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            run_tool([str(tool)], self.repo, log, timeout=1)
        self.assertIsNone(caught.exception.output)
        self.assertIsNone(caught.exception.stderr)
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, json.dumps({"denied": log.denied, "commands": log.commands}))
        self.assertTrue(any(item["outcome"] == "timeout" for item in log.commands))

    def test_run_process_caps_each_output_stream(self):
        self.assertEqual(security._OUTPUT_LIMIT, 8 * 1024 * 1024)
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                pid_file = self.tmp / f"{stream}.pid"
                script = textwrap.dedent(
                    f"""
                    import os, sys, time
                    open({str(pid_file)!r}, "w").write(str(os.getpid()))
                    sys.{stream}.write("P" * 200000)
                    sys.{stream}.flush()
                    time.sleep(30)
                    """
                )
                started = time.monotonic()
                with self.assertRaises(security.OutputLimitExceeded) as caught:
                    security._run_process([sys.executable, "-c", script], str(self.tmp), dict(os.environ), 20, limit=4096)
                self.assertLess(time.monotonic() - started, 10)
                self.assertNotIn("PPPP", str(caught.exception))
                self.assertFalse(_alive(int(pid_file.read_text(encoding="utf-8"))))
        completed = security._run_process([sys.executable, "-c", "print('x' * 1000)"], str(self.tmp), dict(os.environ), 20, limit=4096)
        self.assertEqual(completed.stdout, "x" * 1000 + "\n")

    def test_output_overflow_is_a_denial_not_a_result(self):
        self._accept_fake_sandbox()
        log = self._log()
        with mock.patch("cqa.security._run_process", side_effect=security.OutputLimitExceeded("output exceeded 8 bytes on one stream")):
            with self.assertRaises(PermissionError):
                run_tool(["/usr/bin/true"], self.repo, log)
        self.assertTrue(any(item["operation"] == "output-limit" for item in log.denied))

    @unittest.skipUnless(sys.platform.startswith("linux"), "the /proc descendant sweep is Linux only")
    def test_timeout_kills_descendants_that_left_the_session(self):
        pid_file = self.tmp / "detached.pid"
        script = textwrap.dedent(
            f"""
            import os, time
            if os.fork() == 0:
                os.setsid()
                open({str(pid_file)!r} + ".tmp", "w").write(str(os.getpid()))
                os.replace({str(pid_file)!r} + ".tmp", {str(pid_file)!r})
                time.sleep(30)
                os._exit(0)
            time.sleep(30)
            """
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            security._run_process([sys.executable, "-c", script], str(self.tmp), dict(os.environ), 2)
        detached = int(pid_file.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and _running(detached):
            time.sleep(0.05)
        self.assertFalse(_running(detached))

    def test_broad_or_missing_write_path_is_refused_before_launch(self):
        self._accept_fake_sandbox()
        (self.repo / "build").mkdir()
        refused = ["/", str(Path.home()), tempfile.gettempdir(), str(self.tmp / "missing"), str(self.repo), str(self.repo / "build"), str(self.tmp)]
        refused.extend(path for path in ("/etc", "/usr", "/Library") if Path(path).is_dir())
        for write_path in refused:
            with self.subTest(write_path=write_path):
                log = self._log()
                calls = []
                with mock.patch("cqa.security._run_process", side_effect=lambda *args, **kwargs: calls.append(args)):
                    with self.assertRaises(PermissionError):
                        run_contained(["/usr/bin/env"], self.repo, log, write_path=write_path)
                self.assertEqual(calls, [])
                self.assertFalse(any(item["outcome"] == "started" for item in log.commands))
                self.assertTrue(any(item["operation"] == "containment" and "write path" in item["detail"] for item in log.denied))
                self.assertEqual(_write_roots(_profile([str(self.repo)], write_path, self.repo)), [])
                wrapped = security._contained_command(["/usr/bin/true"], self.repo, write_path)
                self.assertEqual(_write_roots(wrapped[2]), [])
        child = Path(tempfile.mkdtemp(prefix="cqa-tool-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, child, True)
        self.assertEqual(_write_roots(_profile([str(self.repo)], str(child), self.repo)), [child])
        completed = run_contained(["/usr/bin/env"], self.repo, self._log(), timeout=10, write_path=child)
        self.assertEqual(dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)["TMPDIR"], str(child))

    def test_private_scratch_is_accepted_when_the_repository_is_under_temp(self):
        self.assertIn(Path(tempfile.gettempdir()).resolve(), self.repo.parents)
        child = Path(tempfile.mkdtemp(prefix="cqa-runner-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, child, True)
        self.assertTrue(security._writable_scratch(child, self.repo))
        nested = Path(tempfile.mkdtemp(prefix="cqa-runner-", dir=self.repo)).resolve()
        self.assertFalse(security._writable_scratch(nested, self.repo))

    def test_shared_or_foreign_scratch_is_refused_before_launch(self):
        self._accept_fake_sandbox()

        def refused(write_path):
            log = self._log()
            calls = []
            with mock.patch("cqa.security._run_process", side_effect=lambda *args, **kwargs: calls.append(args)):
                with self.assertRaises(PermissionError):
                    run_contained(["/usr/bin/env"], self.repo, log, write_path=write_path)
            self.assertEqual(calls, [])
            self.assertFalse(any(item["outcome"] == "started" for item in log.commands))
            self.assertTrue(any(item["operation"] == "containment" and "write path" in item["detail"] for item in log.denied))
            self.assertEqual(_write_roots(_profile([str(self.repo)], str(write_path), self.repo)), [])
            self.assertEqual(_write_roots(security._contained_command(["/usr/bin/true"], self.repo, str(write_path))[2]), [])

        for mode in (0o755, 0o777, 0o750, 0o701):
            with self.subTest(mode=oct(mode)):
                shared = Path(tempfile.mkdtemp(prefix="cqa-shared-")).resolve()
                self.addCleanup(__import__("shutil").rmtree, shared, True)
                shared.chmod(mode)
                self.assertFalse(security._writable_scratch(shared, self.repo))
                refused(shared)
        private = Path(tempfile.mkdtemp(prefix="cqa-private-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, private, True)
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)
        self.assertTrue(security._writable_scratch(private, self.repo))
        with self.subTest(owner="another uid"):
            with mock.patch("cqa.security.os.geteuid", return_value=os.geteuid() + 1):
                self.assertFalse(security._writable_scratch(private, self.repo))
                refused(private)
        self.assertEqual(_write_roots(_profile([str(self.repo)], str(private), self.repo)), [private])

    def test_git_read_bounds_output_and_logs_no_child_output(self):
        sentinel = "cqa-git-sentinel-" + os.urandom(6).hex()
        fake_dir = self.tmp / "git-bin"
        fake_dir.mkdir()
        _write_executable(fake_dir / "git", f"#!/bin/sh\nwhile :; do echo {sentinel}; echo {sentinel} >&2; done\n")
        os.environ["PATH"] = str(fake_dir) + os.pathsep + os.environ.get("PATH", "")
        log = self._log()
        started = time.monotonic()
        self.assertIsNone(security.git_read(self.repo, ["log"], log, timeout=10, limit=4096))
        self.assertLess(time.monotonic() - started, 8)
        self.assertNotIn(sentinel, json.dumps({"denied": log.denied, "commands": log.commands}))
        self.assertTrue(any("output exceeded" in item["detail"] for item in log.commands))
        _write_executable(fake_dir / "git", f"#!/bin/sh\necho {sentinel}\necho {sentinel} >&2\nsleep 30\n")
        log = self._log()
        self.assertIsNone(security.git_read(self.repo, ["log"], log, timeout=1, limit=4096))
        self.assertNotIn(sentinel, json.dumps({"denied": log.denied, "commands": log.commands}))
        self.assertTrue(any(item["outcome"] == "timeout" for item in log.commands))
        _write_executable(fake_dir / "git", "#!/bin/sh\nprintf 'abc\\n'\n")
        completed = security.git_read(self.repo, ["rev-parse", "HEAD"], self._log())
        self.assertEqual(completed.stdout, b"abc\n")

    def test_install_analyzer_bounds_output_and_logs_no_child_output(self):
        import hashlib

        sentinel = "cqa-install-sentinel-" + os.urandom(6).hex()
        artifact = self.tmp / "tool.whl"
        artifact.write_bytes(b"not a real wheel")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        tool = {"id": "fake", "version_constraint": "*"}
        chatty = [sys.executable, "-c", f"import sys\nwhile True:\n    sys.stderr.write({sentinel!r} * 100)\n"]
        slow = [sys.executable, "-c", f"import sys, time\nsys.stderr.write({sentinel!r})\nsys.stderr.flush()\ntime.sleep(30)\n"]
        failing = [sys.executable, "-c", f"import sys\nsys.stderr.write({sentinel!r})\nsys.exit(3)\n"]
        real = security._run_process
        for name, command, kwargs, exit_code in (("overflow", chatty, {"limit": 4096}, None), ("timeout", slow, {"timeout": 1}, None), ("failure", failing, {}, 3)):
            with self.subTest(case=name):
                log = ExecutionLog()

                def run(_command, cwd, env, timeout, limit=security._OUTPUT_LIMIT, text=True, command=command):
                    return real(command, cwd, env, timeout, limit=limit, text=text)

                with mock.patch("cqa.security._run_process", side_effect=run):
                    result = security.install_analyzer(tool, approve=True, artifact=artifact, expected_sha256=digest, log=log, execute=True, **kwargs)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["installed"])
                self.assertEqual(result["exit_code"], exit_code)
                self.assertNotIn(sentinel, json.dumps({"result": result, "denied": log.denied, "commands": log.commands}, default=str))

    def test_repository_symlink_to_a_host_binary_is_not_a_host_analyzer(self):
        self._accept_fake_sandbox()
        host = Path("/usr/bin/true").resolve()
        (self.repo / "tool").symlink_to(host)
        (self.repo / "bin").symlink_to(host.parent, target_is_directory=True)
        for supplied in (str(self.repo / "tool"), "./tool", str(self.repo / "bin" / host.name), f"bin/{host.name}"):
            with self.subTest(supplied=supplied):
                log = self._log()
                with mock.patch("cqa.security._run_process") as runner:
                    with self.assertRaises(PermissionError):
                        run_tool([supplied], self.repo, log)
                    runner.assert_not_called()
                self.assertTrue(any(item["operation"] == "external-tool" for item in log.denied))

    def test_relative_file_in_the_process_cwd_does_not_override_path(self):
        self._accept_fake_sandbox()
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        marker = self.tmp / "cwd-tool-ran"
        _write_executable(elsewhere / "true", f"#!/bin/sh\n: > {marker}\n")
        self._chdir(elsewhere)
        calls = []

        def record(command, cwd, env, timeout):
            calls.append(list(command))
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch("cqa.security._run_process", side_effect=record):
            run_tool(["true"], self.repo, self._log())
            with self.assertRaises(PermissionError):
                run_tool(["./true"], self.repo, self._log())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][4], str(Path(__import__("shutil").which("true")).resolve()))
        self.assertNotEqual(calls[0][4], str(elsewhere / "true"))
        self.assertFalse(marker.exists())

    def test_discover_skips_symlinks_that_leave_the_repository(self):
        sentinel = "cqa-outside-sentinel-" + os.urandom(6).hex()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "secret.py").write_text(f'AWS_SECRET_ACCESS_KEY = "{sentinel}"\n', encoding="utf-8")
        (self.repo / "inside.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        (self.repo / "alias.py").symlink_to(self.repo / "inside.py")
        (self.repo / "link.py").symlink_to(outside / "secret.py")
        files, _counts = auditor.discover(self.repo)
        self.assertEqual(sorted(path.name for path in files), ["alias.py", "inside.py"])
        out = self.tmp / "out"
        out.mkdir()
        report = auditor.audit(self.repo, skill_root=SKILL, output_dir=out, profile="security")
        self.assertNotIn(sentinel, json.dumps(report, default=str))
        for path in out.rglob("*"):
            if path.is_file():
                self.assertNotIn(sentinel, path.read_text(encoding="utf-8", errors="replace"), path)
        self.assertFalse(any(item.get("file") == "link.py" for item in report["findings"]))

    def test_interpreter_wrapper_is_rejected(self):
        shell = Path("/bin/bash")
        if not shell.is_file():
            self.skipTest("bash is not present")
        os.environ["CQA_SANDBOX_CMD"] = str(shell)
        available, detail = probe_sandbox(self.repo)
        self.assertFalse(available)
        self.assertIn("interpreter or shell", detail)


class ProductionProbeTests(unittest.TestCase):
    """probe_sandbox() must run the restrictive production profile on synthetic fixtures."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-probe-test-")).resolve()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        self._saved = os.environ.copy()
        os.environ.pop("CQA_SANDBOX_CMD", None)
        self.fake = self.tmp / "trusted-bin" / "sandbox-exec"
        self.fake.parent.mkdir()
        _write_executable(self.fake, PASSTHROUGH)
        patcher = mock.patch("cqa.security._trusted_sandbox", return_value=self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tokens = []

        def token(_size):
            value = f"cqa-synthetic-token-{len(self.tokens)}-{os.urandom(4).hex()}"
            self.tokens.append(value)
            return value

        patcher = mock.patch("cqa.security.secrets.token_hex", side_effect=token)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.real_run = security._run_process
        self.sandboxed = []

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def _emulate(self, behave=None, baseline=None):
        """Real unsandboxed baseline; the sandboxed run is replaced by an emulation of an enforcing sandbox."""

        def run(command, cwd, env, timeout):
            if command[0] != str(self.fake):
                if baseline is not None:
                    return baseline(command, cwd, env, timeout)
                return self.real_run(command, cwd, env, timeout)
            self.sandboxed.append({"command": list(command), "cwd": cwd, "env": dict(env)})
            allowed = Path(command[-1])
            context = {"allowed": allowed, "denied": allowed.parent / "denied", "port": int(env["CQA_PROBE_PORT"]), "command": command}
            if behave is not None:
                return behave(context)
            (allowed / "output").write_bytes((allowed / "input").read_bytes())
            return _reply(command, read_write=True, denied_read=False, denied_write=False, network=False)

        return mock.patch("cqa.security._run_process", side_effect=run)

    def _assert_unavailable(self, detail_part=None):
        available, detail = probe_sandbox()
        self.assertFalse(available, detail)
        if detail_part:
            self.assertIn(detail_part, detail)
        for value in self.tokens:
            self.assertNotIn(value, detail)
        return detail

    def test_probe_runs_the_production_profile_through_the_trusted_command(self):
        with self._emulate():
            available, detail = probe_sandbox()
        self.assertTrue(available, detail)
        self.assertEqual(detail, str(self.fake))
        self.assertEqual(len(self.sandboxed), 1)
        call = self.sandboxed[0]
        command = call["command"]
        self.assertEqual(command[:2], [str(self.fake), "-p"])
        self.assertEqual(command[3], "--")
        profile = command[2]
        self.assertNotIn("(allow default)", profile)
        self.assertEqual(_unfiltered_file_allows(profile), [])
        self.assertIn("(deny network*)", profile)
        allowed = Path(command[-1])
        denied = allowed.parent / "denied"
        self.assertTrue(allowed.name == "allowed" and allowed.parent.name.startswith("cqa-probe-"))
        self.assertEqual(_write_roots(profile), [allowed])
        self.assertTrue(_read_allowed(profile, allowed / "input"))
        self.assertFalse(_read_allowed(profile, denied / "sentinel"))
        self.assertFalse(_allowed(profile, "file-write-data", denied / "escape"))
        self.assertEqual(call["env"]["TMPDIR"], str(allowed))
        self.assertFalse(allowed.parent.exists())
        home = Path.home().resolve()
        for item in command[4:]:
            if item.startswith("/") and Path(item).resolve() != Path(sys.executable).resolve():
                self.assertNotIn(home, Path(item).resolve().parents)
        for value in self.tokens:
            self.assertNotIn(value, " ".join(command))
            self.assertNotIn(value, json.dumps(call["env"]))

    def test_probe_rejects_a_sandbox_that_does_not_enforce_the_profile(self):
        self._assert_unavailable("containment is unavailable")

    def test_probe_inconclusive_or_escaping_results_are_unavailable(self):
        def reply(**values):
            return lambda context: _reply(context["command"], **values)

        def copy_then(**values):
            def behave(context):
                (context["allowed"] / "output").write_bytes((context["allowed"] / "input").read_bytes())
                return _reply(context["command"], **values)

            return behave

        clean = {"read_write": True, "denied_read": False, "denied_write": False, "network": False}

        def silent_write(context):
            (context["denied"] / "escape").write_bytes(b"x")
            return copy_then(**clean)(context)

        def silent_network(context):
            socket.create_connection(("127.0.0.1", context["port"]), timeout=2).close()
            return copy_then(**clean)(context)

        def leak(context):
            secret = (context["denied"] / "sentinel").read_text(encoding="utf-8")
            completed = copy_then(**clean)(context)
            completed.stderr = secret
            return completed

        def wrong_content(context):
            (context["allowed"] / "output").write_bytes(b"other")
            return _reply(context["command"], **clean)

        def timeout(context):
            raise subprocess.TimeoutExpired(context["command"], 15)

        cases = {
            "malformed": lambda context: subprocess.CompletedProcess(context["command"], 0, "not json\n", ""),
            "extra output": lambda context: subprocess.CompletedProcess(context["command"], 0, json.dumps(clean) + "\nmore\n", ""),
            "incomplete": copy_then(read_write=True, denied_read=False, denied_write=False),
            "extra key": copy_then(**clean, other=False),
            "non-boolean": copy_then(read_write=True, denied_read="false", denied_write=False, network=False),
            "status 71": lambda context: subprocess.CompletedProcess(context["command"], 71, "", "sandbox_apply: Operation not permitted"),
            "nonzero exit": lambda context: subprocess.CompletedProcess(context["command"], 1, json.dumps(clean) + "\n", ""),
            "timeout": timeout,
            "denied read": copy_then(read_write=True, denied_read=True, denied_write=False, network=False),
            "denied write": copy_then(read_write=True, denied_read=False, denied_write=True, network=False),
            "network": copy_then(read_write=True, denied_read=False, denied_write=False, network=True),
            "silent write escape": silent_write,
            "silent network escape": silent_network,
            "sentinel leak": leak,
            "allowed write missing": reply(**clean),
            "allowed write wrong": wrong_content,
            "allowed read failed": copy_then(read_write=False, denied_read=False, denied_write=False, network=False),
        }
        for name, behave in cases.items():
            with self.subTest(case=name):
                self.tokens.clear()
                with self._emulate(behave):
                    self._assert_unavailable("containment is unavailable")

    def test_probe_requires_a_viable_unsandboxed_baseline(self):
        def no_network(command, cwd, env, timeout):
            return subprocess.CompletedProcess(command, 0, json.dumps({"network": False}) + "\n", "")

        def claims_network(command, cwd, env, timeout):
            return subprocess.CompletedProcess(command, 0, json.dumps({"network": True}) + "\n", "")

        def broken(command, cwd, env, timeout):
            raise subprocess.TimeoutExpired(command, timeout)

        for name, baseline in (("no network", no_network), ("unverified claim", claims_network), ("timeout", broken)):
            with self.subTest(case=name):
                self.sandboxed.clear()
                with self._emulate(baseline=baseline):
                    self._assert_unavailable("baseline")
                self.assertEqual(self.sandboxed, [])

    def test_probe_baseline_runs_unsandboxed_with_only_synthetic_inputs(self):
        baselines = []

        def record(command, cwd, env, timeout):
            baselines.append({"command": list(command), "env": dict(env)})
            return self.real_run(command, cwd, env, timeout)

        with self._emulate(baseline=record):
            available, detail = probe_sandbox()
        self.assertTrue(available, detail)
        self.assertEqual(len(baselines), 1)
        command = baselines[0]["command"]
        self.assertEqual(command[0], sys.executable)
        self.assertEqual(baselines[0]["env"]["CQA_PROBE_MODE"], "baseline")
        self.assertTrue(Path(command[-1]).parent.name.startswith("cqa-probe-"))


def _reply(command, **values):
    return subprocess.CompletedProcess(command, 0, json.dumps(values) + "\n", "")


_RULE = re.compile(r'^\((allow|deny) ([\w*-]+)(?: \((subpath|literal) "(.*)"\))?\)$')


def _rules(profile):
    for raw in profile.splitlines():
        match = _RULE.match(raw.strip())
        if match:
            yield match.groups()


def _covers(rule, operation):
    if rule == "default":
        return True
    if rule.endswith("*"):
        return operation.startswith(rule[:-1])
    return rule == operation


def _allowed(profile, operation, path):
    """Last matching rule wins over `(deny default)`, which is how seatbelt evaluates a profile."""
    decision = False
    target = Path(path)
    for verb, rule, kind, value in _rules(profile):
        if not _covers(rule, operation):
            continue
        if kind == "subpath" and not (target == Path(value) or Path(value) in target.parents):
            continue
        if kind == "literal" and target != Path(value):
            continue
        decision = verb == "allow"
    return decision


def _read_allowed(profile, path):
    return _allowed(profile, "file-read-data", path)


def _unfiltered_file_allows(profile):
    return [f"(allow {rule})" for verb, rule, kind, _value in _rules(profile) if verb == "allow" and kind is None and (rule.startswith("file") or rule == "default")]


def _write_roots(profile):
    return [Path(value) for verb, rule, kind, value in _rules(profile) if verb == "allow" and rule.startswith("file-write")]


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _running(pid):
    """Alive and not a zombie waiting for its new parent to reap it."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return False
    return stat.rsplit(")", 1)[1].split()[0] not in {"Z", "X"}
