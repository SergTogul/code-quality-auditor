"""Adversarial coverage for sandbox trust and untrusted analyzer configuration.

These tests exercise the execution policy directly. They are not a full external
audit, and they do not mark requirements verified in the traceability checklist.
"""

from __future__ import annotations

import importlib.util
import os
import stat
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

from cqa.project import discover_repository, init_repository  # noqa: E402
from cqa.security import (  # noqa: E402
    ExecutionLog,
    _compile_toolchain_grants,
    _profile,
    _seatbelt_aliases,
    probe_sandbox,
    run_contained,
    run_tool,
)

requires_macos_sandbox = unittest.skipUnless(
    sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
    "requires macOS /usr/bin/sandbox-exec",
)


def _write_executable(path, text):
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class SandboxTrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cqa-sandbox-"))
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

    @requires_macos_sandbox
    def test_sandbox_apply_failure_is_not_rerun(self):
        import subprocess

        from cqa import security

        marker = self.tmp / "payload-ran"
        payload = self.tmp / "payload"
        _write_executable(payload, f"#!/bin/sh\n: > {marker}\n")
        calls = []
        real = security._run_process

        def wrapped(command, cwd, env, timeout):
            calls.append(list(command))
            if command and Path(command[0]).name == "sandbox-exec":
                return subprocess.CompletedProcess(command, 71, "", "sandbox_apply failed")
            return real(command, cwd, env, timeout)

        with mock.patch("cqa.security._run_process", side_effect=wrapped):
            with self.assertRaises(PermissionError) as caught:
                run_contained([str(payload)], self.repo, self._log())
        self.assertIn("not rerun", str(caught.exception))
        self.assertFalse(marker.exists())
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0][0]).name, "sandbox-exec")

    def test_repository_executable_is_not_a_trusted_analyzer(self):
        marker = self.repo / "pwned"
        tool = self.repo / "evil-analyzer"
        _write_executable(tool, f"#!/bin/sh\n: > {marker}\n")
        with self.assertRaises(PermissionError):
            run_tool([str(tool)], self.repo, self._log())
        self.assertFalse(marker.exists())

    @requires_macos_sandbox
    def test_tool_timeout_kills_the_grandchild(self):
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
        started = time.monotonic()
        with self.assertRaises(subprocess_timeout()):
            run_tool([str(tool)], self.repo, self._log(), timeout=1)
        self.assertLess(time.monotonic() - started, 5)
        grandchild = int(pid_file.read_text(encoding="utf-8").strip())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and _alive(grandchild):
            time.sleep(0.05)
        self.assertFalse(_alive(grandchild))

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

    @requires_macos_sandbox
    def test_tool_environment_drops_startup_hooks(self):
        os.environ["PYTHONSTARTUP"] = str(self.tmp / "startup.py")
        os.environ["LD_PRELOAD"] = str(self.tmp / "preload.so")
        os.environ["NODE_OPTIONS"] = "--require " + str(self.tmp / "hook.js")
        completed = run_tool(["/usr/bin/env"], self.repo, self._log(), timeout=10)
        self.assertEqual(completed.returncode, 0)
        output = completed.stdout
        self.assertNotIn("PYTHONSTARTUP", output)
        self.assertNotIn("LD_PRELOAD", output)
        self.assertNotIn("NODE_OPTIONS", output)

    def test_profile_closes_reads_outside_the_command_allowlist(self):
        repo = Path.home() / "cqa-allowlist-repo"
        repo.mkdir(exist_ok=True)
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        repo_file = repo / "visible.txt"
        repo_file.write_text("visible", encoding="utf-8")
        sibling = Path.home() / "cqa-allowlist-sibling.txt"
        sibling.write_text("outside", encoding="utf-8")
        self.addCleanup(lambda: sibling.unlink(missing_ok=True))
        profile = _profile([str(repo)], str(repo))
        blanket = profile.index("(allow file-read*)")
        closure = profile.index('(deny file-read* (subpath "/"))')
        self.assertLess(blanket, closure)
        root_inode = profile.index('(allow file-read* (literal "/"))')
        self.assertLess(closure, root_inode)
        self.assertLess(
            profile.index('(deny file-read-metadata (subpath "/"))'),
            profile.index('(allow file-read-metadata (literal "/"))'),
        )
        secret = Path.home() / ".ssh" / "id_ed25519"
        allowed = ("/", repo_file, "/usr/bin/true")
        denied = (
            "/etc/passwd",
            "/var/lib/cqa-not-allowed",
            "/opt/cqa-not-allowed",
            sibling,
            secret,
        )
        for operation in ("file-read*", "file-read-metadata"):
            for path in allowed:
                with self.subTest(operation=operation, path=str(path)):
                    self.assertTrue(_read_allowed(profile, path, operation))
            for path in denied:
                with self.subTest(operation=operation, path=str(path)):
                    self.assertFalse(_read_allowed(profile, path, operation))
        self.assertNotIn('(allow file-read* (subpath "/"))', profile)
        self.assertNotIn('(allow file-read-metadata (subpath "/"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/etc"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/opt"))', profile)

    def test_profile_covers_both_spellings_of_macos_symlinked_paths(self):
        folders = _seatbelt_aliases(Path("/var/folders/ab/T/cqa"))
        self.assertIn(Path("/var/folders/ab/T/cqa"), folders)
        self.assertIn(Path("/private/var/folders/ab/T/cqa"), folders)
        self.assertNotIn(Path("/var"), folders)
        self.assertNotIn(Path("/private/var"), folders)
        work_dir = _seatbelt_aliases(Path("/tmp/cqa-work"))
        self.assertIn(Path("/tmp/cqa-work"), work_dir)
        self.assertIn(Path("/private/tmp/cqa-work"), work_dir)
        self.assertNotIn(Path("/tmp"), work_dir)
        self.assertNotIn(Path("/private/tmp"), work_dir)

        work = Path(tempfile.mkdtemp(prefix="cqa-alias-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(work, ignore_errors=True))
        home = work / "home"
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            profile = _profile([str(work)], str(work), allow_temp_writes=True)
        work_aliases = _seatbelt_aliases(work)
        self.assertGreaterEqual(len(work_aliases), 2)
        for alias in work_aliases:
            self.assertIn(f'(allow file-read* (subpath "{alias}"))', profile)
            self.assertIn(f'(allow file-write* (subpath "{alias}"))', profile)
        for alias in _seatbelt_aliases(tempfile.gettempdir()):
            self.assertIn(f'(allow file-write* (subpath "{alias}"))', profile)
        for broad in ("/var", "/private/var"):
            for operation in ("file-read*", "file-read-metadata", "file-write*"):
                self.assertNotIn(f'(allow {operation} (subpath "{broad}"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/"))', profile)
        self.assertNotIn('(allow file-read-metadata (subpath "/"))', profile)
        self.assertNotIn('(allow file-read* (literal "/tmp"))', profile)
        self.assertIn('(allow file-read-metadata (literal "/tmp"))', profile)

        visible = [alias / "visible.txt" for alias in work_aliases]
        secrets = _seatbelt_aliases(home / ".ssh" / "id_ed25519")
        self.assertGreaterEqual(len(secrets), 2)
        closed = [
            *secrets,
            "/etc/passwd",
            "/private/etc/passwd",
            "/var/lib/cqa-not-allowed",
            "/private/var/lib/cqa-not-allowed",
            "/opt/cqa-not-allowed",
        ]
        for operation in ("file-read*", "file-read-metadata"):
            for path in visible:
                with self.subTest(operation=operation, path=str(path)):
                    self.assertTrue(_read_allowed(profile, path, operation))
            for path in closed:
                with self.subTest(operation=operation, path=str(path)):
                    self.assertFalse(_read_allowed(profile, path, operation))

    def test_clang_toolchain_grant_does_not_open_var_db_or_applications(self):
        link = Path("/var/db/xcode_select_link")
        target = Path("/Applications/Xcode.app/Contents/Developer")
        reads, metadata = _compile_toolchain_grants(link, target)
        self.assertEqual(reads, [link, Path("/Applications/Xcode.app")])
        self.assertIn(Path("/var/db"), metadata)
        self.assertIn(Path("/private/var/db"), metadata)
        self.assertNotIn(Path("/var"), metadata)
        self.assertNotIn(Path("/Applications"), reads)
        profile = _profile([], None, extra_reads=reads, metadata_literals=metadata)
        self.assertIn('(allow file-read* (subpath "/Applications/Xcode.app"))', profile)
        self.assertIn('(allow file-read* (subpath "/var/db/xcode_select_link"))', profile)
        self.assertIn('(allow file-read-metadata (literal "/var/db"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/Applications"))', profile)
        self.assertNotIn('(allow file-read* (subpath "/var/db"))', profile)
        self.assertNotIn('(allow file-read-metadata (subpath "/var/db"))', profile)
        for operation in ("file-read*", "file-read-metadata"):
            self.assertFalse(_read_allowed(profile, "/var/db/sudo", operation))
            self.assertFalse(_read_allowed(profile, "/etc/passwd", operation))
            self.assertFalse(_read_allowed(profile, "/Applications/Other.app/Contents/Info.plist", operation))
        self.assertTrue(_read_allowed(profile, "/Applications/Xcode.app/Contents/Developer/usr/bin/clang"))
        self.assertTrue(_read_allowed(profile, "/var/db", "file-read-metadata"))
        self.assertFalse(_read_allowed(profile, "/var/db", "file-read*"))

    @requires_macos_sandbox
    def test_contained_command_cannot_read_home_secrets(self):
        secret_dir = Path.home() / ".ssh"
        secret_dir.mkdir(exist_ok=True)
        sentinel = secret_dir / "cqa-sandbox-sentinel"
        repo_file = self.repo / "visible.txt"
        repo_file.write_text("visible", encoding="utf-8")
        reader = self.tmp / "reader.py"
        reader.write_text(
            textwrap.dedent(
                f"""
                try:
                    open({str(sentinel)!r}, encoding="utf-8").read()
                    print("SECRET_READ")
                except OSError:
                    print("SECRET_BLOCKED")
                try:
                    print("REPO", open({str(repo_file)!r}, encoding="utf-8").read())
                except OSError:
                    print("REPO_BLOCKED")
                """
            ).lstrip(),
            encoding="utf-8",
        )
        sentinel.write_text("secret", encoding="utf-8")
        private = Path.home() / "cqa-sandbox-private-note"
        private.write_text("private", encoding="utf-8")
        self.addCleanup(lambda: sentinel.unlink(missing_ok=True))
        self.addCleanup(lambda: private.unlink(missing_ok=True))
        reader.write_text(
            reader.read_text(encoding="utf-8")
            + textwrap.dedent(
                f"""
                try:
                    open({str(private)!r}, encoding="utf-8").read()
                    print("PRIVATE_READ")
                except OSError:
                    print("PRIVATE_BLOCKED")
                """
            ),
            encoding="utf-8",
        )
        os.environ.pop("CQA_SANDBOX_CMD", None)
        completed = run_contained([sys.executable, str(reader)], self.repo, self._log(), timeout=20)
        output = completed.stdout
        self.assertIn("SECRET_BLOCKED", output, f"rc={completed.returncode} stderr={completed.stderr!r} stdout={output!r}")
        self.assertIn("PRIVATE_BLOCKED", output)
        self.assertIn("REPO visible", output)
        self.assertNotIn("SECRET_READ", output)
        self.assertNotIn("PRIVATE_READ", output)

    def test_tool_without_containment_does_not_run(self):
        marker = self.tmp / "side-effect"
        tool = self.tmp / "host-tool"
        _write_executable(tool, f"#!/bin/sh\n: > {marker}\n")
        with mock.patch("cqa.security.probe_sandbox", return_value=(False, "containment is unavailable")):
            with self.assertRaises(PermissionError):
                run_tool([str(tool)], self.repo, self._log())
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

    @requires_macos_sandbox
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
        available, detail = probe_sandbox(self.repo)
        self.assertTrue(available)
        self.assertEqual(detail, "/usr/bin/sandbox-exec")
        log = self._log()
        completed = run_tool(["/usr/bin/true"], self.repo, log, timeout=10)
        self.assertEqual(completed.returncode, 0)
        self.assertFalse(log_path.exists())
        self.assertFalse(marker.exists())
        self.assertTrue(any(item["command"] and item["command"][0] == "/usr/bin/sandbox-exec" for item in log.commands))

    def test_interpreter_wrapper_is_rejected(self):
        shell = Path("/bin/bash")
        if not shell.is_file():
            self.skipTest("bash is not present")
        os.environ["CQA_SANDBOX_CMD"] = str(shell)
        available, detail = probe_sandbox(self.repo)
        self.assertFalse(available)
        self.assertIn("interpreter or shell", detail)


def _read_allowed(profile, path, operation="file-read*"):
    """Last matching rule wins, which is how seatbelt evaluates a profile.

    `file-read*` is a wildcard that also covers `file-read-metadata`, so its
    rules count when evaluating metadata reads.
    """
    operations = {"file-read*", operation}
    decision = False
    target = Path(path)
    for raw in profile.splitlines():
        line = raw.strip()
        for verb, allowed in (("allow", True), ("deny", False)):
            for op in operations:
                if line == f"({verb} {op})":
                    decision = allowed
                    continue
                for kind in ("subpath", "literal"):
                    prefix = f'({verb} {op} ({kind} "'
                    if not line.startswith(prefix) or not line.endswith('"))'):
                        continue
                    root = Path(line[len(prefix):-3])
                    if target == root or (kind == "subpath" and root in target.parents):
                        decision = allowed
    return decision


def subprocess_timeout():
    import subprocess

    return subprocess.TimeoutExpired


def _alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
