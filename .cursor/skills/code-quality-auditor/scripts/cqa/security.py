"""Execution policy. Profiles cannot turn these gates off."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from cqa import ENGINE_VERSION

GIT_ALIASES = (
    "rev-parse",
    "log",
    "show",
    "diff",
    "ls-tree",
    "archive",
    "remote",
    "status",
    "rev-list",
    "cat-file",
)


class ExecutionLog:
    def __init__(self, allow_tools=False, allow_repo_execution=False, sandbox_confirmed=False, allow_install=False, allow_network=False, allow_write=False):
        self.allow_tools = bool(allow_tools)
        self.allow_repo_execution = bool(allow_repo_execution)
        self.sandbox_confirmed = bool(sandbox_confirmed)
        self.allow_install = bool(allow_install)
        self.allow_network = bool(allow_network)
        self.allow_write = bool(allow_write)
        self.commands = []
        self.denied = []
        self.approvals = []
        self.ignored_overrides = []

    def record(self, command, outcome, detail=""):
        self.commands.append(
            {
                "command": command if isinstance(command, list) else [str(command)],
                "outcome": outcome,
                "detail": detail,
            }
        )

    def deny(self, operation, detail):
        self.denied.append({"operation": operation, "detail": detail})
        self.record([operation], "denied", detail)


def detect_runtime():
    version = sys.version_info
    return {
        "python": sys.version,
        "executable": sys.executable,
        "proposed_default": "3.12+",
        "meets_proposed_default": version >= (3, 12),
        "platform": sys.platform,
        "engine_version": ENGINE_VERSION,
    }


def runtime_probe(which=None):
    """Used when the engine itself is not what is missing, and by tests that simulate a missing runtime."""
    finder = which or shutil.which
    path = finder("python3") or finder("python")
    if not path:
        return {
            "available": False,
            "approval_required": True,
            "limited_checks_offered": True,
            "message": "Python was not found. Explicit installation approval is required. Limited read-only inspection can continue only where the host agent can read files without this engine.",
        }
    return {"available": True, "path": path, "approval_required": False}


def probe_sandbox():
    custom = os.environ.get("CQA_SANDBOX_CMD")
    if custom:
        return True, "custom containment command"
    sandbox = shutil.which("sandbox-exec")
    if not sandbox:
        return False, "no containment command is available"
    probe = subprocess.run(
        [sandbox, "-p", "(version 1)(allow default)", "/usr/bin/true"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        detail = (probe.stderr or probe.stdout or "sandbox-exec failed").strip()
        return False, f"containment is unavailable: {detail}"
    return True, sandbox


def _profile(read_paths, write_path):
    """Containment that can start CPython: read and execute are allowed, network and repository writes are not.

    read_paths is retained so callers can see which roots were considered. Writes are limited to write_path.
    """
    del read_paths
    write = f'(allow file-write* (subpath "{write_path}"))' if write_path else ""
    return f"""(version 1)
(deny default)
(deny network*)
(allow process*)
(allow signal)
(allow sysctl-read)
(allow file-ioctl)
(allow file-read*)
(allow file-read-metadata)
(allow file-map-executable)
(allow mach-lookup)
(allow ipc-posix*)
(allow system-socket)
{write}
"""


def run_contained(command, cwd, log, timeout=30, write_path=None, env=None):
    """Run a command only when repository execution is approved and containment actually applies."""
    if not log.allow_repo_execution:
        log.deny("repository-execution", "repository code was not executed; approval was not given")
        raise PermissionError("repository execution was not approved")
    if not log.sandbox_confirmed:
        log.deny("sandbox-confirmation", "sandbox confirmation was not given")
        raise PermissionError("sandbox confirmation was not given")
    ok, detail = probe_sandbox()
    if not ok:
        log.deny("containment", detail)
        raise PermissionError(detail)
    custom = os.environ.get("CQA_SANDBOX_CMD")
    command = list(command)
    executable = Path(command[0])
    if executable.is_file():
        command[0] = str(executable.resolve())
    if custom:
        wrapped = custom.split() + command
    else:
        read_paths = [str(Path(cwd).resolve()), str(Path(command[0]).resolve().parent.parent)]
        resolved_write = str(Path(write_path).resolve()) if write_path else None
        profile = _profile(read_paths, resolved_write)
        wrapped = ["sandbox-exec", "-p", profile, "--", *command]
    log.record(wrapped, "started")
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    try:
        completed = subprocess.run(wrapped, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=run_env)
    except subprocess.TimeoutExpired as exc:
        log.record(wrapped, "timeout", str(exc))
        raise
    if completed.returncode == 71 or "sandbox_apply" in (completed.stderr or ""):
        log.deny("containment", completed.stderr.strip() or "sandbox_apply failed")
        raise PermissionError("containment failed; the command was not rerun outside the sandbox")
    log.record(wrapped, f"exit {completed.returncode}")
    return completed


def run_tool(command, cwd, log, timeout=60):
    if not log.allow_tools:
        log.deny("external-tool", "tool execution was not approved")
        raise PermissionError("tool execution was not approved")
    log.record(command, "started")
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    log.record(command, f"exit {completed.returncode}")
    return completed


def git_read(repo, args, log, timeout=20):
    command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=", "-c", "protocol.allow=never", "--no-optional-locks"]
    for alias in GIT_ALIASES:
        command.extend(["-c", f"alias.{alias}="])
    command.extend(args)
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    log.record(command, "started")
    try:
        completed = subprocess.run(command, cwd=repo, capture_output=True, timeout=timeout, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.record(command, "error", str(exc))
        return None
    log.record(command, f"exit {completed.returncode}")
    if completed.returncode != 0:
        return None
    return completed


def install_skill(target, source, approve=False, log=None):
    log = log or ExecutionLog()
    if not approve:
        log.deny("skill-install", "skill installation needs explicit approval")
        return {"status": "approval_required", "installed": False, "path": None}
    destination = Path(target) / ".cursor" / "skills" / "code-quality-auditor"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    log.approvals.append({"action": "install-skill", "path": str(destination), "approved": True})
    log.record(["copy", str(source), str(destination)], "installed")
    return {"status": "installed", "installed": True, "path": str(destination)}


def install_analyzer(tool, approve=False, artifact=None, expected_sha256=None, log=None, execute=False):
    """Record an approved install plan. A download is never implied by the registry."""
    log = log or ExecutionLog()
    plan = {
        "tool": tool.get("id"),
        "version_constraint": tool.get("version_constraint"),
        "source": "local-verified-artifact" if artifact else None,
        "approved": bool(approve),
    }
    if not approve:
        log.deny("analyzer-install", f"{tool.get('id')} was not installed because approval was withheld")
        return {"status": "approval_required", "installed": False, "plan": plan}
    log.approvals.append({"action": "install-analyzer", **plan})
    if not artifact or not expected_sha256:
        return {
            "status": "blocked",
            "installed": False,
            "plan": plan,
            "message": "Approved installation requires a local artifact and a sha256. The registry does not authorize a download.",
        }
    digest = hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
    if digest != expected_sha256:
        log.deny("analyzer-install", "artifact hash did not match")
        return {"status": "blocked", "installed": False, "plan": plan, "message": "artifact verification failed"}
    if not execute:
        return {"status": "verified", "installed": False, "plan": plan, "message": "Artifact verified. Execution of the installer was not requested."}
    command = [sys.executable, "-m", "pip", "install", "--no-index", str(artifact)]
    log.record(command, "started")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    log.record(command, f"exit {completed.returncode}", completed.stderr[-500:])
    return {
        "status": "installed" if completed.returncode == 0 else "failed",
        "installed": completed.returncode == 0,
        "plan": plan,
        "exit_code": completed.returncode,
    }
