"""Execution policy. Profiles cannot turn these gates off."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
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


_DROPPED_ENV = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "NODE_PATH",
    "BASH_ENV",
    "ENV",
    "GIT_DIR",
    "GIT_WORK_TREE",
}
_NEVER_PASS = {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONSTARTUP", "NODE_OPTIONS", "BASH_ENV", "ENV"}
_KEEP_ENV = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "COMSPEC", "USER", "LOGNAME")
_SECRET_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gh")
_SHELLS = {"bash", "sh", "zsh", "dash", "env", "python", "python3", "perl", "ruby", "node"}


def _quote_sb(path):
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _sanitize_env(explicit=None):
    """Drop inherited loader and startup hooks. Explicit PYTHONPATH from the auditor is kept."""
    env = {key: os.environ[key] for key in _KEEP_ENV if key in os.environ and key not in _DROPPED_ENV}
    for key, value in (explicit or {}).items():
        if key in _NEVER_PASS or value is None:
            continue
        env[key] = value
    return env


def _validate_custom(raw, cwd=None):
    if raw != raw.strip() or any(character.isspace() for character in raw):
        raise PermissionError("custom sandbox command must be one absolute executable path")
    path = Path(raw)
    if not path.is_absolute() or not path.is_file():
        raise PermissionError("custom sandbox command must be one absolute executable path")
    resolved = path.resolve()
    name = resolved.name
    if name in _SHELLS or name.startswith("python"):
        raise PermissionError("custom sandbox command is an interpreter or shell")
    if cwd is not None:
        root = Path(cwd).resolve()
        if resolved == root or root in resolved.parents:
            raise PermissionError("custom sandbox command is inside the audited repository")
    return resolved


def _inside(root, path):
    root = Path(root).resolve()
    path = Path(path).resolve()
    return path == root or root in path.parents


def _resolve_executable(command):
    candidate = Path(command)
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which(command)
    if not found:
        raise PermissionError(f"executable was not found: {command}")
    return Path(found).resolve()


def _run_process(command, cwd, env, timeout):
    """Run a command in its own session and kill the whole group on timeout."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
        raise exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _custom_contains(wrapper):
    """Probe write, secret read, and network. A wrapper can still special-case these argv shapes."""
    true_run = _run_process([str(wrapper), "/usr/bin/true"], None, _sanitize_env(), 10)
    if true_run.returncode != 0:
        return False, "custom containment command does not isolate: benign command failed"
    probe_dir = Path(tempfile.mkdtemp(prefix="cqa-sandbox-probe-"))
    probe_file = probe_dir / "outside-write"
    secret = probe_dir / "secret-token"
    token = secrets.token_hex(16)
    secret.write_text(token, encoding="utf-8")
    try:
        write_run = _run_process([str(wrapper), "/usr/bin/touch", str(probe_file)], None, _sanitize_env(), 10)
        created = probe_file.exists()
        if write_run.returncode == 0 or created:
            return False, "custom containment command does not isolate writes"
        read_run = _run_process([str(wrapper), "/bin/cat", str(secret)], None, _sanitize_env(), 10)
        if read_run.returncode == 0 or token in (read_run.stdout or ""):
            return False, "custom containment command does not isolate reads"
        if _network_escapes(wrapper):
            return False, "custom containment command does not isolate network"
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)
    return True, ""


def _network_escapes(wrapper):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    port = server.getsockname()[1]
    connected = {"ok": False}

    def accept():
        try:
            connection, _addr = server.accept()
            connection.close()
            connected["ok"] = True
        except OSError:
            return

    waiter = threading.Thread(target=accept, daemon=True)
    waiter.start()
    code = f"import socket; socket.create_connection(('127.0.0.1', {port}), 2).close()"
    try:
        _run_process([str(wrapper), sys.executable, "-c", code], None, _sanitize_env(), 5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        server.close()
    waiter.join(1)
    return connected["ok"]


def probe_sandbox(cwd=None):
    custom = os.environ.get("CQA_SANDBOX_CMD")
    if custom:
        try:
            path = _validate_custom(custom, cwd)
        except PermissionError as exc:
            return False, str(exc)
        contained, detail = _custom_contains(path)
        if not contained:
            return False, detail
        return True, str(path)
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


def _existing_reads(read_paths):
    candidates = list(read_paths or [])
    candidates.append(sys.prefix)
    candidates.append(getattr(sys, "base_prefix", sys.prefix))
    roots = []
    seen = set()
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw)
        if not path.exists():
            continue
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        roots.append(resolved)
    return roots


def _command_read_paths(cwd, command):
    paths = []
    root = Path(cwd).resolve()
    if root.exists():
        paths.append(str(root))
    for item in command:
        candidate = Path(item)
        if not candidate.exists():
            continue
        resolved = candidate.resolve()
        paths.append(str(resolved if resolved.is_dir() else resolved.parent))
    return paths


def _profile(read_paths, write_path, allow_temp_writes=False):
    """Allow system reads, then close the home directory except paths this command must read.

    Filtered file-read allows are not usable on their own here: seatbelt aborts the process.
    The home deny is applied after the blanket read, and only the command's own paths under
    the home directory are opened again. Credential directories are denied last.
    """
    home = Path.home().resolve()
    reopen = []
    for raw in _existing_reads(read_paths):
        path = Path(raw).resolve()
        if path == home or home in path.parents:
            reopen.append(str(path))
    home_deny = f'(deny file-read* (subpath "{_quote_sb(home)}"))'
    reopened = "\n".join(f'(allow file-read* (subpath "{_quote_sb(path)}"))' for path in reopen)
    secret_denies = "\n".join(
        f'(deny file-read* (subpath "{_quote_sb(home / name)}"))' for name in _SECRET_DIRS
    )
    write = f'(allow file-write* (subpath "{_quote_sb(write_path)}"))' if write_path else ""
    if allow_temp_writes:
        temp = _quote_sb(Path(tempfile.gettempdir()).resolve())
        write = f'{write}\n(allow file-write* (subpath "{temp}"))'
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
{home_deny}
{reopened}
{write}
{secret_denies}
"""


def _contained_command(command, cwd, write_path):
    command = list(command)
    executable = Path(command[0])
    if executable.is_file():
        command[0] = str(executable.resolve())
    custom = os.environ.get("CQA_SANDBOX_CMD")
    if custom:
        return [str(Path(custom).resolve()), *command]
    resolved_write = str(Path(write_path).resolve()) if write_path else None
    profile = _profile(_command_read_paths(cwd, command), resolved_write)
    return ["sandbox-exec", "-p", profile, "--", *command]


def run_contained(command, cwd, log, timeout=30, write_path=None, env=None):
    """Run a command only when repository execution is approved and containment actually applies."""
    if not log.allow_repo_execution:
        log.deny("repository-execution", "repository code was not executed; approval was not given")
        raise PermissionError("repository execution was not approved")
    if not log.sandbox_confirmed:
        log.deny("sandbox-confirmation", "sandbox confirmation was not given")
        raise PermissionError("sandbox confirmation was not given")
    ok, detail = probe_sandbox(cwd)
    if not ok:
        log.deny("containment", detail)
        raise PermissionError(detail)
    wrapped = _contained_command(command, cwd, write_path)
    log.record(wrapped, "started")
    run_env = _sanitize_env(env)
    try:
        completed = _run_process(wrapped, cwd, run_env, timeout)
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
    try:
        executable = _resolve_executable(command[0])
    except PermissionError as exc:
        log.deny("external-tool", str(exc))
        raise
    if _inside(cwd, executable):
        log.deny("external-tool", "repository-controlled executable was not run")
        raise PermissionError("repository-controlled executable was not run")
    command = [str(executable), *list(command)[1:]]
    custom = os.environ.get("CQA_SANDBOX_CMD")
    ok, detail = probe_sandbox(cwd)
    if not ok:
        log.deny("containment", detail)
        raise PermissionError(detail)
    if custom:
        wrapped = [str(Path(custom).resolve()), *command]
    else:
        wrapped = ["sandbox-exec", "-p", _profile(_command_read_paths(cwd, command), None, allow_temp_writes=True), "--", *command]
    log.record(wrapped, "started")
    completed = _run_process(wrapped, cwd, _sanitize_env(), timeout)
    log.record(wrapped, f"exit {completed.returncode}")
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
