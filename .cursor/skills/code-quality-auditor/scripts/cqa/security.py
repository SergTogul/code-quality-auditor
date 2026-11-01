"""Execution policy. Profiles cannot turn these gates off."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
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


_PLATFORM_SANDBOX = {"darwin": "/usr/bin/sandbox-exec"}


def _trusted_sandbox():
    """The platform binary at a fixed path. PATH cannot select a different executable."""
    candidate = _PLATFORM_SANDBOX.get(sys.platform)
    if not candidate:
        return None
    path = Path(candidate)
    try:
        info = path.stat()
    except OSError:
        return None
    if not path.is_file() or info.st_uid != 0:
        return None
    return path.resolve()


def _sandbox_command(profile, command):
    trusted = _trusted_sandbox()
    if trusted is None:
        raise PermissionError("no containment command is available")
    return [str(trusted), "-p", profile, "--", *command]


def probe_sandbox(cwd=None):
    """Trust only the platform sandbox-exec binary, and only when it enforces the production profile."""
    trusted = _trusted_sandbox()
    custom = os.environ.get("CQA_SANDBOX_CMD")
    if custom:
        try:
            path = _validate_custom(custom, cwd)
        except PermissionError as exc:
            return False, str(exc)
        if trusted is None or path != trusted:
            return False, "custom containment command is not an allowlisted implementation"
    if trusted is None:
        return False, "no containment command is available"
    try:
        base = Path(tempfile.mkdtemp(prefix="cqa-probe-")).resolve()
    except OSError:
        return False, "containment is unavailable: the probe scratch directory could not be created"
    try:
        failure = _policy_probe(base)
    except OSError:
        failure = "the containment probe could not be prepared"
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if failure:
        return False, f"containment is unavailable: {failure}"
    return True, str(trusted)


_PROBE_SCRIPT = r"""
import json, os, socket, sys
allowed = sys.argv[1]
denied = os.path.join(os.path.dirname(allowed), "denied")
port = int(os.environ["CQA_PROBE_PORT"])
result = {}

def attempt(key, action):
    try:
        action()
        result[key] = True
    except OSError:
        result[key] = False

def read_write():
    with open(os.path.join(allowed, "input"), "rb") as source:
        data = source.read()
    with open(os.path.join(allowed, "output"), "wb") as target:
        target.write(data)

def denied_read():
    with open(os.path.join(denied, "sentinel"), "rb") as source:
        source.read()

def denied_write():
    with open(os.path.join(denied, "escape"), "wb") as target:
        target.write(b"x")

def network():
    with socket.create_connection(("127.0.0.1", port), timeout=2):
        pass

if os.environ.get("CQA_PROBE_MODE") == "baseline":
    attempt("network", network)
else:
    attempt("read_write", read_write)
    attempt("denied_read", denied_read)
    attempt("denied_write", denied_write)
    attempt("network", network)
print(json.dumps(result))
"""
_PROBE_KEYS = ("read_write", "denied_read", "denied_write", "network")
_PROBE_TIMEOUT = 15


def _probe_result(completed, keys):
    if completed.returncode != 0:
        return None
    lines = (completed.stdout or "").strip().splitlines()
    if len(lines) != 1:
        return None
    try:
        result = json.loads(lines[0])
    except ValueError:
        return None
    if not isinstance(result, dict) or set(result) != set(keys):
        return None
    if not all(isinstance(result[key], bool) for key in keys):
        return None
    return result


def _connection_waiting(listener):
    listener.setblocking(False)
    try:
        connection, _address = listener.accept()
    except (BlockingIOError, InterruptedError):
        return False
    connection.close()
    return True


def _policy_probe(base):
    """Run the production profile on synthetic files. Returns a failure reason, or None when every check holds."""
    allowed = base / "allowed"
    denied = base / "denied"
    allowed.mkdir()
    denied.mkdir()
    expected = secrets.token_hex(16).encode()
    sentinel = secrets.token_hex(16).encode()
    (allowed / "input").write_bytes(expected)
    (denied / "sentinel").write_bytes(sentinel)
    script = allowed / "probe.py"
    script.write_text(_PROBE_SCRIPT, encoding="utf-8")
    command = [sys.executable, "-I", str(script), str(allowed)]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        port = str(listener.getsockname()[1])
        try:
            baseline = _run_process(command, str(allowed), _sanitize_env({"CQA_PROBE_PORT": port, "CQA_PROBE_MODE": "baseline"}), _PROBE_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            return "the unsandboxed probe baseline did not run"
        result = _probe_result(baseline, ("network",))
        listener.settimeout(2)
        try:
            connection, _address = listener.accept()
            connection.close()
            reached = True
        except OSError:
            reached = False
        if result is None or not result["network"] or not reached:
            return "the unsandboxed probe baseline could not reach loopback, so the network check is not conclusive"
        scratch = str(allowed)
        env = _sanitize_env({"CQA_PROBE_PORT": port, "TMPDIR": scratch, "TMP": scratch, "TEMP": scratch})
        try:
            completed = _run_process(_contained_command(command, scratch, scratch), scratch, env, _PROBE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return "the containment probe timed out"
        except OSError:
            return "the containment probe did not start"
        connected = _connection_waiting(listener)
    output = (completed.stdout or "") + (completed.stderr or "")
    if sentinel.decode() in output or expected.decode() in output:
        return "the containment probe exposed a synthetic sentinel"
    if sorted(os.listdir(denied)) != ["sentinel"] or (denied / "sentinel").read_bytes() != sentinel:
        return "the containment probe wrote outside its scratch directory"
    if connected:
        return "the containment probe reached loopback network"
    result = _probe_result(completed, _PROBE_KEYS)
    if result is None:
        return f"the containment probe returned an incomplete result (exit {completed.returncode})"
    if result["denied_read"] or result["denied_write"] or result["network"]:
        return "the containment probe escaped the production profile"
    output_file = allowed / "output"
    if not result["read_write"] or not output_file.is_file() or output_file.read_bytes() != expected:
        return "the containment probe could not use its allowed scratch directory"
    return None


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


# Reviewed runtime roots. /etc, /var, /opt, /Library outside Developer, /dev,
# shared temporary roots, /Users, and /home are intentionally absent.
_SYSTEM_READ_ROOTS = (
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Developer",
    "/opt/homebrew",
)
_DEVICE_FILES = ("/dev/null", "/dev/random", "/dev/urandom")
_SHARED_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders")
_READ_OPERATIONS = ("file-read*", "file-read-metadata", "file-map-executable")


def _rules(verb, operations, path, kind="subpath"):
    quoted = _quote_sb(path)
    return "\n".join(f'({verb} {operation} ({kind} "{quoted}"))' for operation in operations)


def _user_roots():
    roots = []
    for raw in ("/Users", "/home"):
        path = Path(raw)
        if path.is_dir():
            roots.append(path.resolve())
    return roots


def _protected_roots():
    """Roots whose contents are unrelated to any one command: user homes and shared temporary storage."""
    roots = _user_roots()
    roots.append(Path.home().resolve())
    roots.append(Path(tempfile.gettempdir()).resolve())
    for raw in _SHARED_TEMP_ROOTS:
        path = Path(raw)
        if path.exists():
            roots.append(path.resolve())
    return roots


def _too_broad(path, protected):
    """Allowing `/`, a home, a shared temporary root, or any ancestor of one would undo the read closure."""
    if path == Path("/"):
        return True
    return any(path == root or path in root.parents for root in protected)


def _profile(read_paths, write_path):
    """Deny by default and grant only scoped rules.

    No file rule is unfiltered. Reads cover the reviewed system roots, the device
    files, and the command's own inputs, including the write path. Writes cover
    only the write path. User roots are denied before the command's inputs are
    re-opened, and credential directories are denied last. If seatbelt cannot
    launch under this profile, probe_sandbox reports containment unavailable.
    """
    user_roots = _user_roots()
    protected = _protected_roots()
    required = []
    for raw in _existing_reads([*(read_paths or []), *([write_path] if write_path else [])]):
        path = Path(raw).resolve()
        if _too_broad(path, protected):
            continue
        required.append(path)
    system = []
    for raw in _SYSTEM_READ_ROOTS:
        path = Path(raw)
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved in system or _too_broad(resolved, protected):
            continue
        system.append(resolved)
    devices = "\n".join(_rules("allow", ("file-read*", "file-read-metadata", "file-ioctl"), device, "literal") for device in _DEVICE_FILES)
    system_allows = "\n".join(_rules("allow", _READ_OPERATIONS, path) for path in system)
    required_allows = "\n".join(_rules("allow", _READ_OPERATIONS, path) for path in required)
    user_denies = "\n".join(_rules("deny", _READ_OPERATIONS, root) for root in user_roots)
    home = Path.home().resolve()
    secret_denies = "\n".join(_rules("deny", (*_READ_OPERATIONS, "file-write*"), home / name) for name in _SECRET_DIRS)
    write = _rules("allow", ("file-write*",), Path(write_path).resolve()) if write_path else ""
    return f"""(version 1)
(deny default)
(deny network*)
(allow process-exec)
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix*)
{devices}
{system_allows}
{user_denies}
{required_allows}
{write}
{secret_denies}
"""


def _contained_command(command, cwd, write_path):
    command = list(command)
    executable = Path(command[0])
    if executable.is_file():
        command[0] = str(executable.resolve())
    resolved_write = str(Path(write_path).resolve()) if write_path else None
    profile = _profile(_command_read_paths(cwd, command), resolved_write)
    return _sandbox_command(profile, command)


def _containment_failed(completed):
    """Seatbelt reports a profile it cannot apply as status 71, a sandbox_apply diagnostic, or a silent signal death."""
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode == 71 or "sandbox_apply" in stderr:
        return True
    return completed.returncode < 0 and not stdout.strip() and not stderr.strip()


def _run_sandboxed(command, cwd, log, timeout, write_path, env=None):
    """The only launch path for host analyzers and repository code. A containment failure is never retried unsandboxed."""
    ok, detail = probe_sandbox(cwd)
    if not ok:
        log.deny("containment", detail)
        raise PermissionError(detail)
    run_env = _sanitize_env(env)
    for key in ("TMPDIR", "TMP", "TEMP"):
        run_env.pop(key, None)
    if write_path:
        scratch = str(Path(write_path).resolve())
        run_env.update({"TMPDIR": scratch, "TMP": scratch, "TEMP": scratch})
    wrapped = _contained_command(command, cwd, write_path)
    log.record(wrapped, "started")
    try:
        completed = _run_process(wrapped, cwd, run_env, timeout)
    except subprocess.TimeoutExpired as exc:
        log.record(wrapped, "timeout", str(exc))
        raise
    if _containment_failed(completed):
        log.deny("containment", (completed.stderr or "").strip() or f"sandbox launch failed with exit {completed.returncode}")
        raise PermissionError("containment failed; the command was not rerun outside the sandbox")
    log.record(wrapped, f"exit {completed.returncode}")
    return completed


def run_contained(command, cwd, log, timeout=30, write_path=None, env=None):
    """Run a command only when repository execution is approved and containment actually applies."""
    if not log.allow_repo_execution:
        log.deny("repository-execution", "repository code was not executed; approval was not given")
        raise PermissionError("repository execution was not approved")
    if not log.sandbox_confirmed:
        log.deny("sandbox-confirmation", "sandbox confirmation was not given")
        raise PermissionError("sandbox confirmation was not given")
    return _run_sandboxed(command, cwd, log, timeout, write_path, env)


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
    scratch = tempfile.mkdtemp(prefix="cqa-tool-")
    try:
        return _run_sandboxed(command, cwd, log, timeout, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


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
