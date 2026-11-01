"""Execution policy. Profiles cannot turn these gates off."""

from __future__ import annotations

import hashlib
import json
import locale
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
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


def _lexically_inside(root, path):
    path = Path(os.path.abspath(path))
    for base in {Path(os.path.abspath(root)), Path(root).resolve()}:
        if path == base or base in path.parents:
            return True
    return False


def _locate_executable(command, cwd):
    """A bare name is a PATH lookup. A path is taken relative to the audit root, never the auditor's cwd."""
    raw = str(command)
    if os.sep not in raw and (os.altsep is None or os.altsep not in raw):
        found = shutil.which(raw)
        if not found:
            raise PermissionError(f"executable was not found: {command}")
        return Path(os.path.abspath(found))
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    if not candidate.is_file():
        raise PermissionError(f"executable was not found: {command}")
    return Path(os.path.abspath(candidate))


_OUTPUT_LIMIT = 8 * 1024 * 1024
_SWEEP_SECONDS = 2
_SWEEP_DEPTH = 64


class OutputLimitExceeded(Exception):
    """A child wrote more than the per-stream limit. The output was discarded."""


def _proc_children():
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                fields = handle.read().decode("ascii", "replace")
            ppid = int(fields.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(entry))
    return children


def _stop_descendants(root):
    """Linux only. Stop every transitive child of root, including ones that left its process group, and return them."""
    if not sys.platform.startswith("linux"):
        return []
    deadline = time.monotonic() + _SWEEP_SECONDS
    stopped = []
    seen = {root}
    while time.monotonic() < deadline:
        try:
            children = _proc_children()
        except OSError:
            break
        found = []
        frontier = [(root, 0)]
        visited = {root}
        while frontier:
            pid, depth = frontier.pop()
            if depth >= _SWEEP_DEPTH:
                continue
            for child in children.get(pid, ()):
                if child in visited:
                    continue
                visited.add(child)
                frontier.append((child, depth + 1))
                if child not in seen:
                    seen.add(child)
                    found.append(child)
        if not found:
            break
        for pid in found:
            try:
                os.kill(pid, signal.SIGSTOP)
            except OSError:
                continue
            stopped.append(pid)
    return stopped


def _kill_tree(process):
    try:
        os.kill(process.pid, signal.SIGSTOP)
    except OSError:
        pass
    descendants = _stop_descendants(process.pid)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _decode(chunks):
    text = b"".join(chunks).decode(locale.getpreferredencoding(False), errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _run_process(command, cwd, env, timeout, limit=_OUTPUT_LIMIT, text=True):
    """Run a command in its own session with bounded output. Neither exception carries the child's output.

    On timeout or overflow the child's session is killed, and on Linux children still parented under it
    in /proc are stopped and killed as well. This cleanup is best effort, not a containment guarantee: a
    process that calls setsid or is reparented away can survive, especially on macOS, where no /proc
    sweep runs. The sandbox profile, not this cleanup, is the security boundary.
    """
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout
    streams = {process.stdout: [], process.stderr: []}
    sizes = {process.stdout: 0, process.stderr: 0}
    failure = None
    with selectors.DefaultSelector() as selector:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() and failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            for key, _events in selector.select(remaining):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                sizes[key.fileobj] += len(chunk)
                if sizes[key.fileobj] > limit:
                    failure = "overflow"
                    break
                streams[key.fileobj].append(chunk)
    if failure is None:
        try:
            process.wait(timeout=max(deadline - time.monotonic(), 0))
        except subprocess.TimeoutExpired:
            failure = "timeout"
    if failure is not None:
        _kill_tree(process)
    for stream in streams:
        stream.close()
    if failure == "timeout":
        raise subprocess.TimeoutExpired(command, timeout)
    if failure == "overflow":
        raise OutputLimitExceeded(f"output exceeded {limit} bytes on one stream; the process was killed and its output discarded")
    decode = _decode if text else b"".join
    return subprocess.CompletedProcess(command, process.returncode, decode(streams[process.stdout]), decode(streams[process.stderr]))


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
    root = base / "root"
    allowed.mkdir(mode=0o700)
    denied.mkdir()
    root.mkdir()
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
        except (OSError, subprocess.TimeoutExpired, OutputLimitExceeded):
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
            completed = _run_process(_contained_command(command, str(root), scratch), str(root), env, _PROBE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return "the containment probe timed out"
        except OutputLimitExceeded:
            return "the containment probe exceeded the output limit"
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
    """Existing paths from the caller. The interpreter prefix is not added.

    A prefix under the home, such as ~/.local or ~/.pyenv, would be re-allowed
    after the home deny and would expose credential directories there. A system
    interpreter is already covered by the reviewed system roots. Any other
    interpreter stays unreadable and containment fails closed.
    """
    candidates = list(read_paths or [])
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
    """Arguments never widen reads. Only the audit root is granted; anything inside it is already covered."""
    root = Path(cwd).resolve()
    return [str(root)] if root.is_dir() else []


# Reviewed runtime roots. /etc, /var, /opt, /Library outside Developer, /System
# outside Library, /dev, shared temporary roots, /Users, and /home are intentionally absent.
_SYSTEM_READ_ROOTS = (
    "/usr",
    "/bin",
    "/sbin",
    "/System/Library",
    "/Library/Developer",
    "/opt/homebrew",
)
_DEVICE_FILES = ("/dev/null", "/dev/random", "/dev/urandom")
_SHARED_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders")
# The macOS Data volume holds a second path to every user home, /private, and shared temporary storage.
_ALIAS_ROOTS = ("/System/Volumes/Data",)
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
    """Roots whose contents are unrelated to any one command: user homes, shared temporary storage, and volumes that alias them."""
    roots = _user_roots()
    roots.append(Path.home().resolve())
    roots.append(Path(tempfile.gettempdir()).resolve())
    for raw in _SHARED_TEMP_ROOTS:
        path = Path(raw)
        if path.exists():
            roots.append(path.resolve())
    for raw in _ALIAS_ROOTS:
        path = Path(raw)
        roots.append(path)
        if path.exists():
            roots.append(path.resolve())
    return roots


def _too_broad(path, protected):
    """Allowing `/`, a home, a shared temporary root, a volume that aliases them, or any ancestor of one would undo the read closure."""
    if path == Path("/"):
        return True
    return any(path == root or path in root.parents for root in protected)


def _writable_scratch(write_path, cwd):
    """A write path must be a private directory below the system temp root, apart from the audit tree.

    Private means owned by this process's effective uid with no group or other permissions, as mkdtemp creates.
    """
    path = Path(write_path).resolve()
    temp = Path(tempfile.gettempdir()).resolve()
    root = Path(cwd).resolve()
    if not path.is_dir() or _too_broad(path, _protected_roots()) or temp not in path.parents:
        return False
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        return False
    return not (path == root or root in path.parents or path in root.parents)


def _profile(read_paths, write_path, cwd):
    """Deny by default and grant only scoped rules.

    No file rule is unfiltered. Reads cover the reviewed system roots, the device
    files, and the command's own inputs, including an accepted write path. The
    interpreter prefix is not granted. Writes cover only a write path that
    _writable_scratch accepts for cwd. User roots are denied before the command's
    inputs are re-opened, and credential directories are denied last. If seatbelt
    cannot launch under this profile, probe_sandbox reports containment unavailable.
    """
    if write_path and not _writable_scratch(write_path, cwd):
        write_path = None
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


def _audit_root(cwd, read_root):
    """The repository granted for reads. Defaults to the process cwd."""
    return Path(cwd if read_root is None else read_root).resolve()


def _contained_command(command, cwd, write_path, read_root=None):
    command = list(command)
    executable = Path(command[0])
    if os.sep in str(command[0]):
        if not executable.is_absolute():
            executable = Path(cwd) / executable
        if executable.is_file():
            command[0] = str(executable.resolve())
    resolved_write = str(Path(write_path).resolve()) if write_path else None
    root = _audit_root(cwd, read_root)
    profile = _profile(_command_read_paths(root, command), resolved_write, root)
    return _sandbox_command(profile, command)


def _containment_failed(completed):
    """Seatbelt reports a profile it cannot apply as status 71, a sandbox_apply diagnostic, or a silent signal death."""
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode == 71 or "sandbox_apply" in stderr:
        return True
    return completed.returncode < 0 and not stdout.strip() and not stderr.strip()


def _run_sandboxed(command, cwd, log, timeout, write_path, env=None, read_root=None):
    """The only launch path for host analyzers and repository code. A containment failure is never retried unsandboxed."""
    root = _audit_root(cwd, read_root)
    ok, detail = probe_sandbox(root)
    if not ok:
        log.deny("containment", detail)
        raise PermissionError(detail)
    if write_path and not _writable_scratch(write_path, root):
        detail = "the write path is not a private temporary directory outside the audit root; the command was not run"
        log.deny("containment", detail)
        raise PermissionError(detail)
    run_env = _sanitize_env(env)
    for key in ("TMPDIR", "TMP", "TEMP"):
        run_env.pop(key, None)
    if write_path:
        scratch = str(Path(write_path).resolve())
        run_env.update({"TMPDIR": scratch, "TMP": scratch, "TEMP": scratch})
    wrapped = _contained_command(command, cwd, write_path, read_root)
    log.record(wrapped, "started")
    try:
        completed = _run_process(wrapped, cwd, run_env, timeout)
    except subprocess.TimeoutExpired:
        log.record(wrapped, "timeout", f"timed out after {timeout} seconds; output was discarded")
        raise
    except OutputLimitExceeded as exc:
        log.deny("output-limit", "the command exceeded the output limit and was killed; output was discarded")
        raise PermissionError(str(exc)) from None
    if _containment_failed(completed):
        log.deny("containment", f"containment failed with exit {completed.returncode}; the command was not rerun outside the sandbox")
        raise PermissionError("containment failed; the command was not rerun outside the sandbox")
    log.record(wrapped, f"exit {completed.returncode}")
    return completed


def run_contained(command, cwd, log, timeout=30, write_path=None, env=None, read_root=None):
    """Run a command only when repository execution is approved and containment actually applies.

    cwd is the process working directory. read_root is the audit root used for the
    read grant and the scratch-directory check. It defaults to cwd. A relative
    executable is still resolved against cwd.
    """
    if not log.allow_repo_execution:
        log.deny("repository-execution", "repository code was not executed; approval was not given")
        raise PermissionError("repository execution was not approved")
    if not log.sandbox_confirmed:
        log.deny("sandbox-confirmation", "sandbox confirmation was not given")
        raise PermissionError("sandbox confirmation was not given")
    return _run_sandboxed(command, cwd, log, timeout, write_path, env, read_root)


def run_tool(command, cwd, log, timeout=60):
    if not log.allow_tools:
        log.deny("external-tool", "tool execution was not approved")
        raise PermissionError("tool execution was not approved")
    try:
        located = _locate_executable(command[0], cwd)
    except PermissionError as exc:
        log.deny("external-tool", str(exc))
        raise
    executable = located.resolve()
    if _lexically_inside(cwd, located) or _inside(cwd, executable):
        log.deny("external-tool", "repository-controlled executable was not run")
        raise PermissionError("repository-controlled executable was not run")
    command = [str(executable), *list(command)[1:]]
    scratch = tempfile.mkdtemp(prefix="cqa-tool-")
    try:
        return _run_sandboxed(command, cwd, log, timeout, scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


_GIT_CANDIDATES = ("/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git")
_GIT_HELPER_KEYS = (
    "diff.external",
    "core.sshCommand",
    "core.pager",
    "credential.helper",
    "gpg.program",
    "gpg.ssh.program",
    "gpg.x509.program",
)
# log.showSignature makes git log run gpg.program. Submodule recursion would enter another config.
_GIT_FORCED_CONFIG = (
    ("log.showSignature", "false"),
    ("diff.submodule", "short"),
    ("submodule.recurse", "false"),
)
_GIT_DIFF_COMMANDS = {"log", "diff", "show"}


def _trusted_git(repo):
    """A git at a fixed platform path, outside the audit root, owned by root or this user and writable only by its owner.

    PATH is never consulted, so neither the repository nor an earlier PATH entry can choose the git that runs.
    """
    for raw in _GIT_CANDIDATES:
        path = Path(raw)
        try:
            if not path.is_file():
                continue
            resolved = path.resolve()
            info = resolved.stat()
        except OSError:
            continue
        if _lexically_inside(repo, path) or _inside(repo, resolved):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_uid not in {0, os.geteuid()}:
            continue
        return resolved
    return None


def contained_file(root, path):
    """The resolved regular file for path, only when both the path and its target lie inside root."""
    try:
        if not _lexically_inside(root, path) or not _inside(root, path):
            return None
        resolved = Path(path).resolve()
        if not stat.S_ISREG(resolved.stat().st_mode):
            return None
    except OSError:
        return None
    return resolved


_GIT_CONFIG_LIMIT = 1024 * 1024
_GIT_INCLUDE_DEPTH = 4
_GIT_DRIVER_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_GIT_VALUE_ESCAPES = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}


class _GitConfigRefused(Exception):
    """The repository's git config cannot be fully classified, so git must not run."""


def _git_config_value(text, index):
    """Parse a value the way git does: quotes, escapes, continuations, and unquoted comments."""
    value = []
    quoted = False
    pending_space = ""
    while index < len(text):
        char = text[index]
        index += 1
        if char == "\n" and not quoted:
            break
        if char in "#;" and not quoted:
            while index < len(text) and text[index] != "\n":
                index += 1
            break
        if char in " \t" and not quoted:
            if value:
                pending_space += char
            continue
        value.append(pending_space)
        pending_space = ""
        if char == "\\":
            if index >= len(text):
                raise ValueError("dangling escape")
            escaped = text[index]
            index += 1
            if escaped == "\n":
                continue
            if escaped not in _GIT_VALUE_ESCAPES:
                raise ValueError("unknown escape")
            value.append(_GIT_VALUE_ESCAPES[escaped])
        elif char == '"':
            quoted = not quoted
        elif char == "\n":
            raise ValueError("newline inside a quoted value")
        else:
            value.append(char)
    if quoted:
        raise ValueError("unterminated quote")
    return "".join(value), index


def _git_config_header(text, index):
    """Parse `[section]`, `[section.sub]`, or `[section "sub"]` starting after the bracket."""
    start = index
    while index < len(text) and (text[index].isalnum() or text[index] in ".-"):
        index += 1
    name = text[start:index].lower()
    if not name:
        raise ValueError("empty section name")
    if index < len(text) and text[index] == "]":
        section, _dot, subsection = name.partition(".")
        return section, (subsection or None), index + 1
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text) or text[index] != '"' or "." in name:
        raise ValueError("malformed section header")
    index += 1
    subsection = []
    while True:
        if index >= len(text) or text[index] == "\n":
            raise ValueError("unterminated subsection")
        char = text[index]
        index += 1
        if char == '"':
            break
        if char == "\\":
            if index >= len(text) or text[index] == "\n":
                raise ValueError("unterminated subsection")
            char = text[index]
            index += 1
        subsection.append(char)
    if index >= len(text) or text[index] != "]":
        raise ValueError("malformed section header")
    return name, "".join(subsection), index + 1


def _parse_git_config(text):
    """Yield (section, subsection, key, value) entries. Raise ValueError for anything git might read differently."""
    section = subsection = None
    text = text.replace("\r\n", "\n")
    index = 0
    if text.startswith("\ufeff"):
        index = 1
    while index < len(text):
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char in "#;":
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        if char == "[":
            section, subsection, index = _git_config_header(text, index + 1)
            continue
        if not char.isalpha() or section is None:
            raise ValueError("malformed key")
        start = index
        while index < len(text) and (text[index].isalnum() or text[index] == "-"):
            index += 1
        key = text[start:index].lower()
        while index < len(text) and text[index] in " \t\r":
            index += 1
        value = None
        if index < len(text) and text[index] == "=":
            value, index = _git_config_value(text, index + 1)
        elif index < len(text) and text[index] not in "\n#;":
            raise ValueError("malformed key")
        yield section, subsection, key, value


def _git_config_overrides(repo):
    """`-c` arguments that blank every filter and diff driver the repository's own git config defines.

    Git config is read here as bounded text, never through git, because asking git would load it.
    Raise _GitConfigRefused when any file git would read cannot be confirmed to lie inside the repository.
    """
    root = Path(repo)
    git_dir = root / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir() or not _inside(root, git_dir):
        raise _GitConfigRefused("the audit root has no .git directory of its own; git was not run")
    if os.path.lexists(git_dir / "commondir"):
        raise _GitConfigRefused("repository git directory delegates its config to another directory; git was not run")
    outside = "repository git config includes a path outside the audit root; git was not run"
    pending = [(git_dir / name, 0) for name in ("config.worktree", "config") if os.path.lexists(git_dir / name)]
    visited = set()
    filters = set()
    drivers = set()
    while pending:
        path, depth = pending.pop()
        resolved = contained_file(root, path)
        if resolved is None:
            raise _GitConfigRefused(outside)
        if resolved in visited:
            continue
        visited.add(resolved)
        try:
            with resolved.open("rb") as handle:
                data = handle.read(_GIT_CONFIG_LIMIT + 1)
        except OSError:
            raise _GitConfigRefused("repository git config could not be read; git was not run") from None
        if len(data) > _GIT_CONFIG_LIMIT:
            raise _GitConfigRefused("repository git config exceeds 1 MiB; git was not run")
        try:
            entries = list(_parse_git_config(data.decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            raise _GitConfigRefused("repository git config could not be parsed; git was not run") from None
        for section, subsection, key, value in entries:
            if section == "filter" and subsection is not None:
                filters.add(subsection)
            elif section == "diff" and subsection is not None:
                drivers.add(subsection)
            elif section in {"include", "includeif"} and key == "path":
                if not value or value.startswith("~") or Path(value).is_absolute():
                    raise _GitConfigRefused(outside)
                if depth >= _GIT_INCLUDE_DEPTH:
                    raise _GitConfigRefused("repository git config nests includes too deeply; git was not run")
                pending.append((path.parent / value, depth + 1))
    if any(not _GIT_DRIVER_NAME.match(name) for name in filters | drivers):
        raise _GitConfigRefused("repository git config names a filter or diff driver with unsupported characters; git was not run")
    overrides = []
    for name in sorted(filters):
        # required=false keeps a blanked required filter from aborting the read.
        for key, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
            overrides.extend(["-c", f"filter.{name}.{key}={value}"])
    for name in sorted(drivers):
        for key in ("textconv", "command"):
            overrides.extend(["-c", f"diff.{name}.{key}="])
    return overrides


def git_read(repo, args, log, timeout=20, limit=_OUTPUT_LIMIT):
    git = _trusted_git(repo)
    if git is None:
        log.record(["git", *args], "skipped", "no trusted git was found at a fixed platform path; PATH is not consulted, so git was not run")
        return None
    try:
        overrides = _git_config_overrides(repo)
    except _GitConfigRefused as exc:
        log.record(["git", *args], "skipped", str(exc))
        return None
    # The path is this process's view of the audit root, never a value read from repository config.
    # --work-tree overrides core.worktree. -c pins the same path so config cannot choose another tree.
    resolved_repo = Path(repo).resolve()
    command = [str(git), "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=", "-c", "protocol.allow=never", "--no-optional-locks"]
    for key in _GIT_HELPER_KEYS:
        command.extend(["-c", f"{key}="])
    for key, value in _GIT_FORCED_CONFIG:
        command.extend(["-c", f"{key}={value}"])
    command.extend(overrides)
    for alias in GIT_ALIASES:
        command.extend(["-c", f"alias.{alias}="])
    command.extend(["-c", f"core.worktree={resolved_repo}"])
    args = list(args)
    if args and args[0] in _GIT_DIFF_COMMANDS:
        # Repository config and .gitattributes can name external diff and textconv commands.
        args[1:1] = ["--no-ext-diff", "--no-textconv"]
    command.extend(["--work-tree", str(resolved_repo)])
    command.extend(args)
    env = os.environ.copy()
    for key in ("GIT_EXTERNAL_DIFF", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        env.pop(key, None)
    # Only the repository's own .git was classified; never let discovery climb to a parent repository.
    env["GIT_CEILING_DIRECTORIES"] = str(resolved_repo.parent)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    log.record(command, "started")
    try:
        completed = _run_process(command, repo, env, timeout, limit=limit, text=False)
    except subprocess.TimeoutExpired:
        log.record(command, "timeout", f"timed out after {timeout} seconds; output was discarded")
        return None
    except OutputLimitExceeded:
        log.record(command, "error", "output exceeded the limit; the process was killed and its output discarded")
        return None
    except OSError as exc:
        log.record(command, "error", f"git could not start: {exc.strerror or type(exc).__name__}")
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


def install_analyzer(tool, approve=False, artifact=None, expected_sha256=None, log=None, execute=False, timeout=600, limit=_OUTPUT_LIMIT):
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
    try:
        completed = _run_process(command, None, None, timeout, limit=limit)
    except (OSError, subprocess.TimeoutExpired, OutputLimitExceeded) as exc:
        reason = {subprocess.TimeoutExpired: "timed out", OutputLimitExceeded: "exceeded the output limit"}.get(type(exc), "could not start")
        log.record(command, "error", f"the installer {reason}; it was killed and its output discarded")
        return {"status": "failed", "installed": False, "plan": plan, "exit_code": None, "message": f"the installer {reason}"}
    log.record(command, f"exit {completed.returncode}")
    return {
        "status": "installed" if completed.returncode == 0 else "failed",
        "installed": completed.returncode == 0,
        "plan": plan,
        "exit_code": completed.returncode,
    }
