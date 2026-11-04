"""Install the one skill tree into Cursor, Claude Code, and Codex layouts.

The canonical package stays in the repository. Installation copies that tree, or
links it only where the vendor documents symlink loading. It does not download
analyzers, run them, or approve repository execution.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

import yaml

SKILL_NAME = "code-quality-auditor"
LAYOUTS = {
    "cursor": Path(".cursor") / "skills" / SKILL_NAME,
    "claude": Path(".claude") / "skills" / SKILL_NAME,
    "codex": Path(".agents") / "skills" / SKILL_NAME,
}
_AGENTS = ("cursor", "claude", "codex", "all")
_SCOPES = ("project", "global")
_ALL_ORDER = ("codex", "cursor", "claude")
_APPROVAL_DETAIL = "skill installation needs explicit approval"
_COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc")


def plan_slots(root, agent="cursor", scope="project", destination=None) -> list[dict]:
    """Return planned slots. Do not touch the filesystem.

    agent is cursor|claude|codex|all. scope is project|global.
    For agent all, slots are codex, then cursor, then claude.
    destination is allowed only when agent is a single name, and its
    final component must be code-quality-auditor.
    """
    agent = agent or "cursor"
    scope = scope or "project"
    if agent not in _AGENTS:
        raise ValueError("agent must be cursor, claude, codex, or all")
    if scope not in _SCOPES:
        raise ValueError("scope must be project or global")
    if destination is not None and agent == "all":
        raise ValueError("destination cannot be combined with --agent all")
    if destination is not None:
        dest = _absolute(destination)
        if dest.name != SKILL_NAME:
            raise ValueError("the last path component must be code-quality-auditor")
        return [_slot(agent, scope, dest, link=False, link_target=None)]
    root_path = _absolute(root)
    names = _ALL_ORDER if agent == "all" else (agent,)
    slots = []
    for name in names:
        link = agent == "all" and name == "claude"
        target = root_path / LAYOUTS["codex"] if link else None
        slots.append(_slot(name, scope, root_path / LAYOUTS[name], link=link, link_target=target))
    return slots


def install_agents(root, source, agent="cursor", scope="project", destination=None, approve=False, log=None) -> dict:
    """Copy or link the skill. Return status, installed, path, and destinations."""
    slots = plan_slots(root, agent=agent, scope=scope, destination=destination)
    return _dispatch(slots, source, approve=approve, log=log, operation="install")


def update_agents(root, source, agent="cursor", scope="project", destination=None, approve=False, log=None) -> dict:
    """Same writes as install, but a missing slot is absent and nothing is written."""
    slots = plan_slots(root, agent=agent, scope=scope, destination=destination)
    return _dispatch(slots, source, approve=approve, log=log, operation="update")


def uninstall_agents(root, agent="cursor", scope="project", destination=None, approve=False, log=None) -> dict:
    """Unlink a symlink at the exact slot. rmtree a real directory only when it is this skill."""
    slots = plan_slots(root, agent=agent, scope=scope, destination=destination)
    return _dispatch(slots, None, approve=approve, log=log, operation="uninstall")


def is_our_skill(path) -> bool:
    """True when path is a real directory of this skill.

    Reads only YAML frontmatter. A symlink is not followed; the caller classifies
    the symlink node itself.
    """
    path = Path(path)
    try:
        info = path.lstat()
    except OSError:
        return False
    if not info.st_mode or _is_link(info) or not _is_dir(info):
        return False
    skill_md = path / "SKILL.md"
    auditor = path / "scripts" / "auditor.py"
    if not _regular_file(skill_md) or not _regular_file(auditor):
        return False
    return _frontmatter_name(skill_md) == SKILL_NAME


def _slot(agent, scope, path, link, link_target):
    return {
        "agent": agent,
        "scope": scope,
        "path": Path(path),
        "link": bool(link),
        "link_target": None if link_target is None else Path(link_target),
    }


def _absolute(path) -> Path:
    return Path(os.path.abspath(path))


def _ensure_log(log):
    if log is not None:
        return log
    from cqa.security import ExecutionLog

    return ExecutionLog()


def _is_link(info) -> bool:
    return stat.S_ISLNK(info.st_mode)


def _is_dir(info) -> bool:
    return stat.S_ISDIR(info.st_mode)


def _regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode)


def _frontmatter_name(path: Path):
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read(65536)
    except OSError:
        return None
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    end = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end = index
            break
    if end is None:
        return None
    try:
        data = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    name = data.get("name")
    return name if isinstance(name, str) else None


def _classify(path: Path) -> str:
    """Return missing, ours, or foreign. Do not create or delete anything."""
    path = Path(path)
    try:
        linked = path.is_symlink()
    except OSError:
        return "foreign"
    if linked:
        try:
            target = path.resolve(strict=True)
        except OSError:
            return "foreign"
        return "ours" if is_our_skill(target) else "foreign"
    if not path.exists():
        return "missing"
    if path.is_dir() and is_our_skill(path):
        return "ours"
    return "foreign"


def _same_node(left, right) -> bool:
    try:
        return Path(left).resolve() == Path(right).resolve()
    except OSError:
        return False


def _fingerprint(root: Path) -> bytes:
    root = Path(root)
    if root.is_symlink():
        root = root.resolve(strict=True)
    digest = hashlib.sha256()
    paths = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
        for name in sorted(filenames):
            if name.endswith(".pyc"):
                continue
            paths.append(Path(dirpath) / name)
    for path in paths:
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"link\0")
            digest.update(os.readlink(path).encode())
        else:
            digest.update(b"file\0")
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.digest()


def _same_tree(source, dest) -> bool:
    try:
        return _fingerprint(source) == _fingerprint(dest)
    except OSError:
        return False


def _copy_tree(source, destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, destination, ignore=_COPY_IGNORE, symlinks=False, dirs_exist_ok=False)


def _discard_node(path: Path):
    """Remove path itself. Never rmtree a symlink, or the target would be deleted."""
    if path.is_symlink():
        path.unlink()
        return
    if path.is_dir():
        shutil.rmtree(path)
        return
    if path.exists():
        path.unlink()


def _replace_tree(source, slot: Path):
    """Copy to a sibling temp directory, then swap it in. The source is not the slot."""
    if _same_node(source, slot):
        raise RuntimeError("refusing to replace the live skill source")
    parent = slot.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=".cqa-install-", dir=parent))
    staging = staging_root / SKILL_NAME
    try:
        _copy_tree(source, staging)
        if slot.is_symlink() or slot.exists():
            backup_root = None
            if slot.is_symlink() or not slot.is_dir():
                _discard_node(slot)
            else:
                backup_root = Path(tempfile.mkdtemp(prefix=".cqa-old-", dir=parent))
                backup = backup_root / "old"
                slot.rename(backup)
            try:
                staging.rename(slot)
            except Exception:
                if backup_root is not None and not slot.exists() and not slot.is_symlink():
                    (backup_root / "old").rename(slot)
                raise
            else:
                if backup_root is not None:
                    shutil.rmtree(backup_root)
        else:
            staging.rename(slot)
    finally:
        if staging_root.exists():
            shutil.rmtree(staging_root)


def _link_points_at(path: Path, target: Path) -> bool:
    if not path.is_symlink():
        return False
    try:
        return path.resolve(strict=True) == Path(target).resolve(strict=True)
    except OSError:
        return False


def _place_symlink(path: Path, target: Path):
    """Create a relative symlink. On failure the existing node is left in place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(str(target), str(path.parent))
    temporary = path.parent / f".{path.name}.{os.getpid()}.link"
    if temporary.is_symlink() or temporary.exists():
        temporary.unlink()
    os.symlink(relative, temporary)
    try:
        if path.is_symlink() or path.exists():
            _discard_node(path)
        temporary.rename(path)
    except Exception:
        if not (path.exists() or path.is_symlink()) and temporary.is_symlink():
            temporary.rename(path)
        elif temporary.is_symlink() or temporary.exists():
            temporary.unlink()
        raise


def _succeed(log, method, source, dest, status):
    verb = "symlink" if method == "symlink" else "copy"
    log.approvals.append({"action": "install-skill", "path": str(dest), "approved": True})
    log.record([verb, str(source), str(dest)], status)


def _row(method, status):
    return method, status


def _result(status, slots, rows, installed):
    destinations = []
    for slot, (method, slot_status) in zip(slots, rows):
        destinations.append(
            {
                "agent": slot["agent"],
                "scope": slot["scope"],
                "method": method,
                "status": slot_status,
                "path": str(slot["path"]),
            }
        )
    path = None
    if installed and slots:
        chosen = next((slot for slot in slots if slot["agent"] == "cursor"), slots[0])
        path = str(chosen["path"])
    return {"status": status, "installed": installed, "path": path, "destinations": destinations}


def _blocked_rows(states):
    rows = []
    for state in states:
        if state == "foreign":
            rows.append(_row("none", "refused"))
        elif state == "missing":
            rows.append(_row("none", "absent"))
        else:
            rows.append(_row("none", "unchanged"))
    return rows


def _dispatch(slots, source, approve, log, operation):
    log = _ensure_log(log)
    if not approve:
        log.deny("skill-install", _APPROVAL_DETAIL)
        rows = [_row("none", "approval_required") for _planned in slots]
        return _result("approval_required", slots, rows, installed=False)
    states = [_classify(slot["path"]) for slot in slots]
    if any(state == "foreign" for state in states):
        return _result("refused", slots, _blocked_rows(states), installed=False)
    if operation == "update" and any(state == "missing" for state in states):
        return _result("absent", slots, _blocked_rows(states), installed=False)
    if operation == "uninstall":
        return _uninstall(slots, states)
    return _write(slots, states, Path(source), log)


def _write(slots, states, source: Path, log):
    rows = []
    for slot, state in zip(slots, states):
        if slot["link"]:
            rows.append(_install_link(slot, source, state, log))
        else:
            rows.append(_install_copy(slot, source, state, log))
    statuses = [status for _method, status in rows]
    if "updated" in statuses:
        overall = "updated"
    elif "installed" in statuses:
        overall = "installed"
    else:
        overall = "unchanged"
    return _result(overall, slots, rows, installed=True)


def _install_copy(slot, source: Path, state, log):
    path = slot["path"]
    if _same_node(source, path):
        # This slot is the package being copied. Codex is planned first, so an
        # --agent all install has already copied this tree. Do not delete it.
        method = "symlink" if path.is_symlink() else "copy"
        _succeed(log, method, source, path, "unchanged")
        return _row(method, "unchanged")
    if state == "ours" and _same_tree(source, path):
        method = "symlink" if path.is_symlink() else "copy"
        _succeed(log, method, source, path, "unchanged")
        return _row(method, "unchanged")
    if state == "missing":
        path.parent.mkdir(parents=True, exist_ok=True)
        _copy_tree(source, path)
        _succeed(log, "copy", source, path, "installed")
        return _row("copy", "installed")
    _replace_tree(source, path)
    _succeed(log, "copy", source, path, "updated")
    return _row("copy", "updated")


def _install_link(slot, source: Path, state, log):
    path = slot["path"]
    target = Path(slot["link_target"])
    if _same_node(source, path):
        method = "symlink" if path.is_symlink() else "copy"
        _succeed(log, method, source, path, "unchanged")
        return _row(method, "unchanged")
    if state == "ours" and path.is_symlink() and _link_points_at(path, target) and _same_tree(source, target):
        _succeed(log, "symlink", target, path, "unchanged")
        return _row("symlink", "unchanged")
    if state == "ours" and not path.is_symlink() and _same_tree(source, path):
        _succeed(log, "copy", source, path, "unchanged")
        return _row("copy", "unchanged")
    try:
        _place_symlink(path, target)
    except OSError:
        read_from = target if target.is_dir() else source
        if path.is_symlink() or path.exists():
            _replace_tree(read_from, path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            _copy_tree(read_from, path)
        status = "installed" if state == "missing" else "updated"
        _succeed(log, "copy", read_from, path, status)
        return _row("copy", status)
    status = "installed" if state == "missing" else "updated"
    _succeed(log, "symlink", target, path, status)
    return _row("symlink", status)


def _uninstall(slots, states):
    rows = []
    removed = False
    for slot, state in zip(slots, states):
        if state == "missing":
            rows.append(_row("none", "absent"))
            continue
        path = slot["path"]
        if path.is_symlink():
            path.unlink()
            rows.append(_row("symlink", "removed"))
        else:
            shutil.rmtree(path)
            rows.append(_row("copy", "removed"))
        removed = True
    return _result("removed" if removed else "absent", slots, rows, installed=False)
