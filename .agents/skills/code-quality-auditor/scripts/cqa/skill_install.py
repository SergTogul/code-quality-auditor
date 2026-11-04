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
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    _DIR_FLAGS |= os.O_CLOEXEC


class _TreeRefused(Exception):
    """The source tree cannot be copied without following a symlink."""


class _ContainmentError(Exception):
    """The slot is not a real directory under the operator-named root."""


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
        return [_slot(agent, scope, dest, link=False, link_target=None, fixed=True)]
    root_path = _absolute(root)
    names = _ALL_ORDER if agent == "all" else (agent,)
    slots = []
    for name in names:
        link = agent == "all" and name == "claude"
        target = root_path / LAYOUTS["codex"] if link else None
        slots.append(_slot(name, scope, root_path / LAYOUTS[name], link=link, link_target=target, fixed=False))
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


def _slot(agent, scope, path, link, link_target, fixed):
    return {
        "agent": agent,
        "scope": scope,
        "path": Path(path),
        "link": bool(link),
        "link_target": None if link_target is None else Path(link_target),
        "fixed": bool(fixed),
        "root": None,
        "safe": None,
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
    records = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        real_dirs = []
        for name in sorted(dirnames):
            path = current / name
            if path.is_symlink():
                records.append((path.relative_to(root).as_posix(), b"link", os.readlink(path).encode()))
                continue
            if name == "__pycache__":
                continue
            real_dirs.append(name)
        dirnames[:] = real_dirs
        for name in sorted(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                records.append((rel, b"link", os.readlink(path).encode()))
                continue
            if name.endswith(".pyc"):
                continue
            if path.is_file():
                records.append((rel, b"file", path.read_bytes()))
                continue
            records.append((rel, b"other", b""))
    digest = hashlib.sha256()
    for rel, kind, payload in sorted(records):
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(kind)
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.digest()


def _same_tree(source, dest) -> bool:
    try:
        return _fingerprint(source) == _fingerprint(dest)
    except OSError:
        return False


def _inside_root(root: Path, path: Path) -> bool:
    try:
        real = Path(path).resolve()
        real_root = Path(root).resolve()
    except OSError:
        return False
    return real == real_root or real_root in real.parents


def _named_parent_escapes(parent: Path) -> bool:
    """True when a symlink in the destination parent would leave the named directory.

    A first path component such as ``/tmp`` → ``/private/tmp`` is prefix
    canonicalization of the operator-named root and is allowed. A symlink in
    any deeper component is refused, including when that component is the
    parent directory itself.
    """
    parent = _absolute(parent)
    if parent.is_symlink():
        return True
    current = Path(parent.parts[0])
    for part in parent.parts[1:]:
        current = current / part
        try:
            linked = current.is_symlink()
        except OSError:
            return True
        if not linked:
            if current.exists():
                continue
            return False
        if len(current.parts) > 2:
            return True
        try:
            target = current.resolve()
            container = current.parent.resolve()
        except OSError:
            return True
        if target != container and container not in target.parents:
            return True
    return False


def _intermediate_escape(root: Path, slot: Path) -> bool:
    """True when a component between root and the skill directory is unsafe.

    ``root`` is the resolved operator-named directory. Only the final slot
    component may be a symlink. ``lstat`` does not follow that component.
    """
    root = Path(root)
    slot = Path(slot)
    try:
        relative = slot.relative_to(root)
    except ValueError:
        return True
    parts = relative.parts
    if not parts:
        return True
    current = root
    for part in parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return not _inside_root(root, current.parent)
        except OSError:
            return True
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return True
        flags = _DIR_FLAGS
        try:
            fd = os.open(current, flags)
        except OSError:
            return True
        os.close(fd)
    return not _inside_root(root, slot.parent)


def _locate_slot(slot) -> tuple[Path, Path, bool]:
    """Return the resolved containment root, the safe slot path, and whether it escapes."""
    lexical = Path(slot["path"])
    if slot.get("fixed"):
        parent = lexical.parent
        if _named_parent_escapes(parent):
            return parent, lexical, True
        root = parent.resolve()
        safe = root / lexical.name
    else:
        relative = LAYOUTS[slot["agent"]]
        lexical_root = lexical
        for _part in relative.parts:
            lexical_root = lexical_root.parent
        root = lexical_root.resolve()
        safe = root.joinpath(*relative.parts)
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        return root, lexical, True
    return root, safe, _intermediate_escape(root, safe)


def _ensure_real_directory(path: Path):
    """Create a resolved operator root. Its path no longer contains symlink components."""
    if path.is_symlink():
        raise _ContainmentError(path)
    if path.is_dir():
        return
    if path.exists():
        raise _ContainmentError(path)
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise _ContainmentError(path)


def _mkdir_under(root: Path, directory: Path):
    """Create real directories from root through directory. Do not follow symlinks."""
    if directory == root:
        return
    relative = directory.relative_to(root)
    fd = os.open(root, _DIR_FLAGS)
    opened = [fd]
    try:
        for part in relative.parts:
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise _ContainmentError(part) from exc
            opened.append(child)
            fd = child
    finally:
        for handle in reversed(opened):
            os.close(handle)


def _prepare_parent(root: Path, slot: Path):
    if _intermediate_escape(root, slot):
        raise _ContainmentError(slot)
    _ensure_real_directory(root)
    _mkdir_under(root, slot.parent)


def _link_stays_inside(link: Path, source_root: Path) -> bool:
    raw = os.readlink(link)
    candidate = Path(raw) if os.path.isabs(raw) else link.parent / raw
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return False
    root = source_root.resolve()
    return resolved == root or root in resolved.parents


def _assert_tree_copyable(source: Path):
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise _TreeRefused(source)
    _assert_children(source, source.resolve())


def _assert_children(directory: Path, source_root: Path):
    for name in sorted(os.listdir(directory)):
        path = directory / name
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            if not _link_stays_inside(path, source_root):
                raise _TreeRefused(path)
            continue
        if stat.S_ISDIR(info.st_mode):
            if name == "__pycache__":
                continue
            _assert_children(path, source_root)
            continue
        if stat.S_ISREG(info.st_mode):
            continue
        raise _TreeRefused(path)


def _copy_tree(source, destination):
    """Copy source without following symlinks. An outside link refuses the copy."""
    source = Path(source)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    source_root = source.resolve()
    os.mkdir(destination, 0o755)
    try:
        _copy_children(source, destination, source_root)
    except Exception:
        if destination.is_symlink():
            destination.unlink()
        elif destination.exists():
            shutil.rmtree(destination)
        raise


def _copy_children(src: Path, dst: Path, source_root: Path):
    for name in sorted(os.listdir(src)):
        src_child = src / name
        dst_child = dst / name
        info = src_child.lstat()
        if stat.S_ISLNK(info.st_mode):
            if not _link_stays_inside(src_child, source_root):
                raise _TreeRefused(src_child)
            os.symlink(os.readlink(src_child), dst_child)
            continue
        if stat.S_ISDIR(info.st_mode):
            if name == "__pycache__":
                continue
            os.mkdir(dst_child, 0o755)
            _copy_children(src_child, dst_child, source_root)
            continue
        if stat.S_ISREG(info.st_mode):
            if name.endswith(".pyc"):
                continue
            shutil.copy2(src_child, dst_child, follow_symlinks=False)
            continue
        raise _TreeRefused(src_child)


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


def _replace_tree(source, slot: Path, root: Path):
    """Copy to a sibling temp directory, then swap it in. The source is not the slot."""
    if _same_node(source, slot):
        raise RuntimeError("refusing to replace the live skill source")
    _prepare_parent(root, slot)
    parent = slot.parent
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


def _place_symlink(path: Path, target: Path, root: Path):
    """Create a relative symlink. On failure the existing node is left in place."""
    _prepare_parent(root, path)
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
            rows.append(_row("none", "skipped"))
    return rows


def _bind_slots(slots):
    """Attach a resolved root and a safe slot path. Report the lexical path."""
    bound = []
    escaped = False
    for slot in slots:
        root, safe, bad = _locate_slot(slot)
        copied = dict(slot)
        copied["root"] = root
        copied["safe"] = safe
        if bad:
            escaped = True
        bound.append(copied)
    if not escaped:
        safe_by_agent = {slot["agent"]: slot["safe"] for slot in bound}
        for slot in bound:
            if slot["link"]:
                slot["link_target"] = safe_by_agent.get("codex")
    return bound, escaped


def _refused(slots):
    return _result("refused", slots, [_row("none", "refused") for _slot in slots], installed=False)


def _dispatch(slots, source, approve, log, operation):
    log = _ensure_log(log)
    if not approve:
        log.deny("skill-install", _APPROVAL_DETAIL)
        rows = [_row("none", "approval_required") for _planned in slots]
        return _result("approval_required", slots, rows, installed=False)
    slots, escaped = _bind_slots(slots)
    if escaped:
        return _refused(slots)
    if operation != "uninstall":
        try:
            _assert_tree_copyable(Path(source))
        except _TreeRefused:
            return _refused(slots)
    states = [_classify(slot["safe"]) for slot in slots]
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
    path = slot["safe"]
    root = slot["root"]
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
        _prepare_parent(root, path)
        _copy_tree(source, path)
        _succeed(log, "copy", source, path, "installed")
        return _row("copy", "installed")
    _replace_tree(source, path, root)
    _succeed(log, "copy", source, path, "updated")
    return _row("copy", "updated")


def _install_link(slot, source: Path, state, log):
    path = slot["safe"]
    root = slot["root"]
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
        _place_symlink(path, target, root)
    except OSError:
        read_from = target if target.is_dir() and not target.is_symlink() else source
        if path.is_symlink() or path.exists():
            _replace_tree(read_from, path, root)
        else:
            _prepare_parent(root, path)
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
        path = slot["safe"]
        if path.is_symlink():
            path.unlink()
            rows.append(_row("symlink", "removed"))
        else:
            shutil.rmtree(path)
            rows.append(_row("copy", "removed"))
        removed = True
    return _result("removed" if removed else "absent", slots, rows, installed=False)
