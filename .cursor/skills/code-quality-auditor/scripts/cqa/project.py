"""Repository initialization and profile management. Discovery does not execute repository code."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from cqa.adapters import discover
from cqa.profiles import explain_profile, resolve_profile
from cqa.security import ExecutionLog, detect_runtime, runtime_probe

ANALYZER_FILES = (
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    "setup.cfg",
    "tox.ini",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "eslint.config.js",
    ".eslintrc",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".semgrep.yml",
    "bandit.yaml",
    "compile_commands.json",
    "CMakeLists.txt",
    "requirements.txt",
    "Pipfile",
    ".clang-tidy",
    ".pre-commit-config.yaml",
)
PRESERVE_KEYS = ("profiles", "exceptions", "thresholds", "policy", "check_overrides", "architecture")


def _runtimes():
    return {
        "python3": shutil.which("python3"),
        "node": shutil.which("node"),
        "clang": shutil.which("clang"),
        "ruff": shutil.which("ruff"),
        "semgrep": shutil.which("semgrep"),
        "pytest": shutil.which("pytest"),
        "eslint": shutil.which("eslint"),
    }


def _configs(root):
    found = []
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        if path.name in ANALYZER_FILES:
            found.append(path.relative_to(root).as_posix())
    return sorted(found)


def discover_repository(root, languages=None, directories=None):
    files, counts = discover(root, languages=languages, directories=directories)
    return {
        "languages": counts,
        "files": len(files),
        "directories": sorted({str(Path(path).parent) for path in files}),
        "runtimes": _runtimes(),
        "analyzer_configs": _configs(root),
        "engine": detect_runtime(),
        "executed_repository_code": False,
    }


def _dump(path, data):
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def init_repository(root, skill_config, approve_write=False, languages=None, directories=None, approve_install=False):
    """Create or refresh project YAML. Init never installs tools and never overwrites user keys without a merge."""
    discovery = discover_repository(root, languages=languages, directories=directories)
    log = ExecutionLog()
    if approve_install:
        log.ignored_overrides.append("approve_install on init does not install anything")
    target = Path(root) / "quality-auditor.yaml"
    if not approve_write:
        log.deny("config-write", "initialization stayed read-only because write approval was not given")
        return {"discovery": discovery, "written": False, "path": str(target), "log": log.denied, "installations": []}
    existing = {}
    if target.exists():
        existing = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    generated = {
        "version": 1,
        "default_profile": existing.get("default_profile", skill_config.get("default_profile", "full")),
        "scope": existing.get("scope", "repository"),
        "languages": sorted(languages or discovery["languages"].keys()),
        "paths": list(directories or []),
        "discovered": {
            "languages": discovery["languages"],
            "analyzer_configs": discovery["analyzer_configs"],
            "runtimes_present": sorted(name for name, path in discovery["runtimes"].items() if path),
        },
        "profiles": skill_config.get("profiles") or {},
        "exceptions": [],
        "thresholds": {},
        "check_overrides": {},
        "architecture": {"layers": []},
    }
    for key in PRESERVE_KEYS:
        if key in existing:
            generated[key] = existing[key]
    if "languages" in existing and languages is None:
        generated["languages"] = existing["languages"]
    _dump(target, generated)
    return {"discovery": discovery, "written": True, "path": str(target), "preserved": [key for key in PRESERVE_KEYS if key in existing], "installations": [], "log": log.ignored_overrides}


def manage_profile(config_path, action, registry, name=None, body=None, approve_write=False):
    path = Path(config_path)
    document = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {"version": 1, "default_profile": "full", "profiles": {}}
    profiles = document.setdefault("profiles", {})
    if action == "list":
        return {"profiles": sorted(profiles)}
    if action == "explain":
        return {"explanation": explain_profile(name, document, registry), "selected": sorted(resolve_profile(name, document, registry)[0])}
    if action in {"create", "edit", "delete"} and not approve_write:
        return {"status": "approval_required", "written": False}
    if action == "delete":
        if name not in profiles:
            raise ValueError(f"missing profile: {name}")
        del profiles[name]
    elif action in {"create", "edit"}:
        profiles[name] = body or {}
        resolve_profile(name, document, registry)
    else:
        raise ValueError(f"unknown profile action: {action}")
    _dump(path, document)
    return {"status": "updated", "written": True, "profiles": sorted(profiles)}


def missing_runtime_plan():
    return runtime_probe(lambda _name: None)
