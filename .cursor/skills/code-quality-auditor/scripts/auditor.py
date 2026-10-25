#!/usr/bin/env python3
"""Internal entry point for the code-quality-auditor skill.

The host agent invokes this module. It is not the primary user interface.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from cqa.adapters import discover, source_static  # noqa: E402
from cqa.audit import PRECEDENCE, audit  # noqa: E402
from cqa.catalog import catalog_validation, load, render_checks_reference, render_tools_reference  # noqa: E402
from cqa.executor import dag  # noqa: E402
from cqa.profiles import explain_profile as _explain_profile  # noqa: E402
from cqa.profiles import merge_profiles, resolve_profile as _resolve_profile  # noqa: E402
from cqa.project import discover_repository, init_repository, manage_profile  # noqa: E402
from cqa.reporting import compare_history, trends  # noqa: E402
from cqa.security import install_analyzer, install_skill, runtime_probe  # noqa: E402


def _checks():
    return load(HERE / "config" / "checks.yaml")["checks"]


def _metrics():
    return load(HERE / "config" / "metrics.yaml")["metrics"]


def _with_builtin_profiles(conf):
    """Built-in profiles remain available when a caller supplies only a child profile."""
    base = load(HERE / "quality-auditor.yaml").get("profiles") or {}
    supplied = dict(conf or {})
    supplied["profiles"] = merge_profiles(base, supplied.get("profiles") or {})
    return supplied


def resolve_profile(name, conf, registry):
    return _resolve_profile(name, _with_builtin_profiles(conf), registry)


def explain_profile(name, conf, registry):
    return _explain_profile(name, _with_builtin_profiles(conf), registry)


def _build_parser():
    parser = argparse.ArgumentParser(description="Run the code quality auditor for a host agent.")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--repo", required=True)
    audit_parser.add_argument("--profile", default=None)
    audit_parser.add_argument("--out", default=None)
    audit_parser.add_argument("--history", default=None)
    audit_parser.add_argument("--scope", default=None)
    audit_parser.add_argument("--baseline", default=None)
    audit_parser.add_argument("--commit", default=None)
    audit_parser.add_argument("--languages", default="")
    audit_parser.add_argument("--directories", default="")
    audit_parser.add_argument("--allow-tools", action="store_true")
    audit_parser.add_argument("--allow-repo-execution", action="store_true")
    audit_parser.add_argument("--sandbox-confirmed", action="store_true")
    audit_parser.add_argument("--cache-dir", default=None)

    init_parser = sub.add_parser("init")
    init_parser.add_argument("--repo", required=True)
    init_parser.add_argument("--approve-write", action="store_true")
    init_parser.add_argument("--languages", default="")
    init_parser.add_argument("--directories", default="")

    install = sub.add_parser("install")
    install.add_argument("--target", required=True)
    install.add_argument("--approve", action="store_true")

    profiles = sub.add_parser("profiles")
    profiles.add_argument("--config", required=True)
    profiles.add_argument("action", choices=("list", "explain", "create", "edit", "delete"))
    profiles.add_argument("--name", default=None)
    profiles.add_argument("--approve-write", action="store_true")

    sub.add_parser("checks")
    explain = sub.add_parser("explain-profile")
    explain.add_argument("--profile", required=True)
    compare = sub.add_parser("compare")
    compare.add_argument("--history", required=True)
    compare.add_argument("--baseline", required=True)
    compare.add_argument("--current", required=True)
    sub.add_parser("validate")
    sub.add_parser("runtime")
    return parser


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        report = audit(
            args.repo,
            skill_root=HERE,
            profile=args.profile,
            output_dir=args.out,
            history_path=args.history,
            allow_tools=args.allow_tools,
            allow_repo_execution=args.allow_repo_execution,
            sandbox_confirmed=args.sandbox_confirmed,
            scope=args.scope,
            baseline=args.baseline,
            commit=args.commit,
            languages=[item for item in args.languages.split(",") if item] or None,
            directories=[item for item in args.directories.split(",") if item] or None,
            invocation={"cache_dir": args.cache_dir} if args.cache_dir else None,
        )
        print(f"{report['decision']} {report['reports']['json']}")
        return 0 if report["decision"] == "PASS" else 1
    if args.command == "init":
        result = init_repository(
            args.repo,
            load(HERE / "quality-auditor.yaml"),
            approve_write=args.approve_write,
            languages=[item for item in args.languages.split(",") if item] or None,
            directories=[item for item in args.directories.split(",") if item] or None,
        )
        print(result["written"], result["path"])
        return 0
    if args.command == "install":
        result = install_skill(args.target, HERE, approve=args.approve)
        print(result["status"])
        return 0 if result.get("installed") or result["status"] == "approval_required" else 1
    if args.command == "profiles":
        result = manage_profile(args.config, args.action, _checks(), name=args.name, approve_write=args.approve_write)
        print(result.get("explanation") or result)
        return 0
    if args.command == "checks":
        for check_id, spec in _checks().items():
            print(f"{check_id}: {spec['description']}")
        return 0
    if args.command == "explain-profile":
        print(explain_profile(args.profile, load(HERE / "quality-auditor.yaml"), _checks()))
        return 0
    if args.command == "compare":
        print(compare_history(args.history, args.baseline, args.current, _metrics()))
        return 0
    if args.command == "validate":
        metrics = _metrics()
        checks = _checks()
        errors = catalog_validation(metrics, checks)
        if errors:
            print("\n".join(errors))
            return 1
        print(f"valid metrics={len(metrics)} checks={len(checks)}")
        return 0
    if args.command == "runtime":
        print(runtime_probe())
        return 0
    parser.error(args.command)
    return 2


if __name__ == "__main__":
    sys.exit(main())
