"""Audit orchestration. Invocation approvals outrank user YAML; registry defaults are last."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tarfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cqa import ENGINE_VERSION
from cqa.catalog import catalog_validation, load, validate_tools
from cqa.checks import RUNNERS, discover_requirements
from cqa.adapters import discover
from cqa.executor import execute
from cqa.profiles import merge_profiles, resolve_profile
from cqa.reporting import (
    append_history,
    apply_exceptions,
    dedupe_findings,
    assert_known_statuses,
    attach_provenance,
    counts_of,
    decide,
    evaluate_metric,
    recompute_defect_counts,
    write_reports,
)
from cqa.security import ExecutionLog, detect_runtime, git_read

SECURITY_KEYS = {
    "allow_tools",
    "allow_repo_execution",
    "sandbox_confirmed",
    "allow_install",
    "allow_network",
    "allow_write",
}
PRECEDENCE = [
    "explicit invocation overrides",
    "nearest directory quality-auditor.yaml",
    "repository quality-auditor.yaml",
    "resolved profile",
    "skill quality-auditor.yaml",
    "registry defaults (metrics, checks, tools, policy)",
]


class AuditContext:
    def __init__(self, root, files, config, log):
        self.root = Path(root)
        self.files = list(files)
        self.config = config
        self.log = log
        self.analyses = None
        self.graph = None
        self.requirements = None
        self.duplicate_groups = None
        self.texts = {}
        self.lock = threading.RLock()
        self.limitations = []


def _deep_merge(base, override, ignored):
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key in SECURITY_KEYS or key == "execution":
            ignored.append(key)
            continue
        if key == "profiles":
            result["profiles"] = merge_profiles(result.get("profiles") or {}, value or {})
            continue
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value, ignored)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _validate_user(config):
    errors = []
    if not isinstance(config, dict) or "profiles" not in config:
        errors.append("quality-auditor.yaml requires profiles")
    policy = config.get("policy") or {}
    if policy.get("zero_confirmed_violations") is False:
        errors.append("the zero confirmed-violation gate cannot be disabled")
    for rule in config.get("exceptions") or []:
        if not rule.get("justification") or not rule.get("scope"):
            errors.append(f"exception {rule.get('id')} requires justification and scope")
    return errors


def _outside(root, output):
    root = Path(root).resolve()
    output = Path(output).resolve()
    return root != output and root not in output.parents


def _revision(root, log):
    completed = git_read(root, ["rev-parse", "HEAD"], log)
    if completed is None:
        digest = hashlib.sha256()
        for path in sorted(Path(root).rglob("*")):
            if path.is_file() and ".git" not in path.parts:
                digest.update(path.relative_to(root).as_posix().encode())
                digest.update(path.read_bytes()[:100_000])
        return "uncommitted:" + digest.hexdigest()[:16]
    return completed.stdout.decode().strip()


def _materialize_commit(root, revision, log):
    completed = git_read(root, ["archive", "--format=tar", revision], log)
    if completed is None:
        raise ValueError(f"cannot read commit {revision}")
    destination = Path(root).resolve().parent / f".cqa-snapshot-{revision[:12]}"
    if destination.exists():
        return destination
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        archive.extractall(destination, filter="data")
    return destination


def _changed_files(root, baseline, log):
    args = ["diff", "--name-only"]
    if baseline:
        args.append(baseline)
    else:
        args.extend(["HEAD"])
    completed = git_read(root, args, log)
    if completed is None:
        return None
    return {line.strip() for line in completed.stdout.decode().splitlines() if line.strip()}


def _fingerprint_factory(ctx, profile, config_hash):
    file_bytes = []
    for path in ctx.files:
        try:
            file_bytes.append(Path(path).read_bytes())
        except OSError:
            file_bytes.append(b"")

    def fingerprint(task_id):
        digest = hashlib.sha256()
        digest.update(ENGINE_VERSION.encode())
        digest.update(task_id.encode())
        digest.update(profile.encode())
        digest.update(config_hash.encode())
        for blob in file_bytes:
            digest.update(blob)
        return digest.hexdigest()

    return fingerprint


def audit(
    repo,
    *,
    skill_root,
    profile=None,
    output_dir=None,
    history_path=None,
    allow_tools=False,
    allow_repo_execution=False,
    sandbox_confirmed=False,
    allow_install=False,
    allow_network=False,
    allow_write=False,
    scope=None,
    baseline=None,
    commit=None,
    languages=None,
    directories=None,
    invocation=None,
    thresholds=None,
):
    invocation = dict(invocation or {})
    skill_root = Path(skill_root)
    repo = Path(repo).resolve()
    ignored = []
    skill_config = load(skill_root / "quality-auditor.yaml")
    user_config = {}
    user_path = repo / "quality-auditor.yaml"
    if user_path.is_file():
        user_config = load(user_path)
    directory_config = {}
    if directories and len(directories) == 1:
        directory_path = repo / directories[0] / "quality-auditor.yaml"
        if directory_path.is_file():
            directory_config = load(directory_path)
    merged = _deep_merge(skill_config, user_config, ignored)
    merged = _deep_merge(merged, directory_config, ignored)
    if thresholds:
        merged.setdefault("thresholds", {}).update(thresholds)
    if invocation.get("budgets"):
        merged["budgets"] = _deep_merge(merged.get("budgets") or {}, invocation["budgets"], [])
    errors = _validate_user(merged)
    metrics_doc = load(skill_root / "config" / "metrics.yaml")
    checks_doc = load(skill_root / "config" / "checks.yaml")
    tools_doc = load(skill_root / "config" / "tools.yaml")
    policy_doc = load(skill_root / "config" / "policy.yaml")
    errors.extend(catalog_validation(metrics_doc["metrics"], checks_doc["checks"]))
    errors.extend(validate_tools(tools_doc["tools"], checks_doc["checks"]))
    if errors:
        raise ValueError("configuration error: " + "; ".join(errors))

    profile_name = profile or invocation.get("profile") or merged.get("default_profile") or "full"
    selected, trace = resolve_profile(profile_name, merged, checks_doc["checks"])
    disabled = {key for key, value in (merged.get("check_overrides") or {}).items() if isinstance(value, dict) and value.get("enabled") is False}
    selected -= disabled
    profile_body = (merged.get("profiles") or {}).get(profile_name) or {}
    scope = scope or invocation.get("scope") or profile_body.get("scope") or merged.get("scope") or "repository"
    budgets = _deep_merge(merged.get("budgets") or {}, profile_body.get("budgets") or {}, [])

    log = ExecutionLog(
        allow_tools=allow_tools,
        allow_repo_execution=allow_repo_execution,
        sandbox_confirmed=sandbox_confirmed,
        allow_install=allow_install,
        allow_network=allow_network,
        allow_write=allow_write,
    )
    for key in ignored:
        log.ignored_overrides.append(key)
    audit_root = repo
    if commit:
        audit_root = _materialize_commit(repo, commit, log)
    files, language_counts = discover(audit_root, languages=languages, directories=directories)
    scope_error = None
    if scope == "changed":
        changed = _changed_files(repo, baseline, log)
        if changed is None:
            scope_error = "changed scope could not be computed from git, so the run is incomplete"
            files = []
        else:
            files = [path for path in files if path.resolve().relative_to(audit_root).as_posix() in changed]
    if scope == "pull-request" and not invocation.get("base") and not invocation.get("head"):
        if not allow_network:
            scope_error = "pull request data was not fetched because network access was not approved"
            files = []
    elif scope == "pull-request":
        changed = _changed_files(repo, f"{invocation.get('base')}...{invocation.get('head')}", log)
        if changed is None:
            scope_error = "pull request refs are not available locally"
            files = []
        else:
            files = [path for path in files if path.resolve().relative_to(audit_root).as_posix() in changed]

    metrics = copy.deepcopy(metrics_doc["metrics"])
    for metric in metrics:
        override = (merged.get("thresholds") or {}).get(metric["id"])
        if override is not None:
            metric["red_line"]["value"] = override
    metrics_by_id = {metric["id"]: metric for metric in metrics}
    ctx = AuditContext(audit_root, files, merged, log)
    config_hash = hashlib.sha256(json.dumps(merged, sort_keys=True, default=str).encode()).hexdigest()
    started = datetime.now(timezone.utc)
    deadline_seconds = float(budgets.get("time_seconds") or 600)

    def runner(task_id, _evidence):
        return RUNNERS[task_id](ctx)

    import time

    execution = execute(
        selected,
        checks_doc["checks"],
        {task_id: runner for task_id in RUNNERS},
        {},
        {
            "concurrency": int(budgets.get("concurrency") or 1),
            "max_retries": int(budgets.get("max_retries") or 1),
            "retry_backoff_seconds": float(budgets.get("retry_backoff_seconds") or 0),
            "task_timeout_seconds": float(budgets.get("task_timeout_seconds") or 60),
            "cache_dir": invocation.get("cache_dir"),
            "fingerprint": _fingerprint_factory(ctx, profile_name, config_hash),
            "deadline": time.monotonic() + deadline_seconds,
        },
    )
    findings = []
    measurements = {}
    limitations = []
    for task in execution["tasks"]:
        value = task.get("value") or {}
        findings.extend(value.get("findings") or [])
        measurements.update(value.get("measurements") or {})
        limitations.extend(value.get("limitations") or [])
        if not task.get("ok"):
            check = checks_doc["checks"].get(task["task_id"]) or {}
            for metric_id in check.get("metrics") or []:
                measurements.setdefault(
                    metric_id,
                    {"value": None, "applicable": True, "status": "ERROR", "reason": task.get("error") or "task failed"},
                )
    findings = dedupe_findings(findings)
    apply_exceptions(findings, merged.get("exceptions") or [])
    recompute_defect_counts(metrics_by_id, measurements, findings)
    check_for_metric = {}
    for check_id, spec in checks_doc["checks"].items():
        for metric_id in spec["metrics"]:
            check_for_metric[metric_id] = check_id
    metric_results = []
    for metric in metrics:
        check_id = check_for_metric[metric["id"]]
        metric_results.append(evaluate_metric(metric, measurements.get(metric["id"]), check_id in selected and execution["tasks"]))
    # A metric whose check was not selected is skipped. A selected check that did not return the metric stays fail-closed.
    for item in metric_results:
        check_id = check_for_metric[item["metric_id"]]
        if check_id not in selected or check_id in disabled:
            item["status"] = "SKIPPED"
            item["measured_value"] = None
            item["applicable"] = False
            item["reason"] = "check override disabled" if check_id in disabled else "profile exclusion"
    decision, rationale = decide(metric_results)
    if scope_error:
        decision, rationale = "INCOMPLETE", scope_error
    if not execution["ok"] and decision == "PASS":
        decision, rationale = "INCOMPLETE", "A task failed or exhausted its retries."
    repository = {
        "identity": str(repo),
        "name": repo.name,
        "revision": commit or _revision(repo, log),
    }
    missing_provenance = attach_provenance(
        findings,
        {
            "repository": repository["identity"],
            "revision": repository["revision"],
            "profile": profile_name,
            "configuration_hash": config_hash,
        },
    )
    if missing_provenance and decision == "PASS":
        decision, rationale = "INCOMPLETE", "A blocking finding is missing provenance."
    partial = selected != set(checks_doc["checks"])
    scope_note = ""
    if partial:
        scope_note = "PASS means the selected checks passed. It does not mean all 112 metrics were evaluated."
    elif decision == "PASS":
        scope_note = "All registered checks were selected. NOT_APPLICABLE metrics were not treated as passes of inapplicable work."
    counts = counts_of(metric_results, findings)
    skipped = []
    for check_id in checks_doc["checks"]:
        if check_id in disabled:
            skipped.append({"id": check_id, "reason": "check override disabled"})
        elif check_id not in selected:
            skipped.append({"id": check_id, "reason": "profile exclusion"})
    for task in execution["tasks"]:
        if not task.get("ok"):
            reason = task.get("error") or "task failed"
            if "timeout" in reason:
                skipped.append({"id": task["task_id"], "reason": f"blocked or timed out: {reason}"})
    run_id = uuid.uuid4().hex
    report = {
        "engine_version": ENGINE_VERSION,
        "report_schema_version": 1,
        "run_id": run_id,
        "timestamp": started.isoformat(),
        "decision": decision,
        "decision_rationale": rationale,
        "profile": profile_name,
        "profile_scope_note": scope_note,
        "selected_checks": sorted(selected),
        "skipped_checks": skipped,
        "counts": counts,
        "metrics": metric_results,
        "findings": findings,
        "exceptions": merged.get("exceptions") or [],
        "languages": language_counts,
        "graph_completeness": (ctx.graph or {}).get("completeness") if ctx.graph else {},
        "execution": {
            "commands": log.commands,
            "denied": log.denied,
            "approvals": log.approvals,
            "ignored_security_overrides": log.ignored_overrides,
            "tasks": [
                {"task_id": task["task_id"], "ok": task["ok"], "cached": task.get("cached"), "attempts": task.get("attempts"), "error": task.get("error")}
                for task in execution["tasks"]
            ],
            "cache_hits": execution["cache_hits"],
            "runtime": detect_runtime(),
            "limitations": sorted(set(limitations)),
            "platform_limitations": [
                "Windows containment uses CQA_SANDBOX_CMD when sandbox-exec is absent.",
                "External analyzers run only when they are already installed and tool execution is approved.",
            ],
        },
        "configuration_precedence": PRECEDENCE,
        "configuration_hash": config_hash,
        "effective_policy": {
            "zero_confirmed_violations": True,
            "missing_mandatory_evidence": policy_doc.get("missing_mandatory_evidence"),
            "warnings_allow_pass": True,
            "profile_trace": trace,
            "thresholds": {metric["id"]: metric["red_line"] for metric in metrics},
        },
        "repository": repository,
        "reproducibility": {
            "engine_version": ENGINE_VERSION,
            "configuration_hash": config_hash,
            "revision": repository["revision"],
            "profile": profile_name,
        },
    }
    assert_known_statuses(report)
    if output_dir is None:
        output_dir = Path.home() / ".code-quality-auditor" / "reports" / repo.name / run_id
    if not _outside(repo, output_dir) and not invocation.get("allow_in_repo_reports"):
        raise ValueError("reports are written outside the audited repository unless allow_in_repo_reports is set")
    if history_path is None:
        history_path = Path(output_dir) / "history.csv"
    report["reports"] = write_reports(report, output_dir)
    report["history_path"] = str(history_path)
    write_reports(report, output_dir)
    append_history(report, history_path)
    # Requirements discovery is available to callers that want the trace separately.
    report["requirement_count"] = len(discover_requirements(ctx))
    return report
