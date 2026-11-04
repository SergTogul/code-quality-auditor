"""YAML loading and catalog coverage validation."""

from __future__ import annotations

from pathlib import Path

import yaml

METRIC_FIELDS = (
    "id",
    "sector",
    "name",
    "description",
    "criticality",
    "verifies",
    "calculation",
    "result_range",
    "red_line",
    "evaluation_method",
    "recommended_tools",
    "applicability",
    "evidence_requirements",
    "kind",
    "classification",
)
CHECK_FIELDS = (
    "id",
    "description",
    "metrics",
    "evidence",
    "languages",
    "tools",
    "depends_on",
    "default_enabled",
)
TOOL_FIELDS = (
    "id",
    "purpose",
    "languages",
    "checks",
    "prerequisites",
    "inputs",
    "outputs",
    "version_constraint",
    "cost_class",
    "safety",
)
STATUSES = {
    "PASS",
    "FAIL",
    "WARNING",
    "SKIPPED",
    "UNAVAILABLE",
    "NOT_APPLICABLE",
    "ERROR",
    "INCONCLUSIVE",
}
DECISIONS = {"PASS", "FAIL", "INCOMPLETE"}


def load(path):
    """Load one YAML document. JSON is not an authoritative configuration format."""
    path = Path(path)
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError(f"configuration must be YAML, not {path.suffix or 'an extensionless file'}: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML syntax error in {path}: {exc}") from exc
    if data is None:
        raise ValueError(f"empty YAML document: {path}")
    if not isinstance(data, dict):
        raise ValueError(f"YAML document must be a mapping: {path}")
    return data


def _blank(value):
    return value is None or value == "" or value == [] or value == {}


def catalog_validation(metrics, checks):
    """Return configuration errors. An empty list means the coverage contract holds."""
    errors = []
    if not isinstance(metrics, list):
        return ["metrics catalog must be a list"]
    if not isinstance(checks, dict):
        return ["checks registry must be a mapping of check IDs"]

    by_id = {}
    for index, metric in enumerate(metrics):
        if not isinstance(metric, dict):
            errors.append(f"metric at index {index} is not a mapping")
            continue
        mid = metric.get("id")
        if not mid or not isinstance(mid, str):
            errors.append(f"metric at index {index} is missing id")
            continue
        if mid in by_id:
            errors.append(f"conflicting metric definition: {mid}")
            continue
        by_id[mid] = metric
        for field in METRIC_FIELDS:
            if field not in metric or _blank(metric.get(field)) and field != "red_line":
                if field == "red_line":
                    continue
                errors.append(f"{mid} is missing {field}")
        red = metric.get("red_line")
        if not isinstance(red, dict) or "operator" not in red or "value" not in red:
            errors.append(f"{mid} red_line must define operator and value")
        elif red.get("operator") not in {"max", "min", "eq"}:
            errors.append(f"{mid} red_line operator is unsupported")
        if metric.get("kind") not in {"defect_counter", "quality_measure"}:
            errors.append(f"{mid} kind must distinguish defect counters from quality measures")
        if metric.get("classification") not in {"blocking", "advisory"}:
            errors.append(f"{mid} classification must be blocking or advisory")
        if not isinstance(metric.get("recommended_tools"), list):
            errors.append(f"{mid} recommended_tools must be a list")

    referenced = set()
    for key, check in checks.items():
        if not isinstance(check, dict):
            errors.append(f"check {key} is not a mapping")
            continue
        if check.get("id") != key:
            errors.append(f"check key {key} conflicts with id {check.get('id')}")
        for field in CHECK_FIELDS:
            if field not in check:
                errors.append(f"check {key} is missing {field}")
        metric_ids = check.get("metrics") or []
        if not isinstance(metric_ids, list) or not metric_ids:
            errors.append(f"check {key} does not evaluate any metric")
        seen = set()
        for mid in metric_ids:
            if mid in seen:
                errors.append(f"check {key} repeats metric {mid}")
            seen.add(mid)
            if mid not in by_id:
                errors.append(f"check {key} references unknown metric {mid}")
            else:
                referenced.add(mid)
        evidence = check.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"check {key} has no evidence source")
        languages = check.get("languages")
        if not isinstance(languages, list) or not languages:
            errors.append(f"check {key} has no language applicability")
        if not isinstance(check.get("tools"), list):
            errors.append(f"check {key} tools must be a list")
        if not isinstance(check.get("depends_on"), list):
            errors.append(f"check {key} depends_on must be a list")
        else:
            for dep in check["depends_on"]:
                if dep not in checks:
                    errors.append(f"check {key} depends on unknown check {dep}")
        if check.get("default_enabled") is not True:
            errors.append(f"check {key} must be enabled by default")

    for mid, metric in by_id.items():
        if mid not in referenced:
            errors.append(f"orphan metric {mid} has no check")
        if _blank(metric.get("applicability")):
            errors.append(f"{mid} has no applicability rule")
        if _blank(metric.get("evaluation_method")):
            errors.append(f"{mid} has no evaluation procedure")
    return errors


def validate_tools(tools, checks):
    errors = []
    if not isinstance(tools, dict):
        return ["tools registry must be a mapping"]
    for key, tool in tools.items():
        if not isinstance(tool, dict):
            errors.append(f"tool {key} is not a mapping")
            continue
        if tool.get("id") != key:
            errors.append(f"tool key {key} conflicts with id {tool.get('id')}")
        for field in TOOL_FIELDS:
            if field not in tool or tool.get(field) in (None, ""):
                errors.append(f"tool {key} is missing {field}")
            if field == "checks" and not isinstance(tool.get("checks"), list):
                errors.append(f"tool {key} checks must be a list")
        for cid in tool.get("checks") or []:
            if cid not in checks:
                errors.append(f"tool {key} references unknown check {cid}")
    known = set(tools)
    for cid, check in checks.items():
        for tid in check.get("tools") or []:
            if tid not in known:
                errors.append(f"check {cid} references unknown tool {tid}")
    return errors


def render_checks_reference(checks):
    lines = ["# Checks", "", "Generated from `config/checks.yaml`. Do not edit by hand.", ""]
    items = checks["checks"] if "checks" in checks else checks
    for cid, spec in items.items():
        lines.extend(
            [
                f"## {cid}",
                "",
                str(spec["description"]),
                "",
                "Metrics: " + ", ".join(f"`{mid}`" for mid in spec["metrics"]),
                "",
                "Evidence: " + ", ".join(spec["evidence"]),
                "",
                "Languages: " + ", ".join(spec["languages"]),
                "",
                "Tools: " + ", ".join(f"`{tid}`" for tid in spec["tools"]),
                "",
                "Depends on: " + ", ".join(f"`{dep}`" for dep in (spec["depends_on"] or ["none"])),
                "",
            ]
        )
    return "\n".join(lines)


def render_tools_reference(tools):
    lines = [
        "# Tools by purpose and language",
        "",
        "Generated from `config/tools.yaml`. Registry entries do not authorize installation or execution.",
        "",
    ]
    items = tools["tools"] if "tools" in tools else tools
    for tid, spec in items.items():
        checks = spec.get("checks") or []
        lines.extend(
            [
                f"## {tid}",
                "",
                str(spec["purpose"]),
                "",
                "Languages: " + ", ".join(spec["languages"]),
                "",
                "Checks: " + (", ".join(f"`{cid}`" for cid in checks) if checks else "none"),
                "",
                "Prerequisites: " + "; ".join(spec["prerequisites"]),
                "",
                f"Input: {spec['inputs']}",
                "",
                f"Output: {spec['outputs']}",
                "",
                f"Version constraint: `{spec['version_constraint']}`",
                "",
                f"Cost class: {spec['cost_class']}",
                "",
                f"Safety: {spec['safety']}",
                "",
            ]
        )
    return "\n".join(lines)
