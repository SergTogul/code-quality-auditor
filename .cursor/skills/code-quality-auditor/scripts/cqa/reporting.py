"""Decisions, JSON/Markdown/HTML reports, and CSV history."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from cqa.catalog import DECISIONS, STATUSES

CSV_COLUMNS = [
    "schema_version",
    "timestamp",
    "repository",
    "commit_sha",
    "profile",
    "metric_id",
    "status",
    "measured_value",
    "threshold",
    "confirmed_violations",
    "unresolved_candidates",
    "exceptions",
    "failed_checks",
    "skipped_checks",
    "unavailable_checks",
    "run_id",
    "report_path",
]
PROVENANCE_FIELDS = (
    "repository",
    "revision",
    "location",
    "line",
    "check_id",
    "metric_ids",
    "tool",
    "profile",
    "configuration_hash",
    "observation",
    "evidence_pointer",
)


def breaches(metric, value):
    red = metric["red_line"]
    op = red["operator"]
    threshold = red["value"]
    if op == "max":
        return value > threshold
    if op == "min":
        return value < threshold
    if op == "eq":
        return value != threshold
    return False


def evaluate_metric(metric, measurement, selected):
    if not selected:
        return {
            "metric_id": metric["id"],
            "status": "SKIPPED",
            "measured_value": None,
            "threshold": metric["red_line"]["value"],
            "applicable": False,
            "applicability": metric["applicability"],
            "evidence_refs": [],
            "kind": metric["kind"],
            "classification": metric["classification"],
            "reason": "profile exclusion",
        }
    measurement = measurement or {}
    explicit = measurement.get("status")
    applicable = measurement.get("applicable", True)
    value = measurement.get("value")
    reason = measurement.get("reason") or ""
    if not applicable and explicit not in STATUSES:
        status = "NOT_APPLICABLE"
    elif explicit in STATUSES:
        status = explicit
    elif value is None:
        status = "UNAVAILABLE" if metric["classification"] == "blocking" else "NOT_APPLICABLE"
        if not reason:
            reason = "no measurement was produced"
    elif breaches(metric, value):
        status = "WARNING" if metric["classification"] == "advisory" else "FAIL"
    else:
        status = "PASS"
    if status not in STATUSES:
        status = "ERROR"
        reason = "illegal status"
    return {
        "metric_id": metric["id"],
        "status": status,
        "measured_value": value,
        "threshold": metric["red_line"]["value"],
        "applicable": applicable and status not in {"SKIPPED", "NOT_APPLICABLE"},
        "applicability": metric["applicability"],
        "evidence_refs": measurement.get("evidence") or [],
        "kind": metric["kind"],
        "classification": metric["classification"],
        "reason": reason,
        "sector": metric["sector"],
        "name": metric["name"],
    }


def decide(metric_results):
    blocking = [item for item in metric_results if item["classification"] == "blocking" and item["status"] != "SKIPPED"]
    if any(item["status"] == "FAIL" for item in blocking):
        return "FAIL", "A blocking metric breached its red line."
    if any(item["status"] in {"UNAVAILABLE", "ERROR", "INCONCLUSIVE"} for item in blocking if item["status"] != "NOT_APPLICABLE"):
        return "INCOMPLETE", "Mandatory evidence is missing or inconclusive, so the run cannot pass."
    return "PASS", "The selected checks have no confirmed blocking breach. Advisory warnings may still be present. This is not a claim about checks that were not selected."


def attach_provenance(findings, context):
    missing = []
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{index:04d}"
        if finding.get("confidence") != "confirmed" or finding.get("classification") != "blocking":
            continue
        provenance = {
            "repository": context["repository"],
            "revision": context["revision"],
            "location": finding.get("file") or "repository",
            "line": finding.get("line"),
            "check_id": finding.get("check_id"),
            "metric_ids": finding.get("metric_ids") or [],
            "tool": finding.get("tool"),
            "profile": context["profile"],
            "configuration_hash": context["configuration_hash"],
            "observation": finding.get("observation"),
            "evidence_pointer": f"report.json#/findings/{finding['id']}",
        }
        finding["provenance"] = provenance
        if any(provenance.get(field) in (None, "", []) for field in PROVENANCE_FIELDS):
            missing.append(finding["id"])
    return missing


def dedupe_findings(findings):
    """Keep one finding when tools report the same metric at the same location."""
    kept = []
    index = {}
    for finding in findings:
        key = (
            finding.get("file"),
            finding.get("line"),
            tuple(finding.get("metric_ids") or []),
            finding.get("observation"),
        )
        if key in index:
            index[key].setdefault("corroboration", []).append(finding.get("tool"))
            continue
        index[key] = finding
        kept.append(finding)
    return kept


def apply_exceptions(findings, exceptions):
    applied = []
    for finding in findings:
        for rule in exceptions or []:
            if rule.get("metric_id") and rule["metric_id"] not in (finding.get("metric_ids") or []):
                continue
            if rule.get("check_id") and rule["check_id"] != finding.get("check_id"):
                continue
            scope = rule.get("scope")
            target = rule.get("file")
            if scope == "file" and target and finding.get("file") != target:
                continue
            if scope == "directory" and target and not str(finding.get("file") or "").startswith(target):
                continue
            finding["confidence"] = "accepted_exception"
            finding["exception_id"] = rule.get("id")
            finding["justification"] = rule.get("justification")
            finding["exception_scope"] = scope
            applied.append({"finding": finding.get("id"), "exception": rule.get("id")})
            break
    return applied


def recompute_defect_counts(metrics_by_id, measurements, findings):
    for metric_id, metric in metrics_by_id.items():
        if metric.get("kind") != "defect_counter":
            continue
        measurement = measurements.get(metric_id)
        if not measurement or not measurement.get("applicable", True):
            continue
        related = [item for item in findings if metric_id in (item.get("metric_ids") or []) and item.get("confidence") == "confirmed"]
        excepted = [item for item in findings if metric_id in (item.get("metric_ids") or []) and item.get("confidence") == "accepted_exception"]
        if related or excepted:
            measurement["value"] = len(related)
            measurement["status"] = None


def counts_of(metric_results, findings):
    return {
        "confirmed_violations": sum(1 for item in findings if item.get("confidence") == "confirmed" and item.get("classification") == "blocking"),
        "unresolved_candidates": sum(1 for item in findings if item.get("confidence") == "candidate"),
        "exceptions": sum(1 for item in findings if item.get("confidence") == "accepted_exception"),
        "failed_checks": len({item["metric_id"] for item in metric_results if item["status"] == "FAIL"}),
        "skipped_checks": len({item["metric_id"] for item in metric_results if item["status"] == "SKIPPED"}),
        "unavailable_checks": len({item["metric_id"] for item in metric_results if item["status"] == "UNAVAILABLE"}),
    }


def render_json(report):
    return json.dumps(report, indent=2, sort_keys=True, default=str)


def render_markdown(report):
    counts = report["counts"]
    lines = [
        f"# Code quality audit: {report['decision']}",
        "",
        report["decision_rationale"],
        "",
        report.get("profile_scope_note") or "",
        "",
        f"Profile: `{report['profile']}`",
        "",
        f"Repository: `{report['repository']['identity']}`",
        "",
        f"Revision: `{report['repository']['revision']}`",
        "",
        "## Counts",
        "",
        f"- Confirmed violations: {counts['confirmed_violations']}",
        f"- Unresolved candidates: {counts['unresolved_candidates']}",
        f"- Exceptions: {counts['exceptions']}",
        f"- Failed checks: {counts['failed_checks']}",
        f"- Skipped checks: {counts['skipped_checks']}",
        f"- Unavailable checks: {counts['unavailable_checks']}",
        "",
        "## Skipped checks",
        "",
    ]
    if report["skipped_checks"]:
        for item in report["skipped_checks"]:
            lines.append(f"- `{item['id']}`: {item['reason']}")
    else:
        lines.append("None.")
    lines.extend(["", "## Metrics", ""])
    for item in report["metrics"]:
        value = "n/a" if item["measured_value"] is None else item["measured_value"]
        lines.append(f"- `{item['metric_id']}` {item['status']} value={value} threshold={item['threshold']} ({item.get('reason') or item['applicability']})")
    lines.extend(["", "## Findings", ""])
    if not report["findings"]:
        lines.append("None.")
    for finding in report["findings"]:
        lines.append(f"### {finding['id']} {finding['confidence']}")
        lines.append("")
        lines.append(finding["observation"])
        lines.append("")
        lines.append(f"Suggested fix (not applied): {finding.get('suggested_fix') or 'none'}")
        if finding.get("rationale"):
            lines.append(f"Rationale: {finding['rationale']}")
        if finding.get("uncertainty"):
            lines.append(f"Uncertainty: {finding['uncertainty']}")
        lines.append(f"Confirmed by tests: {finding.get('confirmed_by_tests')}")
        if finding.get("provenance"):
            lines.append(f"Provenance: `{json.dumps(finding['provenance'], sort_keys=True)}`")
        lines.append("")
    lines.extend(["## Execution", "", "```", json.dumps(report["execution"], indent=2, default=str), "```", ""])
    return "\n".join(lines)


def render_html(report):
    def esc(value):
        return html.escape(str(value), quote=True)

    rows = []
    for item in report["metrics"]:
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(item["metric_id"]),
                esc(item["status"]),
                esc(item["measured_value"]),
                esc(item["threshold"]),
                esc(item.get("reason") or ""),
            )
        )
    findings = []
    for finding in report["findings"]:
        findings.append(
            "<article><h3>{} {}</h3><p>{}</p><p>Suggested fix (not applied): {}</p></article>".format(
                esc(finding["id"]),
                esc(finding["confidence"]),
                esc(finding["observation"]),
                esc(finding.get("suggested_fix") or ""),
            )
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Code quality audit {esc(report['decision'])}</title>
<style>body{{font-family:sans-serif;margin:2rem}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:.3rem}}</style>
</head>
<body>
<h1>{esc(report['decision'])}</h1>
<p>{esc(report['decision_rationale'])}</p>
<p>{esc(report.get('profile_scope_note') or '')}</p>
<p>Profile {esc(report['profile'])}; revision {esc(report['repository']['revision'])}</p>
<h2>Counts</h2>
<ul>
<li>Confirmed violations: {esc(report['counts']['confirmed_violations'])}</li>
<li>Unresolved candidates: {esc(report['counts']['unresolved_candidates'])}</li>
<li>Exceptions: {esc(report['counts']['exceptions'])}</li>
<li>Failed checks: {esc(report['counts']['failed_checks'])}</li>
<li>Skipped checks: {esc(report['counts']['skipped_checks'])}</li>
<li>Unavailable checks: {esc(report['counts']['unavailable_checks'])}</li>
</ul>
<h2>Metrics</h2>
<table><thead><tr><th>Metric</th><th>Status</th><th>Value</th><th>Threshold</th><th>Reason</th></tr></thead><tbody>
{''.join(rows)}
</tbody></table>
<h2>Findings</h2>
{''.join(findings) or '<p>None.</p>'}
</body></html>
"""


def write_reports(report, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "report.json"
    md_path = output / "report.md"
    html_path = output / "report.html"
    json_path.write_text(render_json(report), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}


def append_history(report, history_path):
    path = Path(history_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not path.exists()
    counts = report["counts"]
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        if new_file:
            writer.writeheader()
        for item in report["metrics"]:
            value = "" if item["measured_value"] is None else item["measured_value"]
            writer.writerow(
                {
                    "schema_version": "1.0",
                    "timestamp": report["timestamp"],
                    "repository": report["repository"]["identity"],
                    "commit_sha": report["repository"]["revision"],
                    "profile": report["profile"],
                    "metric_id": item["metric_id"],
                    "status": item["status"],
                    "measured_value": value,
                    "threshold": item["threshold"],
                    "confirmed_violations": counts["confirmed_violations"],
                    "unresolved_candidates": counts["unresolved_candidates"],
                    "exceptions": counts["exceptions"],
                    "failed_checks": counts["failed_checks"],
                    "skipped_checks": counts["skipped_checks"],
                    "unavailable_checks": counts["unavailable_checks"],
                    "run_id": report["run_id"],
                    "report_path": report["reports"]["json"],
                }
            )
    return str(path)


def _rows(history_path):
    with Path(history_path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def compare_history(history_path, baseline_run, current_run, metrics):
    rows = _rows(history_path)
    directions = {item["id"]: item.get("direction", "lower_is_better") for item in metrics}
    base = {row["metric_id"]: row for row in rows if row["run_id"] == baseline_run}
    current = {row["metric_id"]: row for row in rows if row["run_id"] == current_run}
    comparisons = []
    for metric_id in sorted(set(base) | set(current)):
        left = base.get(metric_id)
        right = current.get(metric_id)
        if left is None or right is None or left["measured_value"] == "" or right["measured_value"] == "":
            comparisons.append({"metric_id": metric_id, "comparison": "not_comparable", "regression": False})
            continue
        before = float(left["measured_value"])
        after = float(right["measured_value"])
        direction = directions.get(metric_id, "lower_is_better")
        regression = after > before if direction == "lower_is_better" else after < before
        comparisons.append(
            {
                "metric_id": metric_id,
                "comparison": "regression" if regression else "no_regression",
                "regression": regression,
                "baseline": before,
                "current": after,
            }
        )
    return {
        "baseline": baseline_run,
        "current": current_run,
        "regressions": [item for item in comparisons if item["regression"]],
        "comparisons": comparisons,
    }


def trends(history_path, metric_id):
    points = []
    for row in _rows(history_path):
        if row["metric_id"] != metric_id or row["measured_value"] == "":
            continue
        points.append({"timestamp": row["timestamp"], "run_id": row["run_id"], "value": float(row["measured_value"]), "status": row["status"]})
    return points


def assert_known_statuses(report):
    if report["decision"] not in DECISIONS:
        raise ValueError(f"illegal decision {report['decision']}")
    for item in report["metrics"]:
        if item["status"] not in STATUSES:
            raise ValueError(f"illegal status {item['status']}")
