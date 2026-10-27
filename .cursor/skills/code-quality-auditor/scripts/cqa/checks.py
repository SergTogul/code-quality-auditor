"""Check runners. Each selected check returns findings and per-metric measurements."""

from __future__ import annotations

import ast
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import zipfile
from collections import Counter
from contextlib import nullcontext
from pathlib import Path
from xml.etree import ElementTree as ET

from cqa import ENGINE_VERSION
from cqa.adapters import _scan_tokens, analyze_path
from cqa.security import run_contained, run_tool
from cqa.duplication import apply_justifications, exact_duplicates, semantic_candidates, structural_duplicates, token_duplicates
from cqa.graph import build_graph

TOOL = {"name": "cqa-builtin", "version": ENGINE_VERSION}
SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
)
CREDENTIAL = re.compile(r"(?i)\b(password|passwd|secret|api_key|apikey|token)\b\s*[:=]\s*['\"`]([^'\"`]{12,})['\"`]")
PLACEHOLDERS = {"password", "secret", "changeme", "example", "your-password", "todo", "redacted", "dummy", "placeholder"}
SINK_PATTERNS = (
    ("eval", re.compile(r"(?<![\w.])eval\s*\("), "SEC-003"),
    ("exec", re.compile(r"(?<![\w.])exec\s*\("), "SEC-003"),
    ("shell", re.compile(r"shell\s*=\s*True"), "SEC-003"),
    ("os.system", re.compile(r"os\.system\s*\("), "SEC-003"),
    ("pickle", re.compile(r"pickle\.loads?\s*\("), "SEC-008"),
    ("yaml.load", re.compile(r"yaml\.load\s*\("), "SEC-008"),
    ("yaml.unsafe_load", re.compile(r"yaml\.unsafe_load\s*\("), "SEC-008"),
    ("marshal", re.compile(r"marshal\.loads?\s*\("), "SEC-008"),
    ("dill", re.compile(r"dill\.loads?\s*\("), "SEC-008"),
    ("cloudpickle", re.compile(r"cloudpickle\.loads?\s*\("), "SEC-008"),
    ("unserialize", re.compile(r"(?<![\w])unserialize\s*\("), "SEC-008"),
    ("md5", re.compile(r"hashlib\.md5\s*\("), "SEC-011"),
    ("sha1", re.compile(r"hashlib\.sha1\s*\("), "SEC-011"),
    ("createHash-md5", re.compile(r"createHash\s*\(\s*['\"]md5['\"]", re.I), "SEC-011"),
    ("createHash-sha1", re.compile(r"createHash\s*\(\s*['\"]sha1['\"]", re.I), "SEC-011"),
    ("evp-md5", re.compile(r"\bEVP_md5\s*\("), "SEC-011"),
    ("evp-sha1", re.compile(r"\bEVP_sha1\s*\("), "SEC-011"),
    ("static-iv", re.compile(r"createCipheriv\s*\(\s*['\"][^'\"]+['\"]\s*,\s*[^,\n]+,\s*['\"][^'\"]+['\"]"), "SEC-011"),
    ("aes-static-iv", re.compile(r"AES\.new\([^)]*\biv\s*=\s*b?['\"][^'\"]+['\"]"), "SEC-011"),
    ("verify-false", re.compile(r"verify\s*=\s*False"), "SEC-006"),
)
HEADING = re.compile(r"^(#{1,6})\s+([A-Z][A-Z0-9]*-\d+|\d+\.\d+(?:\.\d+)*)\b\s*(.*)$")
ID_LINE = re.compile(r"^([A-Z][A-Z0-9]*-\d+)\s*[:\-]\s*(.*)$")
QUANT_WORD = re.compile(r"\b(VaR|DV01|Expected Shortfall|value_at_risk|expected_shortfall)\b")


def _measure(value=None, applicable=True, status=None, reason="", evidence=None):
    return {"value": value, "applicable": applicable, "status": status, "reason": reason, "evidence": evidence or []}


def _finding(path, line, check, metrics, observation, suggestion, confidence="confirmed", classification="blocking", **extra):
    return {
        "file": path,
        "line": line,
        "check_id": check,
        "metric_ids": list(metrics),
        "observation": observation,
        "explanation": extra.get("explanation", observation),
        "suggested_fix": suggestion,
        "fix_applied": False,
        "confidence": confidence,
        "classification": classification,
        "tool": dict(TOOL),
        "rationale": extra.get("rationale", ""),
        "sources": extra.get("sources", [path] if path else []),
        "uncertainty": extra.get("uncertainty", ""),
        "confirmed_by_tests": extra.get("confirmed_by_tests", False),
    }


def _text(ctx, path):
    cached = ctx.texts.get(path)
    if cached is not None:
        return cached
    try:
        value = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        value = ""
    ctx.texts[path] = value
    return value


def _locked(ctx):
    lock = getattr(ctx, "lock", None)
    return lock if lock is not None else nullcontext()


def ensure_analyses(ctx):
    with _locked(ctx):
        if ctx.analyses is None:
            ctx.analyses = [analyze_path(ctx.root, path) for path in ctx.files]
        return ctx.analyses


def ensure_graph(ctx):
    with _locked(ctx):
        if ctx.analyses is None:
            ctx.analyses = [analyze_path(ctx.root, path) for path in ctx.files]
        if ctx.graph is None:
            ctx.graph = build_graph(ctx.analyses)
        return ctx.graph


def _result(findings, measurements, limitations=None):
    return {"findings": findings, "measurements": measurements, "limitations": limitations or []}


_CLANG_DIAGNOSTIC = re.compile(r"^(?P<file>.+?):(?P<line>\d+):\d+:\s+(?:fatal )?error:\s+(?P<message>.+)$")
_CLANG_SYNTAX = re.compile(r"expected|extraneous|unterminated|stray '|invalid suffix", re.I)
_CLANG_IGNORE = re.compile(r"file not found|undeclared|unknown type|no member named|no type named", re.I)


def run_syntax_static(ctx):
    analyses = ensure_analyses(ctx)
    findings = []
    for analysis in analyses:
        for error in analysis["syntax_errors"]:
            findings.append(
                _finding(
                    analysis["path"],
                    error["line"],
                    "syntax_static",
                    ["REL-004"],
                    f"syntax error: {error['message']}",
                    "Correct the syntax so the file parses.",
                )
            )
    clang_findings, clang_limits = _clang_syntax(ctx, analyses)
    seen = {(item["file"], item["line"]) for item in findings}
    for item in clang_findings:
        key = (item["file"], item["line"])
        if key not in seen:
            findings.append(item)
            seen.add(key)
    applicable = bool(analyses)
    return _result(
        findings,
        {"REL-004": _measure(len(findings) if applicable else None, applicable, reason="" if applicable else "no supported source files")},
        [limit for analysis in analyses for limit in analysis["limits"]] + clang_limits,
    )


def _clang_syntax(ctx, analyses):
    """Confirmed C++ parse errors from clang. Semantic and missing-include diagnostics are not syntax failures."""
    log = getattr(ctx, "log", None)
    if log is None or not log.allow_tools:
        return [], []
    paths = [analysis["path"] for analysis in analyses if Path(analysis["path"]).suffix.lower() in {".cpp", ".cc", ".cxx"}]
    if not paths:
        return [], []
    clang = shutil.which("clang")
    if clang is None:
        return [], ["clang syntax checking was approved but clang is not installed"]
    findings = []
    limitations = []
    ignored = 0
    for relative in paths:
        try:
            completed = run_tool(
                [clang, "-fsyntax-only", "-fno-color-diagnostics", "-Wno-everything", relative],
                cwd=str(ctx.root),
                log=log,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            limitations.append(f"clang syntax checking did not finish for {relative}: {exc}")
            continue
        for line in (completed.stderr or "").splitlines():
            match = _CLANG_DIAGNOSTIC.match(line.strip())
            if not match:
                continue
            message = match.group("message")
            if _CLANG_IGNORE.search(message) or not _CLANG_SYNTAX.search(message):
                ignored += 1
                continue
            findings.append(
                _finding(
                    relative,
                    int(match.group("line")),
                    "syntax_static",
                    ["REL-004"],
                    f"syntax error: clang: {message}",
                    "Correct the syntax so the file parses.",
                )
            )
    if ignored:
        limitations.append("clang reported diagnostics that are not confirmed syntax errors; those were not counted")
    return findings, limitations


def run_symbol_index(ctx):
    graph = ensure_graph(ctx)
    completeness = graph["completeness"]
    analyses = ctx.analyses
    applicable = bool(analyses)
    unresolved = completeness["unresolved_edges"]
    dynamic = completeness["dynamic_sites"]
    coverage = completeness["entry_point_coverage"]
    indexed_ratio = 100.0 * completeness["indexed_files"] / completeness["discovered_files"] if completeness["discovered_files"] else None
    return _result(
        [],
        {
            "GRAPH-005": _measure(unresolved if applicable else None, applicable),
            "GRAPH-006": _measure(coverage if applicable else None, applicable, reason="entry-point conventions were applied"),
            "GRAPH-007": _measure(indexed_ratio, applicable),
            "GRAPH-008": _measure(dynamic if applicable else None, applicable),
        },
        completeness["limits"],
    )


def _dead_measurement(items, applicable, can_confirm, label):
    if not applicable:
        return _measure(None, False, reason=f"no {label} in scope")
    confirmed = [item for item in items if item.get("confirmed")]
    candidates = [item for item in items if not item.get("confirmed")]
    if confirmed:
        return _measure(len(confirmed), True, evidence=[item["file"] for item in confirmed])
    if not can_confirm or candidates:
        return _measure(0, True, status="INCONCLUSIVE", reason="unresolved or dynamic references prevent a dead-code confirmation", evidence=[item["file"] for item in candidates])
    return _measure(0, True)


def run_dead_code(ctx):
    graph = ensure_graph(ctx)
    analyses = ctx.analyses
    can_confirm = graph["completeness"]["can_confirm_dead_code"]
    findings = []
    for collection, metric, kind in (
        (graph["dead_functions"], "GRAPH-001", "function"),
        (graph["dead_classes"], "GRAPH-002", "class"),
        (graph["dead_modules"], "GRAPH-003", "module"),
        (graph["dead_branches"], "GRAPH-004", "branch"),
    ):
        for item in collection:
            confirmed = item.get("confirmed", False)
            findings.append(
                _finding(
                    item.get("file"),
                    item.get("line") or item.get("symbol", {}).get("line") or 1,
                    "dead_code",
                    [metric],
                    item.get("reason") or item.get("message") or f"candidate dead {kind}",
                    f"Remove the unused {kind} or reference it from an entry point.",
                    confidence="confirmed" if confirmed else "candidate",
                    classification="blocking" if confirmed else "advisory",
                    uncertainty="" if confirmed else item.get("reason", "uncertain reachability"),
                    rationale=item.get("reason", ""),
                )
            )
    has_functions = any(symbol["kind"] == "function" for analysis in analyses for symbol in analysis["symbols"])
    has_classes = any(symbol["kind"] == "class" for analysis in analyses for symbol in analysis["symbols"])
    return _result(
        findings,
        {
            "GRAPH-001": _dead_measurement(graph["dead_functions"], has_functions, can_confirm, "functions"),
            "GRAPH-002": _dead_measurement(graph["dead_classes"], has_classes, can_confirm, "classes"),
            "GRAPH-003": _dead_measurement(graph["dead_modules"], len(analyses) > 1, can_confirm, "modules"),
            "GRAPH-004": _measure(
                len(graph["dead_branches"]) if analyses else None,
                bool(analyses),
            ),
        },
    )


def _public_symbol(symbol):
    name = symbol.get("name") or ""
    return bool(name) and not name.startswith("_") and not symbol.get("private")


def _naming_violations(analyses, findings):
    snake = re.compile(r"^[a-z][a-z0-9_]*$")
    camel = re.compile(r"^[a-z][a-zA-Z0-9]*$")
    pascal = re.compile(r"^[A-Z][A-Za-z0-9]*$")
    count = 0
    for analysis in analyses:
        language = analysis.get("language")
        for symbol in analysis["symbols"]:
            if not _public_symbol(symbol):
                continue
            name = symbol["name"]
            if symbol["kind"] == "class":
                ok = pascal.match(name) is not None
            elif language == "python":
                ok = snake.match(name) is not None
            elif language in {"javascript", "typescript"}:
                ok = camel.match(name) is not None
            elif language == "cpp":
                ok = snake.match(name) is not None or camel.match(name) is not None
            else:
                continue
            if ok:
                continue
            count += 1
            findings.append(
                _finding(
                    analysis["path"],
                    symbol["line"],
                    "clean_code",
                    ["CC-001"],
                    f"{name} breaks the {language} naming convention",
                    "Rename it to the language convention.",
                    classification="advisory",
                    confidence="confirmed",
                )
            )
    return count


def _max_symbol(analyses, field):
    values = [symbol.get(field) or 0 for analysis in analyses for symbol in analysis["symbols"] if symbol["kind"] != "class"]
    return max(values) if values else 0


def _trivial_number(value):
    return value in {0, 1, 2, -1, 0.0, 1.0, 2.0, -1.0}


def _literal_number(text):
    try:
        if any(mark in text for mark in ".eE"):
            return float(text)
        return int(text, 0)
    except ValueError:
        return None


def _magic_python(tree):
    found = []

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node):
            return

        def visit_AnnAssign(self, node):
            return

        def visit_AugAssign(self, node):
            return

        def visit_FunctionDef(self, node):
            for statement in node.body:
                self.visit(statement)
            for decorator in node.decorator_list:
                self.visit(decorator)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node):
            self.visit(node.body)

        def visit_Constant(self, node):
            if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
                return
            if _trivial_number(node.value):
                return
            found.append((node.lineno, node.value))

        def visit_UnaryOp(self, node):
            if isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and node.operand.value == 1:
                return
            self.generic_visit(node)

    Visitor().visit(tree)
    return found


def _magic_script(text):
    tokens, _error, _comments = _scan_tokens(text)
    found = []
    assigned = False
    previous = None
    for kind, value, line in tokens:
        if kind == "op" and value in {";", "{", "}"}:
            assigned = False
            previous = value
            continue
        if kind == "sym" and value == "=":
            if previous not in {"=", "!", "<", ">"}:
                assigned = True
            previous = "="
            continue
        if kind == "num" and not assigned:
            number = _literal_number(value)
            if number is not None and not _trivial_number(number):
                found.append((line, number))
        previous = value if kind == "sym" else None
    return found


def _magic_literals(ctx, analyses):
    found = []
    for analysis in analyses:
        if _is_test_path(analysis["path"]):
            continue
        text = _text(ctx, Path(ctx.root) / analysis["path"])
        if analysis.get("language") == "python":
            try:
                sites = _magic_python(ast.parse(text))
            except SyntaxError:
                continue
        else:
            sites = _magic_script(text)
        found.extend(f"{analysis['path']}:{line}:{value}" for line, value in sites)
    return len(found), found


def run_clean_code(ctx):
    analyses = ensure_analyses(ctx)
    findings = []
    if not analyses:
        return _result([], {f"CC-{index:03d}": _measure(None, False, reason="no supported source") for index in range(1, 15)})
    naming = _naming_violations(analyses, findings)
    unused_imports = 0
    unused_locals, python_functions = _unused_python_locals(ctx)
    for item in unused_locals:
        findings.append(
            _finding(
                item["file"],
                item["line"],
                "clean_code",
                ["CC-010"],
                f"{item['name']} is assigned and never used",
                "Remove the assignment or use the value.",
                classification="advisory",
                confidence="confirmed",
            )
        )
    for analysis in analyses:
        if analysis["language"] != "python":
            continue
        text = _text(ctx, ctx.root / analysis["path"])
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    local = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                    if local != "*":
                        imported.append((local, node.lineno))
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
        for local, line in imported:
            if local in used:
                continue
            unused_imports += 1
            findings.append(
                _finding(
                    analysis["path"],
                    line,
                    "clean_code",
                    ["CC-009"],
                    f"{local} is imported and never used",
                    "Remove the unused import.",
                    classification="advisory",
                    confidence="candidate",
                )
            )
    for analysis in analyses:
        if analysis.get("language") not in {"javascript", "typescript"}:
            continue
        for item in analysis.get("imports") or []:
            for binding in item.get("bindings") or []:
                if not binding.get("unused"):
                    continue
                unused_imports += 1
                findings.append(
                    _finding(
                        analysis["path"],
                        item["line"],
                        "clean_code",
                        ["CC-009"],
                        f"{binding['local']} is imported and never used",
                        "Remove the unused import.",
                        classification="advisory",
                        confidence="candidate",
                    )
                )
    long_files = max((analysis["line_count"] for analysis in analyses), default=0)

    def disagreeing(key):
        present = [(analysis["path"], analysis["style"].get(key)) for analysis in analyses if analysis["style"].get(key)]
        if len(present) < 2:
            return set()
        majority = Counter(value for _path, value in present).most_common(1)[0][0]
        return {path for path, value in present if value != majority}

    inconsistent_files = disagreeing("indent_kind") | disagreeing("quote_kind") | disagreeing("trailing")
    long_lines = sum(analysis["style"]["long_lines"] for analysis in analyses)
    mixed = sum(analysis["style"]["mixed_indent"] for analysis in analyses)
    commented_blocks = []
    for analysis in analyses:
        text = _text(ctx, Path(ctx.root) / analysis["path"])
        commented_blocks.extend(_commented_code_blocks(analysis["path"], text, analysis.get("language")))
    for block in commented_blocks:
        findings.append(
            _finding(
                block["file"],
                block["line"],
                "clean_code",
                ["CC-014"],
                f"commented-out code from line {block['line']} through {block['end']}",
                "Delete the commented-out block or restore it as real code.",
                classification="advisory",
                confidence="candidate",
            )
        )
    magic, magic_evidence = _magic_literals(ctx, analyses)
    measurements = {
        "CC-001": _measure(naming),
        "CC-002": _measure(_max_symbol(analyses, "end_line") and max((symbol["end_line"] - symbol["line"] + 1 for analysis in analyses for symbol in analysis["symbols"] if symbol["kind"] != "class"), default=0)),
        "CC-003": _measure(long_files),
        "CC-004": _measure(_max_symbol(analyses, "complexity")),
        "CC-005": _measure(_max_symbol(analyses, "cognitive")),
        "CC-006": _measure(_max_symbol(analyses, "nesting")),
        "CC-007": _measure(_max_symbol(analyses, "params")),
        "CC-008": _measure(len(inconsistent_files), evidence=sorted(inconsistent_files)),
        "CC-009": _measure(unused_imports),
        "CC-010": _measure(
            len(unused_locals) if python_functions else None,
            python_functions,
            reason="" if python_functions else "unused-variable proof is limited to Python assignments",
            evidence=[f"{item['file']}:{item['line']}:{item['name']}" for item in unused_locals],
        ),
        "CC-011": _measure(magic, evidence=magic_evidence),
        "CC-012": _boolean_chain(ctx),
        "CC-013": _measure(long_lines + mixed),
        "CC-014": _measure(len(commented_blocks), evidence=[f"{item['file']}:{item['line']}" for item in commented_blocks]),
    }
    return _result(findings, measurements)


def run_architecture(ctx):
    graph = ensure_graph(ctx)
    analyses = ctx.analyses
    findings = []
    cycles = _import_cycles(analyses)
    participants = []
    for cycle in cycles:
        for node in cycle:
            if node in participants:
                continue
            participants.append(node)
            findings.append(_finding(node, 1, "architecture", ["ARCH-012"], f"import cycle: {' -> '.join(cycle)}", "Break the cycle so dependencies point one way."))
    layer_violations = _layer_violations(ctx, analyses)
    for item in layer_violations:
        findings.append(_finding(item["file"], item["line"], "architecture", ["ARCH-011", "ARCH-005"], item["observation"], "Change the import so it follows the layer allow-list."))
    methods = [len([symbol for symbol in analysis["symbols"] if symbol["kind"] == "method" and symbol.get("parent") == item["name"]]) for analysis in analyses for item in analysis["symbols"] if item["kind"] == "class"]
    fanout = []
    for analysis in analyses:
        fanout.append(len(analysis["imports"]))
    applicable = bool(analyses)
    layers_configured = bool((ctx.config.get("architecture") or {}).get("layers"))
    arity_gaps, inheritance_visible = _inheritance_arity_gaps(ctx)
    cohesion_gaps, cohesion_applicable = _low_cohesion_classes(ctx)
    return _result(
        findings,
        {
            "ARCH-001": _measure(max(methods) if methods else 0, applicable),
            "ARCH-002": _extension_violations(ctx, analyses),
            "ARCH-003": _measure(arity_gaps, inheritance_visible, reason="" if inheritance_visible else "no visible class inheritance"),
            "ARCH-004": _interface_width(ctx),
            "ARCH-005": _measure(len(layer_violations), layers_configured, reason="" if layers_configured else "no layer rules are configured"),
            "ARCH-006": _measure(sum(1 for analysis in analyses for symbol in analysis["symbols"] if symbol["complexity"] > 10), applicable),
            "ARCH-007": _measure(len([item for item in graph["dead_functions"] if item.get("confirmed")]), bool(graph["entry_points"])),
            "ARCH-008": _measure(max(fanout) if fanout else 0, applicable),
            "ARCH-009": _measure(cohesion_gaps, cohesion_applicable, reason="" if cohesion_applicable else "no Python class with two methods"),
            "ARCH-010": _measure(_forwarding_wrappers(ctx), applicable),
            "ARCH-011": _measure(len(layer_violations), layers_configured, reason="" if layers_configured else "no layer rules are configured"),
            "ARCH-012": _measure(len(participants), applicable),
        },
    )


def _iter_function_locals(node):
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield child
        yield from _iter_function_locals(child)


def _stored_names(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
        return [node.id]
    names = []
    for child in ast.iter_child_nodes(node):
        names.extend(_stored_names(child))
    return names


def _unused_in_function(path, node):
    non_local = set()
    stored = {}
    loaded = set()
    for child in _iter_function_locals(node):
        if isinstance(child, (ast.Global, ast.Nonlocal)):
            non_local.update(child.names)
        if isinstance(child, (ast.AugAssign, ast.NamedExpr)):
            loaded.update(_stored_names(child.target))
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            stored.setdefault(child.id, child.lineno)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            loaded.add(child.id)
    return [
        {"file": path, "line": line, "name": name}
        for name, line in stored.items()
        if name not in loaded and name not in non_local and not name.startswith("_")
    ]


def _unused_python_locals(ctx):
    found = []
    saw_function = False
    for analysis in ensure_analyses(ctx):
        tree = _python_tree(ctx, analysis)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            saw_function = True
            found.extend(_unused_in_function(analysis["path"], node))
    return found, saw_function


def _python_tree(ctx, analysis):
    if analysis.get("language") != "python":
        return None
    try:
        return ast.parse(_text(ctx, Path(ctx.root) / analysis["path"]))
    except SyntaxError:
        return None


def _required_positional(node):
    positional = list(node.args.args)
    if positional and positional[0].arg in {"self", "cls"}:
        positional = positional[1:]
    return max(0, len(positional) - len(node.args.defaults or []))


def _required_script_params(tokens, name, line):
    for index, (kind, text, token_line) in enumerate(tokens):
        if kind != "id" or text != name or token_line != line:
            continue
        if index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
            continue
        depth = 0
        segment_named = False
        segment_optional = False
        required = 0
        for cursor in range(index + 1, len(tokens)):
            token_kind, token_text, _token_line = tokens[cursor]
            if token_kind == "op" and token_text == "(":
                depth += 1
            elif token_kind == "op" and token_text == ")":
                depth -= 1
                if depth == 0:
                    if segment_named and not segment_optional:
                        required += 1
                    return required
            elif depth == 1 and token_kind == "sym" and token_text == ",":
                if segment_named and not segment_optional:
                    required += 1
                segment_named = False
                segment_optional = False
            elif depth == 1 and token_kind == "sym" and token_text == "=":
                segment_optional = True
            elif depth == 1 and token_kind == "id":
                segment_named = True
        return None
    return None


def _script_arity_gaps(analysis, text):
    tokens, _error, _comments = _scan_tokens(text)
    methods = {}
    for symbol in analysis["symbols"]:
        if symbol["kind"] == "method" and symbol.get("parent"):
            methods.setdefault(symbol["parent"], {})[symbol["name"]] = symbol
    gaps = 0
    saw = False
    for child, base in _script_bases(tokens).items():
        if base not in methods or child not in methods:
            continue
        saw = True
        for name, symbol in methods[child].items():
            parent = methods[base].get(name)
            if parent is None:
                continue
            child_required = _required_script_params(tokens, name, symbol["line"])
            parent_required = _required_script_params(tokens, name, parent["line"])
            if child_required is None or parent_required is None:
                continue
            if child_required > parent_required:
                gaps += 1
    return gaps, saw


def _inheritance_arity_gaps(ctx):
    gaps = 0
    saw = False
    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is None:
            if analysis.get("language") != "python":
                extra, visible = _script_arity_gaps(analysis, _text(ctx, Path(ctx.root) / analysis["path"]))
                gaps += extra
                saw = saw or visible
            continue
        classes = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        for node in classes.values():
            for base in node.bases:
                if not isinstance(base, ast.Name) or base.id not in classes:
                    continue
                saw = True
                parent_methods = {
                    item.name: item
                    for item in classes[base.id].body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                for method in node.body:
                    if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    parent = parent_methods.get(method.name)
                    if parent and _required_positional(method) > _required_positional(parent):
                        gaps += 1
    return gaps, saw


def _low_cohesion_classes(ctx):
    gaps = 0
    applicable = False
    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("__")
            ]
            if len(methods) < 2:
                continue
            applicable = True
            attributes = []
            for method in methods:
                names = set()
                for child in ast.walk(method):
                    if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "self":
                        names.add(child.attr)
                attributes.append(names)
            if all(attributes) and not set.intersection(*attributes):
                gaps += 1
    return gaps, applicable


def _bool_operands(node):
    count = 0
    for value in node.values:
        if isinstance(value, ast.BoolOp) and type(value.op) is type(node.op):
            count += _bool_operands(value)
        else:
            count += 1
    return count


_CODE_COMMENT = re.compile(
    r"^(?:def|class|function|return|import|from|if|elif|else|for|while|switch|case|const|let|var|public|private|protected|void|int|export|yield|try|catch|throw)\b"
    r"|.+(?:[=;{}()\[\]]).+"
)


def _looks_like_code(body):
    body = body.strip()
    if len(body) < 2 or body.startswith(("TODO", "FIXME", "NOTE", "HACK", "XXX")):
        return False
    return bool(_CODE_COMMENT.search(body))


def _python_comment_lines(text):
    lines = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type != tokenize.COMMENT:
                continue
            lines.append((token.start[0], token.string.lstrip("#").strip()))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []
    return lines


def _script_comment_lines(text):
    lines = []
    in_block = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw
        while line:
            if in_block:
                end = line.find("*/")
                if end < 0:
                    lines.append((number, line.strip()))
                    break
                body = line[:end].strip()
                if body:
                    lines.append((number, body))
                line = line[end + 2 :]
                in_block = False
                continue
            stripped = line.strip()
            if stripped.startswith("//"):
                lines.append((number, stripped[2:].strip()))
                break
            if stripped.startswith("/*"):
                in_block = True
                line = stripped[2:]
                continue
            break
    return lines


def _commented_code_blocks(path, text, language):
    rows = _python_comment_lines(text) if language == "python" else _script_comment_lines(text)
    blocks = []
    run_start = None
    run = 0
    previous = None
    for line_no, body in rows:
        code = _looks_like_code(body)
        if code and previous is not None and line_no == previous + 1:
            run += 1
        else:
            if run >= 3 and run_start is not None:
                blocks.append({"file": path, "line": run_start, "end": previous})
            run = 1 if code else 0
            run_start = line_no if code else None
        previous = line_no if code else None
    if run >= 3 and run_start is not None:
        blocks.append({"file": path, "line": run_start, "end": previous})
    return blocks


def _token_bool_chain(tokens):
    best = 0
    run = 0
    current = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        operator = None
        if token == "&" and index + 1 < len(tokens) and tokens[index + 1] == "&":
            operator = "&&"
            index += 2
        elif token == "|" and index + 1 < len(tokens) and tokens[index + 1] == "|":
            operator = "||"
            index += 2
        else:
            if token in {";", "{", "}"}:
                best = max(best, run)
                run = 0
                current = None
            index += 1
            continue
        if operator == current:
            run += 1
        else:
            best = max(best, run)
            run = 1
            current = operator
    return max(best, run)


def _boolean_chain(ctx):
    best = 0
    applicable = False
    for analysis in ctx.analyses or []:
        if analysis.get("language") == "python":
            tree = _python_tree(ctx, analysis)
            if tree is None:
                continue
            applicable = True
            for node in ast.walk(tree):
                if isinstance(node, ast.BoolOp):
                    best = max(best, _bool_operands(node) - 1)
        elif analysis.get("language") in {"javascript", "typescript", "cpp"}:
            applicable = True
            best = max(best, _token_bool_chain(analysis.get("tokens") or []))
    if not applicable:
        return _measure(None, False, reason="no conditions were recorded")
    return _measure(best, True)


def _docstring_stmt(stmt):
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)


def _script_forwarding_wrappers(analysis, text):
    methods = {}
    for symbol in analysis["symbols"]:
        if symbol["kind"] == "method" and symbol.get("parent"):
            methods.setdefault(symbol["parent"], []).append(symbol)
    lines = text.splitlines()
    count = 0
    for group in methods.values():
        if len(group) != 1:
            continue
        symbol = group[0]
        chunk = "\n".join(lines[symbol["line"] - 1 : symbol.get("end_line") or symbol["line"]])
        inner = chunk.split("{", 1)[-1].rsplit("}", 1)[0].strip()
        if re.fullmatch(r"return\s+[A-Za-z_][\w.]*(?:\s*\([^;]*\))\s*;?", inner):
            count += 1
    return count


def _forwarding_wrappers(ctx):
    count = 0
    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is None:
            if analysis.get("language") != "python":
                count += _script_forwarding_wrappers(analysis, _text(ctx, Path(ctx.root) / analysis["path"]))
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("__")
            ]
            if len(methods) != 1:
                continue
            body = [stmt for stmt in methods[0].body if not _docstring_stmt(stmt)]
            if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Call):
                count += 1
    return count


def _embedded_test_percent(ctx, production, tests):
    if not tests:
        return _measure(None, False, reason="no tests")
    considered = 0
    embedded = 0
    for module in production:
        text = _text(ctx, Path(ctx.root) / module["path"])
        internal = bool(re.search(r"^\s*def test_", text, re.M))
        external = any(_test_covers(module, test) for test in tests)
        if not internal and not external:
            continue
        considered += 1
        if internal and not external:
            embedded += 1
    if not considered:
        return _measure(0, True, reason="no production module has a located test")
    return _measure(round(100.0 * embedded / considered, 1), True)


def _path_traversal(ctx):
    source = re.compile(r"\b(?:sys\.argv|request\.(?:args|path|values|form)|input\s*\()")
    sink = re.compile(r"\b(?:open\s*\(|os\.path\.join\s*\(|Path\s*\()")
    script_source = re.compile(r"req\.(?:body|query|params)|request\.(?:body|query|params|args)|process\.argv|(?<![\w.])argv\b")
    script_sink = re.compile(r"path\.join\s*\(|fs\.(?:readFileSync|readFile|createReadStream|open)\s*\(|\bfopen\s*\(|\bifstream\b")
    confirmed = 0
    saw_source = False
    saw_sink = False
    for analysis, text in _iter_source_text(ctx):
        if analysis.get("language") != "python":
            extra, source_hit, sink_hit = _script_pair_count(analysis, text, script_source, script_sink)
            confirmed += extra
            saw_source = saw_source or source_hit
            saw_sink = saw_sink or sink_hit
            continue
        tree = _python_tree(ctx, analysis)
        nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))] if tree is not None else []
        if not nodes:
            saw_source = saw_source or bool(source.search(text))
            saw_sink = saw_sink or bool(sink.search(text))
            continue
        for node in nodes:
            body = _span(text, node)
            has_source = bool(source.search(body))
            has_sink = bool(sink.search(body))
            saw_source = saw_source or has_source
            saw_sink = saw_sink or has_sink
            if has_source and has_sink:
                confirmed += 1
    if confirmed:
        return _measure(confirmed, True)
    if saw_source and saw_sink:
        return _measure(None, True, status="INCONCLUSIVE", reason="external input and a filesystem call are visible but not in the same function")
    return _measure(None, False, reason="no paired external input and filesystem sink was confirmed")


def _html_injection(ctx):
    markup = re.compile(r"<\s*[a-zA-Z]|render_template_string|Markup\(")
    raw = re.compile(r"request\.(?:args|form|values|data|json)|input\s*\(")
    script_raw = re.compile(r"req\.(?:body|query|params)|request\.(?:body|query|params)|process\.argv|(?<![\w.])argv\b")
    confirmed = 0
    saw_markup = False
    for _analysis, text in _iter_source_text(ctx):
        if not markup.search(text):
            continue
        saw_markup = True
        if _analysis.get("language") != "python":
            extra, _source_hit, _sink_hit = _script_pair_count(_analysis, text, script_raw, markup)
            if not _function_spans(_analysis) and script_raw.search(text):
                extra = 1
            confirmed += extra
            continue
        tree = _python_tree(ctx, _analysis)
        nodes = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))] if tree is not None else []
        if not nodes and raw.search(text):
            confirmed += 1
            continue
        for node in nodes:
            body = _span(text, node)
            if markup.search(body) and raw.search(body):
                confirmed += 1
    if not saw_markup:
        return _measure(None, False, reason="no HTML response construction was confirmed")
    return _measure(confirmed, True)


def _called_names(body):
    return set(re.findall(r"(?<![\w.])([A-Za-z_][\w]*)\s*\(", body))


def _self_test_gap(ctx, analyses):
    production = set()
    for analysis in analyses:
        if _is_test_path(analysis["path"]):
            continue
        for symbol in analysis["symbols"]:
            if symbol["kind"] in {"function", "method"} and symbol.get("name"):
                production.add(symbol["name"])
    gaps = 0
    total = 0
    for analysis in analyses:
        if not _is_test_path(analysis["path"]):
            continue
        tree = _python_tree(ctx, analysis)
        if tree is not None:
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("test_"):
                    continue
                total += 1
                called = set()
                for child in ast.walk(node):
                    if not isinstance(child, ast.Call):
                        continue
                    func = child.func
                    if isinstance(func, ast.Name):
                        called.add(func.id)
                    elif isinstance(func, ast.Attribute):
                        called.add(func.attr)
                if not called & production:
                    gaps += 1
            continue
        text = _text(ctx, Path(ctx.root) / analysis["path"])
        lines = text.splitlines()
        for symbol in analysis["symbols"]:
            if symbol["kind"] not in {"function", "method"} or not str(symbol.get("name") or "").lower().startswith("test"):
                continue
            total += 1
            start = max(int(symbol["line"]) - 1, 0)
            end = int(symbol.get("end_line") or symbol["line"])
            if not _called_names("\n".join(lines[start:end])) & production:
                gaps += 1
    if total == 0:
        return _measure(None, False, reason="no test functions")
    return _measure(round(100.0 * gaps / total, 1), True)


def _declared_ids(ctx, pattern):
    found = set()
    for analysis, text in _iter_source_text(ctx):
        if not _is_test_path(analysis["path"]):
            found.update(pattern.findall(text))
    for item in discover_requirements(ctx):
        found.update(pattern.findall(item.get("text") or ""))
        found.update(pattern.findall(item.get("id") or ""))
    return found


def _ids_without_assertion(ctx, tests, idents):
    missing = []
    for ident in sorted(idents):
        cited = False
        for test in tests:
            text = _text(ctx, Path(ctx.root) / test["path"])
            if ident in text and "assert" in text:
                cited = True
                break
        if not cited:
            missing.append(ident)
    return missing


def _import_cycles(analyses):
    graph = {analysis["path"]: set() for analysis in analyses}
    for analysis in analyses:
        for imp in analysis["imports"]:
            if imp.get("resolved") and imp["resolved"] in graph:
                graph[analysis["path"]].add(imp["resolved"])
    cycles = []
    visiting = set()
    visited = set()

    def walk(node, stack):
        if node in visiting:
            cycles.append(stack[stack.index(node) :] + [node])
            return
        if node in visited:
            return
        visiting.add(node)
        for nxt in graph[node]:
            walk(nxt, stack + [node])
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        walk(node, [])
    return cycles


def _layer_of(layers, path):
    for layer in layers:
        for prefix in layer.get("paths") or []:
            prefix = prefix.strip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return layer
    return None


def _extension_violations(ctx, analyses):
    rules = ((ctx.config.get("architecture") or {}).get("extension_points")) or []
    if not rules:
        return _measure(None, False, reason="no extension-point rules are configured")
    count = 0
    for analysis in analyses:
        importer = analysis["path"]
        for imp in analysis["imports"]:
            target = imp.get("resolved") or imp.get("module") or ""
            for rule in rules:
                protected = str(rule.get("protected") or "")
                if not protected:
                    continue
                stem = Path(protected).stem
                target_text = str(target)
                if protected not in target_text and stem != Path(target_text).stem and stem != target_text.split(".")[-1]:
                    continue
                allow = [str(item) for item in rule.get("allow") or []]
                if any(item and (item in importer or importer.endswith(item)) for item in allow):
                    continue
                if protected in importer or importer.endswith(stem + ".py"):
                    continue
                count += 1
    return _measure(count, True)


def _version_tuple(value):
    match = re.search(r"(\d+(?:\.\d+){0,3})", str(value))
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _declared_versions(ctx):
    declared = {}
    root = Path(ctx.root)
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)==([^\s#]+)", line)
            if match:
                declared[match.group(1).lower()] = match.group(2)
    package = root / "package.json"
    if package.is_file():
        try:
            import json

            data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for section in ("dependencies", "devDependencies"):
            for name, version in (data.get(section) or {}).items():
                if isinstance(version, str) and re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
                    declared[name.lower()] = version
    return declared


def _freshness_snapshot(ctx):
    configured = ctx.config.get("freshness_snapshot")
    if isinstance(configured, dict) and configured:
        return {str(key).lower(): value for key, value in configured.items()}
    path = Path(ctx.root) / (ctx.config.get("freshness_snapshot_file") or "freshness-snapshot.yaml")
    if not path.is_file():
        return None
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return None
    return {str(key).lower(): value for key, value in packages.items()}


def _freshness(ctx):
    if not _manifests(ctx.root):
        return _measure(None, False, reason="no dependency manifest")
    snapshot = _freshness_snapshot(ctx)
    if not snapshot:
        return _measure(None, True, status="UNAVAILABLE", reason="no local freshness snapshot; versions were not looked up on the network")
    older = []
    for name, declared in _declared_versions(ctx).items():
        current = snapshot.get(name)
        if current is None:
            continue
        left = _version_tuple(declared)
        right = _version_tuple(current)
        if left is not None and right is not None and left < right:
            older.append(name)
    return _measure(len(older), True, evidence=older)


def _layer_violations(ctx, analyses):
    layers = (ctx.config.get("architecture") or {}).get("layers") or []
    if not layers:
        return []
    violations = []
    for analysis in analyses:
        source = _layer_of(layers, analysis["path"])
        if source is None:
            continue
        allowed = set(source.get("allowed_dependencies") or [])
        for imp in analysis["imports"]:
            if not imp.get("resolved"):
                continue
            target = _layer_of(layers, imp["resolved"])
            if target is None or target.get("name") == source.get("name"):
                continue
            if target.get("name") not in allowed:
                violations.append(
                    {
                        "file": analysis["path"],
                        "line": imp["line"],
                        "observation": f"{source.get('name')} imports {target.get('name')}, which is outside its allow-list",
                    }
                )
    return violations


def run_duplication(ctx):
    analyses = ensure_analyses(ctx)
    exact = exact_duplicates(analyses)
    tokens = token_duplicates(analyses)
    structural = structural_duplicates(analyses)
    groups = apply_justifications(exact + tokens + structural, analyses)
    ctx.duplicate_groups = groups
    findings = []
    for group in groups:
        if not group.get("confirmed"):
            continue
        location = group["locations"][0]
        findings.append(
            _finding(
                location.get("file"),
                location.get("line", 1),
                "duplication",
                [{"exact": "DUP-001", "token": "DUP-002", "structural": "DUP-003"}[group["kind"]]],
                f"{group['kind']} duplicate at {group['locations']}",
                "Share one implementation or record a justification.",
                sources=[item.get("file") for item in group["locations"]],
            )
        )
    applicable = bool(analyses)
    structural_applicable = any(analysis.get("structures") for analysis in analyses)
    return _result(
        findings,
        {
            "DUP-001": _measure(sum(1 for group in groups if group["kind"] == "exact" and group.get("confirmed")), applicable),
            "DUP-002": _measure(sum(1 for group in groups if group["kind"] == "token" and group.get("confirmed")), applicable),
            "DUP-003": _measure(sum(1 for group in groups if group["kind"] == "structural" and group.get("confirmed")), structural_applicable, reason="" if structural_applicable else "no structural hashes"),
        },
    )


def run_semantic_duplication(ctx):
    analyses = ensure_analyses(ctx)
    if getattr(ctx, "duplicate_groups", None) is None:
        run_duplication(ctx)
    candidates = semantic_candidates(analyses)
    languages = {analysis["language"] for analysis in analyses}
    findings = []
    for candidate in candidates:
        location = candidate["locations"][0]
        metric = "DUP-005" if candidate["cross_language"] else "DUP-004"
        findings.append(
            _finding(
                location["file"],
                1,
                "semantic_duplication",
                [metric, "DUP-006"],
                f"semantic candidate score {candidate['score']}",
                "Compare contracts or add a differential test before calling these copies equivalent.",
                confidence="candidate",
                classification="advisory",
                rationale=candidate["rationale"],
                uncertainty=candidate["uncertainty"],
                sources=candidate["sources"],
                confirmed_by_tests=False,
            )
        )
    unjustified = len(candidates)
    return _result(
        findings,
        {
            "DUP-004": _measure(len([item for item in candidates if not item["cross_language"]]), bool(analyses), status="WARNING" if candidates else None),
            "DUP-005": _measure(len([item for item in candidates if item["cross_language"]]), len(languages) > 1, reason="" if len(languages) > 1 else "one language in scope", status="WARNING" if any(item["cross_language"] for item in candidates) else None),
            "DUP-006": _measure(unjustified, bool(candidates), reason="" if candidates else "no duplicate group to justify", status="WARNING" if unjustified else None),
        },
    )


def _iter_source_text(ctx):
    analyses = ensure_analyses(ctx)
    for analysis in analyses:
        yield analysis, _text(ctx, Path(ctx.root) / analysis["path"])


def run_secrets(ctx):
    findings = []
    for analysis, text in _iter_source_text(ctx):
        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(_finding(analysis["path"], line, "secrets", ["SEC-001"], f"confirmed {name}", "Remove the secret and rotate it.", sources=[analysis["path"]]))
        for match in CREDENTIAL.finditer(text):
            value = match.group(2)
            if value.lower() in PLACEHOLDERS or "example" in value.lower():
                continue
            line = text[: match.start()].count("\n") + 1
            findings.append(_finding(analysis["path"], line, "secrets", ["SEC-007"], "hard-coded credential assignment", "Read the credential from an approved secret store.", sources=[analysis["path"]]))
    return _result(
        findings,
        {
            "SEC-001": _measure(sum(1 for item in findings if "SEC-001" in item["metric_ids"]), bool(ctx.analyses)),
            "SEC-007": _measure(sum(1 for item in findings if "SEC-007" in item["metric_ids"]), bool(ctx.analyses)),
        },
    )


def run_security_sast(ctx):
    findings = []
    for analysis, text in _iter_source_text(ctx):
        for name, pattern, metric in SINK_PATTERNS:
            if metric == "SEC-006":
                continue
            for match in pattern.finditer(text):
                if name == "yaml.load" and "SafeLoader" in text[match.start() : match.start() + 80]:
                    continue
                line = text[: match.start()].count("\n") + 1
                findings.append(_finding(analysis["path"], line, "security_sast", [metric], f"confirmed sink {name}", "Replace the sink with a safe API."))
    applicable = bool(ctx.analyses)
    counts = Counter(metric for finding in findings for metric in finding["metric_ids"])
    unvalidated, inputs_visible = _unvalidated_inputs(ctx)
    anonymous_routes, routes_visible = _anonymous_state_changes(ctx)
    return _result(
        findings,
        {
            "SEC-003": _measure(counts.get("SEC-003", 0), applicable),
            "SEC-004": _measure(unvalidated, inputs_visible, reason="" if inputs_visible else "no external input boundary"),
            "SEC-005": _measure(anonymous_routes, routes_visible, reason="" if routes_visible else "no HTTP route"),
            "SEC-008": _measure(counts.get("SEC-008", 0), applicable),
            "SEC-009": _path_traversal(ctx),
            "SEC-010": _html_injection(ctx),
            "SEC-011": _measure(counts.get("SEC-011", 0), applicable),
        },
    )


def _span(text, node):
    lines = text.splitlines()
    start = max((getattr(node, "lineno", 1) or 1) - 1, 0)
    end = getattr(node, "end_lineno", None) or start + 1
    return "\n".join(lines[start:end])


def _function_spans(analysis):
    return [
        (symbol["line"], symbol.get("end_line") or symbol["line"])
        for symbol in analysis["symbols"]
        if symbol["kind"] in {"function", "method"}
    ]


def _function_line_text(text, spans, start, end):
    lines = text.splitlines()
    nested = [(inner, outer) for inner, outer in spans if inner > start and outer <= end]
    selected = []
    for number in range(start, end + 1):
        if any(inner <= number <= outer for inner, outer in nested):
            continue
        if 1 <= number <= len(lines):
            selected.append(lines[number - 1])
    return "\n".join(selected)


def _script_pair_count(analysis, text, source, sink):
    spans = _function_spans(analysis)
    if not spans:
        return 0, bool(source.search(text)), bool(sink.search(text))
    confirmed = 0
    saw_source = False
    saw_sink = False
    for start, end in spans:
        body = _function_line_text(text, spans, start, end)
        has_source = bool(source.search(body))
        has_sink = bool(sink.search(body))
        saw_source = saw_source or has_source
        saw_sink = saw_sink or has_sink
        if has_source and has_sink:
            confirmed += 1
    return confirmed, saw_source, saw_sink


def _function_body_text(tokens, spans, start, end):
    nested = [(inner, outer) for inner, outer in spans if inner > start and outer <= end]
    parts = []
    for token in tokens:
        line = token[2]
        if line < start or line > end or token[0] == "string":
            continue
        if any(inner <= line <= outer for inner, outer in nested):
            continue
        parts.append(token[1])
    return "".join(parts)


def _script_input_gaps(analysis, text):
    validation = re.compile(r"validate|schema|Number\(|parseInt\(|parseFloat\(|Boolean\(|stoi\(|stod\(|int\(|float\(")
    boundary = re.compile(r"req\.(?:body|query|params)|request\.(?:body|query|params|json)|process\.argv|(?<![\w.])argv\b")
    tokens, _error, _comments = _scan_tokens(text)
    spans = [
        (symbol["line"], symbol.get("end_line") or symbol["line"])
        for symbol in analysis["symbols"]
        if symbol["kind"] in {"function", "method"}
    ]
    count = 0
    saw = False
    for start, end in spans:
        body = _function_body_text(tokens, spans, start, end)
        if not boundary.search(body):
            continue
        saw = True
        if not validation.search(body):
            count += 1
    return count, saw


def _unvalidated_inputs(ctx):
    validation = re.compile(r"\b(validate|schema|isinstance|pydantic|int\(|float\(|bool\(|len\()")
    boundary = re.compile(r"\binput\s*\(|\bsys\.argv\b|\brequest\.(?:json|args|form|data)\b")
    count = 0
    saw = False
    for analysis, text in _iter_source_text(ctx):
        tree = _python_tree(ctx, analysis)
        if tree is None:
            if analysis.get("language") == "python":
                continue
            extra, visible = _script_input_gaps(analysis, text)
            count += extra
            saw = saw or visible
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = _span(text, node)
            if not boundary.search(body):
                continue
            saw = True
            if not validation.search(body):
                count += 1
    return count, saw


def _anonymous_state_changes(ctx):
    state_changes = {"post", "put", "delete", "patch"}
    routes = state_changes | {"route", "get", "head"}
    auth = re.compile(r"login_required|permission_required|requires_auth|authorize|current_user|Depends\(")
    count = 0
    saw = False
    for analysis, text in _iter_source_text(ctx):
        tree = _python_tree(ctx, analysis)
        symbols = {symbol["name"]: symbol for symbol in analysis["symbols"]}
        for symbol in analysis["symbols"]:
            leaves = {item.split(".")[-1].lower() for item in symbol.get("decorators") or []}
            if leaves & routes:
                saw = True
            if not (leaves & state_changes):
                continue
            source = symbol.get("decorators") or []
            body = ""
            if tree is not None:
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol["name"] and node.lineno == symbol["line"]:
                        body = _span(text, node)
                        break
            if any(auth.search(item) for item in source) or auth.search(body):
                continue
            count += 1
        for route in analysis.get("routes") or []:
            if route["method"] in routes:
                saw = True
            if route["method"] not in state_changes or route.get("authorized"):
                continue
            count += 1
        del symbols
    return count, saw


def run_dependency_audit(ctx):
    manifests = _manifests(ctx.root)
    if not manifests:
        return _result([], {"SEC-002": _measure(None, False, reason="no dependency manifest")})
    advisories, supplied = _local_advisories(ctx)
    if not supplied:
        return _result(
            [],
            {
                "SEC-002": _measure(
                    None,
                    True,
                    status="UNAVAILABLE",
                    reason="no approved local advisory database or dependency-audit tool result is available; vulnerabilities were not inferred",
                )
            },
            ["dependency advisories were not queried over the network"],
        )
    if advisories is None:
        return _result(
            [],
            {
                "SEC-002": _measure(
                    None,
                    True,
                    status="UNAVAILABLE",
                    reason="the configured local advisory file could not be read; vulnerabilities were not inferred",
                )
            },
        )
    findings = []
    matched = []
    for pin in _pinned_dependencies(ctx):
        hits = [item for item in advisories if item["package"] == pin["name"] and item["version"] == pin["version"]]
        if not hits:
            continue
        matched.append(pin["name"])
        advisory_ids = ", ".join(sorted({item["id"] for item in hits}))
        findings.append(
            _finding(
                pin["file"],
                pin["line"],
                "dependency_audit",
                ["SEC-002"],
                f"{pin['name']}=={pin['version']} matches local advisory {advisory_ids}",
                "Upgrade or replace the dependency using the local advisory.",
            )
        )
    return _result(
        findings,
        {"SEC-002": _measure(len(set(matched)), True, evidence=sorted(set(matched)))},
        ["dependency advisories were compared with the configured local database and were not queried over the network"],
    )


def _advisory_entries(data):
    if isinstance(data, dict) and isinstance(data.get("advisories"), (dict, list)):
        data = data["advisories"]
    records = []
    items = []
    if isinstance(data, dict):
        for package, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        items.append((str(package), item))
            elif isinstance(value, str):
                items.append((str(package), {"version": value, "id": "local-advisory"}))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                items.append((str(item.get("package") or item.get("name") or ""), item))
    for package, item in items:
        versions = item.get("versions")
        if not versions and item.get("version"):
            versions = [item["version"]]
        advisory_id = str(item.get("id") or item.get("advisory") or "local-advisory")
        for version in versions or []:
            if package and version:
                records.append({"package": package.lower(), "version": str(version), "id": advisory_id})
    return records


def _local_advisories(ctx):
    configured = ctx.config.get("advisory_database")
    if configured:
        return _advisory_entries(configured), True
    raw = ctx.config.get("advisory_file")
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = Path(ctx.root) / path
    else:
        path = Path(ctx.root) / "advisories.yaml"
        if not path.is_file():
            return None, False
    if not path.is_file():
        return None, True
    import yaml

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None, True
    return _advisory_entries(data), True


def _pinned_dependencies(ctx):
    pins = []
    root = Path(ctx.root)
    requirements = root / "requirements.txt"
    if requirements.is_file():
        for index, line in enumerate(requirements.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            match = re.match(r"\s*([A-Za-z0-9_.-]+)==([^\s#]+)", line)
            if match:
                pins.append({"file": "requirements.txt", "line": index, "name": match.group(1).lower(), "version": match.group(2)})
    package = root / "package.json"
    if package.is_file():
        try:
            import json

            data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for section in ("dependencies", "devDependencies"):
            for name, version in (data.get(section) or {}).items():
                if isinstance(version, str) and re.fullmatch(r"\d+(?:\.\d+){0,3}", version):
                    pins.append({"file": "package.json", "line": 1, "name": str(name).lower(), "version": version})
    return pins


def _manifests(root):
    names = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "Pipfile", "CMakeLists.txt"}
    found = []
    root = Path(root)
    for dirpath, dirnames, filenames in os_walk_limited(root):
        for name in filenames:
            if name in names:
                found.append(str(Path(dirpath) / name))
    return found


def os_walk_limited(root):
    import os

    skip = {".git", ".venv", "node_modules", "__pycache__", "dist", "build"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in skip]
        yield dirpath, dirnames, filenames


_CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env"}
_TLS_DISABLED = re.compile(r"verify\s*[=:]\s*false|rejectUnauthorized\s*[=:]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", re.I)
_DEBUG_ENABLED = re.compile(r"debug\s*[=:]\s*true", re.I)


def _config_texts(ctx):
    root = Path(ctx.root)
    seen = {analysis["path"] for analysis in ctx.analyses or []}
    for dirpath, _dirnames, filenames in os_walk_limited(root):
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in _CONFIG_SUFFIXES and not name.startswith(".env"):
                continue
            rel = path.relative_to(root).as_posix()
            if rel in seen or path.stat().st_size > 1_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            yield rel, text


def _wildcard_host(text):
    if re.search(r"ALLOWED_HOSTS\s*=\s*\[.*\*.*\]", text):
        return True
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(r"(?i)allowed[_-]?hosts", line):
            continue
        window = "\n".join(lines[index : index + 4])
        if re.search(r"""['"]\*['"]""", window):
            return True
    return False


def _production_named(path):
    return any(token in path.lower() for token in ("settings", "production", "deploy"))


def run_insecure_config(ctx):
    findings = []
    texts = list(_iter_source_text(ctx))
    texts.extend(({"path": path}, text) for path, text in _config_texts(ctx))
    for analysis, text in texts:
        path = analysis["path"]
        for match in _TLS_DISABLED.finditer(text):
            line = text[: match.start()].count("\n") + 1
            findings.append(_finding(path, line, "insecure_config", ["SEC-006"], "TLS verification disabled", "Enable certificate verification."))
        if _wildcard_host(text):
            findings.append(_finding(path, 1, "insecure_config", ["SEC-006"], "wildcard host allow-list", "Restrict allowed hosts."))
        if _production_named(path) and _DEBUG_ENABLED.search(text):
            findings.append(_finding(path, 1, "insecure_config", ["SEC-012"], "DEBUG enabled in a production-named file", "Disable DEBUG outside local development."))
        if _production_named(path) and "Access-Control-Allow-Origin" in text and "*" in text:
            findings.append(_finding(path, 1, "insecure_config", ["SEC-012"], "wildcard CORS in a production-named file", "Restrict the origin."))
    applicable = bool(ctx.analyses) or any(True for _analysis, _text in texts)
    production_present = any(_production_named(analysis["path"]) for analysis, _text in texts)
    return _result(
        findings,
        {
            "SEC-006": _measure(sum(1 for item in findings if "SEC-006" in item["metric_ids"]), applicable),
            "SEC-012": _measure(sum(1 for item in findings if "SEC-012" in item["metric_ids"]), production_present, reason="" if production_present else "no production-named configuration"),
        },
    )


def _test_covers(module, test):
    stem = Path(module["path"]).stem
    if stem in Path(test["path"]).stem or f"/{stem}." in f"/{test['path']}":
        return True
    for imp in test.get("imports") or []:
        module_name = (imp.get("module") or "").lstrip(".")
        if stem and (module_name == stem or module_name.endswith("." + stem)):
            return True
    refs = " ".join(test.get("module_refs") or [])
    return stem in refs.split()


def _is_test_path(path):
    name = Path(path).name.lower()
    if "/tests/" in f"/{path}" or path.startswith("tests/") or path.startswith("test/"):
        return True
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    return any(marker in name for marker in (".test.", ".spec.", "_test."))


def _production(analyses):
    return [analysis for analysis in analyses if not _is_test_path(analysis["path"]) and any(symbol["kind"] == "function" for symbol in analysis["symbols"])]


def run_testing(ctx):
    analyses = ensure_analyses(ctx)
    production = _production(analyses)
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    untested = []
    for module in production:
        if not any(_test_covers(module, test) for test in tests):
            untested.append(module["path"])
    assertion_percent, assertion_gaps = _assertion_percent(ctx, tests)
    findings = []
    for path in untested:
        findings.append(_finding(path, 1, "testing", ["TEST-001"], "production module has no corresponding test", "Add a test that asserts the module's behavior."))
    specs = discover_requirements(ctx)
    ctx.requirements = specs
    property_needed = _property_declared(ctx, specs)
    invariant_items = [item for item in specs if "invariant" in (item.get("text") or "").lower()]
    packages = {key for item in production if (key := _package_key(ctx, item["path"]))}
    regression_markers = []
    for analysis, text in _iter_source_text(ctx):
        if re.search(r"\b(FIXME|REGRESSION|FIX-\d+)\b", text) and not any(analysis["path"] in (_text(ctx, Path(ctx.root) / test["path"])) for test in tests):
            regression_markers.append(analysis["path"])
    test_applicable = bool(tests)
    return _result(
        findings,
        {
            "TEST-001": _measure(len(untested), bool(production), reason="" if production else "no production functions"),
            "TEST-005": _measure(_boundary_percent(ctx, tests), test_applicable, reason="" if test_applicable else "no tests"),
            "TEST-006": _measure(_property_case_count(ctx, tests), property_needed, reason="" if property_needed else "property-based testing is not declared"),
            "TEST-007": _measure(100 if not invariant_items or _ids_tested(ctx, invariant_items, tests) else 0, bool(invariant_items), reason="" if invariant_items else "no declared invariants"),
            "TEST-008": _measure(_integration_count(ctx, tests), len(packages) > 1, reason="" if len(packages) > 1 else "one production package"),
            "TEST-009": _measure(len(regression_markers), bool(regression_markers) or False, reason="no regression marker" if not regression_markers else ""),
            "TEST-011": _measure(
                assertion_percent,
                test_applicable and assertion_percent is not None,
                reason="" if assertion_percent is not None else ("no tests" if not test_applicable else "no test functions"),
                evidence=assertion_gaps,
            ),
            "TEST-012": _embedded_test_percent(ctx, production, tests),
        },
    )


def _assert_call(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
    return name.startswith("assert")


def _meaningful_python_assert(node):
    if isinstance(node, ast.Assert):
        test = node.test
        if isinstance(test, ast.Constant) and test.value is True:
            return False
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
            left, right = test.left, test.comparators[0]
            if isinstance(left, ast.Constant) and isinstance(right, ast.Constant) and left.value == right.value:
                return False
        return True
    return _assert_call(node)


def _match_paren(tokens, open_index):
    depth = 0
    for cursor in range(open_index, len(tokens)):
        if tokens[cursor][1] == "(":
            depth += 1
        elif tokens[cursor][1] == ")":
            depth -= 1
            if depth == 0:
                return cursor
    return None


def _callback_body(tokens, open_index, close_index):
    arrow = None
    cursor = open_index + 1
    while cursor < close_index:
        if tokens[cursor][1] == "function":
            arrow = cursor
            break
        if tokens[cursor][1] == "=" and cursor + 1 < close_index and tokens[cursor + 1][1] == ">":
            arrow = cursor + 1
            break
        cursor += 1
    if arrow is None:
        return None
    brace = None
    for cursor in range(arrow + 1, close_index):
        if tokens[cursor][1] == "{":
            brace = cursor
            break
    if brace is None:
        return tokens[arrow + 1 : close_index]
    depth = 0
    for cursor in range(brace, close_index):
        if tokens[cursor][1] == "{":
            depth += 1
        elif tokens[cursor][1] == "}":
            depth -= 1
            if depth == 0:
                return tokens[brace : cursor + 1]
    return None


def _script_callback_bodies(tokens):
    bodies = []
    index = 0
    while index < len(tokens):
        kind, name, _line = tokens[index]
        previous = tokens[index - 1][1] if index else ""
        if kind == "id" and name in {"it", "test"} and previous != "." and index + 1 < len(tokens) and tokens[index + 1][1] == "(":
            end = _match_paren(tokens, index + 1)
            body = _callback_body(tokens, index + 1, end) if end is not None else None
            if body is not None:
                bodies.append((name, tokens[index][2], body))
            index = (end + 1) if end is not None else index + 1
            continue
        index += 1
    return bodies


def _tokens_have_assertion(tokens):
    for index, (kind, name, _line) in enumerate(tokens):
        if kind != "id" or index + 1 >= len(tokens) or tokens[index + 1][1] != "(":
            continue
        if name not in {"expect", "assert", "CHECK", "REQUIRE"} and not name.startswith(("ASSERT_", "EXPECT_")):
            continue
        argument = tokens[index + 2][1] if index + 2 < len(tokens) else ""
        closer = tokens[index + 3][1] if index + 3 < len(tokens) else ""
        if name in {"assert", "ASSERT_TRUE"} and argument in {"true", "True"} and closer == ")":
            continue
        if name == "expect" and argument in {"true", "True"} and closer == ")":
            tail = [item[1] for item in tokens[index + 4 : index + 9]]
            if tail[:5] == [".", "toBe", "(", "true", ")"] or tail[:5] == [".", "toBe", "(", "True", ")"]:
                continue
        return True
    return False


def _assertion_percent(ctx, tests):
    total = 0
    passed = 0
    gaps = []
    for test in tests:
        text = _text(ctx, Path(ctx.root) / test["path"])
        if test["language"] == "python":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                total += 1
                gaps.append(test["path"])
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("test_"):
                    continue
                total += 1
                if any(_meaningful_python_assert(child) for child in ast.walk(node)):
                    passed += 1
                else:
                    gaps.append(f"{test['path']}:{node.name}")
            continue
        tokens, _error, _comments = _scan_tokens(text)
        seen = set()
        for symbol in test["symbols"]:
            if symbol["kind"] not in {"function", "method"} or not str(symbol.get("name") or "").lower().startswith("test"):
                continue
            start = int(symbol["line"])
            end = int(symbol.get("end_line") or symbol["line"])
            body = [token for token in tokens if start <= token[2] <= end]
            seen.add((symbol["name"], start))
            total += 1
            if _tokens_have_assertion(body):
                passed += 1
            else:
                gaps.append(f"{test['path']}:{symbol['name']}")
        for name, line, body in _script_callback_bodies(tokens):
            if (name, line) in seen:
                continue
            total += 1
            if _tokens_have_assertion(body):
                passed += 1
            else:
                gaps.append(f"{test['path']}:{name}:{line}")
    if total == 0:
        return None, []
    return round(100.0 * passed / total, 1), gaps


def _boundary_percent(ctx, tests):
    if not tests:
        return None
    hits = 0
    for test in tests:
        text = _text(ctx, Path(ctx.root) / test["path"]).lower()
        if any(token in text for token in ("boundary", "empty", "zero", "none", "null", "max", "min")):
            hits += 1
    return 100.0 * hits / len(tests)


_PROPERTY_CASE = re.compile(r"(?<![\w.])(?:hypothesis\.given|given|fc\.assert|RC_PROPERTY|RAPIDCHECK_PROPERTY)\s*\(")


def _property_declared(ctx, specs):
    if any("property" in f"{item.get('text', '')} {item.get('id', '')}".lower() for item in specs):
        return True
    root = Path(ctx.root)
    requirements = root / "requirements.txt"
    if requirements.is_file() and re.search(r"(?im)^\s*hypothesis(?:\s|==|>=|~=|\[|$)", requirements.read_text(encoding="utf-8", errors="replace")):
        return True
    package = root / "package.json"
    if package.is_file() and re.search(r"fast-check|rapidcheck", package.read_text(encoding="utf-8", errors="replace"), re.I):
        return True
    for name in ("CMakeLists.txt", "conanfile.txt", "vcpkg.json"):
        path = root / name
        if path.is_file() and re.search(r"rapidcheck", path.read_text(encoding="utf-8", errors="replace"), re.I):
            return True
    return False


def _property_case_count(ctx, tests):
    count = 0
    for test in tests:
        text = _text(ctx, Path(ctx.root) / test["path"])
        count += len(_PROPERTY_CASE.findall(text))
    return count


def _ids_tested(ctx, items, tests):
    return all(_requirement_verified(ctx, item, tests) for item in items)


_INTEGRATION = re.compile(r"integration|end[-_]?to[-_]?end|(?:^|[^A-Za-z0-9])e2e(?:[^A-Za-z0-9]|$)", re.I)


def _package_key(ctx, path):
    parts = Path(path).parts
    if len(parts) < 2:
        return None
    root = Path(ctx.root)
    directory = Path(path).parent
    while True:
        for marker in ("package.json", "__init__.py", "CMakeLists.txt"):
            if (root / directory / marker).is_file():
                return directory.as_posix()
        parent = directory.parent
        if parent == directory or parent == Path("."):
            break
        directory = parent
    return parts[0]


def _integration_count(ctx, tests):
    count = 0
    for test in tests:
        names = [symbol.get("name") or "" for symbol in test["symbols"] if symbol["kind"] in {"function", "method"}]
        named = [name for name in names if _INTEGRATION.search(name)]
        if named:
            count += len(named)
        elif _INTEGRATION.search(test["path"]):
            count += 1
    return count


def _branch_tool_installed():
    if shutil.which("coverage") or importlib.util.find_spec("coverage") is not None:
        return "coverage"
    if shutil.which("c8"):
        return "c8"
    return None


def _coverage_measurements(line, branch):
    return {"TEST-002": line, "TEST-003": branch}


_PYTEST_IMPORT = re.compile(r"(?m)^\s*(?:import pytest\b|from pytest\b)")


def _uses_pytest(ctx, tests):
    root = Path(ctx.root)
    for directory, _dirs, files in os.walk(root):
        if any(part in {".git", ".venv", "venv", "node_modules", "__pycache__"} for part in Path(directory).parts):
            continue
        if "conftest.py" in files or "pytest.ini" in files:
            return True
    for test in tests:
        if test["path"].endswith(".py") and _PYTEST_IMPORT.search(_text(ctx, root / test["path"])):
            return True
    return False


def _pytest_cwd(ctx, tests):
    root = Path(ctx.root).resolve()
    markers = {"pyproject.toml", "pytest.ini", "setup.cfg", "setup.py", "requirements.txt", "conftest.py"}
    candidates = []
    for test in tests:
        if not test["path"].endswith(".py"):
            continue
        directory = (root / test["path"]).parent
        while True:
            if any((directory / name).is_file() for name in markers):
                candidates.append(directory)
                break
            if directory == root or directory.parent == directory:
                break
            directory = directory.parent
    if not candidates:
        return root
    return max(candidates, key=lambda path: len(path.parts))


def _pytest_executable(cwd):
    for base in (cwd, cwd.parent):
        for name in (".venv", "venv"):
            candidate = base / name / "bin" / "pytest"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
    system = shutil.which("pytest")
    return Path(system).resolve() if system else None


def _parse_pytest_failures(text):
    found = []
    for match in re.finditer(r"FAILED\s+(\S+\.py)::((?:[\w.]+::)*)(test_\w+)", text):
        found.append(f"{match.group(1)}:{match.group(3)}")
    return found


_UNITTEST_OUTCOME = re.compile(r"(?:FAIL|ERROR): (\w+) \(([\w.]+)\)")


def _unittest_rel(qual, root, start_rel):
    module = qual.rsplit(".", 2)[0] if qual.count(".") >= 2 else qual.rsplit(".", 1)[0]
    rel = Path(module.replace(".", "/") + ".py")
    if start_rel not in {"", "."}:
        rel = Path(start_rel) / rel
    return rel if (root / rel).is_file() else None


def _parse_unittest_failures(text, root, start_rel):
    """Map ``FAIL: test_add (test_add.AddTests.test_add)`` onto ``tests/test_add.py:test_add``.

    ``start_rel`` is the discover start directory relative to the repository, such as ``tests`` or ``.``.
    """
    found = []
    for match in _UNITTEST_OUTCOME.finditer(text):
        rel = _unittest_rel(match.group(2), root, start_rel)
        if rel is not None:
            found.append(f"{rel.as_posix()}:{match.group(1)}")
    return found


def _unittest_has_unmapped_outcome(text, root, start_rel):
    """True when an ``ERROR:`` or ``FAIL:`` line does not name a file in the repository."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("ERROR:", "FAIL:")):
            continue
        match = _UNITTEST_OUTCOME.search(stripped)
        if match is None or _unittest_rel(match.group(2), root, start_rel) is None:
            return True
    return False


def project_test_result(ctx):
    cached = getattr(ctx, "project_tests", None)
    if cached is not None or getattr(ctx, "_project_tests_ready", False):
        return cached
    ctx._project_tests_ready = True
    ctx.project_tests = None
    analyses = ensure_analyses(ctx)
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"]) and analysis["path"].endswith(".py")]
    if not tests or not ctx.log.allow_repo_execution or not ctx.log.sandbox_confirmed:
        return None
    work = Path(tempfile.mkdtemp(prefix="cqa-runner-")).resolve()
    try:
        if _uses_pytest(ctx, tests):
            cwd = _pytest_cwd(ctx, tests)
            executable = _pytest_executable(cwd)
            if executable is None:
                return None
            command = [
                str(executable),
                "-q",
                "--tb=no",
                "-p",
                "no:cacheprovider",
                "--override-ini",
                f"cache_dir={work}",
            ]
            runner = "pytest"
        else:
            root = Path(ctx.root).resolve()
            starts = sorted({Path(test["path"]).parent.as_posix() for test in tests})
            failures = []
            returncode = 0
            for start in starts:
                start_dir = root if start == "." else root / start
                command = [sys.executable, "-m", "unittest", "discover", "-s", str(start_dir), "-t", str(start_dir), "-v"]
                env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(root)}
                try:
                    completed = run_contained(command, root, ctx.log, timeout=180, write_path=work, env=env)
                except (PermissionError, subprocess.TimeoutExpired):
                    return None
                text = f"{completed.stdout or ''}\n{completed.stderr or ''}"
                parsed = _parse_unittest_failures(text, root, start)
                if _unittest_has_unmapped_outcome(text, root, start) or (completed.returncode != 0 and not parsed):
                    ctx.project_tests = None
                    ctx._project_tests_ready = True
                    return None
                returncode = completed.returncode or returncode
                failures.extend(parsed)
            ctx.project_tests = {"runner": "unittest", "cwd": root, "failures": failures, "returncode": returncode}
            return ctx.project_tests
        env = {"PYTHONDONTWRITEBYTECODE": "1"}
        previous = os.environ.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(cwd) if not previous else str(cwd) + os.pathsep + previous
        try:
            completed = run_contained(command, cwd, ctx.log, timeout=180, write_path=work, env=env)
        except (PermissionError, subprocess.TimeoutExpired):
            return None
        text = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        failures = _parse_pytest_failures(text)
        if re.search(r"(?m)^ERROR ", text) or (completed.returncode != 0 and not failures):
            ctx.project_tests = None
            ctx._project_tests_ready = True
            return None
        root = Path(ctx.root).resolve()
        failures = [
            f"{(cwd / item.split(':', 1)[0]).resolve().relative_to(root).as_posix()}:{item.split(':', 1)[1]}"
            for item in failures
        ]
        ctx.project_tests = {"runner": runner, "cwd": cwd, "failures": failures, "returncode": completed.returncode}
        return ctx.project_tests
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _line_coverage_unavailable(reason, branch_tool):
    if branch_tool:
        branch = _measure(None, True, status="UNAVAILABLE", reason=f"{branch_tool} is installed; branch coverage is not estimated from line coverage and was not parsed from a branch report")
    else:
        branch = _measure(None, False, reason="no branch-capable coverage tool is installed")
    line = _measure(None, True, status="UNAVAILABLE", reason=reason)
    return _result([], _coverage_measurements(line, branch))


def _pytest_line_reason(ctx, tests, result):
    coverage_installed = bool(shutil.which("coverage") or importlib.util.find_spec("coverage"))
    if result is not None and result.get("runner") == "pytest":
        if coverage_installed:
            return "coverage.py is installed; its report was not parsed and line coverage was not estimated"
        return "pytest ran; coverage.py is not installed and line coverage was not estimated"
    if _pytest_executable(_pytest_cwd(ctx, tests)) is None:
        return "pytest is the repository runner and it is not installed; coverage was not estimated"
    return "pytest did not finish; coverage.py was not run and line coverage was not estimated"


def run_coverage(ctx):
    analyses = ensure_analyses(ctx)
    result = project_test_result(ctx)
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    if not tests:
        return _result([], _coverage_measurements(_measure(None, False, reason="no tests to cover"), _measure(None, False, reason="no tests to cover")))
    branch_tool = _branch_tool_installed()
    if not ctx.log.allow_repo_execution or not ctx.log.sandbox_confirmed:
        reason = "coverage was not measured because repository execution is not approved"
        ctx.log.deny("coverage", reason)
        branch = _measure(None, True, status="UNAVAILABLE", reason=reason) if branch_tool else _measure(None, False, reason="no branch-capable coverage tool is installed")
        return _result([], _coverage_measurements(_measure(None, True, status="UNAVAILABLE", reason=reason), branch))
    python_tests = [item for item in tests if item["path"].endswith(".py")]
    other_tests = [item for item in tests if not item["path"].endswith(".py")]
    if other_tests and branch_tool != "c8" and not python_tests:
        return _result([], _coverage_measurements(
            _measure(None, True, status="UNAVAILABLE", reason="non-Python tests have no installed coverage tool"),
            _measure(None, False, reason="no branch-capable coverage tool is installed"),
        ))
    if other_tests and not python_tests:
        return _result([], _coverage_measurements(
            _measure(None, True, status="UNAVAILABLE", reason="non-Python tests have no installed coverage tool"),
            _measure(None, bool(branch_tool), status="UNAVAILABLE" if branch_tool else None, reason="branch coverage tool is installed but was not run for this language" if branch_tool else "no branch-capable coverage tool is installed"),
        ))
    if other_tests:
        return _result([], _coverage_measurements(
            _measure(None, True, status="UNAVAILABLE", reason="line coverage was not reported because non-Python tests have no installed coverage tool"),
            _measure(None, bool(branch_tool), status="UNAVAILABLE" if branch_tool else None, reason="" if not branch_tool else "branch coverage was not run"),
        ))
    if (result is not None and result.get("runner") == "pytest") or (result is None and _uses_pytest(ctx, python_tests)):
        return _line_coverage_unavailable(_pytest_line_reason(ctx, python_tests, result), branch_tool)
    value, evidence, error = _trace_line_coverage(ctx)
    if value is None:
        line = _measure(None, True, status="UNAVAILABLE", reason=error or "stdlib trace produced no production coverage")
    else:
        line = _measure(value, True, evidence=evidence, reason="line coverage from stdlib trace under the approved sandbox")
    if branch_tool:
        branch = _measure(None, True, status="UNAVAILABLE", reason=f"{branch_tool} is installed; branch coverage is not estimated from line coverage and was not parsed from a branch report")
    else:
        branch = _measure(None, False, reason="no branch-capable coverage tool is installed")
    return _result([], _coverage_measurements(line, branch))


def _trace_line_coverage(ctx):
    cover = Path(tempfile.mkdtemp(prefix="cqa-cover-")).resolve()
    root = Path(ctx.root).resolve()
    try:
        analyses = ctx.analyses or []
        tests = [analysis for analysis in analyses if _is_test_path(analysis["path"]) and analysis["path"].endswith(".py")]
        starts = sorted({Path(test["path"]).parent.as_posix() for test in tests}) or ["."]
        env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(root)}
        for start in starts:
            start_dir = str(root if start == "." else (root / start).resolve())
            # trace's -m is --missing, so --module is what actually runs unittest.
            command = [
                sys.executable, "-m", "trace", "--count", "--missing",
                "--coverdir", str(cover), "--ignore-module", "unittest",
                "--ignore-dir", sys.prefix, "--module", "unittest", "discover",
                "-s", start_dir, "-t", start_dir, "-q",
            ]
            try:
                run_contained(command, root, ctx.log, timeout=180, write_path=cover, env=env)
            except PermissionError as exc:
                return None, [], str(exc)
        production = {}
        for analysis in analyses:
            if analysis["path"].endswith(".py") and not _is_test_path(analysis["path"]):
                source = _text(ctx, ctx.root / analysis["path"])
                production[analysis["path"]] = "\n".join(line.expandtabs(8).rstrip() for line in source.splitlines())
        hits = missing = 0
        evidence = []
        for cover_file in cover.glob("*.cover"):
            body = cover_file.read_text(encoding="utf-8", errors="replace")
            reconstructed = _reconstruct_cover(body)
            if reconstructed not in production.values():
                continue
            file_hits, file_missing = _count_cover(body)
            if file_hits + file_missing == 0:
                continue
            hits += file_hits
            missing += file_missing
            evidence.append(cover_file.name)
        if hits + missing == 0:
            return None, [], "unittest discover produced no production coverage"
        return round(100.0 * hits / (hits + missing), 1), evidence, ""
    finally:
        shutil.rmtree(cover, ignore_errors=True)


def _reconstruct_cover(text):
    lines = []
    for line in text.splitlines():
        if len(line) >= 7 and (line.startswith(">>>>>> ") or line.startswith("       ") or _count_prefix(line)):
            lines.append(line[7:].rstrip())
        else:
            lines.append(line.rstrip())
    return "\n".join(lines)


def _count_prefix(line):
    prefix = line[:7]
    return prefix.endswith(": ") and prefix[:-2].strip().isdigit()


def _count_cover(text):
    hits = missing = 0
    for line in text.splitlines():
        if _count_prefix(line):
            hits += 1
        elif line.startswith(">>>>>> "):
            missing += 1
    return hits, missing


def run_mutation(ctx):
    analyses = ensure_analyses(ctx)
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    if not tests:
        return _result([], {"TEST-004": _measure(None, False, reason="no tests to mutate")})
    if not ctx.log.allow_repo_execution or not ctx.log.sandbox_confirmed:
        reason = "mutation testing was not run because repository execution is not approved"
        ctx.log.deny("mutation", reason)
        return _result([], {"TEST-004": _measure(None, True, status="UNAVAILABLE", reason=reason)})
    tool = shutil.which("mutmut") or shutil.which("stryker")
    if not tool:
        return _result([], {"TEST-004": _measure(None, True, status="UNAVAILABLE", reason="mutmut or Stryker is not installed; a homemade mutation score was not substituted")})
    return _result([], {"TEST-004": _measure(None, True, status="UNAVAILABLE", reason=f"{Path(tool).name} is installed but its report was not parsed; a homemade mutation score was not substituted")})


_CONCURRENCY = re.compile(
    r"\bthreading\.(?:Thread|Lock|RLock|Semaphore|Event)\b"
    r"|\basyncio\.(?:create_task|gather|Lock|Queue|Task)\b"
    r"|\bThreadPoolExecutor\b"
    r"|\bmultiprocessing\.(?:Process|Pool)\b"
    r"|\bstd::(?:thread|async|mutex)\b"
    r"|\bpthread_create\b"
    r"|\bnew\s+Worker\b"
    r"|\bworker_threads\b"
)


def run_concurrency(ctx):
    analyses = ensure_analyses(ctx)
    primitives = []
    for analysis, text in _iter_source_text(ctx):
        if _is_test_path(analysis["path"]):
            continue
        for match in _CONCURRENCY.finditer(text):
            line_no = text[: match.start()].count("\n") + 1
            source = text.splitlines()[line_no - 1].strip()
            if source.startswith(("import ", "from ", "#include", "using ", "const {", "let {", "var {")) or "require(" in source:
                continue
            primitives.append((analysis["path"], line_no, match.group(0)))
    if not primitives:
        return _result([], {"TEST-010": _measure(None, False, reason="no concurrency primitive")})
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    covered = any(re.search(r"concurren|thread|async", _text(ctx, Path(ctx.root) / test["path"]), re.I) for test in tests)
    findings = []
    if not covered:
        for path, line, name in primitives:
            findings.append(
                _finding(
                    path,
                    line,
                    "concurrency",
                    ["TEST-010"],
                    f"{name} has no concurrency test",
                    "Add a test that mentions the concurrency and asserts the behavior.",
                    classification="advisory",
                    confidence="candidate",
                )
            )
    evidence = [f"{path}:{line}:{name}" for path, line, name in primitives]
    return _result(findings, {"TEST-010": _measure(0 if covered else len(primitives), True, evidence=evidence)})


def discover_requirements(ctx):
    with _locked(ctx):
        if getattr(ctx, "requirements", None) is not None:
            return ctx.requirements
        return _discover_requirements(ctx)


def _discover_requirements(ctx):
    found = []
    root = Path(ctx.root)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in {".md", ".markdown"} and ("doc" in rel.lower() or "requirement" in path.name.lower() or "adr" in rel.lower()):
            found.extend(_requirements_from_text(rel, path.read_text(encoding="utf-8", errors="replace")))
        elif path.suffix.lower() == ".docx" and "requirement" in path.name.lower():
            found.extend(_requirements_from_text(rel, _docx_text(path)))
        elif path.name in {"requirements.yaml", "requirements.yml", "traceability.yaml", "traceability.yml"}:
            found.extend(_requirements_from_yaml(rel, path))
    ctx.requirements = found
    return found


def _docx_text(path):
    try:
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml")
    except (OSError, zipfile.BadZipFile, KeyError):
        return ""
    root = ET.fromstring(xml)
    paragraphs = []
    for paragraph in root.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
        text = "".join(node.text or "" for node in paragraph.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t")).strip()
        if text:
            paragraphs.append(text)
    return "\n".join(paragraphs)


def _requirements_from_text(path, text):
    items = []
    current = None
    for line in text.splitlines():
        heading = HEADING.match(line.strip())
        ident = ID_LINE.match(line.strip())
        if heading or ident:
            if current:
                items.append(current)
            match = heading or ident
            current = {"id": match.group(2) if heading else match.group(1), "text": (match.group(3) if heading else match.group(2)) or "", "file": path, "acceptance": "", "links": []}
            continue
        if current is None:
            continue
        linked = re.match(r"(?i)^(implementation|test|tests|link|links|source|see)\s*:\s*(.+)$", line.strip())
        if linked:
            current["links"].extend(part.strip() for part in linked.group(2).split(",") if part.strip())
            continue
        if line.lower().startswith("acceptance"):
            current["acceptance"] += line + "\n"
        else:
            current["text"] += "\n" + line
    if current:
        items.append(current)
    return items


def _requirements_from_yaml(path, file_path):
    import yaml

    try:
        data = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return []
    items = []
    rows = []
    if isinstance(data, dict):
        rows = data.get("requirements") or data.get("items") or []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if isinstance(row, dict) and row.get("id"):
            items.append(
                {
                    "id": str(row["id"]),
                    "text": str(row.get("text") or row.get("statement") or ""),
                    "file": path,
                    "acceptance": str(row.get("acceptance") or ""),
                    "links": list(row.get("tests") or []) + list(row.get("implementation") or []),
                }
            )
    return items


def _requirement_verified(ctx, item, tests):
    for test in tests:
        text = _text(ctx, Path(ctx.root) / test["path"])
        if item["id"] not in text:
            continue
        if test["language"] == "python":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            if any(isinstance(node, ast.Assert) or _assert_call(node) for node in ast.walk(tree)):
                return True
        elif any(token in text for token in ("expect(", "assert(", "ASSERT_")):
            return True
    return False


def _cited_requirements(ctx, analyses):
    cited = []
    for analysis in analyses:
        text = _text(ctx, Path(ctx.root) / analysis["path"])
        for ident in re.findall(r"\b[A-Z][A-Z0-9]*-\d+\b", text):
            cited.append((analysis["path"], ident))
    return cited


def _missing_trace_links(ctx, specs, analyses):
    known = {item["id"] for item in specs}
    root = Path(ctx.root).resolve()
    missing = []
    seen = set()
    for path, ident in _cited_requirements(ctx, analyses):
        if ident in known or (path, ident) in seen:
            continue
        seen.add((path, ident))
        missing.append({"file": path, "target": ident, "observation": f"{ident} is cited but not defined"})
    for item in specs:
        for link in item.get("links") or []:
            target = str(link).strip()
            if not target or (item["id"], target) in seen:
                continue
            if re.fullmatch(r"[A-Z][A-Z0-9]*-\d+", target):
                if target in known:
                    continue
                seen.add((item["id"], target))
                missing.append({"file": item["file"], "target": target, "observation": f"{item['id']} links to undefined {target}"})
                continue
            if "/" not in target and not Path(target).suffix:
                continue
            candidate = (root / target).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                seen.add((item["id"], target))
                missing.append({"file": item["file"], "target": target, "observation": f"{item['id']} links outside the repository: {target}"})
                continue
            if candidate.is_file():
                continue
            seen.add((item["id"], target))
            missing.append({"file": item["file"], "target": target, "observation": f"{item['id']} links to missing file {target}"})
    return missing


def _method_cites_requirement(text, method, known):
    if any(ident in method for ident in known):
        return True
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return any(ident in text for ident in known)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method:
            segment = ast.get_source_segment(text, node) or ""
            return any(ident in segment for ident in known)
    return False


def _authorized_acceptance_failures(ctx, specs):
    known = {item["id"] for item in specs}
    result = project_test_result(ctx)
    if result is None:
        return None
    failures = []
    for item in result["failures"]:
        rel, method = item.split(":", 1)
        text = _text(ctx, Path(ctx.root) / rel)
        if _method_cites_requirement(text, method, known):
            failures.append(f"{rel}:{method}")
    return failures


def run_requirements(ctx):
    specs = discover_requirements(ctx)
    analyses = ensure_analyses(ctx)
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    production_text = {analysis["path"]: _text(ctx, Path(ctx.root) / analysis["path"]) for analysis in analyses if not _is_test_path(analysis["path"])}
    if not specs:
        missing = _missing_trace_links(ctx, [], analyses)
        findings = [
            _finding(item["file"], 1, "requirements_trace", ["REQ-004"], item["observation"], "Define the requirement or remove the citation.")
            for item in missing
        ]
        return _result(
            findings,
            {
                "REQ-001": _measure(None, False, reason="no authoritative specification"),
                "REQ-002": _measure(None, False, reason="no authoritative specification"),
                "REQ-003": _measure(None, False, reason="no authoritative specification"),
                "REQ-004": _measure(len(missing), bool(missing), reason="" if missing else "no traceability file or requirement citation", evidence=[item["target"] for item in missing]),
                "REQ-005": _measure(None, False, reason="no authoritative specification"),
                "REQ-006": _measure(None, False, reason="no authoritative specification"),
                "REQ-007": _measure(1 if production_text else 0, bool(production_text), status="WARNING" if production_text else "NOT_APPLICABLE", reason="no authoritative specification was discovered"),
                "REQ-008": _measure(None, False, reason="no authoritative specification"),
            },
        )
    implemented = [item for item in specs if any(item["id"] in text for text in production_text.values())]
    verified = [item for item in specs if _requirement_verified(ctx, item, tests)]
    missing_acceptance = [item for item in specs if item.get("acceptance") and not _requirement_verified(ctx, item, tests)]
    by_id = {}
    contradictions = []
    for item in specs:
        previous = by_id.get(item["id"])
        if previous and " ".join(previous["text"].split()) != " ".join(item["text"].split()):
            contradictions.append(item)
        by_id[item["id"]] = item
    missing_links = _missing_trace_links(ctx, specs, analyses)
    authorized = bool(getattr(ctx.log, "allow_repo_execution", False) and getattr(ctx.log, "sandbox_confirmed", False))
    runtime = _authorized_acceptance_failures(ctx, specs) if authorized else []
    runtime_missing = authorized and runtime is None
    if runtime is None:
        runtime = []
    findings = []
    for item in missing_acceptance:
        metrics = ["REQ-003"] if runtime_missing else ["REQ-003", "REQ-008"]
        findings.append(_finding(item["file"], 1, "requirements_trace", metrics, f"{item['id']} has acceptance text and no meaningful asserting test", "Add a test that asserts the acceptance criterion and cites the requirement ID."))
    for item in runtime:
        findings.append(_finding(item.split(":", 1)[0], 1, "requirements_trace", ["REQ-008"], f"acceptance test failed: {item}", "Fix the acceptance test or the implementation."))
    for item in missing_links:
        findings.append(_finding(item["file"], 1, "requirements_trace", ["REQ-004"], item["observation"], "Repair the traceability link or remove it."))
    for item in contradictions:
        findings.append(_finding(item["file"], 1, "requirements_trace", ["REQ-006"], f"{item['id']} is defined with conflicting text", "Keep one statement for the ID."))
    impl_pct = 100.0 * len(implemented) / len(specs)
    ver_pct = 100.0 * len(verified) / len(specs)
    return _result(
        findings,
        {
            "REQ-001": _measure(impl_pct, True),
            "REQ-002": _measure(ver_pct, True),
            "REQ-003": _measure(len(missing_acceptance), True),
            "REQ-004": _measure(len(missing_links), True, evidence=[item["target"] for item in missing_links]),
            "REQ-005": _unmentioned_functions(specs, analyses),
            "REQ-006": _measure(len(contradictions), True),
            "REQ-007": _measure(0, True),
            "REQ-008": _measure(
                None if runtime_missing else len(missing_acceptance) + len(runtime),
                True,
                status="UNAVAILABLE" if runtime_missing else None,
                reason="the authorized acceptance run did not report a result" if runtime_missing else "",
                evidence=[item["id"] for item in missing_acceptance] + runtime,
            ),
        },
    )


def run_ai(ctx):
    specs = discover_requirements(ctx)
    graph = ensure_graph(ctx)
    analyses = ctx.analyses
    known = {item["id"] for item in specs}
    hallucinations = []
    for analysis, text in _iter_source_text(ctx):
        for ident in set(re.findall(r"\b[A-Z][A-Z0-9]*-\d+\b", text)):
            if specs and ident not in known:
                hallucinations.append((analysis["path"], ident))
    findings = [
        _finding(path, 1, "ai_evaluation", ["AI-001"], f"citation {ident} is not in the specification", "Cite a real requirement ID or add the requirement.", rationale="The identifier is present in source and absent from discovered specifications.", sources=[path])
        for path, ident in hallucinations
    ]
    semantic = semantic_candidates(analyses)
    applicable_specs = bool(specs)
    return _result(
        findings,
        {
            "AI-001": _measure(len(hallucinations), applicable_specs, reason="" if applicable_specs else "no specification to contradict"),
            "AI-002": _unlinked_exports(specs, analyses),
            "AI-003": _measure(len(_layer_violations(ctx, analyses)), bool((ctx.config.get("architecture") or {}).get("layers")), reason="" if (ctx.config.get("architecture") or {}).get("layers") else "no documented layer rules"),
            "AI-004": _self_test_gap(ctx, analyses),
            "AI-005": _embedded_test_percent(ctx, [item for item in analyses if not _is_test_path(item["path"]) and any(symbol["kind"] == "function" for symbol in item["symbols"])], [item for item in analyses if _is_test_path(item["path"])]),
            "AI-006": _measure(len(semantic), bool(analyses), status="WARNING" if semantic else None, reason="similarity is not confirmation"),
            "AI-007": _invented_behavior(specs, analyses),
            "AI-008": _specification_divergence(specs, analyses),
        },
    )


def run_performance(ctx):
    analyses = ensure_analyses(ctx)
    specs = discover_requirements(ctx)
    perf_specs = [item for item in specs if re.search(r"latency|throughput|memory|cpu", item.get("text") or "", re.I)]
    numbers = _performance_numbers(ctx)
    benchmarks = [analysis["path"] for analysis in analyses if "bench" in analysis["path"].lower()]
    if numbers:
        benchmarks.append("measurement-file")
    return _result(
        [],
        {
            "PERF-001": _performance_ratio(perf_specs, numbers, "latency", "latency", "latency_target", False),
            "PERF-002": _performance_ratio(perf_specs, numbers, "throughput", "throughput", "throughput_target", True),
            "PERF-003": _performance_ratio(perf_specs, numbers, "memory", "memory", "memory_budget", False),
            "PERF-004": _performance_ratio(perf_specs, numbers, "cpu", "cpu", "cpu_budget", False),
            "PERF-005": _measure(0 if benchmarks else len(perf_specs), bool(perf_specs), reason="" if perf_specs else "no performance requirement"),
            "PERF-006": _measure(_loop_depth(ctx), bool(analyses)),
            "PERF-007": _loop_data_access(ctx),
            "PERF-008": _unclosed_opens(ctx),
        },
    )


def run_maintainability(ctx):
    analyses = ensure_analyses(ctx)
    history = _git_numstat(ctx)
    markers = []
    documented = 0
    public = 0
    for analysis, text in _iter_source_text(ctx):
        markers.extend(_debt_markers(analysis["path"], text, analysis.get("language")))
        lines = text.splitlines()
        for symbol in analysis["symbols"]:
            if not _public_callable(symbol):
                continue
            public += 1
            if symbol.get("doc") or _leading_doc(lines, symbol.get("line") or 1):
                documented += 1
    docs_pct = 100.0 * documented / public if public else None
    churn_applicable = history is not None and len(history) >= 1
    max_churn = max(history.values()) if history else None
    return _result(
        [],
        {
            "MAINT-001": _measure(max_churn, churn_applicable, reason="" if churn_applicable else "git history is unavailable and was not stored as zero"),
            "MAINT-002": _measure(len(markers), bool(analyses), evidence=[f"{item['file']}:{item['line']}:{item['kind']}" for item in markers]),
            "MAINT-003": _co_change(ctx),
            "MAINT-004": _rework(ctx),
            "MAINT-005": _export_diff(ctx)[0],
            "MAINT-006": _measure(docs_pct if public else None, bool(public), reason="" if public else "no public functions"),
            "MAINT-007": _freshness(ctx),
            "MAINT-008": _export_diff(ctx)[1],
        },
    )


def _debt_markers(path, text, language):
    rows = _python_comment_lines(text) if language == "python" else _script_comment_lines(text)
    found = []
    for line_no, body in rows:
        for match in re.finditer(r"\b(TODO|FIXME|HACK)\b", body):
            found.append({"file": path, "line": line_no, "kind": match.group(1)})
    return found


def _public_callable(symbol):
    if symbol.get("kind") not in {"function", "method"}:
        return False
    name = symbol.get("name") or ""
    return bool(name) and not name.startswith("_") and not symbol.get("private")


def _leading_doc(lines, line_no):
    index = line_no - 2
    while index >= 0 and not lines[index].strip():
        index -= 1
    if index < 0:
        return False
    text = lines[index].strip()
    if text.startswith(("//", "/*")) or text.endswith("*/"):
        return True
    if text.startswith("#") and not text.startswith(("#include", "#if", "#ifdef", "#ifndef", "#define", "#pragma", "#endif", "#else", "#elif", "#undef")):
        return True
    return False


def _performance_numbers(ctx):
    import json

    import yaml

    numbers = {}
    root = Path(ctx.root)
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        if path.name in {"quality-auditor.yaml", "exports-baseline.yaml"}:
            continue
        if not re.search(r"bench|perf|measure", path.name, re.I):
            continue
        try:
            if path.suffix.lower() == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    numbers[str(key)] = float(value)
    return numbers


def _performance_ratio(specs, numbers, word, observed_key, target_key, invert):
    declared = any(word in (item.get("text") or "").lower() for item in specs) or {observed_key, target_key} <= set(numbers)
    if not declared:
        return _measure(None, False, reason=f"no declared {word} target; production history was not inferred")
    if observed_key not in numbers or target_key not in numbers or numbers[observed_key] == 0 and invert:
        return _measure(None, True, status="UNAVAILABLE", reason=f"a {word} target exists but no numeric measurement was read")
    observed = numbers[observed_key]
    target = numbers[target_key]
    if target == 0 or (invert and observed == 0):
        return _measure(None, True, status="UNAVAILABLE", reason=f"the {word} measurement could not be divided")
    ratio = (target / observed) if invert else (observed / target)
    return _measure(round(ratio, 4), True)


def _script_loop_depth(text):
    tokens, _error, _comments = _scan_tokens(text)
    best = 0
    loop_depth = 0
    braces = []
    pending = False
    paren = 0
    for kind, value, _line in tokens:
        if kind == "op" and value == "(":
            paren += 1
            continue
        if kind == "op" and value == ")":
            paren = max(0, paren - 1)
            continue
        if kind == "id" and value in _LOOP_WORDS and paren == 0:
            pending = True
            continue
        if kind == "op" and value == "{":
            if pending and paren == 0:
                braces.append("loop")
                loop_depth += 1
                best = max(best, loop_depth)
                pending = False
            else:
                braces.append("other")
            continue
        if kind == "op" and value == "}":
            if braces and braces.pop() == "loop":
                loop_depth = max(0, loop_depth - 1)
            pending = False
    return best


def _loop_depth(ctx):
    best = 0

    def walk(node, depth):
        nonlocal best
        next_depth = depth + isinstance(node, (ast.For, ast.AsyncFor, ast.While))
        best = max(best, next_depth)
        for child in ast.iter_child_nodes(node):
            walk(child, next_depth)

    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is not None:
            walk(tree, 0)
            continue
        if analysis.get("language") == "python":
            continue
        best = max(best, _script_loop_depth(_text(ctx, Path(ctx.root) / analysis["path"])))
    return best


def _baseline_exports(ctx):
    import yaml

    configured = ctx.config.get("export_baseline")
    if isinstance(configured, list):
        return {str(item) for item in configured}
    filename = ctx.config.get("export_baseline_file") or "exports-baseline.yaml"
    path = Path(ctx.root) / filename
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    symbols = data.get("symbols") if isinstance(data, dict) else data
    if not isinstance(symbols, list):
        return None
    return {str(item) for item in symbols}


def _current_exports(ctx):
    names = set()
    for analysis in ctx.analyses or []:
        if _is_test_path(analysis["path"]):
            continue
        for symbol in analysis["symbols"]:
            if symbol.get("exported") and symbol["kind"] in {"function", "method", "class"}:
                names.add(symbol["name"])
    return names


def _export_diff(ctx):
    baseline = _baseline_exports(ctx)
    if baseline is None:
        missing = _measure(None, False, reason="no baseline export snapshot")
        return missing, missing
    current = _current_exports(ctx)
    removed = sorted(baseline - current)
    added = sorted(current - baseline)
    return _measure(len(removed), True, evidence=removed), _measure(len(added), True, evidence=added)


def _git_numstat(ctx):
    from cqa.security import git_read

    probe = git_read(ctx.root, ["rev-parse", "--is-inside-work-tree"], ctx.log)
    if probe is None:
        return None
    log = git_read(ctx.root, ["log", "--numstat", "--format=%H"], ctx.log)
    if log is None:
        return None
    counts = Counter()
    for line in log.stdout.decode("utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2]:
            counts[parts[2]] += 1
    return counts


def run_observability(ctx):
    services = []
    for analysis, text in _iter_source_text(ctx):
        if any(entry["kind"] == "framework" for entry in analysis["entries"]):
            services.append((analysis, text))
    if not services:
        return _result([], {f"OBS-{index:03d}": _measure(None, False, reason="no service entry point or runtime evidence") for index in range(1, 7)})
    runbook = any("runbook" in path.name.lower() or path.name.lower() in {"operations.md", "ops.md"} for path in Path(ctx.root).rglob("*.md"))
    missing_logs = missing_metrics = missing_trace = swallowed = missing_health = missing_ops = 0
    for analysis, text in services:
        if not re.search(r"\b(logging\.|getLogger\(|logger\.|console\.log|log\.(?:info|error|warning|debug)\()", text):
            missing_logs += 1
        if not re.search(r"prometheus|statsd|opentelemetry|meter\(|counter\(", text, re.I):
            missing_metrics += 1
        if not re.search(r"opentelemetry|tracer|start_span|trace\.get", text, re.I):
            missing_trace += 1
        swallowed += sum(1 for handler in analysis["handlers"] if handler["bare"] or handler["empty"])
        healthy = bool(re.search(r"\b(health|ready|live|healthz)\b", text, re.I))
        if not healthy:
            missing_health += 1
        if not healthy and not runbook:
            missing_ops += 1
    return _result(
        [],
        {
            "OBS-001": _measure(missing_logs, True),
            "OBS-002": _measure(missing_metrics, True),
            "OBS-003": _measure(missing_trace, True),
            "OBS-004": _measure(swallowed, True),
            "OBS-005": _measure(missing_health, True),
            "OBS-006": _measure(missing_ops, True),
        },
    )


def _resilience_measure(ctx):
    call = re.compile(
        r"(?<![\w.])(?:requests\.(?:get|post|put|delete|patch|head|request)|httpx\.(?:get|post|put|delete|patch|request)|urllib\.request\.urlopen|subprocess\.(?:run|call|check_call|check_output|Popen)|os\.system|std::system|popen|fetch|axios\.(?:get|post|put|delete|patch|head|request)|https?\.(?:get|request)|child_process\.exec|execFileSync|execFile|execSync|spawnSync|spawn)\s*\("
    )
    confirmed = 0
    uncertain = 0
    saw = False
    for _analysis, text in _iter_source_text(ctx):
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if not call.search(line):
                continue
            saw = True
            window = "\n".join(lines[index : index + 4])
            if ")" not in window:
                uncertain += 1
                continue
            statement = window[: window.find(")") + 1]
            if "timeout" not in statement:
                confirmed += 1
    if not saw:
        return _measure(None, False, reason="no network or subprocess call is visible")
    if confirmed == 0 and uncertain:
        return _measure(None, True, status="INCONCLUSIVE", reason="external calls were visible but the timeout argument was not on a closed statement")
    reason = f"{uncertain} additional calls were not closed in the scanned window" if uncertain else ""
    return _measure(confirmed, True, reason=reason)


_RANDOM_CALL = re.compile(
    r"(?<![\w.])(?:random\.(?:random|randint|choice|uniform|randrange|sample)|Math\.random|crypto\.randomBytes|std::rand|rand)\s*\("
)
_SEED_CALL = re.compile(r"(?<![\w.])(?:random\.seed|numpy\.random\.seed|np\.random\.seed|srand)\s*\(")
_DETERMINISM = re.compile(r"\bdeterminis(?:m|tic)\b", re.I)


def _random_sites(analysis, text):
    if _SEED_CALL.search(text):
        return []
    sites = []
    for match in _RANDOM_CALL.finditer(text):
        sites.append((analysis["path"], text.count("\n", 0, match.start()) + 1))
    return sites


def run_reliability(ctx):
    analyses = ensure_analyses(ctx)
    findings = []
    bare = 0
    for analysis in analyses:
        for handler in analysis["handlers"]:
            if handler["bare"] or handler["empty"]:
                bare += 1
                findings.append(_finding(analysis["path"], handler["line"], "reliability", ["REL-001"], "exception handler discards failures", "Handle the exception or re-raise it."))
    texts = list(_iter_source_text(ctx))
    quant = any(QUANT_WORD.search(text) for _analysis, text in texts)
    claims = quant or any(_is_test_path(analysis["path"]) and _DETERMINISM.search(text) for analysis, text in texts)
    sites = [site for analysis, text in texts for site in _random_sites(analysis, text)]
    evidence = [f"{path}:{line}" for path, line in sites]
    if claims:
        for path, line in sites:
            findings.append(_finding(path, line, "reliability", ["REL-003"], "unseeded random in quantitative or determinism-claiming code", "Seed the generator or use a deterministic source."))
        random_measure = _measure(len(sites), True, evidence=evidence)
    elif sites:
        for path, line in sites:
            findings.append(
                _finding(
                    path,
                    line,
                    "reliability",
                    ["REL-003"],
                    "unseeded random outside quantitative code",
                    "Seed the generator where the result must be reproducible.",
                    confidence="candidate",
                    classification="advisory",
                )
            )
        random_measure = _measure(len(sites), True, status="WARNING", reason="unseeded random outside quantitative code is advisory", evidence=evidence)
    else:
        random_measure = _measure(None, False, reason="not a quantitative repository")
    return _result(
        findings,
        {
            "REL-001": _measure(bare, bool(analyses)),
            "REL-002": _resilience_measure(ctx),
            "REL-003": random_measure,
        },
    )


def is_quantitative(ctx):
    for _analysis, text in _iter_source_text(ctx):
        if QUANT_WORD.search(text):
            return True
    return False


def run_quantitative(ctx):
    if not is_quantitative(ctx):
        return _result([], {f"QUANT-{index:03d}": _measure(None, False, reason="not a quantitative repository") for index in range(1, 7)})
    analyses = ctx.analyses
    tests = [analysis for analysis in analyses if _is_test_path(analysis["path"])]
    risk_functions = []
    snapshot_writes = []
    ui_inventions = []
    model_exists = any("model" in analysis["path"].lower() for analysis in analyses)
    for analysis, text in _iter_source_text(ctx):
        for symbol in analysis["symbols"]:
            if re.search(r"var|value_at_risk|expected_shortfall|dv01|attribution", symbol["name"], re.I):
                risk_functions.append((analysis["path"], symbol))
        for match in re.finditer(r"\bsnapshot\b\s*(?:\[[^\]]+\]|\.\w+)\s*=", text):
            line = text[: match.start()].count("\n") + 1
            snapshot_writes.append((analysis["path"], line))
        if "/ui/" in f"/{analysis['path']}" or analysis["path"].startswith("ui/") or "/ui/" in analysis["path"]:
            if QUANT_WORD.search(text) and model_exists and "model." not in text:
                ui_inventions.append(analysis["path"])
    def tested(name):
        return any(name in _text(ctx, Path(ctx.root) / test["path"]) and ("assert" in _text(ctx, Path(ctx.root) / test["path"])) for test in tests)

    missing_risk = [item for item in risk_functions if not tested(item[1]["name"])]
    identities = _declared_ids(ctx, re.compile(r"\b(IDENT-\d+)\b"))
    unit_ids = _declared_ids(ctx, re.compile(r"\b((?:UNIT|TOL)-\d+)\b"))
    missing_identities = _ids_without_assertion(ctx, tests, identities)
    missing_units = _ids_without_assertion(ctx, tests, unit_ids)
    findings = []
    for ident in missing_identities:
        findings.append(_finding(None, 1, "quantitative", ["QUANT-001"], f"{ident} has no asserting test", "Assert the identity in a test that cites its ID."))
    for ident in missing_units:
        findings.append(_finding(None, 1, "quantitative", ["QUANT-002"], f"{ident} has no asserting test", "Assert the unit or tolerance in a test that cites its ID."))
    for path, symbol in missing_risk:
        findings.append(_finding(path, symbol["line"], "quantitative", ["QUANT-003"], f"{symbol['name']} has no asserting reference test", "Add a reference calculation test."))
    for path, line in snapshot_writes:
        findings.append(_finding(path, line, "quantitative", ["QUANT-004"], "market snapshot is mutated", "Build a new snapshot instead of assigning into the existing one."))
    for path in ui_inventions:
        findings.append(_finding(path, 1, "quantitative", ["QUANT-006"], "UI code appears to compute a risk measure", "Read the number from the model or provenance record.", rationale="The UI path contains a risk-measure token while a model module exists."))
    return _result(
        findings,
        {
            "QUANT-001": _measure(len(missing_identities), bool(identities), reason="" if identities else "no numerical identity ID was declared"),
            "QUANT-002": _measure(len(missing_units), bool(unit_ids), reason="" if unit_ids else "no unit or tolerance constraint ID was declared"),
            "QUANT-003": _measure(len(missing_risk), bool(risk_functions), reason="" if risk_functions else "no VaR, ES, or DV01 symbol"),
            "QUANT-004": _measure(len(snapshot_writes), True),
            "QUANT-005": _measure(len([item for item in risk_functions if "attrib" in item[1]["name"].lower() and not tested(item[1]["name"])]), any("attrib" in item[1]["name"].lower() for item in risk_functions), reason="" if any("attrib" in item[1]["name"].lower() for item in risk_functions) else "no attribution symbol"),
            "QUANT-006": _measure(len(ui_inventions), model_exists, reason="" if model_exists else "no model module to compare with a UI"),
        },
    )


def _script_bases(tokens):
    bases = {}
    index = 0
    while index < len(tokens):
        kind, value, _line = tokens[index]
        if kind == "id" and value in {"class", "struct"} and index + 1 < len(tokens) and tokens[index + 1][0] == "id":
            name = tokens[index + 1][1]
            cursor = index + 2
            if cursor + 1 < len(tokens) and tokens[cursor][1] == "extends" and tokens[cursor + 1][0] == "id":
                bases[name] = tokens[cursor + 1][1]
            elif cursor < len(tokens) and tokens[cursor][1] == ":":
                cursor += 1
                while cursor < len(tokens) and tokens[cursor][1] in {"public", "private", "protected", "virtual"}:
                    cursor += 1
                if cursor < len(tokens) and tokens[cursor][0] == "id":
                    bases[name] = tokens[cursor][1]
        index += 1
    return bases


def _script_interface_widths(analysis, text):
    tokens, _error, _comments = _scan_tokens(text)
    implemented = set(_script_bases(tokens).values())
    lines = text.splitlines()
    methods = {}
    for symbol in analysis["symbols"]:
        if symbol["kind"] != "method" or not symbol.get("parent"):
            continue
        methods.setdefault(symbol["parent"], []).append(symbol)
    widths = []
    for name, group in methods.items():
        if name not in implemented:
            continue
        stateful = False
        for symbol in group:
            body = "\n".join(lines[symbol["line"] - 1 : symbol.get("end_line") or symbol["line"]])
            if re.search(r"\b(this|self)\b", body):
                stateful = True
        if stateful:
            continue
        widths.append(len(group))
    return widths


def _interface_width(ctx):
    widths = []
    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is None:
            if analysis.get("language") != "python":
                widths.extend(_script_interface_widths(analysis, _text(ctx, Path(ctx.root) / analysis["path"])))
            continue
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        names = {node.name: node for node in classes}
        for node in classes:
            methods = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not item.name.startswith("__")
            ]
            if len(methods) < 1:
                continue
            stateful = False
            for method in methods:
                for child in ast.walk(method):
                    if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "self":
                        stateful = True
            if stateful:
                continue
            implemented = any(
                isinstance(base, ast.Name) and base.id == node.name
                for other in names.values()
                if other is not node
                for base in other.bases
            )
            if implemented:
                widths.append(len(methods))
    if not widths:
        return _measure(None, False, reason="no interface-like type was identified")
    return _measure(max(widths), True)


def _spec_blob(specs):
    return " ".join(f"{item.get('id', '')} {item.get('text', '')}" for item in specs).lower()


def _unmentioned_functions(specs, analyses):
    if not specs:
        return _measure(None, False, reason="no authoritative specification")
    blob = _spec_blob(specs)
    count = 0
    for analysis in analyses:
        if _is_test_path(analysis["path"]):
            continue
        for symbol in analysis["symbols"]:
            if symbol["kind"] not in {"function", "method"}:
                continue
            name = symbol["name"].lower()
            if name.startswith("_") or name in blob or name.replace("_", " ") in blob:
                continue
            count += 1
    if count:
        return _measure(count, True, status="WARNING", reason="unlinked symbols stay candidates and are not confirmed")
    return _measure(0, True)


def _unlinked_exports(specs, analyses):
    if not specs:
        return _measure(None, False, reason="no specification to compare with exports")
    blob = _spec_blob(specs)
    count = 0
    for analysis in analyses:
        if _is_test_path(analysis["path"]):
            continue
        for symbol in analysis["symbols"]:
            if not symbol.get("exported"):
                continue
            name = symbol["name"].lower()
            if name in blob or name.replace("_", " ") in blob:
                continue
            count += 1
    if count:
        return _measure(count, True, status="WARNING", reason="unlinked exports are candidates, not confirmed unnecessary functionality")
    return _measure(0, True)


def _invented_behavior(specs, analyses):
    clauses = [item for item in specs if "out of scope" in f"{item.get('text', '')} {item.get('id', '')}".lower()]
    if not clauses:
        return _measure(None, False, reason="no out-of-scope clause" if specs else "no specification")
    names = {symbol["name"].lower() for analysis in analyses for symbol in analysis["symbols"]}
    hits = 0
    for item in clauses:
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", item.get("text") or ""):
            token = word.lower()
            if token in {"out", "scope", "this", "that", "with", "from", "the"}:
                continue
            if token in names:
                hits += 1
                break
    return _measure(hits, True)


def _specification_divergence(specs, analyses):
    if not specs:
        return _measure(None, False, reason="no specification")
    names = {symbol["name"].lower() for analysis in analyses for symbol in analysis["symbols"]}
    missing = 0
    stop = {"the", "and", "with", "for", "that", "this", "shall", "must", "from", "into", "when", "are", "not"}
    for item in specs:
        text = item.get("text") or ""
        if "defer" in text.lower():
            continue
        tokens = [token.lower() for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text.split("\n")[0])]
        tokens = [token for token in tokens if token not in stop]
        if tokens and not any(token in names for token in tokens):
            missing += 1
    return _measure(missing, True)


def _is_data_call(node):
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in {"open", "read", "query", "execute", "urlopen"}
    if isinstance(func, ast.Attribute):
        return func.attr in {"read", "read_text", "read_bytes", "query", "execute", "urlopen"}
    return False


def _is_open_call(node):
    func = getattr(node, "func", None)
    return isinstance(node, ast.Call) and isinstance(func, ast.Name) and func.id == "open"


_LOOP_WORDS = {"for", "while", "do"}
_DATA_CALLS = {"open", "read", "query", "execute", "urlopen", "readFile", "readFileSync", "createReadStream", "fetch"}


def _script_loop_reads(text):
    tokens, _error, _comments = _scan_tokens(text)
    count = 0
    loop_depth = 0
    braces = []
    pending = False
    paren = 0
    for index, (kind, value, _line) in enumerate(tokens):
        if kind == "op" and value == "(":
            paren += 1
            continue
        if kind == "op" and value == ")":
            paren = max(0, paren - 1)
            continue
        if kind == "id" and value in _LOOP_WORDS and paren == 0:
            pending = True
            continue
        if kind == "op" and value == "{":
            if pending and paren == 0:
                braces.append("loop")
                loop_depth += 1
                pending = False
            else:
                braces.append("other")
            continue
        if kind == "op" and value == "}":
            if braces and braces.pop() == "loop":
                loop_depth = max(0, loop_depth - 1)
            pending = False
            continue
        call = kind == "id" and value in _DATA_CALLS and index + 1 < len(tokens) and tokens[index + 1][1] == "("
        if call and (loop_depth > 0 or (pending and paren == 0)):
            count += 1
        if pending and paren == 0 and kind == "sym" and value == ";":
            pending = False
    return count


def _loop_data_access(ctx):
    count = 0

    def walk(node, depth):
        nonlocal count
        if isinstance(node, ast.Call) and depth > 0 and _is_data_call(node):
            count += 1
        next_depth = depth + isinstance(node, (ast.For, ast.AsyncFor, ast.While))
        for child in ast.iter_child_nodes(node):
            walk(child, next_depth)

    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is not None:
            walk(tree, 0)
            continue
        if analysis.get("language") == "python":
            continue
        count += _script_loop_reads(_text(ctx, Path(ctx.root) / analysis["path"]))
    if count == 0:
        return _measure(None, False, reason="no data-access call inside a loop was confirmed")
    return _measure(count, True, reason="lexical loop heuristic; not a confirmed defect")


def _unclosed_opens(ctx):
    count = 0
    saw = False
    for analysis in ctx.analyses or []:
        tree = _python_tree(ctx, analysis)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            text = _span(_text(ctx, Path(ctx.root) / analysis["path"]), node)
            managed = set()

            def mark_with(current):
                if isinstance(current, ast.With):
                    for item in current.items:
                        if _is_open_call(item.context_expr):
                            managed.add(id(item.context_expr))
                for child in ast.iter_child_nodes(current):
                    mark_with(child)

            mark_with(node)
            for child in ast.walk(node):
                if _is_open_call(child):
                    saw = True
                    if id(child) not in managed and ".close(" not in text:
                        count += 1
    if not saw:
        return _measure(None, False, reason="no Python open() call")
    return _measure(count, True)


def _git_commits(ctx):
    from cqa.security import git_read

    if git_read(ctx.root, ["rev-parse", "--is-inside-work-tree"], ctx.log) is None:
        return None
    log = git_read(ctx.root, ["log", "--numstat", "--format=%H"], ctx.log)
    if log is None:
        return None
    commits = []
    current = None
    for line in log.stdout.decode("utf-8", errors="replace").splitlines():
        if re.fullmatch(r"[0-9a-f]{7,40}", line):
            if current is not None:
                commits.append(current)
            current = set()
            continue
        parts = line.split("\t")
        if current is not None and len(parts) == 3 and parts[2]:
            current.add(parts[2])
    if current is not None:
        commits.append(current)
    return commits


def _co_change(ctx):
    commits = _git_commits(ctx)
    if not commits or len(commits) < 3:
        return _measure(None, False, reason="fewer than three commits")
    pairs = Counter()
    for files in commits:
        names = sorted(files)
        for index, left in enumerate(names):
            for right in names[index + 1 :]:
                pairs[(left, right)] += 1
    return _measure(sum(1 for count in pairs.values() if count >= 3), True)


def _rework(ctx):
    commits = _git_commits(ctx)
    if not commits or len(commits) < 5:
        return _measure(None, False, reason="fewer than five commits")
    window = commits[:10]
    counts = Counter()
    for files in window:
        counts.update(files)
    threshold = len(window) / 2
    return _measure(sum(1 for count in counts.values() if count > threshold), True)


RUNNERS = {
    "syntax_static": run_syntax_static,
    "symbol_index": run_symbol_index,
    "dead_code": run_dead_code,
    "clean_code": run_clean_code,
    "architecture": run_architecture,
    "duplication": run_duplication,
    "semantic_duplication": run_semantic_duplication,
    "secrets": run_secrets,
    "security_sast": run_security_sast,
    "dependency_audit": run_dependency_audit,
    "insecure_config": run_insecure_config,
    "testing": run_testing,
    "coverage": run_coverage,
    "mutation_testing": run_mutation,
    "concurrency": run_concurrency,
    "requirements_trace": run_requirements,
    "ai_evaluation": run_ai,
    "performance_benchmarks": run_performance,
    "maintainability": run_maintainability,
    "observability": run_observability,
    "reliability": run_reliability,
    "quantitative": run_quantitative,
}
