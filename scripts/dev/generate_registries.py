#!/usr/bin/env python3
"""Regenerate the authoritative YAML registries from the agreed metric set.

The files under `.cursor/skills/code-quality-auditor/config/` are what the
engine loads. This script only rewrites them so the 112 metrics stay aligned
with the check map. Do not treat this script as a second runtime catalog.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / ".cursor" / "skills" / "code-quality-auditor"
CONFIG = SKILL / "config"
REF = SKILL / "references"

LANGS = ["python", "javascript", "typescript", "cpp"]


def q(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if value is None:
        return "null"
    return json.dumps(str(value), ensure_ascii=False)


def dump(obj, indent=0):
    space = "  " * indent
    if isinstance(obj, dict):
        lines = []
        for key, value in obj.items():
            if isinstance(value, (dict, list)):
                if value == [] or value == {}:
                    lines.append(f"{space}{key}: {dump(value)}")
                else:
                    lines.append(f"{space}{key}:")
                    lines.append(dump(value, indent + 1))
            else:
                lines.append(f"{space}{key}: {q(value)}")
        return "\n".join(lines)
    if isinstance(obj, list):
        if not obj:
            return "[]"
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                rendered = dump(item, indent + 1)
                child = rendered.splitlines()
                lines.append(f"{space}- {child[0].strip()}")
                for extra in child[1:]:
                    lines.append(extra)
            else:
                lines.append(f"{space}- {q(item)}")
        return "\n".join(lines)
    return q(obj)


def metric(
    mid,
    sector,
    name,
    description,
    criticality,
    verifies,
    calculation,
    result_range,
    operator,
    value,
    evaluation_method,
    recommended_tools,
    *,
    kind,
    classification,
    units,
    direction,
    applicability,
    evidence_requirements,
):
    return {
        "id": mid,
        "sector": sector,
        "name": name,
        "description": description,
        "criticality": criticality,
        "verifies": verifies,
        "calculation": calculation,
        "result_range": result_range,
        "red_line": {"operator": operator, "value": value},
        "evaluation_method": evaluation_method,
        "recommended_tools": recommended_tools,
        "units": units,
        "direction": direction,
        "applicability": applicability,
        "evidence_requirements": evidence_requirements,
        "kind": kind,
        "classification": classification,
    }


def defect(mid, sector, name, description, criticality, verifies, calculation, evaluation, tools, applicability, evidence, units="count"):
    return metric(
        mid, sector, name, description, criticality, verifies, calculation,
        "integer >= 0", "max", 0, evaluation, tools,
        kind="defect_counter", classification="blocking", units=units,
        direction="lower_is_better", applicability=applicability,
        evidence_requirements=evidence,
    )


def quality(mid, sector, name, description, criticality, verifies, calculation, result_range, operator, value, units, evaluation, tools, applicability, evidence, *, classification="advisory", direction=None):
    if direction is None:
        direction = "higher_is_better" if operator == "min" else "lower_is_better"
    return metric(
        mid, sector, name, description, criticality, verifies, calculation,
        result_range, operator, value, evaluation, tools,
        kind="quality_measure", classification=classification, units=units,
        direction=direction, applicability=applicability,
        evidence_requirements=evidence,
    )


BUILTIN = ["cqa-builtin"]
STYLE_TOOLS = BUILTIN + ["ruff", "eslint", "radon", "clang-tidy"]
GRAPH_TOOLS = BUILTIN + ["vulture", "knip", "clang-tidy"]
SEC_TOOLS = BUILTIN + ["semgrep", "bandit"]
SECRET_TOOLS = BUILTIN + ["gitleaks", "detect-secrets"]
TEST_TOOLS = BUILTIN + ["pytest", "jest", "ctest"]
DUP_TOOLS = BUILTIN + ["jscpd"]

CODE = "Applicable when at least one supported source file is in scope."
TESTS = "Applicable when the selected sources contain executable tests for a supported language."
NO_TESTS = "Applicable when supported production functions exist; not applicable to empty repositories."
DEPS = "Applicable when a dependency manifest is present. Not applicable when the repository declares no dependencies."
QUANT = "Applicable when source declares VaR, ES, DV01, or another quantitative risk calculation. Otherwise not applicable. The same rule applies to every repository."
PERF_REQ = "Applicable when requirements or benchmark files define a performance target. Otherwise not applicable."
SERVICE = "Applicable when a service entry point or runtime instrumentation requirement is present. Otherwise not applicable."
GIT = "Applicable when the repository has comparable git history. Unavailable history is not treated as zero."
LAYERS = "Applicable when architecture layers or dependency rules are configured. Otherwise not applicable."
SPECS = "Applicable when an authoritative specification, ADR, or acceptance document is discovered."

METRICS = [
    quality("CC-001", "clean_code", "Naming conventions", "Names follow the language convention.", "medium", "Identifiers use the conventional form for their language.", "Count of public identifiers that break snake_case, camelCase, or PascalCase rules.", "integer >= 0", "max", 0, "count", "Static symbol names from language adapters.", STYLE_TOOLS, CODE, "Symbol table with file and line."),
    quality("CC-002", "clean_code", "Function length", "Functions stay within the agreed size limit.", "medium", "Functions are small enough to inspect.", "Maximum function length in lines.", "integer >= 0", "max", 60, "lines", "Line span of each function symbol.", STYLE_TOOLS, CODE, "Function spans."),
    quality("CC-003", "clean_code", "File length", "Source files stay within the agreed size limit.", "low", "Files are small enough to navigate.", "Maximum file length in lines.", "integer >= 0", "max", 400, "lines", "Line count of each source file.", STYLE_TOOLS, CODE, "File lengths."),
    quality("CC-004", "clean_code", "Cyclomatic complexity", "Control-flow complexity stays under the red line.", "medium", "Functions avoid excessive branching.", "Maximum cyclomatic complexity.", "integer >= 1", "max", 10, "complexity", "Decision-point count from the language adapter.", STYLE_TOOLS, CODE, "Per-function complexity."),
    quality("CC-005", "clean_code", "Cognitive complexity", "Nested logic stays understandable.", "medium", "Nested conditions stay within the limit.", "Maximum cognitive complexity.", "integer >= 0", "max", 15, "complexity", "Nesting-weighted branch count.", STYLE_TOOLS, CODE, "Per-function cognitive score."),
    quality("CC-006", "clean_code", "Nesting depth", "Blocks are not nested too deeply.", "medium", "Deep nesting is limited.", "Maximum nesting depth.", "integer >= 0", "max", 4, "depth", "Maximum AST or brace nesting per function.", STYLE_TOOLS, CODE, "Nesting measurements."),
    quality("CC-007", "clean_code", "Parameter count", "Functions do not take too many parameters.", "low", "Parameter lists stay short.", "Maximum parameter count.", "integer >= 0", "max", 6, "count", "Parameter list length.", STYLE_TOOLS, CODE, "Function signatures."),
    quality("CC-008", "clean_code", "Style consistency", "The repository uses one formatting convention.", "low", "Indentation and quote style are consistent.", "Count of files whose dominant indentation, dominant quote style, or trailing whitespace disagrees with the repository majority.", "integer >= 0", "max", 0, "count", "Indentation and trailing-whitespace scan.", STYLE_TOOLS, CODE, "Per-file style sample."),
    quality("CC-009", "clean_code", "Unused imports", "Imports resolve to a used name.", "medium", "Imported names are referenced.", "Count of unused imports.", "integer >= 0", "max", 0, "count", "Import versus reference comparison.", STYLE_TOOLS, CODE, "Import and reference edges."),
    quality("CC-010", "clean_code", "Unused variables", "Local assignments are referenced.", "low", "Assigned locals are used.", "Count of unused local assignments where the adapter can see them.", "integer >= 0", "max", 0, "count", "Assignment and load comparison in Python; limited in other languages.", STYLE_TOOLS, "Applicable to Python functions. Other languages report the adapter limit.", "Local symbol table."),
    quality("CC-011", "clean_code", "Magic literals", "Unexplained numeric literals are rare.", "low", "Non-trivial literals are named or explained.", "Count of numeric literals outside declarations and tests.", "integer >= 0", "max", 25, "count", "Numeric token scan excluding -1, 0, 1, and 2.", STYLE_TOOLS, CODE, "Token list."),
    quality("CC-012", "clean_code", "Boolean complexity", "Boolean expressions stay simple.", "low", "Conditions do not chain too many boolean operators.", "Maximum boolean-operator chain length.", "integer >= 0", "max", 4, "count", "Boolean operator count per condition.", STYLE_TOOLS, "Applicable to Python conditions and to languages where the adapter records conditions.", "Condition nodes."),
    quality("CC-013", "clean_code", "Formatting consistency", "Lines do not exceed the length limit and do not mix tabs.", "low", "Basic formatting is uniform.", "Count of overlong lines and tab/space mixtures.", "integer >= 0", "max", 0, "count", "Line scan for length and mixed indentation.", STYLE_TOOLS, CODE, "Source lines."),
    quality("CC-014", "clean_code", "Commented-out code", "Source does not keep large blocks of commented-out code.", "low", "Comments are not a second implementation.", "Count of commented-out code blocks of at least three lines.", "integer >= 0", "max", 0, "count", "Comment block heuristic.", STYLE_TOOLS, CODE, "Comment spans."),
    quality("ARCH-001", "architecture", "Single responsibility", "Modules and types do not accumulate unrelated responsibilities.", "medium", "Large types are reviewed for mixed responsibilities.", "Maximum method count of a class or impl block.", "integer >= 0", "max", 20, "count", "Method count per type.", GRAPH_TOOLS, CODE, "Type symbol table."),
    quality("ARCH-002", "architecture", "Open-closed extension", "Behavior is extended without editing unrelated modules when an extension rule exists.", "medium", "Configured extension points are used.", "Count of configured extension-point violations.", "integer >= 0", "max", 0, "count", "Compare configured extension points with direct edits. Not applicable without a rule.", GRAPH_TOOLS, "Applicable only when extension-point rules are configured.", "Architecture configuration and edit sites."),
    quality("ARCH-003", "architecture", "Liskov substitution", "Subtypes remain substitutable for their declared parent.", "medium", "Overrides keep compatible arity.", "Count of overrides whose required positional arity exceeds the base.", "integer >= 0", "max", 0, "count", "Base and override signature comparison for Python, JavaScript, TypeScript, and C++ when the adapter can see both signatures.", GRAPH_TOOLS, "Applicable when class inheritance is visible to the adapter.", "Class hierarchy."),
    quality("ARCH-004", "architecture", "Interface segregation", "Interfaces stay focused.", "low", "Wide interfaces are visible.", "Maximum method count of a type that has no state and at least one implementation.", "integer >= 0", "max", 12, "count", "Method count of protocol-like types.", GRAPH_TOOLS, "Applicable when an interface-like type is detected. Otherwise not applicable.", "Type symbols."),
    quality("ARCH-005", "architecture", "Dependency inversion", "Higher layers depend on configured abstractions rather than lower layers.", "medium", "Configured dependency direction is honored.", "Count of higher-layer modules depending on a forbidden lower layer.", "integer >= 0", "max", 0, "count", "Layer import edges. Not applicable without layer rules.", GRAPH_TOOLS, LAYERS, "Resolved import edges and layer map."),
    quality("ARCH-006", "architecture", "KISS", "Implementations stay direct.", "low", "Extreme branching is visible.", "Count of functions over the cyclomatic red line.", "integer >= 0", "max", 0, "count", "Same control-flow measurement as cyclomatic complexity, scored as an architecture signal.", STYLE_TOOLS, CODE, "Complexity table."),
    quality("ARCH-007", "architecture", "YAGNI", "Unreferenced production symbols are not treated as required features.", "medium", "Unused exported symbols are reported with graph confidence.", "Count of exported symbols with no reference. Confirmation follows dead-code confidence rules.", "integer >= 0", "max", 0, "count", "Export and reference reachability.", GRAPH_TOOLS, "Applicable when the code graph has at least one entry point.", "Code graph."),
    quality("ARCH-008", "architecture", "Coupling", "Modules have a bounded fan-out.", "medium", "Import fan-out stays limited.", "Maximum import count of a source file.", "integer >= 0", "max", 15, "count", "Import edge count per file.", GRAPH_TOOLS, CODE, "Import edges."),
    quality("ARCH-009", "architecture", "Cohesion", "Types use their own state.", "low", "Methods of a type share state when the adapter can see it.", "Count of Python classes whose methods share no attribute.", "integer >= 0", "max", 0, "count", "Python attribute and method comparison.", GRAPH_TOOLS, "Applicable to Python classes with at least two methods.", "Class attribute uses."),
    quality("ARCH-010", "architecture", "Unjustified abstraction", "One-method wrappers are visible.", "low", "Pass-through wrappers are reported as candidates.", "Count of one-method classes that only forward a call.", "integer >= 0", "max", 0, "count", "Structural wrapper heuristic. Reported as advisory candidates.", GRAPH_TOOLS, CODE, "Class method bodies."),
    defect("ARCH-011", "architecture", "Layering", "Configured layers import only allowed layers.", "high", "Layer dependency rules hold.", "Count of imports that enter a layer outside its allow list.", "Layer import check against architecture.layers.", GRAPH_TOOLS, LAYERS, "Violating import edge with file and line."),
    defect("ARCH-012", "architecture", "Dependency direction", "Module imports do not form cycles.", "high", "There is no circular module dependency.", "Count of modules that participate in an import cycle.", "Strongly connected components of size greater than one in the import graph.", GRAPH_TOOLS, CODE, "Import edges in the cycle."),
    defect("TEST-001", "testing", "Unit test presence", "Production behavior has an executable test module.", "high", "Supported production modules are paired with tests.", "Count of production modules with functions and no corresponding test file.", "Match test file names and imports to production modules.", TEST_TOOLS, NO_TESTS, "Module list and test file list."),
    quality("TEST-002", "testing", "Line coverage", "Executed tests cover source lines.", "high", "Line coverage meets the threshold when it can be measured.", "Covered executable lines divided by executable lines, as a percentage.", "0..100", "min", 80, "percent", "coverage.py when approved and installed; otherwise stdlib trace only under an authorized sandbox. Never estimated.", ["coverage", "cqa-builtin"], TESTS, "Coverage data file and command log.", classification="blocking"),
    quality("TEST-003", "testing", "Branch coverage", "Executed tests cover branches.", "high", "Branch coverage meets the threshold when a branch-capable tool runs.", "Covered branches divided by branches, as a percentage.", "0..100", "min", 70, "percent", "coverage.py branch report when approved. Not estimated from line coverage.", ["coverage"], "Applicable when tests exist and a branch-capable coverage tool is approved and installed.", "Branch coverage report.", classification="blocking"),
    quality("TEST-004", "testing", "Mutation score", "Tests detect seeded faults.", "high", "The mutation score meets the threshold when a mutation tool runs.", "Killed mutants divided by valid mutants, as a percentage.", "0..100", "min", 70, "percent", "mutmut or Stryker when approved and installed. No homemade score is substituted.", ["mutmut", "stryker"], "Applicable when tests exist for a language with a registered mutation tool.", "Mutation tool report.", classification="blocking"),
    quality("TEST-005", "testing", "Boundary cases", "Tests mention boundary inputs.", "medium", "Tests exercise empty, zero, limit, or null boundaries.", "Percentage of test modules that contain a boundary token or assertion.", "0..100", "min", 50, "percent", "Static token scan of test files.", TEST_TOOLS, TESTS, "Test file locations."),
    quality("TEST-006", "testing", "Property-based tests", "Property tests exist where the project uses them.", "low", "Hypothesis, fast-check, or RapidCheck usage is visible when required.", "Count of property-based test cases.", "integer >= 0", "min", 1, "count", "Import and macro scan.", TEST_TOOLS, "Applicable when a requirement or dependency declares property-based testing. Otherwise not applicable.", "Test imports."),
    quality("TEST-007", "testing", "Invariants", "Tests state invariants that the specification names.", "medium", "Named invariants have a test assertion.", "Percentage of declared invariants that appear in a test assertion.", "0..100", "min", 100, "percent", "Match invariant IDs in specifications to test assertions.", TEST_TOOLS, "Applicable when the specification declares invariant IDs.", "Specification and test links."),
    quality("TEST-008", "testing", "Integration tests", "Integration coverage exists when modules cross a process or package boundary.", "medium", "Cross-module behavior has an integration test.", "Count of integration-named tests, or zero when a multi-package repository has none.", "integer >= 0", "min", 1, "count", "Test path and name conventions such as integration or end-to-end.", TEST_TOOLS, "Applicable when the repository has more than one production package.", "Test paths."),
    quality("TEST-009", "testing", "Regression tests", "Fixed defects leave a regression test.", "medium", "Regression markers are paired with tests.", "Count of FIX or regression markers in source that lack a test reference.", "integer >= 0", "max", 0, "count", "Marker scan correlated with tests.", TEST_TOOLS, "Applicable when source contains a regression or FIX marker.", "Marker locations."),
    quality("TEST-010", "testing", "Concurrency tests", "Concurrent code has a concurrent test.", "medium", "Threads, tasks, or locks are covered by a test that mentions concurrency.", "Count of concurrency primitives in production code without a concurrency test.", "integer >= 0", "max", 0, "count", "Scan for threading, asyncio, std::thread, and worker primitives.", TEST_TOOLS, "Applicable when production code uses a concurrency primitive.", "Primitive locations."),
    quality("TEST-011", "testing", "Assertion quality", "Tests contain meaningful assertions.", "high", "A test is not an empty function or a tautology.", "Percentage of test functions that contain an assertion.", "0..100", "min", 100, "percent", "AST or token assertion scan. A link without an assertion does not count.", TEST_TOOLS, TESTS, "Test function bodies.", classification="blocking"),
    quality("TEST-012", "testing", "Independent tests", "Acceptance evidence is not only a self-test embedded in generated code.", "medium", "Tests live outside the implementation file.", "Percentage of production modules whose only tests are inside the same file.", "0..100", "max", 0, "percent", "Compare test locations with implementation locations.", TEST_TOOLS, TESTS, "Test and implementation paths."),
    defect("SEC-001", "security", "Embedded secrets", "Source does not contain confirmed secrets.", "critical", "Confirmed credential patterns are absent.", "Count of confirmed secret matches.", "Pattern match for private keys and known token formats. High-entropy strings stay candidates.", SECRET_TOOLS, CODE, "File, line, pattern id, and redacted line."),
    defect("SEC-002", "security", "Vulnerable dependencies", "Declared dependencies have no known vulnerability when an advisory database is available.", "critical", "Known vulnerable dependencies are absent.", "Count of dependencies with a confirmed advisory.", "pip-audit or npm audit when approved and installed, or a local advisory file supplied by configuration. No network lookup and no invented CVEs.", ["pip-audit", "npm-audit", "cqa-builtin"], DEPS, "Tool report or explicit unavailable reason."),
    defect("SEC-003", "security", "Injection sinks", "Dangerous execution and command sinks are absent.", "critical", "eval, exec, and shell invocation are not used.", "Count of confirmed injection sinks.", "Deterministic sink patterns. SQL concatenation remains a candidate unless the sink is unambiguous.", SEC_TOOLS, CODE, "Sink file and line."),
    quality("SEC-004", "security", "Input validation", "External inputs are validated where a boundary is visible.", "high", "Request or argv boundaries have a validation control.", "Count of visible input boundaries with no validation token in the same function.", "integer >= 0", "max", 0, "count", "Function-level heuristic. Uncertain cases stay candidates.", SEC_TOOLS, "Applicable when a request handler, CLI parser, or input() call is visible.", "Handler locations.", classification="advisory"),
    quality("SEC-005", "security", "Authorization", "State-changing handlers have an authorization check when a framework is visible.", "high", "Handlers are not anonymous by default.", "Count of state-changing routes with no auth decorator or check.", "integer >= 0", "max", 0, "count", "Route decorator scan.", SEC_TOOLS, "Applicable when HTTP route declarations are visible.", "Route symbols.", classification="advisory"),
    defect("SEC-006", "security", "Insecure configuration", "Shipped configuration does not disable TLS verification or open all hosts.", "high", "verify=False and wildcard host allow-lists are absent from configuration.", "Count of confirmed insecure configuration settings.", "Pattern scan of source and configuration files.", SEC_TOOLS, "Applicable when source or configuration files exist.", "Setting file and line."),
    defect("SEC-007", "security", "Hard-coded credentials", "Passwords and tokens are not assigned in source.", "critical", "Credential assignments are absent.", "Count of confirmed credential assignments.", "Assignment patterns excluding documented placeholders.", SECRET_TOOLS, CODE, "Assignment file and line, redacted."),
    defect("SEC-008", "security", "Unsafe deserialization", "Untrusted deserialization sinks are absent.", "critical", "pickle, yaml.load, and eval-like loaders are absent.", "Count of confirmed unsafe loaders.", "Loader pattern scan.", SEC_TOOLS, CODE, "Loader file and line."),
    quality("SEC-009", "security", "Path traversal", "File paths from external input are constrained.", "high", "User-controlled paths are not joined directly into a filesystem call.", "Count of path joins that use a request or argv value.", "integer >= 0", "max", 0, "count", "Data-flow heuristic. Reported as candidates unless the source and sink are both literal in one function.", SEC_TOOLS, "Applicable when both an external input and a filesystem call exist.", "Candidate sink locations.", classification="advisory"),
    quality("SEC-010", "security", "Cross-site scripting", "HTML responses do not interpolate raw request data.", "high", "Response markup is not built from raw request values.", "Count of HTML response constructions using request data.", "integer >= 0", "max", 0, "count", "Template and concatenation heuristic.", SEC_TOOLS, "Applicable when HTML response construction is visible.", "Response locations.", classification="advisory"),
    quality("SEC-011", "security", "Cryptographic misuse", "Broken cryptographic algorithms are not selected.", "high", "MD5, SHA1 for security, and static IVs are absent.", "Count of confirmed broken-crypto uses.", "integer >= 0", "max", 0, "count", "API pattern scan.", SEC_TOOLS, CODE, "Call file and line.", classification="blocking", direction="lower_is_better"),
    defect("SEC-012", "security", "Security misconfiguration", "Debug and wildcard CORS settings are not shipped as production defaults.", "high", "DEBUG and Access-Control-Allow-Origin wildcards are absent from production-named configuration.", "Count of confirmed production misconfigurations.", "Configuration pattern scan restricted to production-named files.", SEC_TOOLS, "Applicable when a production, settings, or deploy configuration file exists.", "Configuration location."),
    quality("PERF-001", "performance", "Latency", "Measured latency meets a declared target.", "high", "A declared latency target is satisfied when a benchmark result exists.", "Observed latency divided by the declared target.", "ratio >= 0", "max", 1, "ratio", "Read benchmark result files. Do not infer latency from source.", ["pytest-benchmark", "google-benchmark", "cqa-builtin"], PERF_REQ, "Benchmark result and requirement id.", classification="blocking"),
    quality("PERF-002", "performance", "Throughput", "Measured throughput meets a declared target.", "high", "A declared throughput target is satisfied when a benchmark result exists.", "Declared throughput divided by observed throughput.", "ratio >= 0", "max", 1, "ratio", "Read benchmark result files. Do not infer throughput from source.", ["pytest-benchmark", "google-benchmark", "cqa-builtin"], PERF_REQ, "Benchmark result and requirement id.", classification="blocking"),
    quality("PERF-003", "performance", "Memory", "Measured memory stays within a declared budget.", "medium", "A declared memory budget is satisfied when a measurement exists.", "Observed memory divided by the budget.", "ratio >= 0", "max", 1, "ratio", "Read measurement files only.", ["cqa-builtin"], PERF_REQ, "Measurement file.", classification="blocking"),
    quality("PERF-004", "performance", "CPU", "Measured CPU stays within a declared budget.", "medium", "A declared CPU budget is satisfied when a measurement exists.", "Observed CPU divided by the budget.", "ratio >= 0", "max", 1, "ratio", "Read measurement files only.", ["cqa-builtin"], PERF_REQ, "Measurement file.", classification="blocking"),
    defect("PERF-005", "performance", "Benchmark presence", "Declared performance targets have a benchmark.", "high", "Every declared performance target has a benchmark file or result.", "Count of performance requirements without a benchmark.", "Match latency, throughput, memory, and CPU requirements to benchmark files.", ["pytest-benchmark", "google-benchmark", "cqa-builtin"], PERF_REQ, "Requirement id and missing benchmark."),
    quality("PERF-006", "performance", "Algorithmic complexity", "Obviously nested hot loops are visible.", "low", "Deep loop nesting is reported.", "Maximum loop nesting depth.", "integer >= 0", "max", 3, "depth", "Loop nesting from the adapter.", STYLE_TOOLS, CODE, "Function and depth."),
    quality("PERF-007", "performance", "Repeated data access", "Queries and filesystem reads are not repeated inside loops by accident.", "medium", "A data-access call inside a loop is reviewed.", "Count of data-access calls lexically inside a loop.", "integer >= 0", "max", 0, "count", "Lexical loop-and-call heuristic. Candidates are not confirmed defects.", GRAPH_TOOLS, "Applicable when a data-access call appears inside a loop.", "Call location."),
    quality("PERF-008", "performance", "Resource lifetime", "Opened resources are closed on every visible path.", "medium", "Files and sockets are closed or used as context managers.", "Count of open calls without a close or context manager in the same function.", "integer >= 0", "max", 0, "count", "Python open and with-statement pairing. Other languages report the limit.", STYLE_TOOLS, "Applicable to Python functions that call open.", "Open call location."),
    quality("MAINT-001", "maintainability", "Churn", "Change frequency is measured from history.", "low", "High-churn files are visible.", "Maximum commit count of a source file in the recorded history.", "integer >= 0", "max", 50, "commits", "git log numstat. Missing history is not applicable and is not stored as zero.", ["cqa-builtin"], GIT, "Commit counts per file."),
    quality("MAINT-002", "maintainability", "Technical debt markers", "Debt markers stay visible and bounded.", "low", "TODO, FIXME, and HACK markers are counted.", "Count of debt markers.", "integer >= 0", "max", 0, "count", "Comment marker scan.", STYLE_TOOLS, CODE, "Marker file and line."),
    quality("MAINT-003", "maintainability", "Change amplification", "Files that always change together are visible.", "low", "Historical co-change pairs are reported.", "Count of file pairs that co-change in at least three commits.", "integer >= 0", "max", 0, "count", "git numstat co-change. Not applicable without enough history.", ["cqa-builtin"], "Applicable when git history contains at least three commits.", "Co-change pairs."),
    quality("MAINT-004", "maintainability", "Regression and rework", "Recent rework is visible.", "low", "Files repeatedly changed in a short window are reported.", "Count of files changed in more than half of the last ten commits.", "integer >= 0", "max", 0, "count", "git log window. Not applicable without enough history.", ["cqa-builtin"], "Applicable when at least five commits exist.", "Reworked files."),
    quality("MAINT-005", "maintainability", "API compatibility", "Public exports do not disappear relative to a baseline.", "high", "Removed public symbols are detected when a baseline exists.", "Count of public symbols present in the baseline and absent now.", "integer >= 0", "max", 0, "count", "Compare the current export list with the selected baseline snapshot.", GRAPH_TOOLS, "Applicable when a baseline audit records public symbols.", "Symbol diff.", classification="blocking"),
    quality("MAINT-006", "maintainability", "Documentation coverage", "Public functions document their behavior.", "low", "Public functions have a docstring or header comment.", "Percentage of public functions with a leading comment.", "0..100", "min", 50, "percent", "Docstring and comment scan.", STYLE_TOOLS, CODE, "Function symbols."),
    quality("MAINT-007", "maintainability", "Dependency freshness", "Declared dependencies are current when a lockfile or index snapshot exists locally.", "medium", "Freshness is measured only from local evidence.", "Count of dependencies older than the local snapshot policy.", "integer >= 0", "max", 0, "count", "Compare manifests with a configured local snapshot. No network index lookup.", ["pip-audit", "npm-audit", "cqa-builtin"], "Applicable when dependencies and a local freshness snapshot are both configured. Missing snapshot is unavailable, not zero.", "Snapshot comparison."),
    quality("MAINT-008", "maintainability", "Public API surface", "Public exports do not grow unexpectedly against a baseline.", "medium", "New public symbols are visible.", "Count of public symbols absent from the baseline.", "integer >= 0", "max", 0, "count", "Export diff against the selected baseline.", GRAPH_TOOLS, "Applicable when a baseline export snapshot exists.", "Symbol diff."),
    quality("OBS-001", "observability", "Logging", "Services emit operational logs.", "medium", "A service module uses a logger.", "Count of service entry modules with no logging call.", "integer >= 0", "max", 0, "count", "Logger call scan.", BUILTIN, SERVICE, "Service module list."),
    quality("OBS-002", "observability", "Metrics instrumentation", "Services expose runtime metrics when required.", "medium", "A metrics API is referenced when observability is required.", "Count of required services without a metrics reference.", "integer >= 0", "max", 0, "count", "Token scan for Prometheus, StatsD, or OpenTelemetry metrics.", BUILTIN, "Applicable when an observability requirement or service entry exists.", "Requirement and scan hits."),
    quality("OBS-003", "observability", "Tracing", "Services reference a tracer when tracing is required.", "low", "Distributed tracing is present when required.", "Count of required services without a tracing reference.", "integer >= 0", "max", 0, "count", "Token scan for OpenTelemetry or tracer APIs.", BUILTIN, "Applicable when a tracing requirement exists.", "Requirement id."),
    quality("OBS-004", "observability", "Error reporting", "Failures are reported rather than discarded.", "medium", "Bare exception swallowing is absent from service code.", "Count of service handlers that swallow exceptions without a log or raise.", "integer >= 0", "max", 0, "count", "Exception handler scan.", BUILTIN, SERVICE, "Handler location."),
    quality("OBS-005", "observability", "Health checks", "Services expose a health entry when required.", "medium", "A health route or probe exists.", "Count of required services without a health entry point.", "integer >= 0", "max", 0, "count", "Entry-point name scan.", BUILTIN, "Applicable when a service entry point exists.", "Entry points."),
    quality("OBS-006", "observability", "Operational readiness", "Runbooks or probe configuration exist when a service is shipped.", "low", "Operational documents accompany a service.", "Count of services with neither a health entry nor an operational document.", "integer >= 0", "max", 0, "count", "Document and entry-point presence.", BUILTIN, SERVICE, "Document paths."),
    defect("AI-001", "ai_evaluation", "Requirement hallucination", "Implementation does not cite requirement IDs that the specification does not contain.", "high", "Every cited requirement ID exists.", "Count of requirement IDs cited by source that are absent from discovered specifications.", "Set difference between citations and specification IDs.", BUILTIN, SPECS, "Citation file and line and the missing ID."),
    quality("AI-002", "ai_evaluation", "Unnecessary functionality", "Exported behavior is linked to a requirement or left inconclusive.", "medium", "Unlinked exports are not confirmed as violations by similarity alone.", "Count of exported symbols with no requirement link. These remain candidates.", "integer >= 0", "max", 0, "count", "Export and requirement-link comparison. Candidates stay unconfirmed.", BUILTIN, SPECS, "Symbol and rationale."),
    quality("AI-003", "ai_evaluation", "Architecture drift", "Implementation follows documented architecture rules.", "high", "Documented layer rules match the import graph.", "Count of confirmed layer violations also reported by the architecture check.", "integer >= 0", "max", 0, "count", "Reuse confirmed architecture evidence. Do not add a second opinion without evidence.", GRAPH_TOOLS, LAYERS, "Architecture finding IDs.", classification="blocking"),
    quality("AI-004", "ai_evaluation", "Self-test gap", "Tests exercise production code rather than only their own doubles.", "medium", "Tests call the unit they name.", "Percentage of test functions that never call a production symbol.", "0..100", "max", 0, "percent", "Call graph from tests into production symbols.", TEST_TOOLS, TESTS, "Test function and missing call."),
    quality("AI-005", "ai_evaluation", "Independent-test gap", "Verification is not solely a test generated beside the implementation.", "medium", "A separate test file exists for production modules.", "Percentage of production modules tested only from the same file.", "0..100", "max", 0, "percent", "Path comparison of tests and implementation.", TEST_TOOLS, TESTS, "Module paths."),
    quality("AI-006", "ai_evaluation", "Semantic redundancy", "Semantically similar functions are investigated, not automatically condemned.", "medium", "Similar functions have a rationale and an uncertainty.", "Count of semantic-duplicate candidates.", "integer >= 0", "max", 0, "count", "Cross-check the semantic duplication candidates. Similarity is not confirmation.", DUP_TOOLS, CODE, "Candidate pair, rationale, and uncertainty."),
    quality("AI-007", "ai_evaluation", "Invented behavior", "Code does not contradict an explicit non-goal in the specification.", "high", "Features marked out of scope are not implemented.", "Count of out-of-scope clauses with a matching implementation symbol.", "integer >= 0", "max", 0, "count", "Match out-of-scope statements to symbol names.", BUILTIN, "Applicable when a specification contains an out-of-scope statement.", "Clause and symbol.", classification="blocking"),
    quality("AI-008", "ai_evaluation", "Specification divergence", "Specification symbols exist in the implementation or are explicitly deferred.", "medium", "Named behaviors in requirements exist as symbols or are marked deferred.", "Count of specification symbols with no implementation symbol.", "integer >= 0", "max", 0, "count", "Token overlap between requirement names and the symbol table.", BUILTIN, SPECS, "Requirement id and missing symbol."),
    quality("REQ-001", "requirements", "Implementation coverage", "Discovered requirements have an implementation reference.", "high", "Each requirement ID appears in implementation or is explicitly deferred.", "Percentage of requirement IDs found in non-test source.", "0..100", "min", 100, "percent", "ID scan of specifications and source.", BUILTIN, SPECS, "Requirement IDs and citing files.", classification="blocking"),
    quality("REQ-002", "requirements", "Verification coverage", "Discovered requirements have meaningful verification.", "high", "Each requirement ID appears in a test that contains an assertion.", "Percentage of requirement IDs with a meaningful test.", "0..100", "min", 100, "percent", "ID scan plus assertion check. A link alone is insufficient.", BUILTIN, SPECS, "Requirement ID and test function.", classification="blocking"),
    defect("REQ-003", "requirements", "Missing verification", "Requirements with acceptance criteria have a meaningful test.", "critical", "Acceptance criteria are verified by a current test with an assertion.", "Count of acceptance criteria without a meaningful test.", "Match acceptance sections to tests that assert and mention the requirement ID.", BUILTIN, SPECS, "Requirement ID and acceptance text."),
    defect("REQ-004", "requirements", "Stale links", "Traceability links point at files and IDs that still exist.", "high", "Links are not dangling.", "Count of links whose target file or requirement ID is missing.", "Open each linked path and compare IDs.", BUILTIN, "Applicable when a traceability file or requirement citation exists.", "Broken link."),
    quality("REQ-005", "requirements", "Unjustified implementation", "Production symbols that no requirement mentions are investigated.", "medium", "Unlinked symbols are reported as candidates.", "Count of production functions not mentioned by any requirement.", "integer >= 0", "max", 0, "count", "Symbol and specification token comparison. Candidates are not confirmed violations.", BUILTIN, SPECS, "Symbol, rationale, and uncertainty."),
    defect("REQ-006", "requirements", "Contradictory requirements", "The same requirement ID is not defined twice with different text.", "high", "Requirement IDs are unique in meaning.", "Count of IDs whose normalized texts differ.", "Group specification clauses by ID and compare text.", BUILTIN, SPECS, "Both clause locations."),
    quality("REQ-007", "requirements", "Missing requirements", "A repository with production code has an authoritative specification.", "medium", "Absence of a specification is visible and is not invented.", "Count of production repositories with no discovered specification.", "integer >= 0", "max", 0, "count", "Specification discovery. Advisory when nothing was declared.", BUILTIN, "Applicable when production source exists.", "Discovery log."),
    defect("REQ-008", "requirements", "Acceptance satisfaction", "Executable acceptance evidence agrees with the criterion when tests are authorized.", "critical", "An acceptance test that ran and failed is a breach.", "Count of acceptance tests that failed in an authorized run, plus statically missing acceptance tests.", "Static link check, plus the authorized test result when sandbox execution is approved.", TEST_TOOLS, SPECS, "Requirement ID, test, and command result."),
    defect("GRAPH-001", "code_graph", "Dead functions", "Functions are reachable from an entry point or reported as uncertain.", "high", "Unreachable functions are removed or justified.", "Count of confirmed unreachable functions.", "Reachability from entry points. Incomplete graphs cannot confirm unreachability.", GRAPH_TOOLS, "Applicable when the graph contains functions and at least one entry point.", "Symbol, entry set, and completeness record."),
    defect("GRAPH-002", "code_graph", "Dead classes", "Classes are reachable or reported as uncertain.", "high", "Unreachable classes are removed or justified.", "Count of confirmed unreachable classes.", "Reachability from entry points and instantiations.", GRAPH_TOOLS, "Applicable when the graph contains classes.", "Class symbol and completeness record."),
    defect("GRAPH-003", "code_graph", "Dead modules", "Modules are imported by a live root or are entry points.", "high", "Unreferenced modules are removed or justified.", "Count of confirmed unreachable modules.", "Import reachability from entry modules.", GRAPH_TOOLS, "Applicable when more than one module is indexed.", "Module and import edges."),
    defect("GRAPH-004", "code_graph", "Dead branches", "Constant-false branches are absent.", "high", "Branches that static control flow proves unreachable are removed.", "Count of confirmed constant-dead branches.", "Constant-condition control-flow check.", GRAPH_TOOLS, CODE, "Branch file and line."),
    quality("GRAPH-005", "code_graph", "Unresolved edges", "The graph records references it could not resolve.", "medium", "Unresolved references reduce dead-code confidence.", "Count of unresolved edges.", "integer >= 0", "max", 0, "count", "Adapter unresolved-reference records.", GRAPH_TOOLS, CODE, "Edge reason, file, and line."),
    quality("GRAPH-006", "code_graph", "Entry-point coverage", "Entry-point discovery is explicit.", "medium", "Known framework and CLI conventions were considered.", "Percentage of indexed modules classified as entry, library export, or internal.", "0..100", "min", 0, "percent", "Entry-point convention scan. The minimum is informational; low coverage forces uncertainty rather than a pass on dead code.", GRAPH_TOOLS, CODE, "Entry-point list and conventions considered."),
    quality("GRAPH-007", "code_graph", "Graph completeness", "Completeness is measured.", "medium", "Indexed files, symbols, unresolved edges, and limits are reported.", "Indexed files divided by discovered supported files, as a percentage.", "0..100", "min", 100, "percent", "Compare discovery with the graph index.", GRAPH_TOOLS, CODE, "Completeness record."),
    quality("GRAPH-008", "code_graph", "Dynamic uncertainty", "Dynamic behavior lowers confidence.", "medium", "Dynamic imports, reflection, and unknown decorators are recorded.", "Count of dynamic sites.", "integer >= 0", "max", 0, "count", "Dynamic-behavior scan.", GRAPH_TOOLS, CODE, "Dynamic site and the symbols it makes uncertain."),
    defect("DUP-001", "duplication", "Exact duplication", "Identical code blocks are not repeated.", "high", "Exact normalized blocks occur once.", "Count of exact duplicate groups of at least six lines.", "Normalized line-block hash.", DUP_TOOLS, CODE, "Both locations and the normalized block hash."),
    defect("DUP-002", "duplication", "Token duplication", "Token-level clones are not repeated.", "high", "Token windows are not copied.", "Count of token-duplicate groups.", "Winnowing hash of token windows.", DUP_TOOLS, CODE, "Both locations and window hash."),
    defect("DUP-003", "duplication", "Structural duplication", "Structurally identical functions are not repeated.", "high", "AST or structure hashes are unique.", "Count of structural duplicate groups.", "Node-type hash of function bodies.", DUP_TOOLS, "Applicable when the adapter can build a structural hash.", "Function locations and structure hash."),
    quality("DUP-004", "duplication", "Semantic duplication", "Similar behavior is investigated without treating similarity as proof.", "medium", "Semantic candidates include rationale and uncertainty.", "Count of semantic candidate pairs.", "integer >= 0", "max", 0, "count", "Normalized token similarity. Similarity alone is never a confirmed violation.", DUP_TOOLS, CODE, "Pair, rationale, uncertainty, and whether a differential test exists."),
    quality("DUP-005", "duplication", "Cross-language duplication", "The same behavior copied across languages is investigated.", "medium", "Cross-language candidates are visible.", "Count of cross-language candidate pairs.", "integer >= 0", "max", 0, "count", "Compare normalized tokens across languages. Do not confirm equivalence.", DUP_TOOLS, "Applicable when two or more languages are in scope.", "Pair and languages."),
    quality("DUP-006", "duplication", "Unjustified redundancy", "Repeated behavior is either justified or still under investigation.", "medium", "Justified shared copies are distinguished from unexplained copies.", "Count of duplicate groups that have no justification record.", "integer >= 0", "max", 0, "count", "Look for a justification comment or an accepted exception before counting a confirmed duplicate as unjustified.", DUP_TOOLS, "Applicable when a duplicate group was found.", "Group id and justification, if any."),
    defect("REL-001", "reliability", "Error handling", "Exceptions are not discarded.", "high", "Bare except and empty handlers are absent.", "Count of bare or empty exception handlers.", "Python handler scan and empty-catch token scan for other languages.", STYLE_TOOLS, CODE, "Handler file and line."),
    quality("REL-002", "reliability", "Resilience", "External calls have a timeout or retry bound when they are visible.", "medium", "Network and process calls are bounded.", "Count of external calls with no timeout argument.", "integer >= 0", "max", 0, "count", "Call heuristic. Uncertain calls stay candidates.", BUILTIN, "Applicable when a network or subprocess call is visible.", "Call location."),
    quality("REL-003", "reliability", "Determinism", "Quantitative and test-critical code does not use unseeded randomness.", "high", "Unseeded random use is absent from quantitative code.", "Count of unseeded random calls in applicable code.", "integer >= 0", "max", 0, "count", "Random call scan.", BUILTIN, "Applicable to quantitative repositories and to tests that claim determinism. Otherwise advisory.", "Call location.", classification="blocking"),
    defect("REL-004", "reliability", "Parse integrity", "Source files parse.", "critical", "Supported source has no syntax errors.", "Count of confirmed syntax errors.", "Python ast parse, delimiter and token checks for JavaScript, TypeScript, and C++, plus clang when tool execution is approved.", ["cqa-builtin", "ruff", "eslint", "clang"], CODE, "Parser message, file, and line."),
    quality("QUANT-001", "quantitative", "Numerical identities", "Declared numerical identities have a checking test.", "high", "Identities such as conservation or add-up are tested.", "Count of declared identities without an asserting test.", "integer >= 0", "max", 0, "count", "Match identity IDs in specifications to asserting tests.", TEST_TOOLS, QUANT, "Identity ID and test.", classification="blocking"),
    quality("QUANT-002", "quantitative", "Signs, units, and tolerances", "Declared units and tolerances appear in tests.", "high", "Sign, unit, and tolerance constraints are tested.", "Count of declared unit or tolerance constraints without a test.", "integer >= 0", "max", 0, "count", "Match constraint IDs to asserting tests.", TEST_TOOLS, QUANT, "Constraint ID and test.", classification="blocking"),
    defect("QUANT-003", "quantitative", "VaR, ES, and DV01 integrity", "Risk measures are tested against a reference.", "critical", "VaR, ES, and DV01 calculations have a reference test.", "Count of risk-measure functions without an asserting reference test.", "Symbol scan for VaR, ES, and DV01 plus test links. Every repository uses the same rule.", TEST_TOOLS, QUANT, "Function symbol and missing or failing test."),
    defect("QUANT-004", "quantitative", "Immutable market snapshots", "Market snapshots are not reassigned.", "critical", "Snapshot objects are not mutated after construction.", "Count of assignments into a snapshot.", "Subscript or attribute assignment whose target name contains snapshot.", TEST_TOOLS, QUANT, "Assignment file and line."),
    defect("QUANT-005", "quantitative", "Risk attribution reconciliation", "Attribution results reconcile to the parent risk measure.", "critical", "Sum of attribution equals the parent measure in a test.", "Count of attribution functions without a reconciliation assertion.", "Symbol scan plus assertion scan for reconciliation.", TEST_TOOLS, QUANT, "Function and test evidence."),
    defect("QUANT-006", "quantitative", "Provenance and non-invention", "User interfaces do not invent risk numbers that the model did not produce.", "critical", "UI code does not compute VaR, ES, or DV01 independently of the model.", "Count of UI calculations of a risk measure when a model module exists.", "Path and symbol scan separating ui from model.", TEST_TOOLS, QUANT, "UI location and model symbol."),
]


CHECKS = [
    ("syntax_static", "Parse supported source and report confirmed syntax errors.", ["REL-004"], ["parser diagnostics"], [], ["cqa-builtin", "ruff", "eslint", "clang"], True),
    ("symbol_index", "Build the shared cross-language code graph and its completeness record.", ["GRAPH-005", "GRAPH-006", "GRAPH-007", "GRAPH-008"], ["code graph", "completeness record"], ["syntax_static"], GRAPH_TOOLS, True),
    ("dead_code", "Find unreachable functions, classes, modules, and constant-dead branches.", ["GRAPH-001", "GRAPH-002", "GRAPH-003", "GRAPH-004"], ["reachability", "control-flow constants"], ["symbol_index"], GRAPH_TOOLS, True),
    ("clean_code", "Measure naming, size, complexity, consistency, unused names, and commented-out code.", [f"CC-{i:03d}" for i in range(1, 15)], ["symbol table", "style scan"], ["syntax_static", "symbol_index"], STYLE_TOOLS, True),
    ("architecture", "Evaluate SOLID signals, coupling, cohesion, layering, and dependency direction.", [f"ARCH-{i:03d}" for i in range(1, 13)], ["import graph", "layer rules"], ["symbol_index"], GRAPH_TOOLS, True),
    ("duplication", "Detect exact, token, and structural duplication.", ["DUP-001", "DUP-002", "DUP-003"], ["clone groups"], ["syntax_static"], DUP_TOOLS, True),
    ("semantic_duplication", "Investigate semantic and cross-language redundancy without treating similarity as proof.", ["DUP-004", "DUP-005", "DUP-006"], ["candidate pairs", "justification records"], ["duplication", "symbol_index"], DUP_TOOLS, True),
    ("secrets", "Detect confirmed secrets and hard-coded credentials.", ["SEC-001", "SEC-007"], ["redacted match"], ["syntax_static"], SECRET_TOOLS, True),
    ("security_sast", "Detect injection, validation, authorization, deserialization, traversal, XSS, and crypto issues.", ["SEC-003", "SEC-004", "SEC-005", "SEC-008", "SEC-009", "SEC-010", "SEC-011"], ["sink locations"], ["syntax_static"], SEC_TOOLS, True),
    ("dependency_audit", "Check declared dependencies against an approved local advisory source.", ["SEC-002"], ["advisory report or unavailable reason"], [], ["pip-audit", "npm-audit", "cqa-builtin"], True),
    ("insecure_config", "Detect insecure shipped configuration.", ["SEC-006", "SEC-012"], ["configuration locations"], [], SEC_TOOLS, True),
    ("testing", "Evaluate test presence, boundaries, properties, invariants, integration, regression, assertions, and independence.", ["TEST-001", "TEST-005", "TEST-006", "TEST-007", "TEST-008", "TEST-009", "TEST-011", "TEST-012"], ["test inventory"], ["syntax_static"], TEST_TOOLS, True),
    ("coverage", "Measure line and branch coverage when an approved runner produces data.", ["TEST-002", "TEST-003"], ["coverage report"], ["testing"], ["coverage", "c8", "cqa-builtin"], True),
    ("mutation_testing", "Measure mutation score with an approved mutation tool.", ["TEST-004"], ["mutation report"], ["testing"], ["mutmut", "stryker"], True),
    ("concurrency", "Evaluate concurrency tests where concurrent code exists.", ["TEST-010"], ["concurrency primitive inventory"], ["testing"], TEST_TOOLS, True),
    ("requirements_trace", "Trace requirements to implementation and meaningful verification.", [f"REQ-{i:03d}" for i in range(1, 9)], ["specification index", "test links"], [], BUILTIN, True),
    ("ai_evaluation", "Evaluate hallucination, unjustified behavior, architecture drift, test independence, and semantic redundancy.", [f"AI-{i:03d}" for i in range(1, 9)], ["requirement citations", "semantic candidates"], ["requirements_trace", "symbol_index", "semantic_duplication"], BUILTIN, True),
    ("performance_benchmarks", "Evaluate declared performance targets, benchmark presence, and static efficiency signals.", [f"PERF-{i:03d}" for i in range(1, 9)], ["requirements", "benchmark results", "loop structure"], ["syntax_static"], ["pytest-benchmark", "google-benchmark", "cqa-builtin"], True),
    ("maintainability", "Evaluate churn, debt, co-change, API compatibility, docs, and dependency freshness from real evidence.", [f"MAINT-{i:03d}" for i in range(1, 9)], ["git history", "baseline snapshot"], ["symbol_index"], BUILTIN, True),
    ("observability", "Evaluate logging, metrics, tracing, errors, health, and operational readiness when a service exists.", [f"OBS-{i:03d}" for i in range(1, 7)], ["service entry points", "operational docs"], ["symbol_index"], BUILTIN, True),
    ("reliability", "Evaluate error handling, bounded external calls, and determinism.", ["REL-001", "REL-002", "REL-003"], ["handler and call inventory"], ["syntax_static"], STYLE_TOOLS, True),
    ("quantitative", "Evaluate numerical, risk, snapshot, attribution, and non-invention constraints for quantitative repositories.", [f"QUANT-{i:03d}" for i in range(1, 7)], ["risk symbols", "reference tests"], ["testing", "requirements_trace"], TEST_TOOLS, True),
]


TOOLS = [
    ("cqa-builtin", "In-process static analysis and orchestration", LANGS, "cheap", "Python 3.12+ proposed runtime", "Repository source files", "Findings, graph, and metric measurements", "1.1.0", "Read-only. Does not install software and does not execute repository code unless a separate authorized sandbox run is requested."),
    ("ruff", "Python lint and format checks", ["python"], "cheap", "ruff on PATH", "Python source", "JSON diagnostics", ">=0.6", "Approved static analyzer. Running it requires tool approval. The registry does not authorize installation."),
    ("vulture", "Python unused-code analysis", ["python"], "cheap", "vulture on PATH", "Python source", "Unused-name report", ">=2.0", "Corroborates dead code. Dynamic behavior remains uncertain. Tool approval required."),
    ("semgrep", "Multi-language static security rules", LANGS, "moderate", "semgrep on PATH and local rules", "Source files", "JSON findings", ">=1.50", "Do not download remote rules without network approval. Tool approval required."),
    ("bandit", "Python security patterns", ["python"], "cheap", "bandit on PATH", "Python source", "JSON findings", ">=1.7", "Static only. Tool approval required."),
    ("jscpd", "Copy-paste detection", LANGS, "moderate", "jscpd on PATH", "Source files", "JSON clone report", ">=3.0", "Corroborates duplication. Tool approval required."),
    ("knip", "JavaScript and TypeScript unused exports", ["javascript", "typescript"], "moderate", "knip on PATH", "JS/TS project", "Unused export report", ">=5.0", "Does not execute application code. Tool approval required."),
    ("eslint", "JavaScript and TypeScript lint", ["javascript", "typescript"], "cheap", "eslint on PATH", "JS/TS source", "JSON diagnostics", ">=8.0", "Use the repository config only as data. Tool approval required."),
    ("clang-tidy", "C++ static analysis", ["cpp"], "expensive", "clang-tidy on PATH", "C++ translation units", "Diagnostics", ">=16", "Do not run repository build scripts. Tool approval required."),
    ("clang", "C++ parse check", ["cpp"], "moderate", "clang on PATH", "C++ source", "Syntax diagnostics", ">=16", "Invoke -fsyntax-only only. Do not link or run the program. Tool approval required."),
    ("pytest", "Python test runner", ["python"], "moderate", "pytest on PATH", "Python tests", "JUnit or console result", ">=7.0", "Executes repository tests. Requires repository-execution approval and a real sandbox."),
    ("jest", "JavaScript and TypeScript test runner", ["javascript", "typescript"], "moderate", "jest on PATH", "JS/TS tests", "JSON result", ">=29.0", "Executes repository tests. Requires repository-execution approval and a real sandbox."),
    ("ctest", "C++ test runner", ["cpp"], "moderate", "ctest on PATH", "CTest tests", "Console result", ">=3.20", "Executes repository tests. Requires repository-execution approval and a real sandbox."),
    ("coverage", "Python line and branch coverage", ["python"], "moderate", "coverage on PATH", "Python tests", "Coverage JSON", ">=7.0", "Executes repository tests. Requires repository-execution approval and a real sandbox."),
    ("c8", "JavaScript and TypeScript coverage", ["javascript", "typescript"], "moderate", "c8 or nyc on PATH", "JS/TS tests", "Coverage JSON", ">=8.0", "Executes repository tests. Requires repository-execution approval and a real sandbox."),
    ("mutmut", "Python mutation testing", ["python"], "expensive", "mutmut on PATH", "Python tests and source", "Mutation score", ">=2.4", "Executes mutated repository code. Requires repository-execution approval and a real sandbox."),
    ("stryker", "JavaScript and TypeScript mutation testing", ["javascript", "typescript"], "expensive", "stryker on PATH", "JS/TS tests and source", "Mutation score", ">=8.0", "Executes mutated repository code. Requires repository-execution approval and a real sandbox."),
    ("pip-audit", "Python dependency advisories", ["python"], "moderate", "pip-audit on PATH and a local database or approved network", "Python dependency manifests", "Advisory JSON", ">=2.6", "Do not install dependencies. Network access requires separate approval."),
    ("npm-audit", "JavaScript dependency advisories", ["javascript", "typescript"], "moderate", "npm on PATH and approved network or a local advisory file", "package manifests", "Advisory JSON", ">=9.0", "Do not run package lifecycle scripts. Network access requires separate approval."),
    ("gitleaks", "Secret detection", LANGS, "cheap", "gitleaks on PATH", "Source and history", "Secret findings", ">=8.0", "Read-only scan. Tool approval required. Findings stay redacted in reports."),
    ("detect-secrets", "Secret detection", LANGS, "cheap", "detect-secrets on PATH", "Source files", "Secret findings", ">=1.4", "Read-only scan. Tool approval required."),
    ("radon", "Python complexity", ["python"], "cheap", "radon on PATH", "Python source", "Complexity JSON", ">=6.0", "Static only. Tool approval required."),
    ("pytest-benchmark", "Python benchmarks", ["python"], "expensive", "pytest-benchmark installed in an approved environment", "Benchmark tests", "Benchmark JSON", ">=4.0", "Executes repository code. Requires repository-execution approval and a real sandbox."),
    ("google-benchmark", "C++ benchmarks", ["cpp"], "expensive", "built benchmark binary supplied by an approved build", "Benchmark binary", "Console measurements", ">=1.8", "Running a repository binary requires repository-execution approval and a real sandbox. The auditor does not build it."),
]


def build_metrics():
    ids = [item["id"] for item in METRICS]
    if len(ids) != 112 or len(set(ids)) != 112:
        raise SystemExit(f"expected 112 unique metrics, found {len(ids)}")
    return {"version": 1, "metrics": METRICS}


def build_checks():
    covered = []
    checks = {}
    for cid, description, metric_ids, evidence, depends, tools, enabled in CHECKS:
        covered.extend(metric_ids)
        checks[cid] = {
            "id": cid,
            "description": description,
            "metrics": metric_ids,
            "evidence": evidence,
            "languages": LANGS,
            "tools": tools,
            "depends_on": depends,
            "default_enabled": enabled,
        }
    missing = sorted(set(item["id"] for item in METRICS) - set(covered))
    extra = sorted(set(covered) - set(item["id"] for item in METRICS))
    if missing or extra or len(covered) != len(set(covered)):
        raise SystemExit(f"check map mismatch missing={missing} extra={extra} dups={len(covered)!=len(set(covered))}")
    return {"version": 1, "checks": checks}


def build_tools():
    tools = {}
    for tid, purpose, languages, cost, prerequisites, inputs, outputs, version, safety in TOOLS:
        supported = [cid for cid, *_rest, tool_ids, _enabled in ((c[0], c[5]) for c in [])]
        supported = [cid for cid, _d, _m, _e, _dep, tool_ids, _en in CHECKS if tid in tool_ids]
        tools[tid] = {
            "id": tid,
            "purpose": purpose,
            "languages": languages,
            "checks": supported,
            "prerequisites": [prerequisites],
            "inputs": inputs,
            "outputs": outputs,
            "version_constraint": version,
            "cost_class": cost,
            "safety": safety,
        }
    return {"version": 1, "registry_version": "1.1.0", "tools": tools}


def build_policy():
    return {
        "version": 1,
        "zero_confirmed_violations": True,
        "missing_mandatory_evidence": "incomplete",
        "inconclusive_blocking": "incomplete",
        "warnings_allow_pass": True,
        "exception_requires_justification": True,
        "exception_requires_scope": True,
        "fail_closed": True,
        "notes": "The zero confirmed-violation gate cannot be disabled. Thresholds and per-metric blocking classifications are configurable.",
    }


def build_schema():
    return {
        "version": 1,
        "documents": {
            "metrics": {"required": ["version", "metrics"], "item_required": ["id", "sector", "name", "description", "criticality", "verifies", "calculation", "result_range", "red_line", "evaluation_method", "recommended_tools", "applicability", "evidence_requirements", "kind", "classification"]},
            "checks": {"required": ["version", "checks"], "item_required": ["id", "description", "metrics", "evidence", "languages", "tools", "depends_on", "default_enabled"]},
            "tools": {"required": ["version", "registry_version", "tools"], "item_required": ["id", "purpose", "languages", "checks", "prerequisites", "inputs", "outputs", "version_constraint", "cost_class", "safety"]},
            "quality_auditor": {"required": ["version", "default_profile", "profiles"], "security_not_overridable": ["allow_tools", "allow_repo_execution", "sandbox_confirmed", "allow_install", "allow_network", "allow_write"]},
        },
    }


def write(path: Path, document: dict, title: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    text = f"# {title}\n" + dump(document) + "\n"
    path.write_text(text, encoding="utf-8")


def markdown_checks(checks):
    lines = ["# Checks", "", "Generated from `config/checks.yaml`. Do not edit by hand.", ""]
    for cid, spec in checks["checks"].items():
        lines.append(f"## {cid}")
        lines.append("")
        lines.append(spec["description"])
        lines.append("")
        lines.append("Metrics: " + ", ".join(f"`{mid}`" for mid in spec["metrics"]))
        lines.append("")
        lines.append("Evidence: " + ", ".join(spec["evidence"]))
        lines.append("")
        lines.append("Languages: " + ", ".join(spec["languages"]))
        lines.append("")
        lines.append("Tools: " + ", ".join(f"`{tid}`" for tid in spec["tools"]))
        lines.append("")
        deps = spec["depends_on"] or ["none"]
        lines.append("Depends on: " + ", ".join(f"`{d}`" for d in deps))
        lines.append("")
    return "\n".join(lines)


def markdown_tools(tools):
    lines = ["# Tools by purpose and language", "", "Generated from `config/tools.yaml`. Registry entries do not authorize installation or execution.", ""]
    for tid, spec in tools["tools"].items():
        lines.append(f"## {tid}")
        lines.append("")
        lines.append(spec["purpose"])
        lines.append("")
        lines.append("Languages: " + ", ".join(spec["languages"]))
        lines.append("")
        lines.append("Checks: " + (", ".join(f"`{c}`" for c in spec["checks"]) if spec["checks"] else "none"))
        lines.append("")
        lines.append("Prerequisites: " + "; ".join(spec["prerequisites"]))
        lines.append("")
        lines.append(f"Input: {spec['inputs']}")
        lines.append("")
        lines.append(f"Output: {spec['outputs']}")
        lines.append("")
        lines.append(f"Version constraint: `{spec['version_constraint']}`")
        lines.append("")
        lines.append(f"Cost class: {spec['cost_class']}")
        lines.append("")
        lines.append(f"Safety: {spec['safety']}")
        lines.append("")
    return "\n".join(lines)


def main():
    metrics = build_metrics()
    checks = build_checks()
    tools = build_tools()
    write(CONFIG / "metrics.yaml", metrics, "Authoritative metric catalog. version 1.1.0")
    write(CONFIG / "checks.yaml", checks, "Authoritative check registry. version 1.1.0")
    write(CONFIG / "tools.yaml", tools, "Approved analyzer registry. version 1.1.0. This file does not authorize downloads or execution.")
    write(CONFIG / "policy.yaml", build_policy(), "Default quality policy. version 1.1.0")
    write(CONFIG / "schema.yaml", build_schema(), "Configuration schema notes. version 1.1.0")
    REF.mkdir(parents=True, exist_ok=True)
    (REF / "checks.md").write_text(markdown_checks(checks), encoding="utf-8")
    (REF / "tools.md").write_text(markdown_tools(tools), encoding="utf-8")
    print(f"metrics={len(metrics['metrics'])} checks={len(checks['checks'])} tools={len(tools['tools'])}")


if __name__ == "__main__":
    main()
