# Requirements coverage

Source: `docs/requirements-v1.1.docx` (146 numbered requirements).
Checklist: `docs/traceability.yaml`.
Catalog: `.cursor/skills/code-quality-auditor/config/metrics.yaml` (112 metrics).

## Test result

Command: `.venv/bin/python -m unittest discover -s tests -v`

Result: 68 tests, OK (58 acceptance, 10 engine).

A requirement is `verified` when a passing acceptance test names that ID and asserts the behavior. Requirement 14.10 is the external acceptance run recorded below. Engine tests additionally lock the public API used by those acceptance tests.

| Status | Count |
| --- | ---: |
| verified | 146 |
| not verified | 0 |
| total | 146 |

## Acceptance run (14.10)

Command: `.venv/bin/python .cursor/skills/code-quality-auditor/scripts/auditor.py audit --repo /Users/user/Desktop/src/quantlineage --profile full --allow-tools`

Repository: `https://github.com/SergTogul/quantlineage`, revision `ba664b203688c83ea393c10fbb4dfce91e9c3d38` (206 commits). The skill scripts do not mention this repository.

Decision: **FAIL**. Rationale: a blocking metric breached its red line. Repository execution was not approved, so tests, coverage, and mutation were not run.

| Result | Count |
| --- | ---: |
| PASS | 25 |
| WARNING | 39 |
| NOT_APPLICABLE | 29 |
| FAIL | 11 |
| UNAVAILABLE | 4 |
| INCONCLUSIVE | 4 |
| Confirmed violations | 4325 |
| Unresolved candidates | 1838 |

Blocking failures: TEST-001 (33), TEST-011 (84.3), SEC-007 (2), REQ-004 (85), DUP-001 (876), DUP-002 (3061), DUP-003 (237), REL-001 (2), QUANT-003 (17), QUANT-004 (12), QUANT-005 (3). TEST-011 is the percentage of test functions with an assertion. REL-004 passes. JavaScript regular expressions and JSX closing tags are not counted as syntax errors.

Unavailable because execution or a local database was not approved: TEST-002, TEST-004, SEC-002, MAINT-007. TEST-003 is not applicable because no branch-coverage tool is installed.

Reports: `/Users/user/.code-quality-auditor/reports/quantlineage/a9de3be7a167482ea0b681e5f680785b/` (`report.json`, `report.md`, `report.html`). History: `~/.code-quality-auditor/history/quantlineage.csv`.

## What the suite covers

- Skill contract, default `full` profile, and YAML-only configuration: 1.1–1.9, 13.1–13.6.
- Metric catalog, statuses, provenance fields, and deduplicated findings: 2.1–2.11, 4.1–4.8.
- Profiles, include/exclude/extends, absent overrides, and user profile edits: 3.1–3.14, 14.2.
- DAG parallelism, retries, timeouts, cache, and shared evidence: 5.1–5.12, 14.3.
- Cross-language graph, dead code, duplication, and architecture: 6.1–6.14, 8.1–8.2, 14.4–14.5.
- Requirements tracing and quantitative measurements on any repository whose source declares them: 7.1–7.9, 8.8.
- Fail-closed policy, reports, exceptions, and CSV history: 8.3–8.7, 8.9, 9.1–9.9, 11.1–11.8, 12.1–12.5, 14.1, 14.7–14.9.
- Execution security, init, and install approval: 10.1–10.12, 14.6, 15.1–15.10.

## External analyzers

Ruff, Semgrep, Vulture, Bandit, jscpd, Knip, ESLint, clang-tidy, pytest, Node, npm, gitleaks, coverage.py, and mutmut are not installed in this environment. The registry names them. The engine does not install them and does not invent their results. When a manifest or test suite exists and execution is not approved, the related blocking metrics stay `UNAVAILABLE` and the decision is `INCOMPLETE`.

When tool execution is approved and `clang` is already installed, C++ parse errors from `clang -fsyntax-only` count toward REL-004. Missing includes and undeclared names are not counted as syntax errors. Without that approval, clang is not run.

When repository execution is approved and the sandbox starts, Python line coverage is measured with the standard-library `trace` module. Branch coverage stays `NOT_APPLICABLE` until coverage.py or c8 is installed. Mutation stays `UNAVAILABLE` until mutmut or Stryker is installed. The sandbox allows the interpreter to read and execute, denies network access, and denies writes except the coverage output directory. A containment failure is not retried outside the sandbox.
