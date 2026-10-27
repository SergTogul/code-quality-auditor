# Measured test runner and provenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When repository execution is approved, measure tests with the repository’s own runner, and record real source lines for token duplicates and unexported script functions.

**Architecture:** `cqa.checks` discovers pytest versus unittest from the tree and runs that runner inside the existing sandbox. Coverage still uses stdlib `trace` only for unittest projects. Pytest projects without coverage.py stay `UNAVAILABLE`. Token fingerprints keep the source line of each token. A script function is exported only when an `export` declaration names it, except C++ headers, whose symbols stay public API of an included file.

**Tech Stack:** Python 3.12, unittest discovery for the auditor suite, sandbox-exec via `run_contained`, PyYAML already in `.venv`.

## Global Constraints

- Do not commit. Leave the working tree dirty. The user has not asked for a commit.
- Do not add a `Co-authored-by` trailer. Do not update git config. Do not force-push.
- Skill scripts under `.cursor/skills/code-quality-auditor/` must not contain the substring `quantlineage` or `QuantLineage` or `QUANTLINEAGE`.
- `auditor.py` must not contain the contiguous substring `pip install`.
- Do not install analyzers, Node, pytest, coverage.py, or mutmut.
- A containment failure (`returncode == 71` or stderr containing `sandbox_apply`) raises `PermissionError` and is not retried outside the sandbox.
- Missing measurements stay `UNAVAILABLE` or `NOT_APPLICABLE`. Never invent a coverage or mutation number.
- Security keys in YAML stay ignored. The zero-violation gate stays on.
- Reports stay outside the audited repository unless that is already allowed.
- Auditor tests: `.venv/bin/python -m unittest discover -s tests -q` from the repository root. Sandbox and git need unrestricted permissions if the sandbox blocks them.
- Requirement 4.4: prefer the repository’s test runner over a loader written by this skill.
- Requirement 11.3: a blocking finding records file and line.
- Requirement 6.8: an unresolved or dynamic graph does not confirm dead code.

---

### Task 1: Run the repository test runner

**Files:**
- Modify: `.cursor/skills/code-quality-auditor/scripts/cqa/checks.py` (replace `_trace_line_coverage` and `_authorized_acceptance_failures`)
- Test: `tests/test_acceptance.py`

**Interfaces:**
- Consumes: `run_contained(command, cwd, log, timeout=30, write_path=None, env=None)` in `cqa.security`. It returns `CompletedProcess` on test failure. It raises `PermissionError` when execution is not approved or containment fails.
- Produces: `project_test_result(ctx) -> dict | None` cached on `ctx.project_tests`. Keys: `runner` (`"pytest"` or `"unittest"`), `cwd` (`pathlib.Path`), `failures` (list of `"relpath:method"`), `returncode` (int). `None` means the runner did not finish.

- [ ] **Step 1: Write the failing pytest-runner test**

Add this method to `AcceptanceTests` in `tests/test_acceptance.py`, next to `test_authorized_acceptance_failures_count`:

```python
def test_pytest_project_uses_its_runner(self):
    """Requirements: 4.4, 7.6, 8.3."""
    repo = self.repo("pyrunner")
    _write(repo / "quality-auditor.yaml", """
    version: 1
    default_profile: accept
    profiles:
      accept:
        include: [requirements_trace, coverage]
    """)
    _write(repo / "docs" / "requirements.md", """
    # REQ-100 Adder
    The adder works.
    Acceptance: test_add returns 2.
    """)
    _write(repo / "app.py", """
    def add(left, right):
        return left + right
    """)
    _write(repo / "tests" / "test_add.py", """
    import pytest

    def test_add():
        \"\"\"REQ-100\"\"\"
        assert 1 + 1 == 3
    """)
    runner = repo / ".venv" / "bin" / "pytest"
    runner.parent.mkdir(parents=True)
    runner.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' 'FAILED tests/test_add.py::test_add - AssertionError'\n"
        "exit 1\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    report = self.audit(repo, profile="accept", allow_repo_execution=True, sandbox_confirmed=True)
    commands = [" ".join(item["command"]) for item in report["execution"]["commands"]]
    blob = "\n".join(commands)
    self.assertIn(".venv/bin/pytest", blob)
    self.assertNotIn("cqa_accept_driver", blob)
    self.assertNotIn("cqa_trace_driver", blob)
    metrics = {item["metric_id"]: item for item in report["metrics"]}
    self.assertIn("tests/test_add.py:test_add", metrics["REQ-008"]["evidence_refs"])
    self.assertEqual(metrics["TEST-002"]["status"], "UNAVAILABLE")
    self.assertIn("coverage.py", metrics["TEST-002"]["reason"])
```

- [ ] **Step 2: Run the new test and confirm it fails**

Run: `.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_pytest_project_uses_its_runner -q`

Expected: FAIL because the engine writes `cqa_accept_driver.py` and does not invoke `.venv/bin/pytest`.

- [ ] **Step 3: Implement discovery and the two runners**

Add these helpers in `checks.py` and use them from `run_coverage` and `_authorized_acceptance_failures`. Delete the file writers that create `cqa_trace_driver.py` and `cqa_accept_driver.py`.

```python
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


def _parse_unittest_failures(text, root, start_rel):
    """Map ``FAIL: test_add (test_add.AddTests.test_add)`` onto ``tests/test_add.py:test_add``.

    ``start_rel`` is the discover start directory relative to the repository, such as ``tests`` or ``.``.
    """
    found = []
    for match in re.finditer(r"(?:FAIL|ERROR): (\w+) \(([\w.]+)\)", text):
        method, qual = match.group(1), match.group(2)
        module = qual.rsplit(".", 2)[0] if qual.count(".") >= 2 else qual.rsplit(".", 1)[0]
        rel = Path(module.replace(".", "/") + ".py")
        if start_rel not in {"", "."}:
            rel = Path(start_rel) / rel
        if (root / rel).is_file():
            found.append(f"{rel.as_posix()}:{method}")
    return found


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
                returncode = completed.returncode or returncode
                text = f"{completed.stdout or ''}\n{completed.stderr or ''}"
                failures.extend(_parse_unittest_failures(text, root, start))
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
        root = Path(ctx.root).resolve()
        failures = [
            f"{(cwd / item.split(':', 1)[0]).resolve().relative_to(root).as_posix()}:{item.split(':', 1)[1]}"
            for item in failures
        ]
        ctx.project_tests = {"runner": runner, "cwd": cwd, "failures": failures, "returncode": completed.returncode}
        return ctx.project_tests
    finally:
        shutil.rmtree(work, ignore_errors=True)
```

`_authorized_acceptance_failures` becomes:

```python
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
```

Replace `_trace_line_coverage` so a pytest result does not run the unittest tracer. When `project_test_result(ctx)` has `runner == "pytest"`, `run_coverage` returns TEST-002 `UNAVAILABLE` with reason `pytest ran; coverage.py is not installed and line coverage was not estimated` unless `importlib.util.find_spec("coverage")` or `shutil.which("coverage")` is true. Do not parse a homemade score in that case. When the runner is unittest, measure lines with stdlib `trace` around `unittest discover`. `discover` does not enter a directory that lacks `__init__.py` unless that directory is the start directory. Run one trace per parent directory of the Python tests. For a test at `tests/test_add.py` the command is:

```python
start_dir = str((Path(ctx.root).resolve() / "tests").resolve())
command = [
    sys.executable, "-m", "trace", "--count", "--missing",
    "--coverdir", str(cover), "--ignore-module", "unittest",
    "--ignore-dir", sys.prefix, "-m", "unittest", "discover",
    "-s", start_dir, "-t", start_dir, "-q",
]
```

Use `run_contained` with `cwd=Path(ctx.root).resolve()`, `write_path=cover`, `timeout=180`, and `env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(Path(ctx.root).resolve())}`. Keep the existing `.cover` reconstruction. Do not require `tests_run.txt`. If no production lines were counted, return `None` and reason `unittest discover produced no production coverage`.

Call `project_test_result(ctx)` once at the start of `run_coverage` so the cache is warm. If it returns `None` for an approved unittest project, still run the trace command above. If it returns `None` for an approved pytest project because pytest is missing, TEST-002 reason is `pytest is the repository runner and it is not installed; coverage was not estimated`.

- [ ] **Step 4: Run the focused tests**

Run:

```bash
.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_pytest_project_uses_its_runner tests.test_acceptance.AcceptanceTests.test_authorized_acceptance_failures_count tests.test_acceptance.AcceptanceTests.test_authorized_line_coverage -q
```

Expected: OK. The two existing tests still pass because those fixtures do not import pytest.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m unittest discover -s tests -q`

Expected: OK. Do not commit.

### Task 2: Token-duplicate source lines

**Files:**
- Modify: `.cursor/skills/code-quality-auditor/scripts/cqa/adapters.py` (`_python` token loop and `_script_like`)
- Modify: `.cursor/skills/code-quality-auditor/scripts/cqa/duplication.py` (`token_duplicates`)
- Test: `tests/test_acceptance.py`

**Interfaces:**
- Consumes: `analysis["tokens"]` as a list of strings, unchanged in order.
- Produces: `analysis["token_lines"]`, a list of ints, same length as `analysis["tokens"]`. `token_duplicates` locations use that line. A missing or short `token_lines` list falls back to line 1.

- [ ] **Step 1: Write the failing test**

Add to `AcceptanceTests`:

```python
def test_token_duplicate_uses_the_source_line(self):
    """Requirements: 6.9, 11.3."""
    repo = self.repo("clone-lines")
    _write(repo / "quality-auditor.yaml", """
    version: 1
    default_profile: clones
    profiles:
      clones:
        include: [duplication]
    """)
    body = "\n\nfunction copy(alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa) { return alpha+beta+gamma+delta+epsilon+zeta+eta+theta+iota+kappa; }\n"
    _write(repo / "left.js", body)
    _write(repo / "right.js", body)
    report = self.audit(repo, profile="clones")
    findings = [item for item in report["findings"] if "DUP-002" in item["metric_ids"]]
    self.assertTrue(findings)
    self.assertTrue(any(item["line"] == 3 for item in findings))
    self.assertFalse(any(item["line"] == 1 for item in findings))
```

- [ ] **Step 2: Run it and confirm failure**

Run: `.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_token_duplicate_uses_the_source_line -q`

Expected: FAIL because every token-duplicate location uses line 1.

- [ ] **Step 3: Record lines and read them**

In `_python`, append `token.start[0]` to a `lines` list in the same branches that append to `names`. Set `analysis["token_lines"] = lines`.

In `_script_like`, replace the tokens assignment with:

```python
chosen = [token for token in tokens if token[0] in {"id", "num", "op", "sym"}]
analysis["tokens"] = [token[1] for token in chosen]
analysis["token_lines"] = [token[2] for token in chosen]
```

In `token_duplicates`:

```python
lines = analysis.get("token_lines") or []
for digest, start in _winnow_fingerprints(tokens, k, winnow):
    line = lines[start] if start < len(lines) else 1
    blocks.append({"file": analysis["path"], "line": line, "hash": digest, "language": analysis["language"], "start": start})
```

- [ ] **Step 4: Run the duplication tests and the full suite**

Run:

```bash
.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_token_duplicate_uses_the_source_line tests.test_acceptance.AcceptanceTests.test_winnowing_detects_token_duplicates -q
.venv/bin/python -m unittest discover -s tests -q
```

Expected: OK. Do not commit.

### Task 3: Export only declared script symbols

**Files:**
- Modify: `.cursor/skills/code-quality-auditor/scripts/cqa/adapters.py` (`_script_like` symbol loop)
- Test: `tests/test_acceptance.py`

**Interfaces:**
- Consumes: symbol `exported` boolean already read by `cqa.graph` as `library_api = imported module and exported and not private`.
- Produces: the same symbol dict. `exported` is true only when an `export` declaration names that symbol, or the file is a C++ header (suffix `.h`, `.hpp`, `.hh`, `.hxx`).

- [ ] **Step 1: Write the failing test**

```python
def test_unexported_script_function_can_be_dead(self):
    """Requirements: 6.4, 6.5, 6.8."""
    repo = self.repo("exports")
    _write(repo / "quality-auditor.yaml", """
    version: 1
    default_profile: dead
    profiles:
      dead:
        include: [dead_code]
    """)
    _write(repo / "main.js", """
    import { used } from "./util.js";
    function main() { return used(); }
    """)
    _write(repo / "util.js", """
    export function used() { return 1; }
    function spare() { return 2; }
    """)
    _write(repo / "main.cpp", """
    #include "util.h"
    int main() { return used(); }
    """)
    _write(repo / "util.h", """
    int used() { return 1; }
    int spare() { return 2; }
    """)
    report = self.audit(repo, profile="dead")
    metrics = {item["metric_id"]: item for item in report["metrics"]}
    confirmed = [item for item in report["findings"] if "GRAPH-001" in item["metric_ids"] and item["confidence"] == "confirmed"]
    self.assertTrue(any(item["file"] == "util.js" and item["line"] == 2 for item in confirmed))
    self.assertFalse(any(item["file"] == "util.h" for item in confirmed))
    self.assertGreaterEqual(metrics["GRAPH-001"]["measured_value"], 1)
```

- [ ] **Step 2: Run it and confirm failure**

Run: `.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_unexported_script_function_can_be_dead -q`

Expected: FAIL because `name == "function"` marks `spare` exported, so the imported module keeps it unconfirmed.

- [ ] **Step 3: Fix export detection**

In the `ids` loop, stop using `name == "function"` as `exported`. A C++ header is `language == "cpp" and Path(path).suffix in {".h", ".hpp", ".hh", ".hxx"}`. Set `"exported": header` when the symbol is created.

When `name == "export"`, walk forward through ids whose text is in `{"function", "class", "default", "const", "let", "var", "async"}` and add the next identifier to `exported`. Keep the later loop that sets `symbol["exported"] = True` when `symbol["name"] in exported`.

- [ ] **Step 4: Run dead-code tests and the full suite**

Run:

```bash
.venv/bin/python -m unittest tests.test_acceptance.AcceptanceTests.test_unexported_script_function_can_be_dead tests.test_acceptance.AcceptanceTests.test_unimported_modules_are_dead_when_an_entry_exists -q
.venv/bin/python -m unittest discover -s tests -q
```

Expected: OK. `leftover.js` and `orphan.cpp` remain the only GRAPH-003 evidence in the existing test. Do not commit.

### Task 4: Record the external acceptance run

**Files:**
- Modify: `docs/REQUIREMENTS_COVERAGE.md`
- Modify: `docs/traceability.yaml` entry `14.10` only

**Interfaces:**
- Consumes: the CLI `auditor.py audit --repo <path> --profile full --allow-tools --allow-repo-execution --sandbox-confirmed`.
- Produces: the measured decision, status counts, and the new report directory. Do not change skill code in this task.

- [ ] **Step 1: Run the full profile against the validation checkout**

The checkout is the sibling directory the user already cloned. Run from this repository:

```bash
.venv/bin/python .cursor/skills/code-quality-auditor/scripts/auditor.py audit --repo /Users/user/Desktop/src/quantlineage --profile full --allow-tools --allow-repo-execution --sandbox-confirmed --history "$HOME/.code-quality-auditor/history/quantlineage.csv"
```

Expected: the process prints `FAIL` or `INCOMPLETE` and a report path. Do not treat a failing decision as a command failure to hide. Do not edit the other repository. Do not install Node.

- [ ] **Step 2: Record the measured result**

Replace the acceptance-run section in `docs/REQUIREMENTS_COVERAGE.md` with the command above, the revision `git -C /Users/user/Desktop/src/quantlineage rev-parse HEAD`, the decision, the status counts from `report.json`, and the new report directory. Set `docs/traceability.yaml` requirement `14.10` evidence to that report path and the decision. Keep `status: verified` only because the run happened and the result was recorded, not because the decision was PASS.

- [ ] **Step 3: Confirm the skill code is still generic**

Run: `rg -n "quantlineage|QuantLineage|QUANTLINEAGE" .cursor/skills/code-quality-auditor`

Expected: no matches. Do not commit.
