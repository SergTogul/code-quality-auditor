# Code Quality Auditor — Cursor skill

Install the folder `.cursor/skills/code-quality-auditor/` into your Cursor project (or `~/.cursor/skills/code-quality-auditor/` globally). Invoke `/code-quality-auditor full`, `/code-quality-auditor fast`, or `/code-quality-auditor init`. Cursor skill discovery follows [Cursor documentation](https://cursor.com/docs/skills).

This repository is the universal Code Quality Auditor. It includes 112 metric definitions in YAML, metric-to-check mapping, registered tool capabilities, user profiles, a safe DAG runner, a cross-language code graph, reporting, and CSV history. Quantitative risk checks run when the source declares those calculations. No repository name is special-cased. For complete security and correctness testing, grant explicit approval and provide approved analyzer environments; unavailable checks are never called PASS.

## Safety defaults
The engine only inspects files by default. External analyzers need `--allow-tools`; repository tests and scripts need an authorized sandbox and `--allow-repo-execution` plus `--sandbox-confirmed`. Installation is never automatic. Reports are written outside the audited repository by default.

## Local verification
Python 3.12 or newer is required. Install `requirements.txt` into `.venv` for local work, then run:

`.venv/bin/python -m unittest discover -s tests -v`

CI (`.github/workflows/tests.yml`) installs the exact pin in `requirements-ci.txt` and runs the same discovery through `scripts/ci/run_unittest.py` on Linux with Python 3.12, 3.13, and 3.14 and on macOS with Python 3.12. On Linux only the portions that need the native macOS `/usr/bin/sandbox-exec` are skipped, with the reason `requires macOS /usr/bin/sandbox-exec`; the unapproved-execution assertions in those tests still run. A skipped test is not counted as platform coverage. The macOS job fails if `/usr/bin/sandbox-exec` is missing or any of those native tests is skipped. Each matrix job attaches machine-readable results (`unittest.json`, `selfcheck.json`, `platform.json`) as an Actions artifact. The stable check to require for merges is `Required tests`.
