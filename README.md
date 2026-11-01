# Code Quality Auditor — Cursor skill

Install the folder `.cursor/skills/code-quality-auditor/` into your Cursor project (or `~/.cursor/skills/code-quality-auditor/` globally). Invoke `/code-quality-auditor full`, `/code-quality-auditor fast`, or `/code-quality-auditor init`. Cursor skill discovery follows [Cursor documentation](https://cursor.com/docs/skills).

This repository is the universal Code Quality Auditor. It includes 112 metric definitions in YAML, metric-to-check mapping, registered tool capabilities, user profiles, a safe DAG runner, a cross-language code graph, reporting, and CSV history. Quantitative risk checks run when the source declares those calculations. No repository name is special-cased. For complete security and correctness testing, grant explicit approval and provide approved analyzer environments; unavailable checks are never called PASS.

## Safety defaults
The engine only inspects files by default. External analyzers need `--allow-tools`; repository tests and scripts need `--allow-repo-execution` plus `--sandbox-confirmed`. Installation is never automatic. Reports are written outside the audited repository by default.

Approved analyzers and repository code both run only under containment, because analyzers read repository-controlled content. The only supported containment is the root-owned `/usr/bin/sandbox-exec` on macOS. Its profile denies by default and allows scoped reads, writes to one scratch directory, and no network. A probe must show that the profile blocks sibling files and loopback network before anything runs. On Linux and Windows containment is unavailable, so external analyzers and repository execution are reported unavailable while built-in static checks continue. `CQA_SANDBOX_CMD` and other custom wrappers cannot authorize containment, and a containment failure is never retried unsandboxed.

## Local verification
`.venv/bin/python -m unittest discover -s tests -v`
