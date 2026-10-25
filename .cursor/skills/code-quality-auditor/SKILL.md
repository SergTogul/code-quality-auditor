---
name: code-quality-auditor
description: >-
  Audit a repository's code quality with the universal code-quality-auditor
  skill. Use when the user invokes /code-quality-auditor, asks for a quality
  audit, dead-code or duplication analysis, security or coverage review,
  mutation or requirements tracing, or repository initialization for quality
  checks. Supports profiles full, fast, expensive, pr-review, security, and
  user-defined profiles.
---

# Code Quality Auditor

Invoke as `/code-quality-auditor [profile]`. When the profile is omitted, use `full`. Natural-language requests such as "audit this repository", "run the quality auditor", "initialize code quality", and "explain the fast profile" use this skill.

The internal runner is `.cursor/skills/code-quality-auditor/scripts/auditor.py`. Reports, catalogs, and the DAG stay behind this skill. Do not ask the user to drive a standalone product.

## Safety defaults

- Inspect source read-only. Do not modify the repository, install runtimes, or install analyzers unless the user explicitly approves that action.
- Do not infer installation approval from `/code-quality-auditor init`.
- External analyzers require `--allow-tools` and must already be installed. The tool registry does not authorize a download.
- Repository tests, mutation, benchmarks, and build scripts are untrusted. Run them only with both `--allow-repo-execution` and `--sandbox-confirmed`, and only when containment actually applies. If containment is unavailable, stop that execution and continue with static checks.
- If Python 3.12+ is missing, ask before any installation and offer a limited file inspection instead of pretending the engine ran.
- Write reports outside the audited repository.
- A failed, unavailable, or inconclusive blocking check is `INCOMPLETE` or `FAIL`, never `PASS`.
- Do not invent vulnerability, coverage, latency, or history numbers. Leave them `UNAVAILABLE` or `NOT_APPLICABLE`.
- User profiles cannot weaken installation, sandbox, or repository-execution limits.

## Commands

From the skill directory, the host agent runs:

- `python scripts/auditor.py audit --repo <path> --profile <name>`
- `python scripts/auditor.py init --repo <path>` and, only after approval, `--approve-write`
- `python scripts/auditor.py install --target <project>` only after approval with `--approve`
- `python scripts/auditor.py profiles --config <quality-auditor.yaml> list|explain|create|edit|delete`
- `python scripts/auditor.py checks`
- `python scripts/auditor.py explain-profile --profile <name>`
- `python scripts/auditor.py compare --history <history.csv> --baseline <run> --current <run>`
- `python scripts/auditor.py validate`

## Configuration

Authoritative files are YAML: `config/metrics.yaml` (112 metrics), `config/checks.yaml`, `config/tools.yaml`, `config/policy.yaml`, and `quality-auditor.yaml`. JSON is not an authoritative configuration format. Reports may be JSON, Markdown, and HTML.

Precedence, highest first: invocation overrides, nearest directory `quality-auditor.yaml`, repository `quality-auditor.yaml`, resolved profile, registry defaults.

Profile rules:

- Neither `include` nor `exclude` selects every registered check.
- `exclude` wins when the same profile also includes a check.
- `extends` runs from parent to child. A child `include` can put back a check the parent excluded. A later `exclude` stays authoritative.
- Unknown IDs, missing profiles, and inheritance cycles are errors.
- Built-in profiles: `full` (default), `fast`, `expensive`, `pr-review`, `security`.
- Users add profiles such as `pre-release` or `deep-quant` in their own YAML.

## What the audit covers

Python, JavaScript, TypeScript, and C++ adapters publish one code graph. The graph feeds dead-code and duplication analysis. Checks cover static quality, architecture, security, tests, coverage, mutation, requirements, semantic review, performance, maintainability, observability, reliability, and quantitative risk constraints. Quantitative metrics apply when source declares VaR, ES, DV01, or another quantitative risk calculation. No repository name is a dependency.

Every blocking confirmed breach carries provenance: repository, revision, location, check, metric, tool, profile, configuration hash, observation, and an evidence pointer. Suggestions are not described as applied.

Historical rows are appended to CSV and compared without treating missing measurements as zero.
