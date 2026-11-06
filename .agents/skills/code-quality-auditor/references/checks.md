# Checks

Generated from `config/checks.yaml`. Do not edit by hand.

## syntax_static

Parse supported source and report confirmed syntax errors.

Metrics: `REL-004`

Evidence: parser diagnostics

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `ruff`, `eslint`, `clang`

Depends on: `none`

## symbol_index

Build the shared cross-language code graph and its completeness record.

Metrics: `GRAPH-005`, `GRAPH-006`, `GRAPH-007`, `GRAPH-008`

Evidence: code graph, completeness record

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `vulture`, `knip`, `clang-tidy`

Depends on: `syntax_static`

## dead_code

Find unreachable functions, classes, modules, and constant-dead branches.

Metrics: `GRAPH-001`, `GRAPH-002`, `GRAPH-003`, `GRAPH-004`

Evidence: reachability, control-flow constants

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `vulture`, `knip`, `clang-tidy`

Depends on: `symbol_index`

## clean_code

Measure naming, size, complexity, consistency, unused names, and commented-out code.

Metrics: `CC-001`, `CC-002`, `CC-003`, `CC-004`, `CC-005`, `CC-006`, `CC-007`, `CC-008`, `CC-009`, `CC-010`, `CC-011`, `CC-012`, `CC-013`, `CC-014`

Evidence: symbol table, style scan

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `ruff`, `eslint`, `radon`, `clang-tidy`

Depends on: `syntax_static`, `symbol_index`

## architecture

Evaluate SOLID signals, coupling, cohesion, layering, and dependency direction.

Metrics: `ARCH-001`, `ARCH-002`, `ARCH-003`, `ARCH-004`, `ARCH-005`, `ARCH-006`, `ARCH-007`, `ARCH-008`, `ARCH-009`, `ARCH-010`, `ARCH-011`, `ARCH-012`

Evidence: import graph, layer rules

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `vulture`, `knip`, `clang-tidy`

Depends on: `symbol_index`

## duplication

Detect exact, token, and structural duplication.

Metrics: `DUP-001`, `DUP-002`, `DUP-003`

Evidence: clone groups

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `jscpd`

Depends on: `syntax_static`

## semantic_duplication

Investigate semantic and cross-language redundancy without treating similarity as proof.

Metrics: `DUP-004`, `DUP-005`, `DUP-006`

Evidence: candidate pairs, justification records

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `jscpd`

Depends on: `duplication`, `symbol_index`

## secrets

Detect confirmed secrets and hard-coded credentials.

Metrics: `SEC-001`, `SEC-007`

Evidence: redacted match

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `gitleaks`, `detect-secrets`

Depends on: `syntax_static`

## security_sast

Detect injection, validation, authorization, deserialization, traversal, XSS, and crypto issues.

Metrics: `SEC-003`, `SEC-004`, `SEC-005`, `SEC-008`, `SEC-009`, `SEC-010`, `SEC-011`

Evidence: sink locations

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `semgrep`, `bandit`

Depends on: `syntax_static`

## dependency_audit

Check declared dependencies against an approved local advisory source.

Metrics: `SEC-002`

Evidence: advisory report or unavailable reason

Languages: python, javascript, typescript, cpp

Tools: `pip-audit`, `npm-audit`, `cqa-builtin`

Depends on: `none`

## insecure_config

Detect insecure shipped configuration.

Metrics: `SEC-006`, `SEC-012`

Evidence: configuration locations

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `semgrep`, `bandit`

Depends on: `none`

## testing

Evaluate test presence, boundaries, properties, invariants, integration, regression, assertions, and independence.

Metrics: `TEST-001`, `TEST-005`, `TEST-006`, `TEST-007`, `TEST-008`, `TEST-009`, `TEST-011`, `TEST-012`

Evidence: test inventory

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `pytest`, `jest`, `ctest`

Depends on: `syntax_static`

## coverage

Measure line and branch coverage when an approved runner produces data.

Metrics: `TEST-002`, `TEST-003`

Evidence: coverage report

Languages: python, javascript, typescript, cpp

Tools: `coverage`, `c8`, `cqa-builtin`

Depends on: `testing`

## mutation_testing

Measure mutation score with an approved mutation tool.

Metrics: `TEST-004`

Evidence: mutation report

Languages: python, javascript, typescript, cpp

Tools: `mutmut`, `stryker`

Depends on: `testing`

## concurrency

Evaluate concurrency tests where concurrent code exists.

Metrics: `TEST-010`

Evidence: concurrency primitive inventory

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `pytest`, `jest`, `ctest`

Depends on: `testing`

## requirements_trace

Trace requirements to implementation and meaningful verification.

Metrics: `REQ-001`, `REQ-002`, `REQ-003`, `REQ-004`, `REQ-005`, `REQ-006`, `REQ-007`, `REQ-008`

Evidence: specification index, test links

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`

Depends on: `none`

## ai_evaluation

Evaluate hallucination, unjustified behavior, architecture drift, test independence, and semantic redundancy.

Metrics: `AI-001`, `AI-002`, `AI-003`, `AI-004`, `AI-005`, `AI-006`, `AI-007`, `AI-008`

Evidence: requirement citations, semantic candidates

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`

Depends on: `requirements_trace`, `symbol_index`, `semantic_duplication`

## performance_benchmarks

Evaluate declared performance targets, benchmark presence, and static efficiency signals.

Metrics: `PERF-001`, `PERF-002`, `PERF-003`, `PERF-004`, `PERF-005`, `PERF-006`, `PERF-007`, `PERF-008`

Evidence: requirements, benchmark results, loop structure

Languages: python, javascript, typescript, cpp

Tools: `pytest-benchmark`, `google-benchmark`, `cqa-builtin`

Depends on: `syntax_static`

## maintainability

Evaluate churn, debt, co-change, API compatibility, docs, and dependency freshness from real evidence.

Metrics: `MAINT-001`, `MAINT-002`, `MAINT-003`, `MAINT-004`, `MAINT-005`, `MAINT-006`, `MAINT-007`, `MAINT-008`

Evidence: git history, baseline snapshot

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`

Depends on: `symbol_index`

## observability

Evaluate logging, metrics, tracing, errors, health, and operational readiness when a service exists.

Metrics: `OBS-001`, `OBS-002`, `OBS-003`, `OBS-004`, `OBS-005`, `OBS-006`

Evidence: service entry points, operational docs

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`

Depends on: `symbol_index`

## reliability

Evaluate error handling, bounded external calls, and determinism.

Metrics: `REL-001`, `REL-002`, `REL-003`

Evidence: handler and call inventory

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `ruff`, `eslint`, `radon`, `clang-tidy`

Depends on: `syntax_static`

## quantitative

Evaluate numerical, risk, snapshot, attribution, and non-invention constraints for quantitative repositories.

Metrics: `QUANT-001`, `QUANT-002`, `QUANT-003`, `QUANT-004`, `QUANT-005`, `QUANT-006`

Evidence: risk symbols, reference tests

Languages: python, javascript, typescript, cpp

Tools: `cqa-builtin`, `pytest`, `jest`, `ctest`

Depends on: `testing`, `requirements_trace`
