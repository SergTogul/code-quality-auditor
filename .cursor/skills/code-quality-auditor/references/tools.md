# Tools by purpose and language

Generated from `config/tools.yaml`. Registry entries do not authorize installation or execution.

## cqa-builtin

In-process static analysis and orchestration

Languages: python, javascript, typescript, cpp

Checks: `syntax_static`, `symbol_index`, `dead_code`, `clean_code`, `architecture`, `duplication`, `semantic_duplication`, `secrets`, `security_sast`, `dependency_audit`, `insecure_config`, `testing`, `coverage`, `concurrency`, `requirements_trace`, `ai_evaluation`, `performance_benchmarks`, `maintainability`, `observability`, `reliability`, `quantitative`

Prerequisites: Python 3.12+ proposed runtime

Input: Repository source files

Output: Findings, graph, and metric measurements

Version constraint: `1.1.0`

Cost class: cheap

Safety: Read-only. Does not install software and does not execute repository code unless a separate authorized sandbox run is requested.

## ruff

Python lint and format checks

Languages: python

Checks: `syntax_static`, `clean_code`, `reliability`

Prerequisites: ruff on PATH

Input: Python source

Output: JSON diagnostics

Version constraint: `>=0.6`

Cost class: cheap

Safety: Approved static analyzer. Running it requires tool approval. The registry does not authorize installation.

## vulture

Python unused-code analysis

Languages: python

Checks: `symbol_index`, `dead_code`, `architecture`

Prerequisites: vulture on PATH

Input: Python source

Output: Unused-name report

Version constraint: `>=2.0`

Cost class: cheap

Safety: Corroborates dead code. Dynamic behavior remains uncertain. Tool approval required.

## semgrep

Multi-language static security rules

Languages: python, javascript, typescript, cpp

Checks: `security_sast`, `insecure_config`

Prerequisites: semgrep on PATH and local rules

Input: Source files

Output: JSON findings

Version constraint: `>=1.50`

Cost class: moderate

Safety: Do not download remote rules without network approval. Tool approval required.

## bandit

Python security patterns

Languages: python

Checks: `security_sast`, `insecure_config`

Prerequisites: bandit on PATH

Input: Python source

Output: JSON findings

Version constraint: `>=1.7`

Cost class: cheap

Safety: Static only. Tool approval required.

## jscpd

Copy-paste detection

Languages: python, javascript, typescript, cpp

Checks: `duplication`, `semantic_duplication`

Prerequisites: jscpd on PATH

Input: Source files

Output: JSON clone report

Version constraint: `>=3.0`

Cost class: moderate

Safety: Corroborates duplication. Tool approval required.

## knip

JavaScript and TypeScript unused exports

Languages: javascript, typescript

Checks: `symbol_index`, `dead_code`, `architecture`

Prerequisites: knip on PATH

Input: JS/TS project

Output: Unused export report

Version constraint: `>=5.0`

Cost class: moderate

Safety: Does not execute application code. Tool approval required.

## eslint

JavaScript and TypeScript lint

Languages: javascript, typescript

Checks: `syntax_static`, `clean_code`, `reliability`

Prerequisites: eslint on PATH

Input: JS/TS source

Output: JSON diagnostics

Version constraint: `>=8.0`

Cost class: cheap

Safety: Use the repository config only as data. Tool approval required.

## clang-tidy

C++ static analysis

Languages: cpp

Checks: `symbol_index`, `dead_code`, `clean_code`, `architecture`, `reliability`

Prerequisites: clang-tidy on PATH

Input: C++ translation units

Output: Diagnostics

Version constraint: `>=16`

Cost class: expensive

Safety: Do not run repository build scripts. Tool approval required.

## clang

C++ parse check

Languages: cpp

Checks: `syntax_static`

Prerequisites: clang on PATH

Input: C++ source

Output: Syntax diagnostics

Version constraint: `>=16`

Cost class: moderate

Safety: Invoke -fsyntax-only only. Do not link or run the program. Tool approval required.

## pytest

Python test runner

Languages: python

Checks: `testing`, `concurrency`, `quantitative`

Prerequisites: pytest on PATH

Input: Python tests

Output: JUnit or console result

Version constraint: `>=7.0`

Cost class: moderate

Safety: Executes repository tests. Requires repository-execution approval and a real sandbox.

## jest

JavaScript and TypeScript test runner

Languages: javascript, typescript

Checks: `testing`, `concurrency`, `quantitative`

Prerequisites: jest on PATH

Input: JS/TS tests

Output: JSON result

Version constraint: `>=29.0`

Cost class: moderate

Safety: Executes repository tests. Requires repository-execution approval and a real sandbox.

## ctest

C++ test runner

Languages: cpp

Checks: `testing`, `concurrency`, `quantitative`

Prerequisites: ctest on PATH

Input: CTest tests

Output: Console result

Version constraint: `>=3.20`

Cost class: moderate

Safety: Executes repository tests. Requires repository-execution approval and a real sandbox.

## coverage

Python line and branch coverage

Languages: python

Checks: `coverage`

Prerequisites: coverage on PATH

Input: Python tests

Output: Coverage JSON

Version constraint: `>=7.0`

Cost class: moderate

Safety: Executes repository tests. Requires repository-execution approval and a real sandbox.

## c8

JavaScript and TypeScript coverage

Languages: javascript, typescript

Checks: `coverage`

Prerequisites: c8 or nyc on PATH

Input: JS/TS tests

Output: Coverage JSON

Version constraint: `>=8.0`

Cost class: moderate

Safety: Executes repository tests. Requires repository-execution approval and a real sandbox.

## mutmut

Python mutation testing

Languages: python

Checks: `mutation_testing`

Prerequisites: mutmut on PATH

Input: Python tests and source

Output: Mutation score

Version constraint: `>=2.4`

Cost class: expensive

Safety: Executes mutated repository code. Requires repository-execution approval and a real sandbox.

## stryker

JavaScript and TypeScript mutation testing

Languages: javascript, typescript

Checks: `mutation_testing`

Prerequisites: stryker on PATH

Input: JS/TS tests and source

Output: Mutation score

Version constraint: `>=8.0`

Cost class: expensive

Safety: Executes mutated repository code. Requires repository-execution approval and a real sandbox.

## pip-audit

Python dependency advisories

Languages: python

Checks: `dependency_audit`

Prerequisites: pip-audit on PATH and a local database or approved network

Input: Python dependency manifests

Output: Advisory JSON

Version constraint: `>=2.6`

Cost class: moderate

Safety: Do not install dependencies. Network access requires separate approval.

## npm-audit

JavaScript dependency advisories

Languages: javascript, typescript

Checks: `dependency_audit`

Prerequisites: npm on PATH and approved network or a local advisory file

Input: package manifests

Output: Advisory JSON

Version constraint: `>=9.0`

Cost class: moderate

Safety: Do not run package lifecycle scripts. Network access requires separate approval.

## gitleaks

Secret detection

Languages: python, javascript, typescript, cpp

Checks: `secrets`

Prerequisites: gitleaks on PATH

Input: Source and history

Output: Secret findings

Version constraint: `>=8.0`

Cost class: cheap

Safety: Read-only scan. Tool approval required. Findings stay redacted in reports.

## detect-secrets

Secret detection

Languages: python, javascript, typescript, cpp

Checks: `secrets`

Prerequisites: detect-secrets on PATH

Input: Source files

Output: Secret findings

Version constraint: `>=1.4`

Cost class: cheap

Safety: Read-only scan. Tool approval required.

## radon

Python complexity

Languages: python

Checks: `clean_code`, `reliability`

Prerequisites: radon on PATH

Input: Python source

Output: Complexity JSON

Version constraint: `>=6.0`

Cost class: cheap

Safety: Static only. Tool approval required.

## pytest-benchmark

Python benchmarks

Languages: python

Checks: `performance_benchmarks`

Prerequisites: pytest-benchmark installed in an approved environment

Input: Benchmark tests

Output: Benchmark JSON

Version constraint: `>=4.0`

Cost class: expensive

Safety: Executes repository code. Requires repository-execution approval and a real sandbox.

## google-benchmark

C++ benchmarks

Languages: cpp

Checks: `performance_benchmarks`

Prerequisites: built benchmark binary supplied by an approved build

Input: Benchmark binary

Output: Console measurements

Version constraint: `>=1.8`

Cost class: expensive

Safety: Running a repository binary requires repository-execution approval and a real sandbox. The auditor does not build it.
