# Configuration and profiles

The skill's authoritative configuration is YAML. Reports may be JSON, Markdown, and HTML.

## Files

| File | Purpose |
| --- | --- |
| `quality-auditor.yaml` | Default profile, scope, budgets, language/path selection, and overrides |
| `config/metrics.yaml` | 112 registered metrics, including calculations and red lines |
| `config/checks.yaml` | Check definitions, dependencies, supported languages, metrics, tools, and evidence |
| `config/tools.yaml` | Registered tool capabilities by language |
| `config/policy.yaml` | Evaluation and safety policy |
| `config/schema.yaml` | Configuration schema |

All paths above are relative to `.agents/skills/code-quality-auditor/`. Your target repository may provide its own `quality-auditor.yaml`.

## Profile behavior

Built-in profiles: `full` (default), `fast`, `expensive`, `pr-review`, `security`. User-defined profiles can `extends` another profile.

```yaml
version: 1
default_profile: fast
profiles:
  team-fast:
    extends: fast
    exclude:
      - semantic_duplication
```

- Neither `include` nor `exclude`: select all registered checks.
- `include`: allowlist of checks.
- `exclude`: removes checks; when both include and exclude contain the same check, exclude wins.
- Inheritance resolves from parent to child. Child `include` can restore a parent-excluded check, while a later `exclude` wins.
- Unknown check IDs, missing profiles, and inheritance cycles are errors.

Settings precedence (highest first): explicit invocation override, nearest directory `quality-auditor.yaml`, repository `quality-auditor.yaml`, resolved profile, registry defaults.

## Inspect the effective configuration

From the skill directory:

```bash
python scripts/auditor.py checks
python scripts/auditor.py explain-profile --profile fast
python scripts/auditor.py profiles --config quality-auditor.yaml list
python scripts/auditor.py validate
```

Create or edit a profile using the engine's `profiles` command or a validated YAML file. Profile configuration cannot grant execution permissions or weaken sandbox requirements. A selected check may still return `UNAVAILABLE` when prerequisites or evidence are missing.
