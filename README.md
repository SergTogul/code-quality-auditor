# Code Quality Auditor

One skill package, `.agents/skills/code-quality-auditor/`, is the engine. Cursor, Claude Code, and Codex install that same tree. The YAML registries live only there: `config/metrics.yaml` (112 metrics), `config/checks.yaml`, `config/tools.yaml`, `config/policy.yaml`, `config/schema.yaml`, and `quality-auditor.yaml`.

This repository includes metric-to-check mapping, registered tool capabilities, user profiles, a safe DAG runner, a cross-language code graph, reporting, and CSV history. Quantitative risk checks run when the source declares those calculations. No repository name is special-cased. For complete security and correctness testing, grant explicit approval and provide approved analyzer environments; unavailable checks are never called PASS.

Run the commands below from the directory that contains `SKILL.md`. `--repo` is the host project. Installing does not approve analyzers or repository execution. Without `--approve`, the command prints `approval_required`, exits 0, and writes nothing.

## Install

Cursor project slot (the default, and the same destination earlier releases used):

```bash
python scripts/auditor.py install --target /path/to/project --approve
```

That writes `/path/to/project/.cursor/skills/code-quality-auditor/` and does not create `.claude` or `.agents`.

Claude Code, project:

```bash
python scripts/auditor.py install --agent claude --scope project --target /path/to/project --approve
```

Codex, project:

```bash
python scripts/auditor.py install --agent codex --scope project --target /path/to/project --approve
```

All three, project:

```bash
python scripts/auditor.py install --agent all --scope project --target /path/to/project --approve
```

`--agent all` writes a real copy at `.agents/skills/code-quality-auditor/`, a real copy at `.cursor/skills/code-quality-auditor/`, and a symlink at `.claude/skills/code-quality-auditor/` (a copy if the symlink cannot be created).

Global installs use the same relative suffixes. `--target` is the directory standing in for the home directory, shown here as `"$HOME"`:

```bash
python scripts/auditor.py install --agent cursor --scope global --target "$HOME" --approve
python scripts/auditor.py install --agent claude --scope global --target "$HOME" --approve
python scripts/auditor.py install --agent codex --scope global --target "$HOME" --approve
```

Update and uninstall take the same selector flags:

```bash
python scripts/auditor.py update --agent claude --scope project --target /path/to/project --approve
python scripts/auditor.py uninstall --agent all --scope project --target /path/to/project --approve
```

## Invocation

Cursor: `/code-quality-auditor`. Project skills load from `.agents/skills/` and `.cursor/skills/`. User skills load from `~/.agents/skills/` and `~/.cursor/skills/`. See [Cursor skills](https://cursor.com/docs/skills).

Claude Code: `/code-quality-auditor`. Project: `.claude/skills/code-quality-auditor/SKILL.md`. Personal: `~/.claude/skills/code-quality-auditor/SKILL.md`. A skill directory in those locations may be a symlink; Claude loads the target once. See [Claude Code skills](https://code.claude.com/docs/en/skills).

Codex: `$code-quality-auditor` (`/skills` or `$` in the CLI). Project skills load from `$REPO_ROOT/.agents/skills` and ancestors up to the repo root. User skills load from `$HOME/.agents/skills`. Codex follows symlinked skill folders. See [Codex skills](https://learn.chatgpt.com/docs/build-skills.md).

## Migration

An existing `.cursor/skills/code-quality-auditor/` install remains a Cursor slot. To refresh it from this repository, run the default install from `.agents/skills/code-quality-auditor/` with `--target` set to the project root. That replaces this skill's Cursor directory and leaves every other skill where it is. Use `--agent all` when Claude Code and Codex should see the same package: the Codex copy is `.agents/skills/code-quality-auditor/`, and Claude's slot is a symlink to that copy.

## Known limitations

- Claude Code does not document `.agents/skills`. A checkout of this repository is not a Claude install until the Claude slot exists. This was checked against [Claude Code skills](https://code.claude.com/docs/en/skills), which lists `.claude/skills` only.
- `--agent all` can show the skill twice in Cursor, once from `.agents/skills` and once from `.cursor/skills`. Both directories are documented at [Cursor skills](https://cursor.com/docs/skills).
- `~/.agents/skills` is not synced to Cursor Cloud Agents. `~/.cursor/skills/` is the documented sync location.
- Personal Claude skills are not loaded in Cowork or Claude cloud sessions.
- Codex admin skills live at `/etc/codex/skills`, and `~/.codex/skills` is a legacy path. This installer does not write either one. Codex's documented locations are `$REPO_ROOT/.agents/skills` and `$HOME/.agents/skills` ([Codex skills](https://learn.chatgpt.com/docs/build-skills.md)).
- Installing does not approve analyzers or repository execution.
- Native agent discovery was not verified by the presence of a directory. CI does not treat directory layout as native agent invocation. The manual check is: Cursor Customize → Skills, Claude `/code-quality-auditor` after `claude plugin validate`, Codex `$code-quality-auditor` (restart if it does not appear).

## Safety defaults
The engine only inspects files by default. External analyzers need `--allow-tools`; repository tests and scripts need `--allow-repo-execution` plus `--sandbox-confirmed`. Installation is never automatic. Reports are written outside the audited repository by default.

Approved analyzers and repository code both run only under containment, because analyzers read repository-controlled content. The only supported containment is the root-owned `/usr/bin/sandbox-exec` on macOS. Its profile denies by default and allows scoped reads, writes to one scratch directory, and no network. A probe must show that the profile blocks sibling files and loopback network before anything runs. On Linux and Windows containment is unavailable, so external analyzers and repository execution are reported unavailable while built-in static checks continue. `CQA_SANDBOX_CMD` and other custom wrappers cannot authorize containment, and a containment failure is never retried unsandboxed.

The profile still allows `sysctl-read`, `mach-lookup`, and `ipc-posix*` without filters. These are compatibility exceptions so that macOS processes can start, not least privilege, and `mach-lookup` in particular reaches system services outside the file and network rules. Native enforcement of the profile has not been verified yet; that is tracked in issue #10. The sandbox trust tests mock `_trusted_sandbox()` and check policy text, probe decisions, and the launch path; they are not evidence that macOS Seatbelt enforces the profile. On timeout or output overflow the engine kills the command's session, and on Linux also its remaining `/proc` children, but this cleanup is best effort: a process that calls `setsid` or is reparented can survive, especially on macOS, so it is not part of the containment guarantee.

## Local verification
`.venv/bin/python -m unittest discover -s tests -v`
