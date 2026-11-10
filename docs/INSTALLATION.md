# Installation and agent discovery

This document preserves the project's agent-specific installation and migration instructions. Commands run from the canonical engine directory, `.agents/skills/code-quality-auditor/`, after cloning this repository. Python 3.12+ is required.

## Project installation

```bash
# Cursor: default selection
python scripts/auditor.py install --target /path/to/project --approve

# Claude Code
python scripts/auditor.py install --agent claude --scope project --target /path/to/project --approve

# Codex
python scripts/auditor.py install --agent codex --scope project --target /path/to/project --approve

# All three
python scripts/auditor.py install --agent all --scope project --target /path/to/project --approve
```

Cursor's default writes a copy to `.cursor/skills/code-quality-auditor/` without creating `.claude` or `.agents`. With `--agent all`, the installer creates copies under `.agents/skills/` and `.cursor/skills/`, plus a Claude symlink to the `.agents` copy (or a copy if the symlink cannot be created).

## Personal/global installation

For global installs, `--target` is the home-directory root:

```bash
python scripts/auditor.py install --agent cursor --scope global --target "$HOME" --approve
python scripts/auditor.py install --agent claude --scope global --target "$HOME" --approve
python scripts/auditor.py install --agent codex --scope global --target "$HOME" --approve
```

### Skill locations and invocation

| Agent | Project slot | Personal slot | Command |
| --- | --- | --- | --- |
| Cursor | `.cursor/skills/` or `.agents/skills/` | `~/.cursor/skills/` or `~/.agents/skills/` | `/code-quality-auditor` |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` | `/code-quality-auditor` |
| Codex | `.agents/skills/` | `~/.agents/skills/` | `$code-quality-auditor` |

Read the [Cursor](https://cursor.com/docs/skills), [Claude Code](https://code.claude.com/docs/en/skills), and [Codex](https://learn.chatgpt.com/docs/build-skills.md) skill docs for the host application's current discovery conventions.

## Update, uninstall and migration

```bash
python scripts/auditor.py update --agent claude --scope project --target /path/to/project --approve
python scripts/auditor.py uninstall --agent all --scope project --target /path/to/project --approve
```

An older Cursor installation in `.cursor/skills/code-quality-auditor/` remains a valid Cursor slot. To refresh only that skill, run the default installer with the project root as `--target`. Other skills are left in place.

Installation, update, and uninstall are write operations requiring `--approve`. Without it, the command prints `approval_required`, exits 0, and makes no changes. Installing **never** grants approval to run external analyzers or repository code.

## Known discovery caveats

- A repository checkout does not automatically create a Claude skill slot; install to `.claude/skills/`.
- `--agent all` may display the skill twice in Cursor because Cursor can discover both `.agents/skills/` and `.cursor/skills/`.
- `~/.agents/skills/` does not sync to Cursor Cloud Agents; use the documented `~/.cursor/skills/` sync location.
- Personal Claude skills are not loaded in Cowork or Claude cloud sessions.
- Codex's documented personal slot is `$HOME/.agents/skills`; this installer does not write legacy `~/.codex/skills` or admin `/etc/codex/skills`.
- A directory existing is **not proof** of successful native agent discovery. Verify by invoking the skill in your target host; restart the agent if necessary.
