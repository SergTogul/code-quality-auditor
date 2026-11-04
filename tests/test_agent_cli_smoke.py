"""Native agent discovery smoke tests.

A directory on disk is not evidence that an agent loaded the skill. Cursor and
Codex document no non-interactive discovery command, so those tests always skip
with the manual check. ``--version`` is not a compatibility pass. Claude's
``plugin validate`` is a frontmatter check, not an audit.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".agents" / "skills" / "code-quality-auditor"
SCRIPT = SKILL / "scripts" / "auditor.py"

CURSOR_MANUAL = (
    "Cursor has no documented non-interactive skill discovery command. "
    "Manual check: Cursor Customize → Skills. --version is not a compatibility pass."
)
CODEX_MANUAL = (
    "Codex has no documented non-interactive skill discovery command. "
    "Manual check: $code-quality-auditor (restart if it does not appear). "
    "--version is not a compatibility pass."
)
CLAUDE_MANUAL = (
    "claude is not installed. Manual check: claude plugin validate <skills-dir>, "
    "then /code-quality-auditor. --version is not a compatibility pass."
)


class AgentCliSmokeTests(unittest.TestCase):
    def test_cursor_discovery_is_manual(self):
        self.skipTest(CURSOR_MANUAL)

    def test_codex_discovery_is_manual(self):
        self.skipTest(CODEX_MANUAL)

    def test_claude_plugin_validate_when_installed(self):
        if shutil.which("claude") is None:
            self.skipTest(CLAUDE_MANUAL)
        tmp = Path(tempfile.mkdtemp(prefix="cqa-claude-smoke-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        installed = subprocess.run(
            [sys.executable, str(SCRIPT), "install", "--agent", "claude", "--target", str(tmp), "--approve"],
            cwd=tmp,
            capture_output=True,
            text=True,
        )
        self.assertEqual(installed.returncode, 0, installed.stderr)
        skills_dir = tmp / ".claude" / "skills"
        self.assertTrue((skills_dir / "code-quality-auditor" / "SKILL.md").is_file())
        try:
            completed = subprocess.run(
                ["claude", "plugin", "validate", str(skills_dir)],
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            self.fail("claude plugin validate timed out")
        combined = f"{completed.stdout}\n{completed.stderr}".lower()
        if completed.returncode != 0 and any(
            token in combined
            for token in ("unknown command", "unknown plugin", "unrecognized", "not found", "no such command", "invalid choice")
        ):
            self.skipTest(
                "claude plugin validate is unavailable. Manual check: claude plugin validate <skills-dir>, "
                "then /code-quality-auditor. --version is not a compatibility pass."
            )
        self.assertEqual(completed.returncode, 0, combined)


if __name__ == "__main__":
    unittest.main()
