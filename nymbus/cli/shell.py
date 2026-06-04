from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Literal

import typer
import yaml
from rich.console import Console

_RULES_PATH = Path.home() / ".local" / "share" / "nb" / "shell_rules.yaml"

RuleAction = Literal["allow", "deny"]

console = Console()


class ShellRunner:
    """
    Execute shell commands suggested by the LLM, with configurable allow/deny
    rules and an interactive fallback when no rule matches.
    """

    def __init__(
        self,
        confirm: bool = True,
        allow_patterns: list[str] | None = None,
        deny_patterns: list[str] | None = None,
    ) -> None:
        self._confirm = confirm
        self._persistent = _load_rules()
        self._session_always: dict[str, RuleAction] = {}
        self._allow_patterns = allow_patterns or []
        self._deny_patterns = deny_patterns or []

    # ── Public ─────────────────────────────────────────────────────────────────

    def run(self, command: str) -> int | None:
        """
        Present the command to the user and execute it if approved.
        Returns the exit code (or None if not executed).
        """
        action = self._resolve(command)

        if action == "deny":
            console.print(f"[red][BLOCK][/] Shell command denied: {command!r}")
            return None

        if action == "allow":
            console.print(f"[green][EXEC][/] {command}")
            return _execute(command)

        # No pre-existing rule → interactive
        if not self._confirm:
            console.print(
                f"[yellow][SKIP][/] No rule for command (--no-shell active): {command!r}"
            )
            return None

        return self._prompt_and_run(command)

    # ── Private ────────────────────────────────────────────────────────────────

    def _resolve(self, command: str) -> RuleAction | None:
        # Config-level patterns take priority
        for pat in self._deny_patterns:
            if pat in command:
                return "deny"
        for pat in self._allow_patterns:
            if pat in command:
                return "allow"

        # Session-level overrides
        if command in self._session_always:
            return self._session_always[command]

        # Persistent user rules
        if command in self._persistent:
            return self._persistent[command]

        return None

    def _prompt_and_run(self, command: str) -> int | None:
        console.print(f"\n[bold yellow]LLM suggested command:[/] {command!r}")
        console.print(
            "  [y] Execute once   [A] Always allow   [n] Skip   [D] Always deny"
        )

        choice = _prompt_char()
        if choice == "y":
            return _execute(command)
        if choice == "A":
            self._session_always[command] = "allow"
            _save_rule(command, "allow")
            return _execute(command)
        if choice == "D":
            self._session_always[command] = "deny"
            _save_rule(command, "deny")
            console.print("[red]Command denied and rule saved.[/]")
            return None
        # n or anything else
        console.print("[dim]Command skipped.[/]")
        return None


# ── Module-level helpers ──────────────────────────────────────────────────────

def _prompt_char() -> str:
    try:
        val = typer.prompt("Choice", default="n").strip().lower()
    except Exception:
        val = "n"
    return val[0] if val else "n"


def _execute(command: str) -> int:
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=False,
        )
        return result.returncode
    except Exception as exc:
        console.print(f"[red]Execution error:[/] {exc}")
        return 1


def _load_rules() -> dict[str, RuleAction]:
    if not _RULES_PATH.exists():
        return {}
    try:
        data = yaml.safe_load(_RULES_PATH.read_text()) or {}
        return {k: v for k, v in data.items() if v in ("allow", "deny")}
    except Exception:
        return {}


def _save_rule(command: str, action: RuleAction) -> None:
    _RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    rules = _load_rules()
    rules[command] = action
    _RULES_PATH.write_text(yaml.safe_dump(rules))
