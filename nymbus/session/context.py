from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

from ..config import Settings
from ..connectors.litellm_conn import LiteLLMConnector
from ..proxy.engine import AnonymisationEngine
from ..proxy.local_llm import LocalLLM
from ..proxy.vault import PseudonymVault
from ..cli.transparency import TransparencyLog

_SESSIONS_DIR = Path.home() / ".local" / "share" / "nb" / "sessions"
_SHELL_RULES = Path.home() / ".local" / "share" / "nb" / "shell_rules.yaml"


class SessionLockedError(RuntimeError):
    """Another process holds the lock on this session file."""


class Session:
    """
    Lifecycle: load() → one or more send() → (auto-saved after each send).
    The .nbs file holds the vault + anonymised conversation history.
    """

    def __init__(self, session_id: str, settings: Settings) -> None:
        self._id = session_id
        self._settings = settings
        self._vault = PseudonymVault()
        self._history: list[dict[str, str]] = []
        self._path = _session_file(session_id)
        self._lock_fd: int | None = None

        self._local_llm: LocalLLM | None = (
            LocalLLM(settings) if settings.local_llm_model else None
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load vault + history from disk (if the session file exists)."""
        _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self._acquire_lock()
        if self._path.exists():
            data = json.loads(self._path.read_text())
            self._vault = PseudonymVault.from_dict(data["vault"])
            self._history = data.get("history", [])

    def save(self) -> None:
        """Atomically persist vault + history."""
        _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        data: dict[str, Any] = {
            "version": 1,
            "session_id": self._id,
            "vault": self._vault.to_dict(),
            "history": self._history,
        }
        tmp = self._path.with_suffix(".nbs.tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.chmod(0o600)
        os.rename(tmp, self._path)

    def close(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None

    # ── Core send ─────────────────────────────────────────────────────────────

    def send(
        self,
        user_text: str,
        *,
        allow_semantic_warn: bool = False,
        log: TransparencyLog | None = None,
        debug: bool = False,
    ) -> tuple[str, TransparencyLog]:
        """
        Anonymise *user_text*, call the external LLM, de-anonymise reply.
        Returns (real_reply, log).
        """
        if log is None:
            log = TransparencyLog()

        engine = AnonymisationEngine(
            self._vault,
            tier2_threshold=self._settings.tier2_threshold,
            allow_semantic_warn=allow_semantic_warn,
            custom_patterns=self._settings.custom_patterns,
            custom_wordlists=self._settings.custom_wordlists,
            local_llm=self._local_llm,
        )

        anon_prompt = engine.forward(user_text, log, debug=debug)

        self._history.append({"role": "user", "content": anon_prompt})

        messages = self._history
        if self._settings.system_prompt:
            messages = [{"role": "system", "content": self._settings.system_prompt}] + messages

        connector = LiteLLMConnector(self._settings)
        anon_reply = connector.complete(messages)

        self._history.append({"role": "assistant", "content": anon_reply})

        real_reply = engine.backward(anon_reply, log)

        self.save()

        return real_reply, log

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _acquire_lock(self) -> None:
        lock_path = self._path.with_suffix(".lock")
        fd = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise SessionLockedError(
                f"Session '{self._id}' is locked by another nb process.\n"
                f"Use a different --session id or wait for the other process to finish."
            )
        self._lock_fd = fd

    # ── Session-management helpers (used by CLI session subcommands) ──────────

    @staticmethod
    def list_sessions() -> list[dict[str, Any]]:
        if not _SESSIONS_DIR.exists():
            return []
        sessions = []
        for p in sorted(_SESSIONS_DIR.glob("*.nbs")):
            stat = p.stat()
            sessions.append({
                "id": p.stem,
                "path": str(p),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            })
        return sessions

    def export_transcript(self) -> str:
        """Return de-anonymised conversation as plain text."""
        lines: list[str] = []
        for msg in self._history:
            role = msg["role"].upper()
            content = self._vault.deanonymise(msg["content"])
            lines.append(f"[{role}]\n{content}\n")
        return "\n".join(lines)


def _session_file(session_id: str) -> Path:
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    return _SESSIONS_DIR / f"{session_id}.nbs"
