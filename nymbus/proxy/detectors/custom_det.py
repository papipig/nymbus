from __future__ import annotations

import re

from .base import Detector, Span


class CustomDetector(Detector):
    """User-defined regex patterns and literal wordlists from nymbus.yaml."""

    def __init__(
        self,
        patterns: list[str] | None = None,
        wordlists: list[str] | None = None,
    ) -> None:
        self._compiled: list[re.Pattern[str]] = []
        for pat in patterns or []:
            try:
                self._compiled.append(re.compile(pat))
            except re.error:
                pass
        # Wordlist: compile as alternation, longest words first to avoid partial matches
        words = sorted(wordlists or [], key=len, reverse=True)
        if words:
            self._compiled.append(
                re.compile(r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b")
            )

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        claimed: set[int] = set()
        for pattern in self._compiled:
            for m in pattern.finditer(text):
                s, e = m.start(), m.end()
                if claimed.intersection(range(s, e)):
                    continue
                spans.append(
                    Span(
                        start=s,
                        end=e,
                        text=m.group(),
                        type="CUSTOM",
                        confidence=1.0,
                        source="custom",
                    )
                )
                claimed.update(range(s, e))
        return sorted(spans, key=lambda sp: sp.start)
