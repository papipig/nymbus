from __future__ import annotations

import sys

from .detectors.base import Span, merge_spans
from .detectors.custom_det import CustomDetector
from .detectors.ner_det import NERDetector
from .detectors.regex_det import RegexDetector
from .local_llm import LocalLLM
from .vault import PseudonymVault
from .watchdog import Watchdog
from ..cli.transparency import Event, TransparencyLog

# Types that are never substituted
_PASSTHROUGH_TYPES = frozenset({"IPv4_PRIVATE", "CIDR_PRIVATE", "IPv6_PRIVATE"})


class AnonymisationEngine:
    """
    Orchestrates: detect → (tier2 reclassify) → substitute → watchdog.
    """

    def __init__(
        self,
        vault: PseudonymVault,
        *,
        tier2_threshold: float = 0.85,
        allow_semantic_warn: bool = False,
        custom_patterns: list[str] | None = None,
        custom_wordlists: list[str] | None = None,
        local_llm: LocalLLM | None = None,
    ) -> None:
        self._vault = vault
        self._tier2_threshold = tier2_threshold
        self._local_llm = local_llm
        self._watchdog = Watchdog(vault, local_llm, allow_semantic_warn)
        self._detectors = [
            RegexDetector(),
            NERDetector(tier2_threshold),
            CustomDetector(custom_patterns, custom_wordlists),
        ]

    # ── Forward pass ──────────────────────────────────────────────────────────

    def forward(self, text: str, log: TransparencyLog, *, debug: bool = False) -> str:
        """
        Anonymise *text*.  Appends events to *log*.
        Returns the anonymised string.
        Raises on watchdog failure.
        """
        # Tier 1: detect
        spans = merge_spans([d.detect(text) for d in self._detectors])

        if debug:
            print("[debug] Tier-1 spans:", file=sys.stderr)
            for sp in spans:
                print(
                    f"  [{sp.source}] {sp.type} @{sp.start}-{sp.end} "
                    f"conf={sp.confidence:.0%} text={sp.text!r}",
                    file=sys.stderr,
                )

        # Tier 2: reclassify ambiguous spans via local LLM
        if self._local_llm:
            spans = self._reclassify(text, spans)
            if debug:
                print("[debug] After Tier-2 reclassification:", file=sys.stderr)
                for sp in spans:
                    print(
                        f"  [{sp.source}] {sp.type} @{sp.start}-{sp.end} text={sp.text!r}",
                        file=sys.stderr,
                    )

        # Substitute (right → left to keep offsets valid)
        anon = text
        for span in reversed(spans):
            if span.type in _PASSTHROUGH_TYPES:
                log.add(Event("PASS", span.text, None, span.type))
                continue
            if span.confidence < self._tier2_threshold and not self._local_llm:
                log.add(
                    Event(
                        "WARN", span.text, None, span.type,
                        f"low confidence ({span.confidence:.0%}), kept as {span.type}",
                    )
                )
            fake = self._vault.anonymise(span.text, span.type)
            log.add(Event("SUBST", span.text, fake, span.type))
            anon = anon[: span.start] + fake + anon[span.end :]

        # Watchdog forward
        warnings = self._watchdog.check_forward(text, anon)
        for w in warnings:
            log.add(Event("WARN", message=w))
        log.add(Event("OK", message="watchdog ① ② ③ passed"))
        if debug:
            print(f"[debug] Anonymised prompt:\n{anon}", file=sys.stderr)
        return anon

    # ── Backward pass ─────────────────────────────────────────────────────────

    def backward(self, anon_reply: str, log: TransparencyLog) -> str:
        """De-anonymise the external LLM reply."""
        real_reply = self._vault.deanonymise(anon_reply)
        for w in self._watchdog.check_backward(anon_reply, real_reply):
            log.add(Event("WARN", message=w))
        return real_reply

    # ── Tier 2 reclassification ───────────────────────────────────────────────

    def _reclassify(self, text: str, spans: list[Span]) -> list[Span]:
        result: list[Span] = []
        for span in spans:
            if span.confidence >= self._tier2_threshold:
                result.append(span)
                continue
            new_type = self._local_llm.reclassify(text, span)  # type: ignore[union-attr]
            if new_type is None:
                # IGNORE — remove from substitution
                continue
            result.append(
                Span(
                    start=span.start,
                    end=span.end,
                    text=span.text,
                    type=new_type,
                    confidence=1.0,
                    source="tier2",
                )
            )
        return result
