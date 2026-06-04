from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .vault import PseudonymVault
    from .local_llm import LocalLLM


class AnonymisationError(RuntimeError):
    """Check ①: round-trip deanon(anon(x)) ≠ x."""


class LeakDetectedError(RuntimeError):
    """Check ②: real value found in anonymised text."""


class SemanticLeakError(RuntimeError):
    """Check ③: local LLM detected a semantic leak."""


class Watchdog:
    def __init__(
        self,
        vault: "PseudonymVault",
        local_llm: "LocalLLM | None",
        allow_semantic_warn: bool = False,
    ) -> None:
        self._vault = vault
        self._local_llm = local_llm
        self._allow_semantic_warn = allow_semantic_warn

    # ── Forward checks (before sending to external LLM) ──────────────────────

    def check_forward(
        self,
        original: str,
        anon: str,
    ) -> list[str]:
        """
        Run checks ①②③.  Returns a list of warning messages (non-fatal).
        Raises on hard failures.
        """
        warnings: list[str] = []

        # ① Completeness: deanon(anon(x)) == x
        restored = self._vault.deanonymise(anon)
        if restored != original:
            # Find first differing position for diagnostics
            pos = next(
                (i for i, (a, b) in enumerate(zip(original, restored)) if a != b),
                min(len(original), len(restored)),
            )
            raise AnonymisationError(
                f"Round-trip check failed at position {pos}: "
                f"original[{pos}]={original[pos:pos+20]!r} "
                f"restored[{pos}]={restored[pos:pos+20]!r}"
            )

        # ② Exact scan: real value must not appear in anon text (case-folded)
        anon_lower = anon.lower()
        for real_val in self._vault.real_values():
            if real_val.lower() in anon_lower:
                raise LeakDetectedError(
                    f"Real value {real_val!r} found in anonymised text"
                )

        # ③ LLM semantic scan
        if self._local_llm is not None:
            active_reals = self._vault.active_real_values_for(anon)
            if active_reals:
                result = self._local_llm.semantic_check(anon, active_reals)
                if result.startswith("LEAK"):
                    if self._allow_semantic_warn:
                        warnings.append(f"Semantic scan: {result}")
                    else:
                        raise SemanticLeakError(result)
        else:
            warnings.append(
                "Watchdog ③ skipped: no local_llm_model configured "
                "(pass --allow-semantic-warn to silence)"
            )

        return warnings

    # ── Backward check (after external LLM reply) ─────────────────────────────

    def check_backward(self, anon_reply: str, real_reply: str) -> list[str]:
        """
        Check ④: alias residue — unreplaced fake tokens in de-anonymised reply.
        Always a warning, never a hard block.
        """
        warnings: list[str] = []
        for fake in self._vault.fake_values():
            if fake in real_reply:
                warnings.append(
                    f"Alias residue: fake value {fake!r} still present in reply "
                    f"(LLM may have hallucinated an unknown identifier)"
                )
        return warnings
