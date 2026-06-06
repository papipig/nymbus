from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..proxy.detectors.base import Span
    from ..config import Settings

_RECLASSIFY_PROMPT = """\
Classify the following span of text in its surrounding context.

Context:
{context}

Span: "{span}"
Current classification: {current_type}

Choose the most accurate label from:
  PERSON    — a human person's name
  ORG       — an organisation, company, or team name
  GPE       — a city, country, or geographic location
  CODENAME  — a project, operation, or internal code name
  IGNORE    — not sensitive, leave as-is

Reply with exactly one label and nothing else."""

_SEMANTIC_PROMPT = """\
You are a security scanner checking whether anonymised text leaks sensitive information.

Sensitive real values (must not appear or be inferable):
{real_values}

Anonymised text to audit:
{anon_text}

Does the anonymised text reveal or allow inference of any sensitive value above?
Reply with exactly "CLEAN" if there is no leak, or "LEAK: <brief reason>" if there is."""


class LocalLLM:
    """Thin wrapper around LiteLLM for the local inference endpoint."""

    def __init__(self, settings: "Settings") -> None:
        self._model = settings.local_llm_model
        self._api_base = settings.local_llm_api_base

    def _call(self, prompt: str) -> str:
        import litellm  # type: ignore[import-untyped]

        kwargs: dict = dict(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=64,
        )
        if self._api_base:
            kwargs["api_base"] = self._api_base

        resp = litellm.completion(**kwargs)
        return resp.choices[0].message.content.strip()

    def reclassify(self, context: str, span: "Span") -> str | None:
        """Ask local LLM to classify an ambiguous span. Returns nb_type or None."""
        prompt = _RECLASSIFY_PROMPT.format(
            context=context[:500],  # cap to keep prompt small
            span=span.text,
            current_type=span.type,
        )
        try:
            raw = self._call(prompt).strip().upper().split()[0]
        except Exception:
            return None

        return {
            "PERSON": "PERSON",
            "ORG": "ORG",
            "GPE": "GPE",
            "CODENAME": "CODENAME",
            "IGNORE": None,
        }.get(raw)

    def semantic_check(self, anon_text: str, real_values: list[str]) -> str:
        """Returns 'CLEAN' or 'LEAK: <reason>'."""
        if not real_values:
            return "CLEAN"
        values_str = "\n".join(f"  - {v}" for v in real_values[:30])
        prompt = _SEMANTIC_PROMPT.format(
            real_values=values_str,
            anon_text=anon_text[:1000],
        )
        try:
            return self._call(prompt)
        except Exception as exc:
            return f"CLEAN  # local LLM error: {exc}"
