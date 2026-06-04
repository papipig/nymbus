from __future__ import annotations

from .base import LLMClient
from ..config import Settings


class LiteLLMConnector(LLMClient):
    """Adapter for any provider supported by LiteLLM."""

    def __init__(self, settings: Settings) -> None:
        self._model = settings.external_llm_model

    def complete(self, messages: list[dict]) -> str:
        import litellm  # type: ignore[import-untyped]

        resp = litellm.completion(
            model=self._model,
            messages=messages,
        )
        return resp.choices[0].message.content.strip()
