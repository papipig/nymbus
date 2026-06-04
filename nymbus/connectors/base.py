from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    @abstractmethod
    def complete(self, messages: list[dict]) -> str:
        """Send *messages* and return the assistant reply."""
        ...
