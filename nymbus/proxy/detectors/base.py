from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

# Priority: higher value = matched first when spans overlap
_TYPE_PRIORITY: dict[str, int] = {
    "CIDR_PRIVATE": 100,
    "CIDR_PUBLIC": 100,
    "IPv4_PRIVATE": 90,
    "IPv4_PUBLIC": 90,
    "IPv6": 90,
    "IPv6_PRIVATE": 90,
    "IPv6_PUBLIC": 90,
    "MAC": 80,
    "EMAIL": 70,
    "URL": 70,
    "FQDN": 60,
    "FILEPATH_WIN": 50,
    "FILEPATH_UNIX": 50,
    "HASH": 40,
    "CREDENTIAL": 40,
    "UUID": 30,
    "PERSON": 20,
    "ORG": 20,
    "GPE": 10,
    "CUSTOM": 10,
}


@dataclass
class Span:
    start: int
    end: int
    text: str
    type: str
    confidence: float = 1.0
    source: str = "regex"  # "regex" | "ner" | "tier2" | "custom"

    @property
    def priority(self) -> int:
        return _TYPE_PRIORITY.get(self.type, 0)


class Detector(ABC):
    @abstractmethod
    def detect(self, text: str) -> list[Span]: ...


def merge_spans(span_lists: list[list[Span]]) -> list[Span]:
    """Merge multiple detector outputs, resolving overlaps by priority then order."""
    all_spans = sorted(
        (s for spans in span_lists for s in spans),
        key=lambda s: (-s.priority, s.start),
    )
    claimed: set[int] = set()
    result: list[Span] = []
    for span in all_spans:
        chars = set(range(span.start, span.end))
        if chars & claimed:
            continue
        claimed |= chars
        result.append(span)
    return sorted(result, key=lambda s: s.start)
