from __future__ import annotations

from .base import Detector, Span

# spaCy label → nymbus type
_LABEL_MAP: dict[str, str] = {
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "GPE",   # geo-political entity (city, country); always escalates to Tier 2
}

# Heuristic confidence by entity type / token count.
# spaCy en_core_web_sm does not expose per-entity probability, so we
# approximate: multi-word PERSON/ORG entities are highly reliable; single-word
# ORG and all GPE are ambiguous and will be escalated to Tier 2.
def _confidence(label: str, text: str) -> float:
    words = text.split()
    if label == "PERSON":
        return 0.90 if len(words) >= 2 else 0.78
    if label == "ORG":
        return 0.88 if len(words) >= 2 else 0.72
    # GPE — always below default threshold so Tier 2 fires
    return 0.65


class NERDetector(Detector):
    def __init__(self, tier2_threshold: float = 0.85) -> None:
        self._threshold = tier2_threshold
        self._nlp = None
        try:
            import spacy  # type: ignore[import-untyped]
            self._nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
        except (ImportError, OSError):
            pass  # NER disabled; Tier 1 still works via regex

    def available(self) -> bool:
        return self._nlp is not None

    def detect(self, text: str) -> list[Span]:
        if self._nlp is None:
            return []
        doc = self._nlp(text)
        spans: list[Span] = []
        for ent in doc.ents:
            nb_type = _LABEL_MAP.get(ent.label_)
            if nb_type is None:
                continue
            conf = _confidence(ent.label_, ent.text)
            spans.append(
                Span(
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    type=nb_type,
                    confidence=conf,
                    source="ner",
                )
            )
        return spans
