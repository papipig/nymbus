from __future__ import annotations

import ipaddress
import re

from .base import Detector, Span

_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
_IPV4 = rf"(?:{_OCTET}\.){{3}}{_OCTET}"

# Ordered list of (label, compiled_pattern).  More-specific patterns first.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # CIDR before bare IPv4
    ("CIDR", re.compile(rf"\b{_IPV4}/(?:3[0-2]|[12]?\d)\b")),
    ("IPv4", re.compile(rf"\b{_IPV4}\b")),
    # MAC (colon or hyphen separated)
    (
        "MAC",
        re.compile(
            r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"
            r"|\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b"
        ),
    ),
    # Email before FQDN (email contains a domain)
    ("EMAIL", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")),
    # URL before FQDN
    ("URL", re.compile(r"https?://[^\s\"'<>\]\[)({}\|\\]+")),
    # Windows file paths — before FQDN so e.g. file.txt inside path is not stolen
    ("FILEPATH_WIN", re.compile(r"[A-Za-z]:\\(?:[^\\\n\"']+\\)*[^\\\n\"']*")),
    # Unix file paths — must have at least two segments to reduce false positives
    (
        "FILEPATH_UNIX",
        re.compile(r"/(?:[a-zA-Z0-9_.@\-]+/)+[a-zA-Z0-9_.@\-]*"),
    ),
    # FQDN — at least two labels, TLD is 2-6 alpha chars
    (
        "FQDN",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b"
        ),
    ),
    # Hashes: SHA-256 (64), SHA-1 (40), MD5 (32) — longest first
    (
        "HASH",
        re.compile(
            r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b"
        ),
    ),
    # KEY=VALUE credentials (e.g. API_KEY=abc123)
    ("CREDENTIAL", re.compile(r"\b[A-Z][A-Z0-9_]{2,}=[^\s\"']{4,}")),
    # UUID
    (
        "UUID",
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
    ),
]


def _resolve_type(label: str, text: str) -> str:
    if label == "CIDR":
        try:
            net = ipaddress.ip_network(text, strict=False)
            return "CIDR_PRIVATE" if net.is_private else "CIDR_PUBLIC"
        except ValueError:
            return "CIDR_PUBLIC"
    if label == "IPv4":
        try:
            addr = ipaddress.ip_address(text)
            return "IPv4_PRIVATE" if (addr.is_private or addr.is_loopback) else "IPv4_PUBLIC"
        except ValueError:
            return "IPv4_PUBLIC"
    return label


class RegexDetector(Detector):
    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        claimed: set[int] = set()

        for label, pattern in _PATTERNS:
            for m in pattern.finditer(text):
                s, e = m.start(), m.end()
                if claimed.intersection(range(s, e)):
                    continue
                nb_type = _resolve_type(label, m.group())
                spans.append(
                    Span(start=s, end=e, text=m.group(), type=nb_type, source="regex")
                )
                claimed.update(range(s, e))

        return sorted(spans, key=lambda sp: sp.start)
