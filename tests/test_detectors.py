"""Tests for regex and custom detectors."""
from __future__ import annotations

import pytest

from nymbus.proxy.detectors.regex_det import RegexDetector
from nymbus.proxy.detectors.custom_det import CustomDetector


class TestRegexDetector:
    def setup_method(self):
        self.det = RegexDetector()

    def _types(self, text: str) -> set[str]:
        return {s.type for s in self.det.detect(text)}

    def _spans(self, text: str):
        return self.det.detect(text)

    def test_ipv4_public(self):
        # Use a globally routable address (not RFC 5737 / TEST-NET ranges)
        spans = self._spans("server at 1.1.1.1 please")
        assert any(s.type == "IPv4_PUBLIC" and s.text == "1.1.1.1" for s in spans)

    def test_ipv4_private(self):
        spans = self._spans("gateway is 192.168.0.1")
        assert any(s.type == "IPv4_PRIVATE" and s.text == "192.168.0.1" for s in spans)

    def test_cidr_public(self):
        # Use a globally routable prefix (not RFC 5737 / TEST-NET ranges)
        spans = self._spans("block 1.1.1.0/24")
        assert any(s.type == "CIDR_PUBLIC" for s in spans)

    def test_cidr_private(self):
        spans = self._spans("block 10.0.0.0/8")
        assert any(s.type == "CIDR_PRIVATE" for s in spans)

    def test_cidr_takes_priority_over_ipv4(self):
        """CIDR span should swallow the raw IP, not co-exist with it."""
        spans = self._spans("route 10.0.0.0/8")
        types = {s.type for s in spans}
        assert "CIDR_PRIVATE" in types
        assert "IPv4_PRIVATE" not in types  # swallowed by CIDR span

    def test_email(self):
        spans = self._spans("email me at alice@example.com")
        assert any(s.type == "EMAIL" and "alice@example.com" in s.text for s in spans)

    def test_fqdn(self):
        spans = self._spans("visit internal.corp.example.com now")
        assert any(s.type == "FQDN" for s in spans)

    def test_uuid(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        spans = self._spans(f"id={uid}")
        assert any(s.type == "UUID" and s.text == uid for s in spans)

    def test_mac_address(self):
        spans = self._spans("mac 00:1A:2B:3C:4D:5E")
        assert any(s.type == "MAC" for s in spans)

    def test_sha256_hash(self):
        h = "a" * 64
        spans = self._spans(f"hash {h}")
        assert any(s.type == "HASH" for s in spans)

    def test_filepath_unix(self):
        spans = self._spans("found at /etc/passwd in config")
        assert any(s.type == "FILEPATH_UNIX" for s in spans)

    def test_filepath_win(self):
        spans = self._spans(r"path C:\Users\Alice\file.txt")
        assert any(s.type == "FILEPATH_WIN" for s in spans)

    def test_no_false_positive_on_plain_text(self):
        spans = self._spans("the quick brown fox jumps over the lazy dog")
        assert len(spans) == 0


class TestCustomDetector:
    def test_wordlist_match(self):
        det = CustomDetector(patterns=None, wordlists=["Project Apollo", "TopSecret"])
        spans = det.detect("We discussed Project Apollo yesterday.")
        assert any(s.text == "Project Apollo" for s in spans)

    def test_pattern_match(self):
        det = CustomDetector(patterns=[r"PROJ-\d+"], wordlists=None)
        spans = det.detect("Ticket PROJ-1234 is open.")
        assert any(s.text == "PROJ-1234" for s in spans)

    def test_empty_detectors(self):
        det = CustomDetector(patterns=None, wordlists=None)
        spans = det.detect("anything")
        assert spans == []
