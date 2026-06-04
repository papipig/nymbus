"""Tests for PseudonymVault round-trip and key properties."""
from __future__ import annotations

import pytest

from nymbus.proxy.vault import PseudonymVault


def _vault() -> PseudonymVault:
    return PseudonymVault()


class TestVaultAnonymise:
    def test_same_real_same_fake(self):
        v = _vault()
        f1 = v.anonymise("alice@corp.com", "EMAIL")
        f2 = v.anonymise("alice@corp.com", "EMAIL")
        assert f1 == f2

    def test_different_real_different_fake(self):
        v = _vault()
        f1 = v.anonymise("alice@corp.com", "EMAIL")
        f2 = v.anonymise("bob@corp.com", "EMAIL")
        assert f1 != f2

    def test_private_ipv4_passthrough(self):
        v = _vault()
        result = v.anonymise("192.168.1.1", "IPv4_PRIVATE")
        assert result == "192.168.1.1"

    def test_private_cidr_passthrough(self):
        v = _vault()
        result = v.anonymise("10.0.0.0/8", "CIDR_PRIVATE")
        assert result == "10.0.0.0/8"

    def test_fake_differs_from_real(self):
        v = _vault()
        real = "malicious@attacker.com"
        fake = v.anonymise(real, "EMAIL")
        assert fake != real


class TestVaultDeanonymise:
    def test_single_token(self):
        v = _vault()
        real = "alice@corp.com"
        fake = v.anonymise(real, "EMAIL")
        assert v.deanonymise(fake) == real

    def test_text_with_multiple_tokens(self):
        v = _vault()
        real_email = "alice@corp.com"
        real_ip = "203.0.113.5"  # public
        fe = v.anonymise(real_email, "EMAIL")
        fi = v.anonymise(real_ip, "IPv4_PUBLIC")
        text = f"Contact {fe} from {fi}"
        restored = v.deanonymise(text)
        assert real_email in restored
        assert real_ip in restored

    def test_unknown_token_unchanged(self):
        v = _vault()
        assert v.deanonymise("no substitutions here") == "no substitutions here"


class TestVaultPersistence:
    def test_to_from_dict_round_trip(self):
        v1 = _vault()
        v1.anonymise("alice@corp.com", "EMAIL")
        v1.anonymise("Bob Smith", "PERSON")
        data = v1.to_dict()

        v2 = PseudonymVault.from_dict(data)
        # Same real values produce same fakes in restored vault
        assert v2.anonymise("alice@corp.com", "EMAIL") == v1.anonymise("alice@corp.com", "EMAIL")

    def test_real_values_set(self):
        v = _vault()
        v.anonymise("alice@corp.com", "EMAIL")
        v.anonymise("bob@example.com", "EMAIL")
        rv = v.real_values()
        assert "alice@corp.com" in rv
        assert "bob@example.com" in rv
