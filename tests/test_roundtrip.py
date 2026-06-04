"""Property-based round-trip tests: anonymise then deanonymise = identity."""
from __future__ import annotations

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from nymbus.proxy.vault import PseudonymVault
from nymbus.proxy.detectors.regex_det import RegexDetector


# ── Strategies for typed tokens ───────────────────────────────────────────────

ip_public = st.from_regex(
    r"(198\.51\.100\.\d{1,3})", fullmatch=True
)

email = st.from_regex(
    r"[a-z]{3,10}@[a-z]{3,8}\.(com|org|net)", fullmatch=True
)

fqdn = st.from_regex(
    r"[a-z]{3,8}\.[a-z]{3,8}\.(com|net|io)", fullmatch=True
)

uuid_ = st.from_regex(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    fullmatch=True,
)


# ── Round-trip properties ─────────────────────────────────────────────────────

@given(ip_public)
@settings(max_examples=50)
def test_roundtrip_ipv4_public(real: str):
    v = PseudonymVault()
    fake = v.anonymise(real, "IPv4_PUBLIC")
    assert v.deanonymise(fake) == real


@given(email)
@settings(max_examples=50)
def test_roundtrip_email(real: str):
    v = PseudonymVault()
    fake = v.anonymise(real, "EMAIL")
    assert v.deanonymise(fake) == real


@given(uuid_)
@settings(max_examples=50)
def test_roundtrip_uuid(real: str):
    v = PseudonymVault()
    fake = v.anonymise(real, "UUID")
    assert v.deanonymise(fake) == real


@given(fqdn)
@settings(max_examples=50)
def test_roundtrip_fqdn(real: str):
    v = PseudonymVault()
    fake = v.anonymise(real, "FQDN")
    assert v.deanonymise(fake) == real


# ── Idempotency: deanonymising twice is safe ──────────────────────────────────

@given(email)
@settings(max_examples=30)
def test_deanonymise_idempotent(real: str):
    v = PseudonymVault()
    fake = v.anonymise(real, "EMAIL")
    first = v.deanonymise(fake)
    second = v.deanonymise(first)
    assert first == second


# ── Multiple tokens in one string ─────────────────────────────────────────────

@given(email, ip_public)
@settings(max_examples=30)
def test_roundtrip_multi_token(em: str, ip: str):
    assume(em != ip)
    v = PseudonymVault()
    fake_em = v.anonymise(em, "EMAIL")
    fake_ip = v.anonymise(ip, "IPv4_PUBLIC")
    text = f"contact {fake_em} from {fake_ip}"
    restored = v.deanonymise(text)
    assert em in restored
    assert ip in restored


# ── Persistence round-trip ────────────────────────────────────────────────────

@given(email, fqdn)
@settings(max_examples=25)
def test_vault_persistence_roundtrip(em: str, fq: str):
    v1 = PseudonymVault()
    fe = v1.anonymise(em, "EMAIL")
    ff = v1.anonymise(fq, "FQDN")
    data = v1.to_dict()

    v2 = PseudonymVault.from_dict(data)
    assert v2.deanonymise(fe) == em
    assert v2.deanonymise(ff) == fq
