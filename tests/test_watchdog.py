"""Tests for the Watchdog: leak injection, warning paths."""
from __future__ import annotations

import pytest

from nymbus.proxy.vault import PseudonymVault
from nymbus.proxy.watchdog import Watchdog, AnonymisationError, LeakDetectedError, SemanticLeakError


def _vault_with(*reals_and_types: tuple[str, str]) -> PseudonymVault:
    v = PseudonymVault()
    for real, nb_type in reals_and_types:
        v.anonymise(real, nb_type)
    return v


class TestWatchdogForward:
    def test_clean_text_no_error(self):
        v = _vault_with(("alice@example.com", "EMAIL"))
        wd = Watchdog(v, local_llm=None, allow_semantic_warn=False)
        # If original and anon are identical (no tokens in text), should be fine
        warnings = wd.check_forward("hello world", "hello world")
        assert not any("leak" in w.lower() for w in warnings)

    def test_check2_raises_on_raw_real_value_in_anon(self):
        v = _vault_with(("alice@example.com", "EMAIL"))
        wd = Watchdog(v, local_llm=None, allow_semantic_warn=False)
        # Simulate a bug: real email leaked into anon text
        with pytest.raises(LeakDetectedError):
            wd.check_forward(
                "contact alice@example.com",
                "contact alice@example.com",  # anon == original: leak!
            )

    def test_check2_case_insensitive(self):
        # The anon text still contains the real value (case-folded).
        # Whichever watchdog check fires first should raise an exception.
        v = _vault_with(("Alice@Example.COM", "EMAIL"))
        wd = Watchdog(v, local_llm=None, allow_semantic_warn=False)
        with pytest.raises((AnonymisationError, LeakDetectedError)):
            wd.check_forward(
                "contact Alice@Example.COM",
                "contact alice@example.com",
            )

    def test_check1_raises_when_anon_longer_by_real_value(self):
        """
        Check ① detects if the anonymised text still contains one of the
        known real values verbatim.
        """
        v = _vault_with(("secret@corp.com", "EMAIL"))
        wd = Watchdog(v, local_llm=None, allow_semantic_warn=False)
        fake = v.anonymise("secret@corp.com", "EMAIL")
        # Put the *real* value into anon (simulates a substitution miss)
        anon_with_leak = f"send to secret@corp.com"
        with pytest.raises(LeakDetectedError):
            wd.check_forward("send to secret@corp.com", anon_with_leak)


class TestWatchdogBackward:
    def test_backward_never_raises(self):
        """Watchdog ④ should only warn, never raise."""
        v = _vault_with(("alice@example.com", "EMAIL"))
        fake = v.anonymise("alice@example.com", "EMAIL")
        wd = Watchdog(v, local_llm=None, allow_semantic_warn=False)
        # Even if the anon_reply contains real values (shouldn't happen but test robustness)
        warnings = wd.check_backward(
            f"reply referencing {fake}",
            "reply referencing alice@example.com",
        )
        # Should return list (possibly with warnings) but not raise
        assert isinstance(warnings, list)
