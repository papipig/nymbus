from __future__ import annotations

import json
from typing import Any

from . import pseudonyms as ps


class PseudonymVault:
    """
    Forward + reverse pseudonym maps with cross-type namespace consistency.

    Two namespace dicts ensure the same real org/person always maps to the
    same fake org/person across all token types (FQDN, EMAIL, ORG, PERSON, …).
    """

    def __init__(self) -> None:
        self._forward: dict[str, str] = {}       # real → fake
        self._fwd_type: dict[str, str] = {}      # real → nb_type
        self._reverse: dict[str, str] = {}       # fake → real

        # Shared namespaces for cross-type consistency
        self._org_ns: dict[str, str] = {}        # normalised SLD → fake SLD
        self._person_ns: dict[str, tuple[str, str]] = {}  # normalised last → (fake_first, fake_last)

        # Monotonic counters (wrapped in list for pass-by-reference to generators)
        self._org_ctr: list[int] = [0]
        self._person_ctr: list[int] = [0]
        self._ip_ctr: list[int] = [0]

    # ── Public API ────────────────────────────────────────────────────────────

    def anonymise(self, real: str, nb_type: str) -> str:
        """Return the consistent fake alias for *real*, generating one if needed."""
        if real in self._forward:
            return self._forward[real]
        fake = self._generate(real, nb_type)
        self._forward[real] = fake
        self._fwd_type[real] = nb_type
        # Guard against collision (two real values → same fake)
        if fake not in self._reverse:
            self._reverse[fake] = real
        return fake

    def deanonymise(self, text: str) -> str:
        """Replace all known fake aliases with their real values."""
        # Longest aliases first to avoid partial replacements
        for fake in sorted(self._reverse, key=len, reverse=True):
            text = text.replace(fake, self._reverse[fake])
        return text

    def real_values(self) -> list[str]:
        return list(self._forward.keys())

    def fake_values(self) -> list[str]:
        return list(self._reverse.keys())

    def active_real_values_for(self, anon_text: str) -> list[str]:
        """Return only the real values whose fakes appear in *anon_text*."""
        return [
            real
            for real, fake in self._forward.items()
            if fake in anon_text
        ]

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "forward": self._forward,
            "fwd_type": self._fwd_type,
            "reverse": self._reverse,
            "org_ns": self._org_ns,
            "person_ns": {k: list(v) for k, v in self._person_ns.items()},
            "org_ctr": self._org_ctr[0],
            "person_ctr": self._person_ctr[0],
            "ip_ctr": self._ip_ctr[0],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PseudonymVault":
        v = cls()
        v._forward = data.get("forward", {})
        v._fwd_type = data.get("fwd_type", {})
        v._reverse = data.get("reverse", {})
        v._org_ns = data.get("org_ns", {})
        v._person_ns = {k: tuple(val) for k, val in data.get("person_ns", {}).items()}  # type: ignore[misc]
        v._org_ctr = [data.get("org_ctr", 0)]
        v._person_ctr = [data.get("person_ctr", 0)]
        v._ip_ctr = [data.get("ip_ctr", 0)]
        return v

    # ── Generator dispatch ────────────────────────────────────────────────────

    def _generate(self, real: str, nb_type: str) -> str:  # noqa: PLR0911
        match nb_type:
            case "FQDN":
                return ps.gen_fqdn(real, self._org_ns, self._org_ctr)
            case "IPv4_PUBLIC":
                return ps.gen_ipv4_public(None, self._ip_ctr)
            case "IPv4_PRIVATE" | "CIDR_PRIVATE":
                return real  # never substituted
            case "CIDR_PUBLIC":
                return ps.gen_cidr_public(real, self._ip_ctr)
            case "EMAIL":
                return ps.gen_email(
                    real, self._org_ns, self._person_ns,
                    self._org_ctr, self._person_ctr,
                )
            case "USERNAME":
                return ps.gen_username(real, self._person_ns, self._person_ctr)
            case "PERSON":
                return ps.gen_person_name(real, self._person_ns, self._person_ctr)
            case "ORG" | "GPE" | "CODENAME" | "CUSTOM":
                return ps.gen_org_name(real, self._org_ns, self._org_ctr)
            case "URL":
                return ps.gen_url(real, self._org_ns, self._org_ctr)
            case "FILEPATH_UNIX":
                return ps.gen_filepath_unix(real, self._person_ns, self._person_ctr)
            case "FILEPATH_WIN":
                return ps.gen_filepath_win(real, self._person_ns, self._person_ctr)
            case "HASH":
                return ps.gen_hash(real)
            case "MAC":
                return ps.gen_mac(real)
            case "UUID":
                return ps.gen_uuid(real)
            case "CREDENTIAL":
                return ps.gen_credential(real, self._org_ns, self._org_ctr)
            case _:
                return real
