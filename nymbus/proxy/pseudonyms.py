"""
Isomorphic pseudonym generators.

All generators are pure functions that take explicit namespace dicts and
counters managed by PseudonymVault.  This keeps vault state centralised.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid

# ── Fake data pools ───────────────────────────────────────────────────────────

_FAKE_ORG_SLDS: list[str] = [
    "zenith", "apex", "nexus", "orbis", "stratos", "vantage",
    "meridian", "cipher", "prism", "vertex", "aurora", "solaris",
    "phaedra", "helix", "nova", "quasar", "titan", "polaris",
    "zephyr", "tesseract",
]

_FAKE_PERSONS: list[tuple[str, str]] = [
    ("marc", "chen"), ("sara", "kim"), ("luca", "rossi"), ("ana", "reyes"),
    ("tom", "wagner"), ("mei", "lin"), ("david", "park"), ("nadia", "okonkwo"),
    ("raj", "patel"), ("elena", "kovacs"), ("omar", "hassan"), ("yuki", "tanaka"),
    ("felix", "bauer"), ("amara", "diallo"), ("ivan", "petrov"), ("fiona", "walsh"),
    ("carlos", "mendez"), ("aya", "nakamura"), ("sven", "lindqvist"), ("zara", "ahmed"),
]

# RFC 5737 documentation ranges — safe fake public IPs
_DOC_NETS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]

_CORP_SUFFIXES: list[str] = [
    " corporation", " incorporated", " limited", " industries",
    " technologies", " solutions", " systems", " services", " group",
    " holdings", " enterprises", " labs", " studio", " studios",
    " corp", " inc", " ltd", " llc", " co",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_fqdn(fqdn: str) -> tuple[list[str], str, str]:
    """Split FQDN into (subdomains, sld, tld).  Minimal heuristic: last = TLD."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) < 2:
        return [], fqdn, ""
    return parts[:-2], parts[-2], parts[-1]


def _match_case(fake: str, real: str) -> str:
    if not real:
        return fake
    if real.isupper():
        return fake.upper()
    if real[0].isupper():
        return fake.capitalize()
    return fake.lower()


def _strip_corp_suffix(name: str) -> tuple[str, str]:
    lower = name.lower()
    for sfx in _CORP_SUFFIXES:
        if lower.endswith(sfx):
            return name[: len(name) - len(sfx)].strip(), name[len(name) - len(sfx):]
    return name, ""


def _ns_key(s: str) -> str:
    """Normalise to a namespace key (lowercase, strip separators)."""
    return s.lower().replace("-", "").replace("_", "").replace(" ", "")


# ── Namespace helpers ─────────────────────────────────────────────────────────

def get_or_create_org(sld: str, org_ns: dict[str, str], ctr: list[int]) -> str:
    key = _ns_key(sld)
    if key not in org_ns:
        org_ns[key] = _FAKE_ORG_SLDS[ctr[0] % len(_FAKE_ORG_SLDS)]
        ctr[0] += 1
    return org_ns[key]


def get_or_create_person(
    last: str,
    person_ns: dict[str, tuple[str, str]],
    ctr: list[int],
) -> tuple[str, str]:
    key = _ns_key(last)
    if key not in person_ns:
        person_ns[key] = _FAKE_PERSONS[ctr[0] % len(_FAKE_PERSONS)]
        ctr[0] += 1
    return person_ns[key]


# ── Generators ────────────────────────────────────────────────────────────────

def gen_fqdn(real: str, org_ns: dict[str, str], ctr: list[int]) -> str:
    subdomains, sld, tld = parse_fqdn(real)
    fake_sld = get_or_create_org(sld, org_ns, ctr)
    return ".".join(subdomains + [fake_sld, tld])


def gen_ipv4_public(org_ctr_unused: None, ip_ctr: list[int]) -> str:  # noqa: ARG001
    net = _DOC_NETS[ip_ctr[0] % len(_DOC_NETS)]
    host = (ip_ctr[0] // len(_DOC_NETS)) % 254 + 1
    ip_ctr[0] += 1
    return str(net.network_address + host)


def gen_cidr_public(real: str, ip_ctr: list[int]) -> str:
    try:
        real_net = ipaddress.ip_network(real, strict=False)
        prefix = real_net.prefixlen
    except ValueError:
        prefix = 24
    net = _DOC_NETS[ip_ctr[0] % len(_DOC_NETS)]
    ip_ctr[0] += 1
    return f"{net.network_address}/{prefix}"


def gen_email(
    real: str,
    org_ns: dict[str, str],
    person_ns: dict[str, tuple[str, str]],
    org_ctr: list[int],
    person_ctr: list[int],
) -> str:
    local, _, domain = real.partition("@")
    subdomains, sld, tld = parse_fqdn(domain)
    fake_sld = get_or_create_org(sld, org_ns, org_ctr)
    fake_domain = ".".join(subdomains + [fake_sld, tld])
    fake_local = _gen_email_local(local, person_ns, person_ctr)
    return f"{fake_local}@{fake_domain}"


def _gen_email_local(
    local: str, person_ns: dict[str, tuple[str, str]], ctr: list[int]
) -> str:
    for sep in (".", "_", "-"):
        if sep in local:
            parts = local.split(sep, 1)
            first_part, last_part = parts[0], parts[-1]
            ff, fl = get_or_create_person(last_part, person_ns, ctr)
            fake_first = ff[0] if len(first_part) == 1 else ff
            return f"{fake_first}{sep}{fl}"
    ff, fl = get_or_create_person(local, person_ns, ctr)
    return ff[0] + fl


def gen_username(
    real: str, person_ns: dict[str, tuple[str, str]], ctr: list[int]
) -> str:
    for sep in (".", "_", "-"):
        if sep in real:
            parts = real.split(sep, 1)
            first_part, last_part = parts[0], parts[-1]
            ff, fl = get_or_create_person(last_part, person_ns, ctr)
            fake_first = ff[0] if len(first_part) == 1 else ff
            return f"{fake_first}{sep}{fl}"
    ff, fl = get_or_create_person(real, person_ns, ctr)
    return ff + fl


def gen_person_name(
    real: str, person_ns: dict[str, tuple[str, str]], ctr: list[int]
) -> str:
    parts = real.split()
    last = parts[-1] if parts else real
    ff, fl = get_or_create_person(last, person_ns, ctr)
    if real.isupper():
        return f"{ff.upper()} {fl.upper()}"
    return f"{ff.capitalize()} {fl.capitalize()}"


def gen_org_name(real: str, org_ns: dict[str, str], ctr: list[int]) -> str:
    base, suffix = _strip_corp_suffix(real)
    fake_base = get_or_create_org(base, org_ns, ctr)
    return _match_case(fake_base, base) + suffix


def gen_url(real: str, org_ns: dict[str, str], ctr: list[int]) -> str:
    m = re.match(r"(https?://)([^/?#\s]+)(.*)", real, re.IGNORECASE | re.DOTALL)
    if m:
        scheme, host, rest = m.groups()
        return scheme + gen_fqdn(host, org_ns, ctr) + rest
    return real


def gen_filepath_unix(
    real: str, person_ns: dict[str, tuple[str, str]], ctr: list[int]
) -> str:
    for prefix in ("/home/", "/Users/"):
        if real.lower().startswith(prefix.lower()):
            rest = real[len(prefix):]
            username, sep, remainder = rest.partition("/")
            ff, _ = get_or_create_person(username, person_ns, ctr)
            return prefix + ff + (sep + remainder if sep else "")
    return real


def gen_filepath_win(
    real: str, person_ns: dict[str, tuple[str, str]], ctr: list[int]
) -> str:
    m = re.match(r"([A-Za-z]:\\[Uu]sers\\)([^\\]+)(.*)", real)
    if m:
        prefix, username, remainder = m.groups()
        ff, _ = get_or_create_person(username, person_ns, ctr)
        return prefix + ff + remainder
    return real


def gen_hash(real: str) -> str:
    seed = hashlib.sha256(real.encode()).hexdigest()
    # Repeat seed to cover any hash length
    fake = (seed * ((len(real) // len(seed)) + 1))[: len(real)]
    if real.isupper():
        return fake.upper()
    if real.islower():
        return fake.lower()
    return fake


def gen_mac(real: str) -> str:
    raw = hashlib.md5(real.encode()).digest()[:6]
    b = bytearray(raw)
    # Set locally-administered bit, clear multicast bit
    b[0] = (b[0] & 0xFE) | 0x02
    sep = "-" if "-" in real else ":"
    parts = [f"{x:02x}" for x in b]
    result = sep.join(parts)
    if real[0].isupper():
        return result.upper()
    return result


def gen_uuid(_real: str) -> str:
    return str(uuid.uuid4())


def gen_credential(real: str, org_ns: dict[str, str], ctr: list[int]) -> str:
    key, _, value = real.partition("=")
    # Keep key name, replace value with a hash-derived fake
    fake_val = hashlib.sha256(value.encode()).hexdigest()[: len(value)]
    return f"{key}={fake_val}"


# RFC 3849 documentation prefix — 2001:db8::/32
_IPV6_DOC_BASE = int(ipaddress.IPv6Address("2001:db8::"))


def gen_ipv6(real: str, ip_ctr: list[int]) -> str:
    """Replace IPv6 address with a documentation-range (2001:db8::/32) address."""
    fake_int = _IPV6_DOC_BASE + ip_ctr[0] + 1
    ip_ctr[0] += 1
    return str(ipaddress.IPv6Address(fake_int))
