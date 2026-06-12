"""End-to-end IP-literal substitution tests — scanner pass-1.5 through
pass-2 substitution, round-trip, and leak-detector interaction."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- bare-IP substitution --------------------------------------------


def test_bare_ipv4_in_body_substituted():
    src = "ltm node /Common/web1 {\n    address 10.0.0.42\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "10.0.0.42" not in sanitized
    # First allocated docs /24 is 192.0.2.0/24; host octet .42 preserved.
    assert "192.0.2.42" in sanitized


def test_bare_ipv4_round_trip():
    src = "ltm node /Common/web1 {\n    address 10.0.0.42\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ipv4_with_port_suffix_round_trip():
    src = "destination 192.168.1.5:443\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "192.168.1.5" not in sanitized
    assert ":443" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ipv4_with_route_domain_round_trip():
    src = "destination 192.168.1.5%rd0:443\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "192.168.1.5" not in sanitized
    assert "%rd0:443" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ipv4_cidr_preserves_mask():
    src = "network 10.0.0.0/24\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "10.0.0.0/24" not in sanitized
    assert "/24" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ipv6_substituted():
    src = "address fc00::1\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "fc00::1" not in sanitized
    # 2001:db8::/32 base — first /64 is 2001:db8:0:0::/64, host ::1.
    assert "2001:db8" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ipv6_route_domain_round_trip():
    src = "address fc00::1%rd0\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "fc00::1" not in sanitized
    assert "%rd0" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- subnet preservation ---------------------------------------------


def test_same_source_24_preserves_host_octet():
    src = "a 10.0.0.42\nb 10.0.0.43\nc 10.0.0.44\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # All three share source /24 10.0.0.0/24 → docs 192.0.2.0/24.
    assert "192.0.2.42" in sanitized
    assert "192.0.2.43" in sanitized
    assert "192.0.2.44" in sanitized


def test_distinct_source_24s_get_distinct_docs_24s():
    src = "a 10.0.0.42\nb 192.168.1.5\nc 172.16.0.99\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # First-seen-first-allocated maps to the 3 RFC 5737 docs /24s.
    assert "192.0.2.42" in sanitized      # 10.0.0.0/24 → 192.0.2.0/24
    assert "198.51.100.5" in sanitized    # 192.168.1.0/24 → 198.51.100.0/24
    assert "203.0.113.99" in sanitized    # 172.16.0.0/24 → 203.0.113.0/24


def test_fourth_source_24_triggers_collapse_diagnostic():
    src = (
        "a 10.0.0.42\n"
        "b 192.168.1.5\n"
        "c 172.16.0.99\n"
        "d 10.10.10.10\n"  # 4th distinct /24
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert diag.ipv4_subnet_collapsed, (
        "expected 4th source /24 to collapse into shared pool"
    )
    # Round-trip remains exact even with collapse.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- wildcard / netmask exemptions in output -------------------------


def test_wildcard_v4_passes_through_sanitized():
    src = "address 0.0.0.0\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert sanitized == src


def test_wildcard_v6_passes_through_sanitized():
    src = "address ::\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert sanitized == src


def test_netmask_passes_through_sanitized():
    src = "mask 255.255.255.0\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "255.255.255.0" in sanitized


# ----- leak detector interaction ---------------------------------------


def test_leak_detector_clean_after_ip_substitution():
    """With pass-1.5 IP substitution active, bare RFC1918 IPs in body
    context should no longer survive — leak detector reports clean."""
    src = "ltm node /Common/web1 {\n    address 10.0.0.42\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    rfc1918 = [lk for lk in report.leaks if lk.kind == LeakKind.RFC1918_IPV4]
    assert rfc1918 == [], (
        f"RFC1918 IP leaked after IP substitution: {rfc1918}"
    )


def test_ipv6_ula_clean_after_substitution():
    src = "address fc00::1\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    ula = [lk for lk in report.leaks if lk.kind == LeakKind.ULA_IPV6]
    assert ula == []


def test_description_embedded_ip_passes_through_verbatim():
    """IPs inside ``description`` values are out of v0.0.3 scope. The
    description body emits verbatim (always firing the
    ``unredacted_description`` diagnostic, regardless of content). The
    bare WORD-context IP elsewhere in the same config IS substituted."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        '    description "primary node at 10.0.0.42"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # The WORD-context 10.0.0.42 was substituted, but the description
    # body emits verbatim — bare 10.0.0.42 still present.
    assert "10.0.0.42" in sanitized
    # And the description diagnostic fires (covers all description bodies
    # regardless of IP content; aggressive DESC_NNNN redaction deferred).
    assert diag.unredacted_description, (
        "expected unredacted_description to fire for the description body"
    )


def test_bare_qstring_with_ip_fires_qstring_diagnostic():
    """A bare QSTRING (NOT inside a description) containing a ledger
    original surfaces via qstring_contains_identifier — orthogonal to the
    description path."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    "raw 10.0.0.42 reference"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.qstring_contains_identifier, (
        f"expected qstring_contains_identifier; got {diag}"
    )


# ----- node-with-IP-leaf coexistence -----------------------------------


def test_node_path_with_ip_leaf_uses_node_placeholder_for_path():
    """An IP-keyed NODE path keeps its NODE_NNNN placeholder for path
    references; the BARE IP (when seen in body context, not as a path)
    renders via the IPADDR mapping. The two forms coexist intentionally
    — round-trip handles both."""
    src = (
        "ltm node /Common/10.0.0.42 {\n"
        "    address 10.0.0.42\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Path form: /Common/NODE_0001
    assert "/Common/NODE_0001" in sanitized
    # Bare form: docs-range IP
    assert "192.0.2.42" in sanitized
    # Original IP nowhere in sanitized output.
    assert "10.0.0.42" not in sanitized
    # Round-trip restores both forms.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
