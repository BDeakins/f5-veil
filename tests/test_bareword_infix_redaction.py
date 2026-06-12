"""v1.1 — BAREWORD infix substring substitution.

Pass-1.5 now finds IP literals embedded inside compound BAREWORD
tokens (URL shapes like ``https://10.0.0.42/path``, IP ranges like
``10.0.0.1-10.0.0.50``) in addition to the legacy leading-IP forms.

Pass-2's WORD branch routes any bareword that didn't exact-match
through the same substring-substitution walker v0.0.12 / v0.0.13 /
v0.0.14 use for QSTRINGs — char-by-char, longest-match-first,
word-boundary on both sides. The legacy longest-prefix-match tier is
subsumed: it correctly substituted ``/Common/web1`` from
``/Common/web1:80`` but truncated after the first prefix, leaving any
identifier in the suffix verbatim (e.g. the second IP of an IP range).
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- compound-URL BAREWORD: IP infix ----------


def test_ip_inside_url_bareword_substituted():
    """``application-uri https://10.0.0.42/path`` is one compound
    BAREWORD; the embedded IP is substituted in place."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "apm policy access-policy /Common/p1 {\n"
        "    application-uri https://10.0.0.42/login\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "https://10.0.0.42/login" not in sanitized
    assert "https://192.0.2.42/login" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_ip_inside_url_with_port_substituted():
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "apm policy access-policy /Common/p1 {\n"
        "    target-uri http://10.0.0.42:8080/login\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "10.0.0.42" not in sanitized
    assert "192.0.2.42" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- IP range BAREWORD ----------


def test_ip_range_bareword_both_endpoints_substituted():
    """A bareword like ``10.0.0.1-10.0.0.50`` carries two IPs separated
    by a hyphen. Pre-v1.1, the legacy prefix match would substitute the
    first IP and leave the second verbatim (because tier 2 truncated
    after the prefix). v1.1's infix walker handles both."""
    src = (
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        10.0.0.1-10.0.0.50 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "10.0.0.1-10.0.0.50" not in sanitized
    assert "10.0.0.1" not in sanitized
    assert "10.0.0.50" not in sanitized
    # Both IPs were substituted to docs-range form; the hyphen survives.
    assert "192.0.2.1-192.0.2.50" in sanitized
    assert diag.orphan_entries == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- IP with port suffix (legacy prefix case) ----------


def test_member_port_suffix_still_round_trips():
    """The legacy ``/Common/web1:80`` member-port shape that the
    prefix-match tier used to handle must still round-trip cleanly
    under v1.1's infix-only path."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        /Common/web1:80 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/web1:80" not in sanitized
    assert "/Common/NODE_0001:80" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- IP CIDR ----------


def test_ip_cidr_bareword_substituted():
    """``10.0.0.42/24`` — IP + CIDR. The leading-IP path interns
    ``10.0.0.42``; the bareword infix walker substitutes it and
    preserves the ``/24`` suffix."""
    src = (
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        10.0.0.42 { }\n"
        "    }\n"
        "}\n"
        "net route /Common/r1 {\n"
        "    network 10.0.0.42/24\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "10.0.0.42" not in sanitized
    assert "192.0.2.42/24" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- partition path infix inside compound bareword ----------


def test_partition_path_infix_inside_compound_bareword_substituted():
    """A ledger path like ``/Common/foo_pool`` appearing as a substring
    of a longer bareword (with non-word boundary) is substituted."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        "    set ref @/Common/foo_pool@\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/foo_pool" not in sanitized
    assert "@/Common/POOL_0001@" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- word-boundary protection ----------


def test_word_boundary_rejects_partial_match_in_bareword():
    """``/Common/foo_pool_extra`` contains ``/Common/foo_pool`` as
    substring but the trailing character ``_`` is a word char — the
    boundary check correctly REJECTS substitution to prevent producing
    ``/Common/POOL_0001_extra`` (which would be a leak: original
    identifier mixed with placeholder)."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        "    set x /Common/foo_pool_extra\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # The compound stays verbatim — partial substitution would be a
    # leak (placeholder mixed with original suffix). The leak detector
    # is the last line of defence for cases like this.
    assert "/Common/foo_pool_extra" in sanitized
    assert "POOL_0001_extra" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- IPv4 infix regex behaviour ----------


def test_ipv4_infix_regex_rejects_partial_match_against_longer_octet():
    """``10.0.0.2222`` must NOT yield an intern for ``10.0.0.222``
    or ``10.0.0.2`` — the boundary checks ``(?<![\\d.])`` /
    ``(?![\\d.])`` make the regex match nothing here (because either
    side abuts a digit)."""
    # Use it in a body context so pass-1.5 sees it as a WORD.
    src = (
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        target 10.0.0.2222 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    # Neither nested IP qualifies.
    assert (Kind.IPADDR, "10.0.0.222") not in ledger.by_original
    assert (Kind.IPADDR, "10.0.0.2") not in ledger.by_original
    # The full quad ``10.0.0.2222`` is also not valid as an IP
    # (256+ octet), so the leading-IP extractor's ``ipaddress.ip_address``
    # rejects it too. Nothing IPADDR-shaped is interned.
    assert not any(
        e.kind == Kind.IPADDR for e in ledger.entries.values()
    )


# ---------- empty / no-match ----------


def test_bareword_with_no_substrings_unchanged():
    src = (
        "ltm pool /Common/p1 {\n"
        "    members { }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # No identifiers other than POOL — its body has no infix-eligible
    # tokens.
    assert "/Common/POOL_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- references / orphans ----------


def test_infix_substitution_records_references():
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "apm policy access-policy /Common/p1 {\n"
        "    target-uri http://10.0.0.42/login\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    ip_entry = ledger.entries["192.0.2.42"]
    # 1 ref from `address 10.0.0.42` body; 1 ref from the infix URL.
    assert len(ip_entry.references) >= 2
    assert diag.orphan_entries == []
