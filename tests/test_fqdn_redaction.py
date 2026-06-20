"""v1.2 — Internal-FQDN redaction.

Pass-2.0 (``fqdn_discovery``) regex-scans every WORD and QSTRING token
for FQDN-shaped substrings whose top label is one of a fixed set of
internal / private suffixes (``.local``, ``.corp``, ``.lan``,
``.internal``, ``.intranet``, ``.home.arpa``, ``.private``). Each
unique match is interned as ``Kind.FQDN``. Pass-2 substitutes via the
same v0.0.14 (QSTRING) + v1.1 (BAREWORD) substring walker.

FQDN entries use a relaxed RIGHT-side word-boundary character set
(``_`` is NOT a word char on the right) so the F5 file-storage
compound-filename shape ``<fqdn>_<index>`` substitutes cleanly. Left
boundary stays strict to avoid partial-substitution leaks where a
shorter FQDN inside a longer customer-defined compound on the LEFT
would lose the leading customer label.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- standalone FQDN BAREWORD ----------


def test_standalone_internal_fqdn_bareword_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain example.local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "example.local" not in sanitized
    assert "FQDN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- FQDN inside compound URL BAREWORD ----------


def test_fqdn_inside_url_bareword_redacted():
    # Pre-T8 this asserted ``https://FQDN_0001/saml/idp`` — FQDN
    # redacted, path leaked. v121_t2 round 3 flagged the surviving
    # path as a leak class; T8 (v1.2.1) now intercepts URL-bearing
    # fields at pass-1.85k.1 and interns the FULL URL as
    # MONITOR_PATH, so both host AND path are redacted together.
    src = (
        "apm policy access-policy /Common/p1 {\n"
        "    application-uri https://idp01.example.local/saml/idp\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "idp01.example.local" not in sanitized
    assert "/saml/idp" not in sanitized
    assert "MONITOR_PATH_" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- FQDN inside QSTRING ----------


def test_fqdn_inside_qstring_redacted():
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    expression "host equals \\"host02.example.local\\""\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "host02.example.local" not in sanitized
    assert "FQDN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- F5 file-storage compound name ----------


def test_fqdn_followed_by_underscore_index_substituted():
    """The F5 file-storage layer auto-generates compound filenames
    ``:Common:<fqdn>_<index>_<index>``. Pre-v1.2's strict right-boundary
    check would reject substitution (underscore is a word char). v1.2
    relaxes the right boundary for FQDN entries so the FQDN substitutes
    and the trailing ``_<index>`` survives verbatim (F5 bookkeeping)."""
    src = (
        "sys file ssl-cert /Common/host01.example.local {\n"
        "    source-path /config/filestore/files_d/Common_d/certificate_d/:Common:host01.example.local_69313_3\n"
        "    revision 3\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # FQDN is gone from BOTH the header path AND the compound filename.
    assert "host01.example.local" not in sanitized
    # The trailing _<index>_<index> survives verbatim. v1.2 Phase 3b
    # added a colon-form path variant to substring sub, so
    # ``:Common:host01.example.local`` matches as a whole path (longer
    # than the inner FQDN) and substitutes via the UNK entry registered
    # for ``/Common/host01.example.local`` by the ssl-cert top-level
    # block. Either placeholder form (FQDN_NNNN or UNK_NNNN) is
    # acceptable; assert the F5 file-storage suffix survives.
    assert "_69313_3" in sanitized
    assert ("FQDN_0001" in sanitized) or ("UNK_0001" in sanitized)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple distinct FQDNs ----------


def test_multiple_distinct_fqdns_get_distinct_placeholders():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain example.local\n"
        "}\n"
        "apm aaa active-directory /Common/ad2 {\n"
        "    domain corp.example.corp\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "FQDN_0001" in sanitized
    assert "FQDN_0002" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- shared FQDN dedups ----------


def test_identical_fqdn_in_two_sites_dedups_to_single_placeholder():
    # T8 (v1.2.1) intercepts ``application-uri`` and interns the
    # FULL URL as MONITOR_PATH, so this test moved to a non-URL
    # surface to keep verifying FQDN-walker dedup behavior. Two
    # bareword FQDN refs in pool-member context should dedup to a
    # single FQDN entry.
    src = (
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        host02.example.local:443 { address 10.0.0.1 }\n"
        "    }\n"
        "}\n"
        "ltm pool /Common/p2 {\n"
        "    members {\n"
        "        host02.example.local:443 { address 10.0.0.2 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert sanitized.count("FQDN_0001") == 2
    assert "FQDN_0002" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- public-internet FQDN NOT redacted ----------


def test_public_fqdn_not_redacted():
    """Public-internet FQDNs (``.com``, ``.org``, ``.net``, etc.) are
    NOT customer-identifying — they pass through verbatim. Only the
    fixed set of internal suffixes trigger interning."""
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain vendor.example.com\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert not any(
        e.kind == Kind.FQDN for e in ledger.entries.values()
    )


# ---------- internal suffix variations ----------


def test_lan_local_compound_suffix_redacted():
    """The two-component ``.lan.local`` suffix is matched as a unit
    (the regex orders multi-component suffixes first)."""
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain box.lan.local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "box.lan.local" not in sanitized
    assert "FQDN_0001" in sanitized


def test_home_arpa_suffix_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain host.home.arpa\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "host.home.arpa" not in sanitized
    assert "FQDN_0001" in sanitized


# ---------- FQDN inside description NOT separately interned ----------


def test_fqdn_inside_description_qstring_not_separately_interned():
    """Description QSTRINGs are interned by pass-1.7 as DESC; pass-2.0
    skips them to avoid orphan FQDN entries (the DESC redaction covers
    the whole QSTRING including any embedded FQDN)."""
    src = (
        "ltm pool /Common/p1 {\n"
        '    description "monitors example.local"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert not any(
        e.kind == Kind.FQDN for e in ledger.entries.values()
    )
    sanitized, _ = substitute(src, ledger, diag)
    assert "example.local" not in sanitized
    assert '"DESC_0001"' in sanitized


# ---------- leak detector exemption ----------


def test_leak_detector_does_not_flag_fqdn_placeholder():
    from veil.leak_detector import scan_leaks
    sanitized = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain FQDN_0001\n"
        "}\n"
    )
    report = scan_leaks(sanitized)
    assert all(
        "FQDN_0001" not in lk.token for lk in report.leaks
    )


def test_leak_detector_treats_FQDN_path_as_safe_leading_partition():
    """A path starting with ``/FQDN_NNNN/`` is a known-safe leading
    partition shape (the FQDN is already substituted). The detector
    must NOT flag it under IDENTIFIER_PATH."""
    from veil.leak_detector import LeakKind, scan_leaks
    sanitized = "    application-uri https://FQDN_0001/saml/idp/profile\n"
    report = scan_leaks(sanitized)
    # No IDENTIFIER_PATH leaks for the /FQDN_NNNN/... path.
    assert not any(
        lk.kind == LeakKind.IDENTIFIER_PATH
        and lk.token.startswith("/FQDN_")
        for lk in report.leaks
    )


# ---------- ledger invariants ----------


def test_no_fqdn_anywhere_no_entries():
    src = (
        "ltm pool /Common/p1 {\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert not any(
        e.kind == Kind.FQDN for e in ledger.entries.values()
    )


def test_fqdn_entry_has_no_partition():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    domain example.local\n"
        "}\n"
    )
    ledger, _ = scan(src)
    entries = [e for e in ledger.entries.values() if e.kind == Kind.FQDN]
    assert len(entries) == 1
    assert entries[0].partition is None
    assert entries[0].placeholder == "FQDN_0001"
