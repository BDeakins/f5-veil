"""End-to-end tests for DESC_NNNN description redaction (pass-1.7
discovery + pass-2 substitution + round-trip)."""

from __future__ import annotations

import pytest

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- QSTRING form -----------------------------------------------------


def test_qstring_description_redacted():
    src = 'ltm pool /Common/foo {\n    description "primary cluster"\n}\n'
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "primary cluster" not in sanitized
    assert '"DESC_0001"' in sanitized
    assert diag.unredacted_description == []


def test_qstring_description_round_trip():
    src = 'ltm pool /Common/foo {\n    description "primary cluster"\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_qstring_with_embedded_ip_fully_redacted():
    """The previous fail-closed source (description body containing an
    IP) should now obfuscate clean — body is redacted, the IP is no
    longer visible in sanitized output."""
    src = (
        'ltm pool /Common/foo {\n'
        '    description "primary node at 10.0.0.42"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "10.0.0.42" not in sanitized
    assert "primary node" not in sanitized
    assert '"DESC_0001"' in sanitized
    assert diag.unredacted_description == []


def test_qstring_with_special_chars_round_trip():
    # Quoted special chars — confirm tokenizer's QSTRING handling and
    # our redaction don't get confused by punctuation/brackets/etc.
    src = 'ltm pool /Common/foo {\n    description "complex: [a/b/c] & d?"\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_empty_qstring_description_unchanged():
    src = 'ltm pool /Common/foo {\n    description ""\n}\n'
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Empty body — nothing to redact, nothing minted, no diagnostic.
    assert '""' in sanitized
    assert diag.unredacted_description == []
    # Round-trip unchanged.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- bareword form ----------------------------------------------------


def test_bareword_description_redacted():
    src = 'ltm pool /Common/foo {\n    description primary\n}\n'
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "primary" not in sanitized.split("description ")[-1].split("\n")[0]
    assert "DESC_0001" in sanitized
    assert diag.unredacted_description == []


def test_bareword_description_round_trip():
    src = 'ltm pool /Common/foo {\n    description primary\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- braced form (v0.0.10) -------------------------------------------


def test_braced_description_redacted():
    src = 'ltm pool /Common/foo {\n    description { multi line body }\n}\n'
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "multi line body" not in sanitized
    assert '"DESC_0001"' in sanitized
    assert diag.unredacted_description == []


def test_braced_description_round_trip_single_space():
    src = 'ltm pool /Common/foo {\n    description { primary cluster }\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_braced_description_round_trip_no_inner_ws():
    # Brace with no inner whitespace — round-trip must preserve.
    src = 'ltm pool /Common/foo {\n    description {primary_cluster}\n}\n'
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_braced_description_round_trip_multi_line():
    src = (
        "ltm pool /Common/foo {\n"
        "    description {\n"
        "        line one of description\n"
        "        line two with stuff\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "line one of description" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_braced_description_with_nested_braces_round_trip():
    # The body itself contains a nested ``{...}`` — depth tracker must
    # find the OUTER RBRACE, not the inner one.
    src = (
        "ltm pool /Common/foo {\n"
        "    description { outer { inner } more }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "outer { inner } more" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_braced_descriptions_with_different_ws_distinct_placeholders():
    """Same substantive content with different inner whitespace stores
    distinct entries (because dedup key includes the full span). This is
    needed for byte-exact round-trip of each reference site."""
    src = (
        'ltm pool /Common/a {\n'
        '    description { primary }\n'
        '}\n'
        'ltm pool /Common/b {\n'
        '    description {primary}\n'
        '}\n'
    )
    ledger, diag = scan(src)
    desc_entries = [e for e in ledger.entries.values() if e.kind == Kind.DESC]
    assert len(desc_entries) == 2
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- dedup behavior ---------------------------------------------------


def test_same_qstring_body_dedups_to_same_placeholder():
    src = (
        'ltm pool /Common/a {\n'
        '    description "shared text"\n'
        '}\n'
        'ltm pool /Common/b {\n'
        '    description "shared text"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    desc_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.DESC
    ]
    assert len(desc_entries) == 1, (
        f"expected dedup; got {len(desc_entries)} DESC entries"
    )
    sanitized, _ = substitute(src, ledger, diag)
    # Both occurrences use the same placeholder.
    assert sanitized.count('"DESC_0001"') == 2


def test_qstring_and_bareword_get_distinct_placeholders():
    # Same substantive text in different forms — distinct placeholders
    # so reverse can restore each wrapping byte-exactly.
    src = (
        'ltm pool /Common/a {\n'
        '    description "primary"\n'
        '}\n'
        'ltm pool /Common/b {\n'
        '    description primary\n'
        '}\n'
    )
    ledger, diag = scan(src)
    desc_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.DESC
    ]
    assert len(desc_entries) == 2, (
        f"QSTRING and bareword forms of the same text should mint "
        f"distinct placeholders; got {len(desc_entries)}"
    )
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- mixed-content round trip ----------------------------------------


def test_realistic_config_round_trip():
    src = (
        'ltm node /Common/web1 {\n'
        '    address 10.0.0.42\n'
        '    description "primary web node"\n'
        '}\n'
        'ltm pool /Common/web_pool {\n'
        '    description "load balanced web tier"\n'
        '    members {\n'
        '        /Common/web1:80 {}\n'
        '    }\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # All identifying content redacted.
    assert "10.0.0.42" not in sanitized
    assert "primary web node" not in sanitized
    assert "load balanced web tier" not in sanitized
    # No diagnostics fired (descriptions are redacted, IPs substituted).
    assert diag.unredacted_description == []
    # Byte-exact round trip.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- description-only obfuscation no longer needs --allow-incomplete --


def test_description_only_config_clean_diagnostics():
    """Before v0.0.4 a config with only descriptions would fire
    unredacted_description and force --allow-incomplete. After: clean."""
    src = (
        'ltm pool /Common/foo {\n'
        '    description "anything here"\n'
        '}\n'
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unredacted_description == []
    assert diag.unknown_top_level == []
    assert diag.malformed_paths == []
    assert diag.qstring_contains_identifier == []
    assert diag.orphan_entries == []
