"""v1.2 — QSTRING-wrapped unknown-block header paths.

Real BIG-IP configs wrap a top-level block's path identifier in
``"..."`` whenever the customer-defined name contains a character TMSH
can't tokenize as a bareword — most commonly spaces. Bot-defense
signatures are the canonical case:

    security bot-defense signature "/Common/Example Bot B" {
        category "/Common/HTTP Libraries"
        ...
    }

Pre-v1.2, ``_find_unknown_header_path`` only matched WORD tokens that
started with ``/``; the QSTRING-wrapped path silently passed through
and the customer-identifying name leaked verbatim. v1.2 extends the
helper to also accept QSTRING tokens whose inner content starts with
``/`` and register them as ``Kind.UNKNOWN`` with the bare (unquoted)
path as the canonical original. Pass-2's QSTRING substring sub then
finds the original inside the original ``"..."`` token and substitutes
in place; round-trip restores byte-exactly.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_qstring_wrapped_bot_defense_signature_path_registered():
    src = (
        'security bot-defense signature "/Common/Example Bot B" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, _ = scan(src)
    unk_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.UNKNOWN
    ]
    assert len(unk_entries) == 1
    assert unk_entries[0].original == "/Common/Example Bot B"
    assert unk_entries[0].partition == "Common"


def test_qstring_wrapped_path_substituted_round_trip():
    src = (
        'security bot-defense signature "/Common/Example Bot B" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Original path must not survive in sanitized output.
    assert "Example" not in sanitized
    assert "/Common/Example Bot B" not in sanitized
    # Placeholder appears in QSTRING form because substring sub replaces
    # the inner path; the wrapping quotes pass through.
    assert "/Common/UNK_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_multiple_qstring_wrapped_paths_distinct_placeholders():
    src = (
        'security bot-defense signature "/Common/Signature One" {\n'
        '    enabled true\n'
        "}\n"
        'security bot-defense signature "/Common/Signature Two" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "Signature One" not in sanitized
    assert "Signature Two" not in sanitized
    assert "/Common/UNK_0001" in sanitized
    assert "/Common/UNK_0002" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_qstring_without_leading_slash_not_registered():
    """A QSTRING in a header position whose content doesn't lead with
    ``/`` is NOT a path — must not be misregistered."""
    src = (
        'auth ldap "ldap.example.com" {\n'
        "    server 10.0.0.42\n"
        "}\n"
    )
    ledger, _ = scan(src)
    # Only IPADDR for 10.0.0.42 should be present; no UNK entry for
    # the QSTRING.
    assert not any(
        e.kind == Kind.UNKNOWN for e in ledger.entries.values()
    )


def test_qstring_wrapped_non_common_partition_path_registered():
    src = (
        'security bot-defense signature "/Tenant_A/Custom Signature" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "Custom Signature" not in sanitized
    # Non-Common partition gets a PARTITION_NNNN placeholder + UNK leaf.
    assert "/PARTITION_0001/UNK_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_word_path_still_takes_precedence_when_both_present():
    """If a header has BOTH a QSTRING-wrapped path AND a WORD-shaped
    path, the rightmost wins — and the function walks right-to-left,
    so the more-specific WORD identifier is selected first. (Real
    BIG-IP configs don't combine these in a single block header, but
    test the ordering contract explicitly.)"""
    src = (
        'security bot-defense signature "/Common/Quoted Name" /Common/word_name {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, _ = scan(src)
    unk_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.UNKNOWN
    ]
    # The WORD path /Common/word_name (rightmost) is what gets
    # registered — _find_unknown_header_path walks right-to-left and
    # returns the first ``/``-prefixed token of either WORD or QSTRING
    # type.
    assert len(unk_entries) == 1
    assert unk_entries[0].original == "/Common/word_name"


def test_empty_qstring_not_registered():
    src = (
        'security bot-defense signature "" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, _ = scan(src)
    assert not any(
        e.kind == Kind.UNKNOWN for e in ledger.entries.values()
    )


def test_qstring_starts_with_slash_but_no_partition_segment_malformed():
    """A QSTRING ``"/"`` or ``"/leaf"`` (no partition) — malformed; the
    register path falls into ``malformed_paths`` diagnostic rather than
    interning a garbage UNK entry."""
    src = (
        'security bot-defense signature "/no_partition" {\n'
        '    enabled true\n'
        "}\n"
    )
    ledger, diag = scan(src)
    # No UNK entry for the malformed path.
    assert not any(
        e.kind == Kind.UNKNOWN for e in ledger.entries.values()
    )
    # Diagnostic carries the rejection.
    assert any(
        "/no_partition" in raw for _kind, raw, _line in diag.malformed_paths
    )
