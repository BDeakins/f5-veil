"""v0.0.11 — Tcl ``#`` comment redaction inside ``ltm rule`` bodies.

Covers pass-1.8 (irule_comment_discovery) + pass-2 substitution + the
new comment reverse map. Round-trip is byte-exact for every accepted
shape; out-of-scope shapes (top-level comments, data-group bodies)
pass through verbatim.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- in-rule comment redaction --------------------------------


def test_single_irule_comment_redacted():
    src = (
        "ltm rule /Common/r1 {\n"
        "    when CLIENT_ACCEPTED {\n"
        "        # log the client IP for the audit team\n"
        "        log local0. [IP::client_addr]\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "audit team" not in sanitized
    assert "# IRULE_COMMENT_0001" in sanitized
    # The IRULE entry for /Common/r1 still substitutes normally.
    assert "/Common/IRULE_0001" in sanitized


def test_single_irule_comment_round_trip():
    src = (
        "ltm rule /Common/r1 {\n"
        "    when CLIENT_ACCEPTED {\n"
        "        # log the client IP for the audit team\n"
        "        log local0. \"hi\"\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_multiple_irule_comments_distinct_placeholders():
    src = (
        "ltm rule /Common/r1 {\n"
        "    # alpha\n"
        "    # beta\n"
        "    # gamma\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    for body in ("alpha", "beta", "gamma"):
        assert body not in sanitized
    assert "# IRULE_COMMENT_0001" in sanitized
    assert "# IRULE_COMMENT_0002" in sanitized
    assert "# IRULE_COMMENT_0003" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_identical_comment_text_dedups():
    src = (
        "ltm rule /Common/r1 {\n"
        "    # repeated note\n"
        "    set x 1\n"
        "    # repeated note\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Only one placeholder minted; two sites both reference it.
    assert sanitized.count("# IRULE_COMMENT_0001") == 2
    assert "IRULE_COMMENT_0002" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_comment_leading_whitespace_preserved():
    src = (
        "ltm rule /Common/r1 {\n"
        "        # deeply indented comment\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Indent is whitespace BETWEEN tokens, copied verbatim by cursor
    # tracking in substitute() — so the placeholder line still has the
    # 8-space lead.
    assert "        # IRULE_COMMENT_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_comment_inside_nested_braces_redacted():
    src = (
        "ltm rule /Common/r1 {\n"
        "    when CLIENT_ACCEPTED {\n"
        "        if { [HTTP::host] equals \"x\" } {\n"
        "            # nested deeply\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "nested deeply" not in sanitized
    assert "# IRULE_COMMENT_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- out-of-scope: top-level comments pass through ------------


def test_top_level_tmsh_version_comment_not_redacted():
    src = (
        "#TMSH-VERSION: 15.1.0\n"
        "\n"
        "ltm pool /Common/p1 {\n"
        "    members {\n"
        "        /Common/n1:80 { address 1.2.3.4 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Top-level comment is universal BIG-IP signal — verbatim.
    assert "#TMSH-VERSION: 15.1.0" in sanitized
    assert "IRULE_COMMENT_" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_top_level_comment_after_rule_block_not_redacted():
    src = (
        "ltm rule /Common/r1 {\n"
        "    # inside — redact\n"
        "}\n"
        "# outside — keep verbatim\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "inside" not in sanitized
    assert "# outside — keep verbatim" in sanitized
    assert "# IRULE_COMMENT_0001" in sanitized
    # Exactly one IRULE_COMMENT minted.
    assert "IRULE_COMMENT_0002" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_comment_inside_data_group_body_not_redacted():
    """Scope boundary: only ``ltm rule`` bodies. Data-group bodies are
    out of scope for v0.0.11 — comments embedded in them pass through
    verbatim. (Real data-groups rarely contain Tcl comments, but the
    behaviour is documented and asserted.)"""
    src = (
        "ltm data-group internal /Common/dg1 {\n"
        "    # not an iRule body — not redacted\n"
        "    records { foo { data bar } }\n"
        "    type string\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "# not an iRule body — not redacted" in sanitized
    assert "IRULE_COMMENT_" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- discovery / ledger invariants ----------------------------


def test_comment_interned_with_kind_irule_comment():
    src = (
        "ltm rule /Common/r1 {\n"
        "    # the only comment\n"
        "}\n"
    )
    ledger, _ = scan(src)
    irule_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.IRULE_COMMENT
    ]
    assert len(irule_entries) == 1
    entry = irule_entries[0]
    assert entry.original == "# the only comment"
    assert entry.placeholder == "IRULE_COMMENT_0001"
    assert entry.partition is None


def test_no_irule_comments_no_entries_no_diagnostic():
    src = (
        "ltm rule /Common/r1 {\n"
        "    when CLIENT_ACCEPTED {\n"
        "        log local0. \"hi\"\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert not any(
        e.kind == Kind.IRULE_COMMENT for e in ledger.entries.values()
    )
    sanitized, _ = substitute(src, ledger, diag)
    assert "IRULE_COMMENT_" not in sanitized


def test_multiple_rule_blocks_each_get_comments():
    src = (
        "ltm rule /Common/r1 {\n"
        "    # from r1\n"
        "}\n"
        "ltm rule /Common/r2 {\n"
        "    # from r2\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "from r1" not in sanitized
    assert "from r2" not in sanitized
    assert "# IRULE_COMMENT_0001" in sanitized
    assert "# IRULE_COMMENT_0002" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector recognises the new placeholder -------------


def test_leak_detector_does_not_flag_irule_comment_placeholder():
    from veil.leak_detector import scan_leaks
    sanitized = (
        "ltm rule /Common/IRULE_0001 {\n"
        "    # IRULE_COMMENT_0001\n"
        "}\n"
    )
    report = scan_leaks(sanitized)
    # Placeholder must not be flagged as identifier-shaped bareword.
    assert all(
        "IRULE_COMMENT_0001" not in lk.token for lk in report.leaks
    ), [lk for lk in report.leaks if "IRULE_COMMENT" in lk.token]
