"""v0.0.11 — Tcl ``#`` comment redaction inside ``ltm rule`` bodies.
v0.0.12 — Tcl ``"..."`` string substring substitution inside the same.

v0.0.11 covers pass-1.8 (irule_comment_discovery) + pass-2 substitution
of COMMENT tokens + the new comment reverse map.
v0.0.12 extends pass-2 / reverse-pass with substring substitution on
QSTRINGs that fall inside an ``ltm rule /path { ... }`` body. Round-trip
is byte-exact for every accepted shape; out-of-scope shapes (top-level
comments, data-group bodies, monitor QSTRINGs) pass through verbatim
and surface via ``qstring_contains_identifier`` where applicable.
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


# =====================================================================
# v0.0.12 — Tcl QSTRING substring substitution inside iRule bodies
# =====================================================================


def test_irule_qstring_pool_path_redacted():
    """A path identifier embedded in a Tcl string inside an iRule body
    is substituted in place to its rendered placeholder."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        "    when HTTP_REQUEST {\n"
        '        log local0. "routed to /Common/foo_pool"\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/foo_pool" not in sanitized
    assert '"routed to /Common/POOL_0001"' in sanitized
    # The diagnostic must NOT fire — v0.0.12 contract is that iRule QSTRINGs
    # get substituted, not flagged.
    assert diag.qstring_contains_identifier == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_ip_literal_redacted():
    """An IP literal embedded in a Tcl string inside an iRule body is
    substituted to its RFC 5737 docs-range form."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "client connected from 10.0.0.42"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "10.0.0.42" not in sanitized
    assert "192.0.2.42" in sanitized
    assert diag.qstring_contains_identifier == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_multiple_identifiers_in_one_string():
    """A single Tcl string containing several identifiers gets each
    substituted independently; round-trip is byte-exact."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm pool /Common/bar_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "primary=/Common/foo_pool fallback=/Common/bar_pool"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "foo_pool" not in sanitized
    assert "bar_pool" not in sanitized
    assert "/Common/POOL_0001" in sanitized
    assert "/Common/POOL_0002" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_word_boundary_prevents_false_match():
    """A ledger original that is a strict substring inside a longer
    word-character run must NOT match — otherwise a token like
    ``foo_pool_alt`` would be partially substituted to
    ``POOL_0001_alt``."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "container=/Common/foo_pool_extra"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # The whole compound stays verbatim — partial substitution would be
    # a leak (placeholder mixed with original suffix).
    assert "/Common/foo_pool_extra" in sanitized
    assert "POOL_0001_extra" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_partition_name_redacted():
    """A non-Common partition name embedded as a Tcl string substring
    is substituted to its PARTITION_NNNN placeholder."""
    src = (
        "ltm pool /Tenant_A/p1 {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "tenant=Tenant_A"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "PARTITION_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_no_match_is_verbatim():
    """A Tcl string containing no ledger original is emitted unchanged
    (including round-trip)."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "unrelated message"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert '"unrelated message"' in sanitized
    assert diag.qstring_contains_identifier == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_builtin_profile_not_substituted_from_string():
    """A built-in TMOS profile name (``http``, ``tcp``, etc.) is exempt
    from substitution — there is no ledger entry for it — so iRule
    strings containing it pass through verbatim."""
    src = (
        "ltm rule /Common/r1 {\n"
        '    log local0. "selected http profile"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert '"selected http profile"' in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_qstring_outside_irule_body_also_substituted():
    """v0.0.14 unified QSTRING substitution: a monitor send-string
    QSTRING containing a ledger identifier ALSO gets substring
    substitution. The v0.0.12 split (iRule body = sub, non-iRule =
    verbatim + diagnostic) was a conservative call premised on
    probe-payload bytes; v0.0.14 unifies because the sanitized output is
    never deployed to live BIG-IP."""
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.42\n"
        "}\n"
        "ltm monitor http /Common/m1 {\n"
        '    send "GET / HTTP/1.0 from 10.0.0.42"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Substituted — even in monitor send-strings.
    assert "10.0.0.42" not in sanitized
    assert "192.0.2.42" in sanitized
    # No diagnostic — the leak surface is actively redacted.
    assert diag.qstring_contains_identifier == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_qstring_inside_data_group_body_also_substituted():
    """v0.0.14 unified QSTRING substitution: data-group record QSTRINGs
    are ALSO scanned for ledger originals. (v0.0.12 had data-group
    bodies out of scope because the substring sub was gated to
    ``ltm rule`` bodies; v0.0.14 lifts the gate.)"""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm data-group internal /Common/dg1 {\n"
        '    records {\n'
        '        key1 { data "see /Common/foo_pool" }\n'
        "    }\n"
        "    type string\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Data-group body QSTRINGs ARE substituted now.
    assert "/Common/foo_pool" not in sanitized
    assert "/Common/POOL_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_substitution_records_references():
    """Each substring substitution inside an iRule QSTRING records a Ref
    on the underlying ledger entry — non-zero reference counts and the
    orphan diagnostic stays clean."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "pool=/Common/foo_pool"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    pool_entry = ledger.entries["POOL_0001"]
    assert len(pool_entry.references) >= 1
    assert diag.orphan_entries == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_longest_match_wins():
    """When two ledger originals could match at a position, the longest
    wins — protecting compound paths like ``/Common/foo_extra`` from
    being partially substituted via a shorter ``/Common/foo`` candidate.
    """
    src = (
        "ltm pool /Common/foo {\n"
        "}\n"
        "ltm pool /Common/foo_extra {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "ref /Common/foo_extra here"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # The longer path takes precedence; we must not see a partial
    # ``/Common/POOL_0001_extra`` mash-up.
    assert "/Common/POOL_0002" in sanitized
    assert "POOL_0001_extra" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_multiple_rule_bodies_all_substituted():
    """Two separate iRule blocks both get their QSTRINGs substituted."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "from r1: /Common/foo_pool"\n'
        "}\n"
        "ltm rule /Common/r2 {\n"
        '    log local0. "from r2: /Common/foo_pool"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert sanitized.count("/Common/POOL_0001") >= 2
    assert "foo_pool" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_irule_qstring_with_escaped_quote_substring_substituted():
    """A Tcl string containing an escaped quote (``\\"``) still gets
    substring substitution and round-trips byte-exactly."""
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "marker=\\"/Common/foo_pool\\" end"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/foo_pool" not in sanitized
    assert "/Common/POOL_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
