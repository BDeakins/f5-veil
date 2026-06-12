from veil.ledger import Kind, Ledger, Ref
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def _scan_and_substitute(src):
    ledger, diag = scan(src)
    return substitute(src, ledger, diag)


def test_non_common_partition_renders_as_path_piece():
    src = "ltm pool /Tenant_A/foo_pool {\n}\n"
    sanitized, _ = _scan_and_substitute(src)
    assert "/PARTITION_0001/POOL_0001" in sanitized
    assert "Tenant_A" not in sanitized
    assert "foo_pool" not in sanitized


def test_common_partition_left_literal_in_sanitized_output():
    src = "ltm pool /Common/foo_pool {\n}\n"
    sanitized, _ = _scan_and_substitute(src)
    assert "/Common/POOL_0001" in sanitized
    assert "foo_pool" not in sanitized


def test_whitespace_indentation_and_comments_preserved():
    src = (
        "# my pool\n"
        "\n"
        "ltm pool /Common/foo {\n"
        "    members {\n"
        "    }\n"
        "}\n"
    )
    sanitized, _ = _scan_and_substitute(src)
    assert sanitized.startswith("# my pool\n\nltm pool")
    assert "    members {" in sanitized
    assert "    }\n" in sanitized


def test_substitution_records_reference_for_each_occurrence():
    src = "ltm pool /Common/foo {\n}\n"
    ledger, diag = scan(src)
    substitute(src, ledger, diag)
    entry = ledger.entries["POOL_0001"]
    assert len(entry.references) == 1
    ref = entry.references[0]
    assert src[ref.byte_offset : ref.byte_offset + ref.length] == "/Common/foo"


def test_in_body_pool_reference_inside_virtual_is_substituted():
    src = (
        "ltm pool /Common/foo_pool {\n"
        "}\n"
        "ltm virtual /Common/vs1 {\n"
        "    pool /Common/foo_pool\n"
        "}\n"
    )
    sanitized, _ = _scan_and_substitute(src)
    assert sanitized.count("/Common/POOL_0001") == 2
    assert "foo_pool" not in sanitized


def test_partition_gets_a_reference_recorded_for_every_path_render():
    src = (
        "ltm pool /Tenant_A/foo {\n"
        "}\n"
        "ltm virtual /Tenant_A/vs1 {\n"
        "    pool /Tenant_A/foo\n"
        "}\n"
    )
    ledger, diag = scan(src)
    substitute(src, ledger, diag)
    part_entry = ledger.entries["PARTITION_0001"]
    # Three path renders mention Tenant_A: pool def, virtual def, in-body
    # pool reference. Each records one partition reference.
    assert len(part_entry.references) == 3


def test_quoted_description_logs_diagnostic_and_passes_through():
    src = (
        "ltm pool /Common/foo {\n"
        '    description "customer prod pool"\n'
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert '"customer prod pool"' in sanitized
    assert len(diag.unredacted_description) == 1


def test_brace_description_logs_diagnostic_and_passes_through():
    src = (
        "ltm pool /Common/foo {\n"
        "    description { customer prod pool 2024 }\n"
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert "{ customer prod pool 2024 }" in sanitized
    assert len(diag.unredacted_description) == 1


def test_qstring_containing_ledger_original_logs_diagnostic():
    src = (
        "ltm pool /Common/foo {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    when CLIENT_ACCEPTED { log "see /Common/foo for ref" }\n'
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert len(diag.qstring_contains_identifier) >= 1
    # QSTRING content is emitted verbatim — no Tcl-lexer yet.
    assert '"see /Common/foo for ref"' in sanitized


def test_orphan_entry_surfaces_when_pass2_finds_no_reference():
    ledger = Ledger()
    ledger.intern(Kind.POOL, "/Common/orphan", Ref(0, 1, 1), partition="Common")
    ledger.freeze()
    _, diag = substitute("ltm virtual /Common/vs1 {\n}\n", ledger)
    assert "POOL_0001" in diag.orphan_entries


def test_no_orphans_when_every_entry_is_referenced():
    src = "ltm pool /Common/foo {\n}\n"
    _, diag = _scan_and_substitute(src)
    assert diag.orphan_entries == []


def test_substitute_freezes_an_unfrozen_ledger():
    src = "ltm pool /Common/foo {\n}\n"
    ledger, diag = scan(src)
    assert ledger.frozen is False
    substitute(src, ledger, diag)
    assert ledger.frozen is True


def test_substitute_works_with_already_frozen_ledger():
    src = "ltm pool /Common/foo {\n}\n"
    ledger, diag = scan(src)
    ledger.freeze()
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/POOL_0001" in sanitized


def test_unknown_top_level_block_body_is_passed_through_unchanged():
    src = "gtm wideip /Common/app.example.com {\n  pools none\n}\n"
    sanitized, diag = _scan_and_substitute(src)
    assert "/Common/app.example.com" in sanitized
    assert ("gtm wideip", 1) in diag.unknown_top_level


def test_realistic_tracer_config_round_trip():
    src = (
        "ltm pool /Tenant_A/customer_app_pool_2024 {\n"
        "}\n"
        "ltm virtual /Tenant_A/vs_customer_app_https {\n"
        "    pool /Tenant_A/customer_app_pool_2024\n"
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert "customer_app_pool_2024" not in sanitized
    assert "vs_customer_app_https" not in sanitized
    assert "Tenant_A" not in sanitized
    assert "POOL_0001" in sanitized
    assert "VS_0001" in sanitized
    assert "PARTITION_0001" in sanitized
    assert diag.orphan_entries == []


def test_byte_for_byte_round_trip_when_ledger_is_empty():
    # Empty ledger -> sanitized equals source (no substitutions, just
    # token-walk + gap-copy). Guards the round-trip property.
    src = "# header\nsys global-settings {\n    mgmt-dhcp enabled\n}\n"
    ledger = Ledger()
    ledger.freeze()
    sanitized, _ = substitute(src, ledger)
    assert sanitized == src


def test_substitute_raises_on_unresolvable_partition_rather_than_leak():
    # CRUCIBLE C2-1: if an object claims a partition that was never
    # interned, substitute() must crash loudly rather than silently
    # emit the literal partition name into sanitized output. This path
    # is unreachable via the normal scan -> substitute flow; the test
    # documents the invariant by hand-crafting a broken ledger.
    ledger = Ledger()
    ledger.intern(
        Kind.POOL,
        "/Tenant_Secret/foo",
        Ref(byte_offset=9, length=18, line=1),
        partition="Tenant_Secret",
    )
    # Deliberately did NOT call intern_partition("Tenant_Secret", ...).
    ledger.freeze()
    src = "ltm pool /Tenant_Secret/foo {\n}\n"
    try:
        sanitized, _ = substitute(src, ledger)
    except RuntimeError as exc:
        # The error message may mention the partition; what matters is
        # that no sanitized output got written.
        assert "partition" in str(exc).lower()
        return
    raise AssertionError(
        "expected RuntimeError on unresolvable partition; "
        f"got sanitized output instead: {sanitized!r}"
    )


def test_reverse_substitute_round_trip_common_partition():
    src = "ltm pool /Common/foo {\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert reverse_substitute(sanitized, ledger) == src


def test_reverse_substitute_round_trip_non_common_partition():
    src = (
        "ltm pool /Tenant_A/foo {\n"
        "}\n"
        "ltm virtual /Tenant_A/vs1 {\n"
        "    pool /Tenant_A/foo\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert reverse_substitute(sanitized, ledger) == src


def test_reverse_substitute_passes_unknown_placeholder_through_verbatim():
    # An AI-introduced placeholder (`POOL_9999`) that's not in the ledger
    # must pass through unchanged — we never synthesize originals.
    src = "ltm pool /Common/foo {\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    sanitized_plus = sanitized + "\n# AI added: see also POOL_9999\n"
    restored = reverse_substitute(sanitized_plus, ledger)
    assert restored.endswith("# AI added: see also POOL_9999\n")
    assert restored.startswith("ltm pool /Common/foo")


def test_reverse_substitute_restores_bare_partition_token():
    # `partition Tenant_A` becomes `partition PARTITION_0001` in sanitized
    # output; reverse must restore the bare partition reference.
    src = "ltm pool /Tenant_A/foo {\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    sanitized_with_bare = sanitized + "\npartition PARTITION_0001\n"
    restored = reverse_substitute(sanitized_with_bare, ledger)
    assert "partition Tenant_A" in restored


def test_node_referenced_inside_pool_members_is_substituted():
    src = (
        "ltm node /Common/web1 {\n"
        "    address 10.0.0.1\n"
        "}\n"
        "ltm pool /Common/web_pool {\n"
        "    members {\n"
        "        /Common/web1:80 { }\n"
        "    }\n"
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    # The node is defined and its definition gets substituted.
    assert "/Common/NODE_0001" in sanitized
    assert "/Common/POOL_0001" in sanitized
    # The `/Common/web1:80` token is NOT a clean match for /Common/web1
    # — it's a different bareword. Expected to pass through verbatim.
    # This documents the tracer-bullet gap: member-port suffix handling
    # is a follow-up PR.
    assert "/Common/web1:80" in sanitized
