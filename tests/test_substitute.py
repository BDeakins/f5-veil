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


def test_quoted_description_redacted_to_placeholder():
    # v0.0.4: QSTRING-form descriptions are now redacted to DESC_NNNN
    # placeholders. The body no longer survives in sanitized output and
    # the legacy ``unredacted_description`` diagnostic no longer fires.
    src = (
        "ltm pool /Common/foo {\n"
        '    description "customer prod pool"\n'
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert '"customer prod pool"' not in sanitized
    assert '"DESC_0001"' in sanitized
    assert diag.unredacted_description == []


def test_brace_description_redacted_to_placeholder():
    # v0.0.10: braced-form descriptions are now redacted to DESC_NNNN
    # placeholders (emitted as "DESC_NNNN" qstring), with the full
    # braced span stored as the ledger original so reverse restores
    # byte-exactly.
    src = (
        "ltm pool /Common/foo {\n"
        "    description { customer prod pool 2024 }\n"
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert "{ customer prod pool 2024 }" not in sanitized
    assert '"DESC_0001"' in sanitized
    assert diag.unredacted_description == []


def test_qstring_containing_ledger_original_logs_diagnostic():
    # v0.0.12: QSTRINGs inside ``ltm rule`` bodies now get substring
    # substitution, so the diagnostic is now scoped to non-iRule
    # QSTRINGs (monitor send-strings, etc., where probe payloads may
    # legitimately need original bytes). The diagnostic-fires-and-text-
    # passes-through contract is preserved for that context.
    src = (
        "ltm pool /Common/foo {\n"
        "}\n"
        "ltm monitor http /Common/m1 {\n"
        '    send "see /Common/foo for ref"\n'
        "}\n"
    )
    sanitized, diag = _scan_and_substitute(src)
    assert len(diag.qstring_contains_identifier) >= 1
    # Non-iRule QSTRING content is emitted verbatim.
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


def test_unknown_top_level_block_header_path_is_substituted():
    # Updated PR #6: the unknown-block header path is registered as
    # Kind.UNKNOWN and substituted by pass-2 (was: passed through
    # verbatim). Body content with no matching ledger entries still
    # passes through unchanged.
    src = "gtm wideip /Common/app.example.com {\n  pools none\n}\n"
    sanitized, diag = _scan_and_substitute(src)
    assert "/Common/app.example.com" not in sanitized
    assert "/Common/UNK_0001" in sanitized
    assert "pools none" in sanitized  # body content unchanged
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


def test_unknown_block_header_path_is_registered_as_unknown_kind():
    # EXAMPLE_CORPUS integration surfaced a leak where an unknown-block header
    # path (e.g. gtm pool /Common/<node>_servers) shares a prefix with a
    # registered NODE. Without registering the UNKNOWN path, the NODE's
    # full path leaks via substring inside the unknown header. After the
    # fix, the unknown path gets substituted to /Common/UNK_NNNN.
    src = (
        "ltm node /Common/web1 {\n"
        "}\n"
        "gtm pool /Common/web1_servers {\n"
        "    members none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # The unknown header path is registered.
    assert (Kind.UNKNOWN, "/Common/web1_servers") in ledger.by_original
    # The unknown header is substituted (no literal /Common/web1_servers).
    assert "/Common/web1_servers" not in sanitized
    # The NODE's path no longer leaks as substring.
    assert "/Common/web1" not in sanitized
    # The unknown diagnostic still fires so callers fail closed by default.
    assert ("gtm wideip", 1) not in diag.unknown_top_level  # not gtm wideip
    assert any(sig == "gtm pool" for sig, _ in diag.unknown_top_level)


def test_unknown_block_skips_registration_if_path_already_known():
    # When the same /Partition/name appears as both a known-kind
    # top-level (e.g. ltm pool) AND an unknown-kind top-level (e.g.
    # gtm pool), the known kind wins. Without this skip, the UNK
    # entry becomes an orphan because pass-2's Kind iteration matches
    # the more specific kind first.
    src = (
        "ltm pool /Common/shared_name {\n"
        "}\n"
        "gtm pool /Common/shared_name {\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.POOL, "/Common/shared_name") in ledger.by_original
    assert (Kind.UNKNOWN, "/Common/shared_name") not in ledger.by_original
    # The gtm pool block is still flagged as unknown.
    assert any(sig == "gtm pool" for sig, _ in diag.unknown_top_level)


def test_unknown_block_with_no_path_does_not_break_scan():
    # Some unknown blocks have no /Partition/leaf path token (e.g. a
    # ``sys global-settings`` block). Registration should skip cleanly.
    src = "sys global-settings {\n    hostname foo\n}\n"
    ledger, diag = scan(src)
    assert ("sys global-settings", 1) in diag.unknown_top_level
    assert (Kind.UNKNOWN, "global-settings") not in ledger.by_original


def test_member_port_suffix_does_not_leak_node_path():
    # The bug EXAMPLE_CORPUS integration surfaced: /Common/10.0.0.1:80 is a
    # single WORD token, distinct from the ledger key /Common/10.0.0.1.
    # Prefix-match must substitute the path portion and preserve :80.
    src = (
        "ltm node /Common/10.0.0.1 {\n"
        "    address 10.0.0.1\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        "    members {\n"
        "        /Common/10.0.0.1:80 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # The literal node path must not appear anywhere — not standalone,
    # not as substring of a :port token.
    assert "10.0.0.1" not in sanitized.replace("10.0.0.1", "ZZZ", 1) or "/Common/10.0.0.1" not in sanitized
    # Cleaner check: the rendered prefix-substituted token is present.
    assert "/Common/NODE_0001:80" in sanitized
    # And the literal full path isn't.
    assert "/Common/10.0.0.1" not in sanitized


def test_prefix_match_picks_longest_candidate():
    src = "ltm node /Common/web {\n}\nltm node /Common/web1 {\n}\n"
    ledger, diag = scan(src)
    # Add a synthetic body line via a second scan/substitute pass would
    # be awkward; instead, exercise substitute on the same src after
    # appending a member-style line that doesn't have its own header.
    extended = src + "members { /Common/web1:80 }\n"
    sanitized, _ = substitute(extended, ledger, diag)
    # /Common/web1 wins (longer prefix); /Common/web is rejected because
    # the boundary character '1' is a word character.
    web1_ph = ledger.by_original[(Kind.NODE, "/Common/web1")]
    assert f"/Common/{web1_ph}:80" in sanitized


def test_prefix_match_rejects_word_character_boundary():
    src = "ltm node /Common/web {\n}\n"
    ledger, diag = scan(src)
    extended = src + "junk /Common/web_pool more\n"
    sanitized, _ = substitute(extended, ledger, diag)
    # /Common/web_pool must NOT prefix-match /Common/web because the
    # boundary character '_' is a word char.
    assert "/Common/web_pool" in sanitized


def test_prefix_match_handles_ipv6_port_suffix_with_dot():
    # IPv6 nodes can have member port references using '.' separator.
    src = (
        "ltm node /Common/2001:db8::1 {\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        "    members {\n"
        "        /Common/2001:db8::1.80 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "2001:db8::1" not in sanitized
    assert "/Common/NODE_0001.80" in sanitized


def test_reverse_substitute_round_trips_port_suffix():
    src = (
        "ltm node /Common/10.0.0.1 {\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        "    members {\n"
        "        /Common/10.0.0.1:80 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_reverse_substitute_round_trips_ipv6_with_dot_port():
    src = (
        "ltm node /Common/2001:db8::1 {\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        "    members {\n"
        "        /Common/2001:db8::1.80 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


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
    # Updated after PR #6: prefix-match substitution closes the
    # member-port suffix gap. /Common/web1:80 now substitutes the
    # path prefix and preserves the :80 suffix.
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
    assert "/Common/NODE_0001" in sanitized
    assert "/Common/POOL_0001" in sanitized
    # Member-port suffix token now substitutes via prefix-match.
    assert "/Common/NODE_0001:80" in sanitized
    assert "/Common/web1" not in sanitized
