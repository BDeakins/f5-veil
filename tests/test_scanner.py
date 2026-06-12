from veil.ledger import Kind
from veil.scanner import scan


def test_scan_registers_top_level_pool():
    src = "ltm pool /Common/foo_pool {\n  members { }\n}\n"
    ledger, _ = scan(src)
    assert ledger.by_original[(Kind.POOL, "/Common/foo_pool")] == "POOL_0001"


def test_scan_registers_virtual_and_node():
    src = (
        "ltm virtual /Common/vs1 {\n"
        "}\n"
        "ltm node /Common/10.0.0.1 {\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.VS, "/Common/vs1") in ledger.by_original
    assert (Kind.NODE, "/Common/10.0.0.1") in ledger.by_original


def test_scan_registers_monitor_with_subtype():
    src = "ltm monitor http /Common/http_mon {\n}\n"
    ledger, _ = scan(src)
    assert (Kind.MON, "/Common/http_mon") in ledger.by_original


def test_scan_registers_irule():
    src = (
        "ltm rule /Common/my_rule {\n"
        "  when CLIENT_ACCEPTED { log local0. hi }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.IRULE, "/Common/my_rule") in ledger.by_original


def test_distinct_partitions_get_distinct_placeholders():
    src = (
        "ltm pool /Common/foo {\n}\n"
        "ltm pool /Tenant_A/foo {\n}\n"
    )
    ledger, _ = scan(src)
    common_p = ledger.by_original[(Kind.POOL, "/Common/foo")]
    tenant_p = ledger.by_original[(Kind.POOL, "/Tenant_A/foo")]
    assert common_p != tenant_p


def test_common_partition_is_not_registered():
    src = "ltm pool /Common/foo {}\n"
    ledger, _ = scan(src)
    assert (Kind.PARTITION, "Common") not in ledger.by_original


def test_non_common_partition_is_registered():
    src = "ltm pool /Tenant_A/foo {}\n"
    ledger, _ = scan(src)
    assert ledger.by_original[(Kind.PARTITION, "Tenant_A")] == "PARTITION_0001"


def test_scanner_ignores_object_like_tokens_inside_block_bodies():
    # /Common/http appearing as a profile reference inside a virtual must
    # NOT be picked up as a top-level object — pass 2 handles in-body refs.
    src = (
        "ltm virtual /Common/vs1 {\n"
        "    profiles {\n"
        "        /Common/http { }\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.VS, "/Common/vs1") in ledger.by_original
    # Only the VS should be in the ledger; /Common/ partition is exempt.
    assert len(ledger) == 1


def test_ipv6_shaped_node_name_is_registered_intact():
    # IPv6 nodes are stored as /Partition/<ipv6-addr>; colons must not
    # split the bareword. This is also a high-leak-risk identifier.
    src = "ltm node /Tenant_A/2001:db8::1 {\n}\n"
    ledger, _ = scan(src)
    assert (Kind.NODE, "/Tenant_A/2001:db8::1") in ledger.by_original


def test_folder_nested_object_path_preserves_full_path():
    src = "ltm pool /Common/app/folder/foo_pool {\n}\n"
    ledger, _ = scan(src)
    assert (Kind.POOL, "/Common/app/folder/foo_pool") in ledger.by_original


def test_unknown_ltm_subtype_emits_diagnostic_not_ledger_entry():
    # `ltm dns` is a known module but unknown tracer-bullet subtype —
    # CRUCIBLE C-2: must NOT silently pass through. Must surface in
    # diagnostics.unknown_top_level so the caller can fail closed.
    src = (
        "ltm dns /Common/cache1 {\n"
        "}\n"
        "ltm pool /Common/foo {\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.POOL, "/Common/foo") in ledger.by_original
    assert ("ltm dns", 1) in diag.unknown_top_level


def test_gtm_block_is_recorded_in_diagnostics():
    # GTM is on the v1.0 roadmap but not implemented yet. A `gtm wideip`
    # header must NOT pass through silently — that's the career-ending
    # leak CRUCIBLE C-2 was about.
    src = "gtm wideip /Common/app.example.com {\n  pools none\n}\n"
    ledger, diag = scan(src)
    assert ("gtm wideip", 1) in diag.unknown_top_level
    # No ledger entries should have been minted.
    assert len(ledger) == 0


def test_malformed_path_with_empty_leaf_is_surfaced_to_diagnostics():
    # CRUCIBLE C-1: `/Common/` with no leaf must not register garbage,
    # but it also must not vanish silently — it surfaces as a malformed
    # path diagnostic so callers can fail closed.
    src = "ltm pool /Common/ {\n}\n"
    ledger, diag = scan(src)
    assert len(ledger) == 0
    assert ("POOL", "/Common/", 1) in diag.malformed_paths


def test_malformed_path_with_empty_partition_is_surfaced_to_diagnostics():
    src = "ltm pool //foo {\n}\n"
    ledger, diag = scan(src)
    assert len(ledger) == 0
    assert ("POOL", "//foo", 1) in diag.malformed_paths


def test_empty_input_does_not_crash():
    # CRUCIBLE C-6: defensive coverage.
    ledger, diag = scan("")
    assert len(ledger) == 0
    assert diag.unknown_top_level == []


def test_discovery_ref_byte_offset_matches_source():
    src = "ltm pool /Common/foo {\n}\n"
    ledger, _ = scan(src)
    p = ledger.by_original[(Kind.POOL, "/Common/foo")]
    entry = ledger.entries[p]
    assert src[entry.discovery.byte_offset : entry.discovery.byte_offset + entry.discovery.length] == "/Common/foo"
