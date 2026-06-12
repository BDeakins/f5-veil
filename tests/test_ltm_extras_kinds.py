"""Tests for LTM extras kinds — DG (data-group), SNAT, SNATPOOL, VADDR.
Pattern mirrors test_profile_kind.py / test_gtm_kinds.py."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- DG (data-group) --------------------------------------------------


def test_internal_data_group_registered():
    src = (
        "ltm data-group internal /Common/customer_url_list {\n"
        "    type string\n"
        "    records {\n"
        '        "/api/v1" { data "backend1" }\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DG, "/Common/customer_url_list") in ledger.by_original
    assert diag.unknown_top_level == []


def test_external_data_group_registered():
    src = (
        "ltm data-group external /Common/external_ip_list {\n"
        "    external-file-name /Common/blocked-ips\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DG, "/Common/external_ip_list") in ledger.by_original
    assert diag.unknown_top_level == []


def test_data_group_round_trip():
    src = (
        "ltm data-group internal /Common/customer_url_list {\n"
        "    type string\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_url_list" not in sanitized
    assert "/Common/DG_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- SNAT -------------------------------------------------------------


def test_snat_registered():
    src = (
        "ltm snat /Common/customer_snat {\n"
        "    translation /Common/customer_snat_addr\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNAT, "/Common/customer_snat") in ledger.by_original
    assert diag.unknown_top_level == []


def test_snat_round_trip():
    src = (
        "ltm snat /Common/customer_snat {\n"
        "    automap\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_snat" not in sanitized
    assert "/Common/SNAT_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- SNATPOOL ---------------------------------------------------------


def test_snatpool_registered():
    src = (
        "ltm snatpool /Common/customer_snatpool {\n"
        "    members {\n"
        "        /Common/10.0.0.5\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNATPOOL, "/Common/customer_snatpool") in ledger.by_original
    assert diag.unknown_top_level == []


def test_snatpool_round_trip():
    src = (
        "ltm snatpool /Common/customer_snatpool {\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_snatpool" not in sanitized
    assert "/Common/SNATPOOL_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- VADDR (virtual-address) -----------------------------------------


def test_virtual_address_registered():
    src = (
        "ltm virtual-address /Common/customer_vs_addr {\n"
        "    address 192.168.1.100\n"
        "    mask 255.255.255.255\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.VADDR, "/Common/customer_vs_addr") in ledger.by_original
    assert diag.unknown_top_level == []


def test_virtual_address_round_trip():
    src = (
        "ltm virtual-address /Common/customer_vs_addr {\n"
        "    address 192.168.1.100\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_vs_addr" not in sanitized
    assert "192.168.1.100" not in sanitized  # IP also substituted
    assert "/Common/VADDR_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- distinct counters ------------------------------------------------


def test_each_new_kind_has_own_counter():
    src = (
        "ltm data-group internal /Common/dg1 {\n}\n"
        "ltm data-group internal /Common/dg2 {\n}\n"
        "ltm snat /Common/s1 {\n}\n"
        "ltm snatpool /Common/sp1 {\n}\n"
        "ltm virtual-address /Common/va1 {\n}\n"
    )
    ledger, _ = scan(src)
    placeholders = {e.placeholder for e in ledger.entries.values()}
    assert "DG_0001" in placeholders
    assert "DG_0002" in placeholders
    assert "SNAT_0001" in placeholders
    assert "SNATPOOL_0001" in placeholders
    assert "VADDR_0001" in placeholders


# ----- leak detector exempts new kinds ---------------------------------


@pytest.mark.parametrize("kind_str", ["DG", "SNAT", "SNATPOOL", "VADDR"])
def test_new_placeholders_not_flagged_as_leak(kind_str):
    sanitized = f"x /Common/{kind_str}_0001 y\n"
    report = scan_leaks(sanitized)
    bw = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD
        and lk.token == f"{kind_str}_0001"
    ]
    assert bw == [], (
        f"{kind_str}_NNNN should be exempt from bareword leak detection"
    )


# ----- realistic combined config ---------------------------------------


def test_shadowed_vaddr_not_flagged_as_orphan():
    """Real configs (EXAMPLE_CORPUS-confirmed) declare an IP both as a NODE
    and as a VADDR sharing the same path. Pass-2's Kind iteration order
    substitutes via NODE, leaving the VADDR entry with no references.
    The shadowed-duplicate suppression in _check_orphan_entries must
    treat this as NOT a parser gap."""
    src = (
        "ltm node /Common/10.0.0.179 {\n"
        "    address 10.0.0.179\n"
        "}\n"
        "ltm virtual-address /Common/10.0.0.179 {\n"
        "    address 10.0.0.179\n"
        "    arp enabled\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Both entries exist in the ledger.
    assert (Kind.NODE, "/Common/10.0.0.179") in ledger.by_original
    assert (Kind.VADDR, "/Common/10.0.0.179") in ledger.by_original
    # But the orphan diagnostic suppresses the shadowed VADDR entry
    # because NODE handled the path substitution.
    assert diag.orphan_entries == []


def test_real_world_combo_clean_diagnostics():
    """A snippet hitting most v0.0.7 kinds at once — should obfuscate
    clean without --allow-incomplete."""
    src = (
        "ltm virtual-address /Common/customer_vip {\n"
        "    address 192.168.1.100\n"
        "}\n"
        "ltm snatpool /Common/customer_snatpool {\n"
        "    members {\n"
        "        /Common/10.0.0.5\n"
        "    }\n"
        "}\n"
        "ltm data-group internal /Common/customer_dg {\n"
        "    type string\n"
        "}\n"
        "ltm pool /Common/customer_pool {\n"
        "    monitor /Common/http\n"
        "}\n"
        "ltm virtual /Common/customer_vs {\n"
        "    destination /Common/customer_vip:443\n"
        "    pool /Common/customer_pool\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unknown_top_level == []
    assert diag.malformed_paths == []
    # Round-trip exact.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
