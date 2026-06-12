"""Tests for the GTM family kinds — GTM_POOL, GTM_WIDEIP, GTM_SERVER,
GTM_DC. Pattern mirrors test_profile_kind.py."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- GTM_POOL ---------------------------------------------------------


def test_gtm_pool_a_registered():
    src = (
        "gtm pool a /Common/my_app_pool {\n"
        "    load-balancing-mode round-robin\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.GTM_POOL, "/Common/my_app_pool") in ledger.by_original
    assert diag.unknown_top_level == []


@pytest.mark.parametrize("subtype", ["a", "aaaa", "mx", "cname", "naptr", "srv"])
def test_gtm_pool_subtype_agnostic(subtype):
    src = (
        f"gtm pool {subtype} /Common/my_pool {{\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.GTM_POOL, "/Common/my_pool") in ledger.by_original


def test_gtm_pool_round_trip():
    src = (
        "gtm pool a /Common/my_app_pool {\n"
        "    load-balancing-mode round-robin\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/GTM_POOL_0001" in sanitized
    assert "my_app_pool" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- GTM_WIDEIP -------------------------------------------------------


def test_gtm_wideip_a_registered():
    src = (
        "gtm wideip a /Common/www.example.com {\n"
        "    pools none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.GTM_WIDEIP, "/Common/www.example.com") in ledger.by_original
    assert diag.unknown_top_level == []


def test_gtm_wideip_round_trip():
    src = (
        "gtm wideip a /Common/app.customer.com {\n"
        "    pools none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "app.customer.com" not in sanitized
    assert "/Common/GTM_WIDEIP_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- GTM_SERVER -------------------------------------------------------


def test_gtm_server_registered():
    src = (
        "gtm server /Common/site1_bigip {\n"
        "    addresses {\n"
        "        10.0.0.5 { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.GTM_SERVER, "/Common/site1_bigip") in ledger.by_original
    assert diag.unknown_top_level == []


def test_gtm_server_round_trip():
    src = (
        "gtm server /Common/site1_bigip {\n"
        "    product bigip\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "site1_bigip" not in sanitized
    assert "/Common/GTM_SERVER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- GTM_DC -----------------------------------------------------------


def test_gtm_datacenter_registered():
    src = (
        "gtm datacenter /Common/east_dc {\n"
        "    contact ops@example.com\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.GTM_DC, "/Common/east_dc") in ledger.by_original


def test_gtm_datacenter_round_trip():
    src = (
        "gtm datacenter /Common/east_dc {\n"
        "    location us-east\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "east_dc" not in sanitized
    assert "/Common/GTM_DC_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- distinct placeholders per kind ----------------------------------


def test_gtm_kinds_get_distinct_counters():
    """GTM_POOL_0001 and GTM_WIDEIP_0001 share the suffix ``0001`` but
    are independent counters — each kind has its own sequence."""
    src = (
        "gtm pool a /Common/p1 {\n}\n"
        "gtm pool a /Common/p2 {\n}\n"
        "gtm wideip a /Common/w1 {\n}\n"
        "gtm server /Common/s1 {\n}\n"
        "gtm datacenter /Common/dc1 {\n}\n"
    )
    ledger, _ = scan(src)
    placeholders = {e.placeholder for e in ledger.entries.values()}
    assert "GTM_POOL_0001" in placeholders
    assert "GTM_POOL_0002" in placeholders
    assert "GTM_WIDEIP_0001" in placeholders
    assert "GTM_SERVER_0001" in placeholders
    assert "GTM_DC_0001" in placeholders


# ----- deferred GTM forms still fire unknown_top_level -----------------


def test_gtm_topology_still_unknown():
    """``gtm topology`` and ``gtm region`` are deferred to v0.0.7."""
    src = "gtm topology /Common/topo {\n}\n"
    _, diag = scan(src)
    # Topology has unusual structure; either path here is fine — what
    # matters is the cycle still surfaces a diagnostic.
    assert diag.unknown_top_level != []


# ----- leak detector exempts new kinds --------------------------------


@pytest.mark.parametrize("kind_str", [
    "GTM_POOL", "GTM_WIDEIP", "GTM_SERVER", "GTM_DC",
])
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


def test_full_gtm_stack_clean_diagnostics():
    src = (
        "gtm datacenter /Common/east_dc {\n}\n"
        "gtm server /Common/east_bigip {\n"
        "    datacenter /Common/east_dc\n"
        "}\n"
        "gtm pool a /Common/app_pool {\n"
        "    load-balancing-mode global-availability\n"
        "}\n"
        "gtm wideip a /Common/app.customer.com {\n"
        "    pools {\n"
        "        /Common/app_pool { order 0 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unknown_top_level == []
    assert diag.malformed_paths == []
    # Round-trip intact.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
