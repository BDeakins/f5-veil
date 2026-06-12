"""Tests for net family kinds + GTM_REGION."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


@pytest.mark.parametrize("header,kind,placeholder", [
    ("net vlan", Kind.VLAN, "VLAN_0001"),
    ("net route-domain", Kind.ROUTE_DOMAIN, "ROUTE_DOMAIN_0001"),
    ("net self", Kind.SELF_IP, "SELF_IP_0001"),
    ("net trunk", Kind.TRUNK, "TRUNK_0001"),
    ("gtm region", Kind.GTM_REGION, "GTM_REGION_0001"),
])
def test_kind_registered_and_substituted(header, kind, placeholder):
    src = f"{header} /Common/customer_obj {{\n}}\n"
    ledger, diag = scan(src)
    assert (kind, "/Common/customer_obj") in ledger.by_original
    assert diag.unknown_top_level == []
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_obj" not in sanitized
    assert f"/Common/{placeholder}" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


@pytest.mark.parametrize("placeholder", [
    "VLAN_0001", "ROUTE_DOMAIN_0001", "SELF_IP_0001",
    "TRUNK_0001", "GTM_REGION_0001",
])
def test_placeholder_not_flagged_as_leak(placeholder):
    sanitized = f"x /Common/{placeholder} y\n"
    report = scan_leaks(sanitized)
    bw = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD
        and lk.token == placeholder
    ]
    assert bw == []


def test_net_interface_still_unknown():
    """``net interface`` lacks a /partition prefix — deferred."""
    src = "net interface 1.1 {\n    media-fixed\n}\n"
    _, diag = scan(src)
    assert diag.unknown_top_level != []


def test_gtm_topology_still_unknown():
    """``gtm topology`` has no path — deferred."""
    src = "gtm topology {\n    records {\n    }\n}\n"
    _, diag = scan(src)
    assert diag.unknown_top_level != []


def test_realistic_l3_config_round_trip():
    src = (
        "net trunk /Common/customer_trunk {\n"
        "    lacp enabled\n"
        "}\n"
        "net vlan /Common/customer_vlan {\n"
        "    tag 100\n"
        "}\n"
        "net route-domain /Common/customer_rd {\n"
        "    id 1\n"
        "}\n"
        "net self /Common/customer_self {\n"
        "    address 10.0.0.1/24\n"
        "    vlan /Common/customer_vlan\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unknown_top_level == []
    assert "customer_" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
