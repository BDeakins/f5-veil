"""Tests for APM + security firewall kinds (v0.0.9)."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- APM --------------------------------------------------------------


def test_apm_policy_registered():
    src = (
        "apm policy access-policy /Common/customer_apm_policy {\n"
        "    default-ending-deny none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_POLICY, "/Common/customer_apm_policy") in ledger.by_original
    assert diag.unknown_top_level == []


def test_apm_policy_customization_source_registered():
    """``apm policy customization-source`` is the same kind as
    access-policy — both feed Kind.APM_POLICY (subtype-agnostic)."""
    src = (
        "apm policy customization-source /Common/customer_cust {\n}\n"
    )
    ledger, _ = scan(src)
    assert (Kind.APM_POLICY, "/Common/customer_cust") in ledger.by_original


def test_apm_profile_access_registered():
    src = (
        "apm profile access /Common/customer_apm_access {\n"
        "    access-policy /Common/customer_apm_policy\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_PROFILE, "/Common/customer_apm_access") in ledger.by_original
    assert diag.unknown_top_level == []


def test_apm_policy_round_trip():
    src = (
        "apm policy access-policy /Common/customer_apm_policy {\n"
        "    default-ending-deny none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_apm_policy" not in sanitized
    assert "/Common/APM_POLICY_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- security firewall -----------------------------------------------


@pytest.mark.parametrize("subtype,kind,placeholder", [
    ("policy", Kind.FIREWALL_POLICY, "FIREWALL_POLICY_0001"),
    ("rule-list", Kind.FIREWALL_RULE_LIST, "FIREWALL_RULE_LIST_0001"),
    ("address-list", Kind.FIREWALL_ADDRESS_LIST, "FIREWALL_ADDRESS_LIST_0001"),
    ("port-list", Kind.FIREWALL_PORT_LIST, "FIREWALL_PORT_LIST_0001"),
])
def test_firewall_subtype_round_trip(subtype, kind, placeholder):
    src = (
        f"security firewall {subtype} /Common/customer_fw_obj {{\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (kind, "/Common/customer_fw_obj") in ledger.by_original
    assert diag.unknown_top_level == []
    sanitized, _ = substitute(src, ledger, diag)
    assert "customer_fw_obj" not in sanitized
    assert f"/Common/{placeholder}" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- deferred shapes still unknown -----------------------------------


def test_security_dos_still_unknown():
    """``security dos profile`` is NOT in v0.0.9 scope — deferred."""
    src = "security dos profile /Common/x {\n}\n"
    _, diag = scan(src)
    assert diag.unknown_top_level != []


def test_apm_aaa_still_unknown():
    """``apm aaa ldap`` is NOT in v0.0.9 scope — deferred."""
    src = "apm aaa ldap /Common/x {\n}\n"
    _, diag = scan(src)
    assert diag.unknown_top_level != []


# ----- placeholder exemption from leak detector ------------------------


@pytest.mark.parametrize("placeholder", [
    "APM_POLICY_0001", "APM_PROFILE_0001",
    "FIREWALL_POLICY_0001", "FIREWALL_RULE_LIST_0001",
    "FIREWALL_ADDRESS_LIST_0001", "FIREWALL_PORT_LIST_0001",
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


# ----- combined config -------------------------------------------------


def test_combined_apm_firewall_clean():
    src = (
        "security firewall address-list /Common/customer_addrs {\n"
        "    addresses {\n"
        "        10.0.0.0/24 { }\n"
        "    }\n"
        "}\n"
        "security firewall policy /Common/customer_fwp {\n"
        "    rules {\n"
        "    }\n"
        "}\n"
        "apm policy access-policy /Common/customer_apm {\n"
        "}\n"
        "apm profile access /Common/customer_apm_access {\n"
        "    access-policy /Common/customer_apm\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unknown_top_level == []
    assert "customer_" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
