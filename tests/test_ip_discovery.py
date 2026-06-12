"""Unit tests for veil.ip_discovery — pass-1.5 IP literal interning."""

from __future__ import annotations

import ipaddress

import pytest

from veil.diagnostics import Diagnostics
from veil.ip_discovery import (
    _extract_ip_prefix,
    _is_netmask,
    discover_ip_literals,
)
from veil.ledger import Kind, Ledger


def _scan(src: str) -> tuple[Ledger, Diagnostics]:
    ledger = Ledger()
    diag = Diagnostics()
    discover_ip_literals(src, ledger, diag)
    return ledger, diag


# ----- basic interning ---------------------------------------------------


def test_bare_ipv4_interned():
    ledger, _ = _scan("a 10.0.0.42 b\n")
    assert (Kind.IPADDR, "10.0.0.42") in ledger.by_original


def test_ipv4_port_suffix_extracts_address_only():
    ledger, _ = _scan("dest 10.0.0.42:80\n")
    assert (Kind.IPADDR, "10.0.0.42") in ledger.by_original
    # The port suffix is NOT part of the interned original.
    assert (Kind.IPADDR, "10.0.0.42:80") not in ledger.by_original


def test_ipv4_route_domain_extracts_address():
    ledger, _ = _scan("dest 10.0.0.42%rd0\n")
    assert (Kind.IPADDR, "10.0.0.42") in ledger.by_original


def test_ipv4_route_domain_and_port():
    ledger, _ = _scan("dest 10.0.0.42%rd0:80\n")
    assert (Kind.IPADDR, "10.0.0.42") in ledger.by_original


def test_ipv4_cidr_extracts_network_address():
    ledger, _ = _scan("network 10.0.0.0/24\n")
    assert (Kind.IPADDR, "10.0.0.0") in ledger.by_original


def test_ipv6_interned():
    ledger, _ = _scan("a fc00::1 b\n")
    assert (Kind.IPADDR, "fc00::1") in ledger.by_original


def test_ipv6_route_domain():
    ledger, _ = _scan("dest fc00::1%rd0\n")
    assert (Kind.IPADDR, "fc00::1") in ledger.by_original


def test_unique_ip_interned_once():
    ledger, _ = _scan("a 10.0.0.42 b 10.0.0.42 c\n")
    n_ipaddr = sum(
        1 for k, _v in ledger.by_original if k == Kind.IPADDR
    )
    assert n_ipaddr == 1


# ----- wildcard / netmask exemptions ------------------------------------


def test_wildcard_v4_not_interned():
    ledger, _ = _scan("a 0.0.0.0 b\n")
    assert (Kind.IPADDR, "0.0.0.0") not in ledger.by_original


def test_wildcard_v6_not_interned():
    ledger, _ = _scan("a :: b\n")
    assert (Kind.IPADDR, "::") not in ledger.by_original


def test_loopback_v6_IS_interned():
    # ``::1`` is loopback, NOT a wildcard — should be interned and
    # substituted (matches v0.0.2 leak detector behaviour).
    ledger, _ = _scan("a ::1 b\n")
    assert (Kind.IPADDR, "::1") in ledger.by_original


@pytest.mark.parametrize("nm", [
    "255.255.255.0",
    "255.255.0.0",
    "255.0.0.0",
    "255.255.255.255",
    "255.255.255.252",
    "128.0.0.0",
])
def test_netmasks_not_interned(nm):
    ledger, _ = _scan(f"mask {nm}\n")
    assert (Kind.IPADDR, nm) not in ledger.by_original


def test_almost_netmask_IS_interned():
    # 255.255.255.1 is NOT a contiguous-high-bits pattern — IS interned.
    ledger, _ = _scan("address 255.255.255.1\n")
    assert (Kind.IPADDR, "255.255.255.1") in ledger.by_original


# ----- invalid / mid-token rejection ------------------------------------


def test_invalid_ip_octet_out_of_range_ignored():
    ledger, _ = _scan("a 192.168.1.500 b\n")
    assert (Kind.IPADDR, "192.168.1.500") not in ledger.by_original


def test_ip_substring_inside_larger_token_not_extracted():
    # ``host_10.0.0.42_extra`` — IP is mid-token, prefix doesn't match.
    ledger, _ = _scan("name host_10.0.0.42_extra\n")
    assert (Kind.IPADDR, "10.0.0.42") not in ledger.by_original


def test_qstring_content_not_walked():
    # IPs inside QSTRING content are out of scope (qstring tokens, not
    # WORD). Verify the discovery doesn't extract them.
    src = 'description "node at 10.0.0.42"\n'
    ledger, _ = _scan(src)
    assert (Kind.IPADDR, "10.0.0.42") not in ledger.by_original


# ----- _extract_ip_prefix helper unit tests ----------------------------


@pytest.mark.parametrize("token,expected", [
    ("10.0.0.42", "10.0.0.42"),
    ("10.0.0.42:80", "10.0.0.42"),
    ("10.0.0.42%rd0", "10.0.0.42"),
    ("10.0.0.42%rd0:80", "10.0.0.42"),
    ("10.0.0.0/24", "10.0.0.0"),
    ("fc00::1", "fc00::1"),
    ("fc00::1%rd0", "fc00::1"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_extract_prefix_accepts(token, expected):
    assert _extract_ip_prefix(token) == expected


@pytest.mark.parametrize("token", [
    "",
    "not_an_ip",
    "/Common/foo",
    "host10.0.0.42_extra",
    "foo_10.0.0.42",
])
def test_extract_prefix_rejects(token):
    assert _extract_ip_prefix(token) is None


# ----- _is_netmask helper ------------------------------------------------


@pytest.mark.parametrize("addr", [
    "255.255.255.0",
    "255.255.0.0",
    "255.0.0.0",
    "255.255.255.255",
    "0.0.0.0",  # defensively true; wildcard check handles upstream
    "128.0.0.0",
    "255.255.255.128",
])
def test_is_netmask_true(addr):
    assert _is_netmask(ipaddress.IPv4Address(addr))


@pytest.mark.parametrize("addr", [
    "10.0.0.1",
    "192.168.1.5",
    "255.255.255.1",
    "127.0.0.1",
])
def test_is_netmask_false(addr):
    assert not _is_netmask(ipaddress.IPv4Address(addr))


# ----- lifecycle / freeze contract --------------------------------------


def test_discover_raises_after_freeze():
    ledger = Ledger()
    ledger.freeze()
    diag = Diagnostics()
    with pytest.raises(RuntimeError, match="freeze"):
        discover_ip_literals("a 10.0.0.1 b\n", ledger, diag)


def test_collapsed_diagnostic_populated_when_more_than_3_24s():
    src = (
        "a 10.0.0.1\n"
        "b 11.0.0.1\n"
        "c 12.0.0.1\n"
        "d 13.0.0.1\n"
    )
    _, diag = _scan(src)
    assert diag.ipv4_subnet_collapsed, (
        "expected ipv4_subnet_collapsed to flag the 4th source /24"
    )


def test_three_or_fewer_24s_no_collapse():
    src = (
        "a 10.0.0.1\n"
        "b 11.0.0.1\n"
        "c 12.0.0.1\n"
    )
    _, diag = _scan(src)
    assert diag.ipv4_subnet_collapsed == []
