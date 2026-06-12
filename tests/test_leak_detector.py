"""Unit tests for veil.leak_detector.scan_leaks."""

from __future__ import annotations

import pytest

from veil.leak_detector import (
    Leak,
    LeakKind,
    LeakReport,
    scan_leaks,
)


# ----- empty / no-leak baseline ----------------------------------------


def test_empty_input_yields_empty_report():
    report = scan_leaks("")
    assert isinstance(report, LeakReport)
    assert report.leaks == []
    assert not report
    assert len(report) == 0


def test_clean_obfuscated_output_has_no_leaks():
    s = (
        "ltm pool /Common/POOL_0001 {\n"
        "    members {\n"
        "        /Common/NODE_0001:80 {\n"
        "            address 192.0.2.42\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm virtual /PARTITION_0001/VS_0001 {\n"
        "    destination /PARTITION_0001/198.51.100.5:443\n"
        "    pool /PARTITION_0001/POOL_0002\n"
        "}\n"
    )
    report = scan_leaks(s)
    assert report.leaks == [], (
        f"clean obfuscated output flagged: "
        f"{[(lk.kind, lk.token) for lk in report.leaks]}"
    )


# ----- IPv4 -------------------------------------------------------------


@pytest.mark.parametrize("addr", [
    "10.0.0.1",
    "10.255.255.254",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.0.1",
    "192.168.255.254",
])
def test_rfc1918_ipv4_flagged(addr):
    report = scan_leaks(f"address {addr}\n")
    assert any(
        lk.kind == LeakKind.RFC1918_IPV4 and lk.token == addr
        for lk in report.leaks
    ), report.leaks


def test_cgnat_ipv4_flagged():
    report = scan_leaks("address 100.64.0.5\n")
    assert any(lk.kind == LeakKind.CGNAT_IPV4 for lk in report.leaks)


def test_link_local_ipv4_flagged():
    report = scan_leaks("address 169.254.1.1\n")
    assert any(lk.kind == LeakKind.LINKLOCAL_IPV4 for lk in report.leaks)


def test_loopback_ipv4_flagged():
    report = scan_leaks("address 127.0.0.1\n")
    assert any(lk.kind == LeakKind.LOOPBACK_IPV4 for lk in report.leaks)


@pytest.mark.parametrize("addr", [
    "192.0.2.1", "192.0.2.255",
    "198.51.100.1", "198.51.100.42",
    "203.0.113.1", "203.0.113.255",
])
def test_rfc5737_exempt(addr):
    report = scan_leaks(f"address {addr}\n")
    ip_leaks = [lk for lk in report.leaks if "IPV4" in lk.kind.value]
    assert ip_leaks == [], f"RFC 5737 addr {addr} was flagged: {ip_leaks}"


def test_public_ipv4_not_flagged():
    # 8.8.8.8 is public; the detector flags only private/CGNAT/LL/loopback.
    report = scan_leaks("address 8.8.8.8\n")
    ip_leaks = [lk for lk in report.leaks if "IPV4" in lk.kind.value]
    assert ip_leaks == []


def test_ipv4_reason_label_carries_rfc():
    report = scan_leaks("a 10.1.2.3 b 100.64.5.6 c 169.254.1.1 d 127.0.0.1")
    by_kind = {lk.kind: lk.reason for lk in report.leaks}
    assert "RFC 1918" in by_kind[LeakKind.RFC1918_IPV4]
    assert "RFC 6598" in by_kind[LeakKind.CGNAT_IPV4]
    assert "RFC 3927" in by_kind[LeakKind.LINKLOCAL_IPV4]
    assert "RFC 1122" in by_kind[LeakKind.LOOPBACK_IPV4]


# ----- IPv6 -------------------------------------------------------------


def test_ula_ipv6_flagged():
    report = scan_leaks("address fc00::1\n")
    assert any(lk.kind == LeakKind.ULA_IPV6 for lk in report.leaks)


def test_link_local_ipv6_flagged():
    report = scan_leaks("address fe80::1234\n")
    assert any(lk.kind == LeakKind.LINKLOCAL_IPV6 for lk in report.leaks)


def test_loopback_ipv6_flagged():
    report = scan_leaks("address ::1\n")
    assert any(lk.kind == LeakKind.LOOPBACK_IPV6 for lk in report.leaks)


def test_rfc3849_ipv6_exempt():
    report = scan_leaks("address 2001:db8::1\n")
    v6_leaks = [lk for lk in report.leaks if "IPV6" in lk.kind.value]
    assert v6_leaks == []


# ----- MAC addresses ----------------------------------------------------


def test_mac_colon_separated_flagged():
    report = scan_leaks("mac 00:11:22:33:44:55\n")
    assert any(lk.kind == LeakKind.MAC_ADDRESS for lk in report.leaks)


def test_mac_dash_separated_flagged():
    report = scan_leaks("mac 00-11-22-33-44-55\n")
    assert any(lk.kind == LeakKind.MAC_ADDRESS for lk in report.leaks)


def test_mac_cisco_dotted_flagged():
    report = scan_leaks("mac 0011.2233.4455\n")
    assert any(lk.kind == LeakKind.MAC_ADDRESS for lk in report.leaks)


# ----- internal FQDN suffixes ------------------------------------------


@pytest.mark.parametrize("fqdn,suffix", [
    ("server.local", "local"),
    ("db.corp", "corp"),
    ("host.lan", "lan"),
    ("svc.internal", "internal"),
    ("app.intranet", "intranet"),
    ("router.home.arpa", "home.arpa"),
    ("api.private", "private"),
    ("box.lan.local", "lan.local"),
])
def test_internal_fqdn_suffixes_flagged(fqdn, suffix):
    report = scan_leaks(f"host {fqdn}\n")
    fqdn_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.INTERNAL_FQDN]
    assert any(lk.token == fqdn for lk in fqdn_leaks), (
        f"{fqdn} not flagged. Leaks: {[lk.token for lk in fqdn_leaks]}"
    )
    assert any(suffix in lk.reason for lk in fqdn_leaks)


def test_external_fqdn_not_flagged():
    report = scan_leaks("host www.example.com\n")
    fqdn_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.INTERNAL_FQDN]
    assert fqdn_leaks == []


# ----- paths and placeholders ------------------------------------------


def test_common_partition_path_not_flagged():
    report = scan_leaks("pool /Common/POOL_0001\n")
    path_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.IDENTIFIER_PATH]
    assert path_leaks == []


def test_partition_placeholder_path_not_flagged():
    report = scan_leaks("pool /PARTITION_0001/POOL_0042\n")
    path_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.IDENTIFIER_PATH]
    assert path_leaks == []


def test_non_safe_partition_path_flagged():
    report = scan_leaks("pool /Tenant_A/widget_pool\n")
    path_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.IDENTIFIER_PATH]
    assert any(lk.token == "/Tenant_A/widget_pool" for lk in path_leaks), (
        f"path leak missed. report: {report.leaks}"
    )


# ----- bareword identifier heuristic -----------------------------------


@pytest.mark.parametrize("keyword", [
    "enabled", "disabled", "description", "monitor", "pool", "virtual",
    "members", "destination", "ip-protocol", "Common", "ltm", "gtm",
])
def test_tmsh_keyword_not_flagged(keyword):
    report = scan_leaks(f"    {keyword} foo\n")
    bw_leaks = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD and lk.token == keyword
    ]
    assert bw_leaks == []


@pytest.mark.parametrize("ident", [
    "web01", "prod42", "customer_app", "tenant-a", "db-server-3",
    "my_pool", "app_lb",
])
def test_identifier_shaped_bareword_flagged(ident):
    # Provide enough surrounding context so the regex anchors cleanly.
    report = scan_leaks(f"name {ident} more\n")
    bw_leaks = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD and lk.token == ident
    ]
    assert bw_leaks, (
        f"{ident} not flagged. report: {[lk.token for lk in report.leaks]}"
    )


def test_placeholder_bareword_not_flagged():
    for ph in ["POOL_0001", "VS_0042", "NODE_9999", "PARTITION_0001", "UNK_0017"]:
        report = scan_leaks(f"    {ph}\n")
        bw = [
            lk for lk in report.leaks
            if lk.kind == LeakKind.IDENTIFIER_BAREWORD
        ]
        assert bw == [], f"placeholder {ph} was flagged: {bw}"


def test_plain_word_not_flagged():
    # No digit, no underscore, no hyphen -> too noisy to flag.
    report = scan_leaks("    randomword\n")
    bw = [lk for lk in report.leaks if lk.kind == LeakKind.IDENTIFIER_BAREWORD]
    assert bw == []


# ----- line/col computation --------------------------------------------


def test_line_col_first_line():
    report = scan_leaks("address 10.0.0.1\n")
    leak = next(lk for lk in report.leaks if lk.kind == LeakKind.RFC1918_IPV4)
    assert leak.line == 1
    assert leak.col == len("address ") + 1


def test_line_col_later_line():
    s = "first line\nsecond line\n    address 10.0.0.1\n"
    report = scan_leaks(s)
    leak = next(lk for lk in report.leaks if lk.kind == LeakKind.RFC1918_IPV4)
    assert leak.line == 3
    assert leak.col == len("    address ") + 1


def test_line_col_correct_across_many_lines():
    lines = ["\n"] * 99 + ["address 192.168.1.1\n"]
    s = "".join(lines)
    report = scan_leaks(s)
    leak = next(lk for lk in report.leaks if lk.kind == LeakKind.RFC1918_IPV4)
    assert leak.line == 100
    assert leak.col == len("address ") + 1


# ----- multi-leak ordering and deduping --------------------------------


def test_multiple_leaks_sorted_by_offset():
    s = "address 10.0.0.1\nhost db.corp\naddress fc00::1\n"
    report = scan_leaks(s)
    # Each leak appears strictly after the previous by offset.
    offsets = [lk.byte_offset for lk in report.leaks]
    assert offsets == sorted(offsets)


def test_overlapping_matches_not_double_counted():
    # A MAC and a bareword cannot occupy the exact same span, but ensure
    # an FQDN like server.local isn't ALSO flagged as a bareword token.
    s = "host server.local\n"
    report = scan_leaks(s)
    fqdn = [lk for lk in report.leaks if lk.kind == LeakKind.INTERNAL_FQDN]
    bw_in_fqdn = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD and lk.token in ("server",)
    ]
    assert len(fqdn) == 1
    assert bw_in_fqdn == [], (
        f"bareword inside FQDN span double-flagged: {bw_in_fqdn}"
    )


def test_report_truthiness():
    assert not scan_leaks("")
    assert scan_leaks("address 10.0.0.1\n")


# ----- security: bypass attempts ---------------------------------------


def test_v4_mapped_ipv6_rfc1918_still_caught():
    # ``::ffff:10.0.0.1`` is a v4-mapped IPv6 form of an RFC1918 address.
    # The dotted-quad tail isn't recognised by the IPv6 regex (which uses
    # pure hex), but the IPv4 scanner catches the embedded ``10.0.0.1``
    # via the negative-lookbehind boundary on ``:``. Net effect: the leak
    # is still detected, just labelled as plain RFC1918.
    report = scan_leaks("address ::ffff:10.0.0.1\n")
    assert any(
        lk.kind == LeakKind.RFC1918_IPV4 and lk.token == "10.0.0.1"
        for lk in report.leaks
    ), report.leaks


def test_v4_mapped_ipv6_rfc5737_still_exempt():
    # ``::ffff:192.0.2.1`` wraps a docs-range v4 — exempt as v4.
    report = scan_leaks("address ::ffff:192.0.2.1\n")
    v4_or_v6 = [
        lk for lk in report.leaks
        if "IPV4" in lk.kind.value or "IPV6" in lk.kind.value
    ]
    assert v4_or_v6 == []


def test_sub_folder_under_common_still_flagged():
    # /Common/ is a safe partition prefix but Customer_X is a leaked
    # sub-component the obfuscator should have substituted. Catch it.
    report = scan_leaks("pool /Common/Customer_X/leaf\n")
    path_leaks = [lk for lk in report.leaks if lk.kind == LeakKind.IDENTIFIER_PATH]
    assert any("Customer_X" in lk.token for lk in path_leaks), (
        f"sub-folder leak not caught. report: {report.leaks}"
    )


def test_placeholder_segments_under_safe_partition_not_flagged():
    # /Common/POOL_0001 → safe. /PARTITION_0001/POOL_0001 → safe.
    # /Common/POOL_0001:80 → safe (port suffix).
    for path in [
        "/Common/POOL_0001",
        "/PARTITION_0001/POOL_0001",
        "/Common/NODE_0001:80",
        "/PARTITION_0001/NODE_0001%rd0",
    ]:
        report = scan_leaks(f"x {path}\n")
        path_leaks = [
            lk for lk in report.leaks
            if lk.kind == LeakKind.IDENTIFIER_PATH
        ]
        assert path_leaks == [], (
            f"safe path {path} was flagged: {path_leaks}"
        )


def test_leak_dataclass_is_frozen():
    leak = Leak(
        kind=LeakKind.RFC1918_IPV4,
        token="10.0.0.1",
        byte_offset=0,
        line=1,
        col=1,
        reason="x",
    )
    with pytest.raises((AttributeError, Exception)):
        leak.token = "tampered"  # type: ignore[misc]
