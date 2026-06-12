"""Tests for Kind.PROFILE — LTM profile object recognition + built-in
exemption + round-trip."""

from __future__ import annotations

import pytest

from veil.leak_detector import LeakKind, scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- custom profile registration -------------------------------------


def test_custom_http_profile_interned():
    src = (
        "ltm profile http /Common/my_custom_http_profile {\n"
        "    insert-xforwarded-for enabled\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PROFILE, "/Common/my_custom_http_profile") in ledger.by_original
    # And no unknown_top_level since profile is now a recognized header.
    assert diag.unknown_top_level == []


def test_custom_profile_substituted_in_pass2():
    src = (
        "ltm profile http /Common/my_custom_http_profile {\n"
        "    insert-xforwarded-for enabled\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "my_custom_http_profile" not in sanitized
    assert "/Common/PROFILE_0001" in sanitized


def test_custom_profile_round_trip():
    src = (
        "ltm profile http /Common/my_custom_http_profile {\n"
        "    insert-xforwarded-for enabled\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_custom_profile_in_non_common_partition_round_trip():
    src = (
        "ltm profile clientssl /Tenant_A/tenant_ssl_profile {\n"
        "    options-list { dont-insert-empty-fragments }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Header path renders as /PARTITION_NNNN/PROFILE_NNNN. Body cert
    # references are a separate concern (CERT_NNNN kind is future work).
    assert "/Tenant_A/tenant_ssl_profile" not in sanitized
    assert "/PARTITION_0001/PROFILE_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- built-in profile exemption --------------------------------------


@pytest.mark.parametrize("builtin", [
    "http", "http2", "tcp", "udp", "fastL4", "fasthttp",
    "clientssl", "serverssl", "oneconnect", "dns", "sip",
])
def test_builtin_profiles_not_interned(builtin):
    src = (
        f"ltm profile {builtin} /Common/{builtin} {{\n"
        "    defaults-from none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PROFILE, f"/Common/{builtin}") not in ledger.by_original
    assert diag.unknown_top_level == [], (
        f"built-in {builtin} should be consumed, not flagged as unknown"
    )


def test_builtin_profile_passes_through_sanitized():
    src = (
        "ltm profile http /Common/http {\n"
        "    defaults-from none\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "/Common/http" in sanitized  # untouched
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_hyphenated_builtin_profile_exempt():
    # ``clientssl-insecure-compatible`` is a factory variant — exempt.
    src = (
        "ltm profile clientssl /Common/clientssl-insecure-compatible {\n"
        "    defaults-from /Common/clientssl\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PROFILE, "/Common/clientssl-insecure-compatible") not in ledger.by_original


def test_non_common_partition_builtin_NOT_exempt():
    """A profile named exactly ``http`` but living in a tenant partition
    is NOT the factory built-in — could be a customer-created override.
    Must be interned."""
    src = (
        "ltm profile http /Tenant_A/http {\n"
        "    defaults-from /Common/http\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PROFILE, "/Tenant_A/http") in ledger.by_original


# ----- realistic config combining profiles + virtuals ------------------


def test_virtual_referencing_builtin_and_custom_profile():
    src = (
        "ltm profile http /Common/my_custom_http {\n"
        "    insert-xforwarded-for enabled\n"
        "}\n"
        "ltm virtual /Common/vs1 {\n"
        "    destination /Common/vs1_addr:80\n"
        "    profiles {\n"
        "        /Common/tcp { }\n"
        "        /Common/my_custom_http { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/tcp" in sanitized  # built-in survives
    assert "my_custom_http" not in sanitized  # custom redacted
    assert "/Common/PROFILE_0001" in sanitized
    # Round-trip exact.
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_no_unknown_top_level_for_profile_blocks():
    """v0.0.5 win: a config of pure profile definitions obfuscates
    clean without --allow-incomplete."""
    src = (
        "ltm profile http /Common/custom_http {\n"
        "}\n"
        "ltm profile tcp /Common/custom_tcp {\n"
        "}\n"
        "ltm profile clientssl /Common/custom_ssl {\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.unknown_top_level == []
    assert diag.malformed_paths == []
    assert diag.unredacted_description == []


# ----- leak detector interaction ---------------------------------------


def test_placeholder_profile_not_flagged_as_leak():
    src = "ltm profile http /Common/custom_http {\n}\n"
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    bw = [
        lk for lk in report.leaks
        if lk.kind == LeakKind.IDENTIFIER_BAREWORD
        and lk.token == "PROFILE_0001"
    ]
    assert bw == [], (
        f"PROFILE_NNNN should be exempt from bareword leak detection"
    )


def test_hyphenated_builtin_profile_path_not_flagged():
    """Sanitized output containing ``/Common/clientssl-insecure-compatible``
    should NOT trigger the bareword path-segment leak detector — it's
    a known TMOS factory name."""
    src = (
        "ltm virtual /Common/vs1 {\n"
        "    profiles {\n"
        "        /Common/clientssl-insecure-compatible { }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    bw_or_path = [
        lk for lk in report.leaks
        if "clientssl-insecure-compatible" in lk.token
    ]
    assert bw_or_path == [], (
        f"hyphenated built-in profile name flagged as leak: {bw_or_path}"
    )
