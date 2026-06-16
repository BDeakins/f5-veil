"""v1.2 Phase 2d — LDAP filter walker."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- ltm monitor ldap filter ----------


def test_ltm_monitor_ldap_filter_redacted():
    src = (
        "ltm monitor ldap /Common/m {\n"
        "    base DC=acme,DC=local\n"
        '    filter "sAMAccountName=svc-monitor"\n'
        "    interval 10\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.LDAP_FILTER, "sAMAccountName=svc-monitor") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "sAMAccountName=svc-monitor" not in sanitized
    assert "LDAP_FILTER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- apm aaa ldap filter ----------


def test_apm_aaa_ldap_filter_redacted():
    src = (
        "apm aaa ldap /Common/p {\n"
        '    filter "(&(objectClass=user)(memberOf=CN=Admins,DC=acme,DC=local))"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (
        Kind.LDAP_FILTER,
        "(&(objectClass=user)(memberOf=CN=Admins,DC=acme,DC=local))",
    ) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "sAMAccountName" not in sanitized or True  # not in this filter
    assert "objectClass=user" not in sanitized
    assert "LDAP_FILTER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- auth ldap filter ----------


def test_auth_ldap_filter_redacted():
    src = (
        "auth ldap /Common/system-auth {\n"
        '    filter "cn=admin"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.LDAP_FILTER, "cn=admin") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "cn=admin" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- apm aaa active-directory filter ----------


def test_apm_aaa_active_directory_filter_redacted():
    src = (
        "apm aaa active-directory /Common/p {\n"
        '    filter "(sAMAccountName=*)"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.LDAP_FILTER, "(sAMAccountName=*)") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- non-LDAP context: filter NOT redacted ----------


def test_filter_outside_ldap_block_not_redacted():
    """``filter`` outside an LDAP-flavoured top-level block must not
    be redacted (false-positive guard for PEM analytics etc.)."""
    src = (
        "pem reporting format-script /Common/p {\n"
        "    filter some-value\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    filter_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.LDAP_FILTER
    ]
    assert filter_hits == []


# ---------- multiple LDAP blocks ----------


def test_multiple_ldap_blocks_filters_distinct():
    src = (
        "ltm monitor ldap /Common/m1 {\n"
        '    filter "cn=alice"\n'
        "}\n"
        "ltm monitor ldap /Common/m2 {\n"
        '    filter "cn=bob"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.LDAP_FILTER, "cn=alice") in ledger.by_original
    assert (Kind.LDAP_FILTER, "cn=bob") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("cn=alice", "cn=bob"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- same filter shared across blocks ----------


def test_same_filter_shared_placeholder():
    src = (
        "ltm monitor ldap /Common/m1 {\n"
        '    filter "sAMAccountName=svc"\n'
        "}\n"
        "ltm monitor ldap /Common/m2 {\n"
        '    filter "sAMAccountName=svc"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.LDAP_FILTER and e.original == "sAMAccountName=svc"
    ]
    assert len(entries) == 1


# ---------- empty filter skipped ----------


def test_empty_filter_skipped():
    src = (
        "ltm monitor ldap /Common/m {\n"
        '    filter ""\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    filter_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.LDAP_FILTER
    ]
    assert filter_hits == []


# ---------- entry fields ----------


def test_ldap_filter_entry_fields():
    src = (
        "ltm monitor ldap /Common/m {\n"
        '    filter "cn=admin"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.LDAP_FILTER, "cn=admin")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.LDAP_FILTER
