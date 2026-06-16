"""v1.2 Phase 2a — identity / hostname field walker."""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- admin-name ----------


def test_admin_name_qstring_redacted():
    src = (
        "apm profile connectivity /Common/p {\n"
        '    admin-name "Acme Operator"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "Acme Operator") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme Operator" not in sanitized
    assert "USERNAME_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_admin_name_bareword_redacted():
    src = "apm profile connectivity /Common/p {\n    admin-name svc-admin\n}\n"
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "svc-admin") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "svc-admin" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- basic-auth-username ----------


def test_basic_auth_username_redacted():
    src = "apm aaa http /Common/p {\n    basic-auth-username acmeuser\n}\n"
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "acmeuser") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "acmeuser" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- user (in apm report favorite-report context) ----------


def test_user_field_redacted():
    src = (
        "apm report favorite-report /Common/r {\n"
        "    user blake\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "blake") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "blake" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- account-name ----------


def test_account_name_redacted():
    src = (
        "apm aaa kerberos /Common/k {\n"
        "    account-name svc-bigip\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "svc-bigip") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "svc-bigip" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- server-name (in monitor context) ----------


def test_server_name_redacted():
    src = (
        "ltm monitor https /Common/m {\n"
        "    server-name internal-host\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.USERNAME, "internal-host") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "internal-host" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- TMSH literal keywords skipped ----------


def test_tmsh_literals_skipped():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    admin-name none\n"
        "    basic-auth-username default\n"
        "    user any\n"
        "    server-name auto\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    username_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.USERNAME
    ]
    assert username_entries == []


# ---------- path-shaped values skipped ----------


def test_path_shaped_values_skipped():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    admin-name /Common/some_admin\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    username_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.USERNAME
    ]
    assert username_entries == []


# ---------- multiple field types coexist ----------


def test_multiple_username_fields_coexist():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    admin-name blake_admin\n"
        "    basic-auth-username acme_svc\n"
        "    user end_user_1\n"
        "    account-name ad_svc_account\n"
        "    server-name target.example.com\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for v in (
        "blake_admin", "acme_svc", "end_user_1",
        "ad_svc_account", "target.example.com",
    ):
        assert (Kind.USERNAME, v) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in (
        "blake_admin", "acme_svc", "end_user_1",
        "ad_svc_account", "target.example.com",
    ):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- dedup: same username in two contexts shares placeholder ----------


def test_same_username_shared_placeholder():
    src = (
        "apm profile connectivity /Common/p1 {\n"
        "    admin-name blake\n"
        "}\n"
        "apm profile connectivity /Common/p2 {\n"
        "    user blake\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.USERNAME and e.original == "blake"
    ]
    assert len(entries) == 1


# ---------- leak detector accepts new placeholder ----------


def test_leak_detector_accepts_username_placeholder():
    src = "apm profile connectivity /Common/p {\n    admin-name blake\n}\n"
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "USERNAME_0001" not in leak.token


# ---------- entry fields ----------


def test_username_entry_fields():
    src = "apm profile connectivity /Common/p {\n    admin-name blake\n}\n"
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.USERNAME, "blake")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.USERNAME
