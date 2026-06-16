"""v1.2 Phase 2h — Monitor recv field walker."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_recv_qstring_redacted():
    src = (
        "ltm monitor http /Common/m {\n"
        '    recv "Welcome to Acme Web Portal"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.MONITOR_RECV, "Welcome to Acme Web Portal") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Welcome to Acme Web Portal" not in sanitized
    assert "MONITOR_RECV_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_recv_bareword_redacted():
    src = (
        "ltm monitor http /Common/m {\n"
        '    recv MainMenu\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.MONITOR_RECV, "MainMenu") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_recv_none_skipped():
    src = (
        "ltm monitor http /Common/m {\n"
        "    recv none\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    hits = [e for e in ledger.entries.values() if e.kind == Kind.MONITOR_RECV]
    assert hits == []


def test_recv_disable_not_caught():
    """``recv-disable`` is a DIFFERENT field with the same prefix —
    must not be confused with ``recv``."""
    src = (
        "ltm monitor http /Common/m {\n"
        "    recv-disable enabled\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    hits = [e for e in ledger.entries.values() if e.kind == Kind.MONITOR_RECV]
    assert hits == []


def test_multiple_monitors_distinct_recv():
    src = (
        "ltm monitor http /Common/m1 {\n"
        '    recv "Service One"\n'
        "}\n"
        "ltm monitor http /Common/m2 {\n"
        '    recv "Service Two"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    for v in ("Service One", "Service Two"):
        assert (Kind.MONITOR_RECV, v) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("Service One", "Service Two"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_same_recv_shared_placeholder():
    src = (
        "ltm monitor http /Common/m1 {\n"
        '    recv "200 OK"\n'
        "}\n"
        "ltm monitor http /Common/m2 {\n"
        '    recv "200 OK"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.MONITOR_RECV and e.original == "200 OK"
    ]
    assert len(entries) == 1


def test_recv_with_html_redacted():
    src = (
        "ltm monitor http /Common/m {\n"
        '    recv "<title>Acme Console</title>"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.MONITOR_RECV, "<title>Acme Console</title>") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme Console" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
