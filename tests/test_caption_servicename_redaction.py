"""v1.2 Phase 2g — extend DESC walker to caption + service-name."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- caption ----------


def test_caption_qstring_redacted():
    src = (
        "apm policy customization-group /Common/c {\n"
        '    caption "Acme Login Portal"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DESC, '"Acme Login Portal"') in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme Login Portal" not in sanitized
    assert "DESC_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_caption_bareword_redacted():
    src = (
        "apm policy customization-group /Common/c {\n"
        "    caption Welcome\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DESC, "Welcome") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- service-name ----------


def test_service_name_qstring_redacted():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        '    service-name "Acme Universal ACS"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DESC, '"Acme Universal ACS"') in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme Universal ACS" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_service_name_bareword_redacted():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    service-name MainSP\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.DESC, "MainSP") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- description still works (regression) ----------


def test_description_still_works():
    src = (
        "ltm pool /Common/p {\n"
        '    description "Acme primary node"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    assert (Kind.DESC, '"Acme primary node"') in ledger.by_original


# ---------- all three coexist ----------


def test_all_three_desc_fields_coexist():
    src = (
        "apm policy customization-group /Common/g {\n"
        '    description "general description"\n'
        '    caption "user-facing caption"\n'
        '    service-name "ACS service name"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    for v in (
        '"general description"',
        '"user-facing caption"',
        '"ACS service name"',
    ):
        assert (Kind.DESC, v) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("general description", "user-facing caption", "ACS service name"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
