"""v1.2 (post-Phase-4) — APM variable-assign expression literal walker.

User-found leak: ``apm policy agent variable-assign`` blocks have
``expression "return {LITERAL}"`` constructs where LITERAL is a
hard-coded value being assigned to a session variable. Real-corpus
examples include AD domain names, usernames, and (alarmingly)
plaintext passwords — F5's ``secure true`` flag does NOT actually
encrypt these source-config literals.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_return_domain_literal_redacted():
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return {acme}"\n'
        "            varname session.logon.last.domain\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_VAR_LITERAL, "acme") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "{acme}" not in sanitized
    assert "APM_VAR_LITERAL_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_return_username_literal_redacted():
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return {admin}"\n'
        "            varname session.custom.cygnus.webui.userid\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_VAR_LITERAL, "admin") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_return_password_literal_redacted():
    """The most important case: plaintext passwords embedded in
    expression literals."""
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        "    variables {\n"
        "        {\n"
        '            expression "return {Pa$$w0rd!}"\n'
        "            secure true\n"
        "            varname session.custom.pihole.password\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.APM_VAR_LITERAL, "Pa$$w0rd!") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Pa$$w0rd!" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_complex_tcl_expression_not_redacted():
    """Non-``return {LITERAL}`` expressions (complex Tcl manipulating
    session vars) should pass through unchanged — they don't contain
    hard-coded customer literals."""
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        "    variables {\n"
        "        {\n"
        '            expression "expr { [lindex [split [mcget {session.saml.last.identity}] \\"@\\"] 0] }"\n'
        "            varname session.logon.last.logonname\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    apm_hits = [e for e in ledger.entries.values() if e.kind == Kind.APM_VAR_LITERAL]
    assert apm_hits == []


def test_multiple_literals_distinct():
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        "    variables {\n"
        '        { expression "return {acme}" varname session.a }\n'
        '        { expression "return {admin}" varname session.b }\n'
        '        { expression "return {Secret}" varname session.c }\n'
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for v in ("acme", "admin", "Secret"):
        assert (Kind.APM_VAR_LITERAL, v) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("{acme}", "{admin}", "{Secret}"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_same_literal_shared_placeholder():
    src = (
        "apm policy agent variable-assign /Common/v1 {\n"
        "    variables { { expression \"return {acme}\" varname x } }\n"
        "}\n"
        "apm policy agent variable-assign /Common/v2 {\n"
        "    variables { { expression \"return {acme}\" varname y } }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.APM_VAR_LITERAL and e.original == "acme"
    ]
    assert len(entries) == 1


def test_empty_literal_skipped():
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        '    variables { { expression "return {}" varname x } }\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    apm_hits = [e for e in ledger.entries.values() if e.kind == Kind.APM_VAR_LITERAL]
    assert apm_hits == []


def test_entry_fields():
    src = (
        "apm policy agent variable-assign /Common/v {\n"
        '    variables { { expression "return {acme}" varname x } }\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.APM_VAR_LITERAL, "acme")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.APM_VAR_LITERAL
