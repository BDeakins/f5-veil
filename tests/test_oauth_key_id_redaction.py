"""v1.2 Phase 2f — OAuth key-id field walker (folded into SAML/OAuth)."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


def test_key_id_bareword_redacted():
    src = (
        "apm oauth jwk-config /Common/jwk {\n"
        "    key-id argo_acme_local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.OAUTH_KEY_ID, "argo_acme_local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "argo_acme_local" not in sanitized
    assert "OAUTH_KEY_ID_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_key_id_qstring_redacted():
    src = (
        "apm oauth jwk-config /Common/jwk {\n"
        '    key-id "compound key id"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.OAUTH_KEY_ID, "compound key id") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_same_key_id_shared_across_jwk_blocks():
    """Real configs use the same key-id across jwk-config and
    jwt-config blocks referencing the same key. Dedup yields one
    placeholder."""
    src = (
        "apm oauth jwk-config /Common/jwk_a {\n"
        "    key-id shared_key_acme_local\n"
        "}\n"
        "apm oauth jwk-config /Common/jwk_b {\n"
        "    key-id shared_key_acme_local\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.OAUTH_KEY_ID and e.original == "shared_key_acme_local"
    ]
    assert len(entries) == 1


def test_key_id_literal_keyword_skipped():
    src = (
        "apm oauth jwk-config /Common/jwk {\n"
        "    key-id none\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    hits = [e for e in ledger.entries.values() if e.kind == Kind.OAUTH_KEY_ID]
    assert hits == []
