"""v1.2 Phase 2e — SAML / OAuth identifier field walker."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- entity-id (URL form) ----------


def test_entity_id_url_redacted():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id https://sp.acme.local/svc\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SAML_ENTITY_ID, "https://sp.acme.local/svc") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "https://sp.acme.local/svc" not in sanitized
    assert "SAML_ENTITY_ID_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- entity-id (URN opaque string) ----------


def test_entity_id_urn_redacted():
    """Non-URL entity-IDs (URNs, opaque strings) that the FQDN walker
    can never catch."""
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id urn:acme:saml:idp\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SAML_ENTITY_ID, "urn:acme:saml:idp") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "urn:acme:saml:idp" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- entity-id (public-TLD URL — FQDN walker skips) ----------


def test_entity_id_public_tld_url_redacted():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id core-prime.acme.com\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SAML_ENTITY_ID, "core-prime.acme.com") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "core-prime.acme.com" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- sso-uri / slo-uri / slo-response-uri ----------


def test_sso_slo_uris_redacted():
    src = (
        "apm aaa saml-idp-connector /Common/idp {\n"
        "    sso-uri https://idp.acme.local/saml/sso\n"
        "    single-logout-uri https://idp.acme.local/saml/slo\n"
        "    single-logout-response-uri https://idp.acme.local/saml/slr\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SAML_SSO_URI, "https://idp.acme.local/saml/sso") in ledger.by_original
    assert (Kind.SAML_SLO_URI, "https://idp.acme.local/saml/slo") in ledger.by_original
    assert (Kind.SAML_SLO_RESPONSE_URI, "https://idp.acme.local/saml/slr") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in (
        "https://idp.acme.local/saml/sso",
        "https://idp.acme.local/saml/slo",
        "https://idp.acme.local/saml/slr",
    ):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- issuer ----------


def test_issuer_redacted():
    src = (
        "apm oauth oauth-provider /Common/op {\n"
        "    issuer https://idp.acme.local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.OAUTH_ISSUER, "https://idp.acme.local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "https://idp.acme.local" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- audience (braced list) ----------


def test_audience_braced_list_redacted():
    src = (
        "apm oauth oauth-provider /Common/op {\n"
        "    audience { https://aud1.acme.local https://aud2.acme.local }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.OAUTH_AUDIENCE, "https://aud1.acme.local") in ledger.by_original
    assert (Kind.OAUTH_AUDIENCE, "https://aud2.acme.local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("https://aud1.acme.local", "https://aud2.acme.local"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- audience (bareword fallback) ----------


def test_audience_bareword_fallback_redacted():
    """Some configs use ``audience <single-value>`` without braces."""
    src = (
        "apm oauth oauth-provider /Common/op {\n"
        "    audience https://aud.acme.local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.OAUTH_AUDIENCE, "https://aud.acme.local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "https://aud.acme.local" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- double-tokenization with FQDN walker ----------


def test_saml_walker_runs_before_fqdn_full_url_wins():
    """User-approved design: SAML walker interns the full URL; FQDN
    walker may register the inner FQDN separately. At substitute
    time, longest-match-first picks the full-URL placeholder."""
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id https://idp.acme.local/some/path\n"
        "}\n"
    )
    ledger, diag = scan(src)
    # SAML walker registered the full URL.
    assert (Kind.SAML_ENTITY_ID, "https://idp.acme.local/some/path") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    # The full URL was replaced (no leaked sub-path).
    assert "/some/path" not in sanitized
    assert "SAML_ENTITY_ID_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- TMSH literal-keyword values skipped ----------


def test_literal_keyword_values_skipped():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id none\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    saml_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.SAML_ENTITY_ID
    ]
    assert saml_hits == []


# ---------- path-shaped values skipped ----------


def test_path_shaped_values_skipped():
    src = (
        "apm aaa saml-sp-service /Common/sp {\n"
        "    entity-id /Common/some_path\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    saml_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.SAML_ENTITY_ID
    ]
    assert saml_hits == []


# ---------- dedup ----------


def test_same_value_shared_placeholder():
    src = (
        "apm aaa saml-sp-service /Common/sp1 {\n"
        "    entity-id https://shared.acme.local\n"
        "}\n"
        "apm aaa saml-sp-service /Common/sp2 {\n"
        "    entity-id https://shared.acme.local\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.SAML_ENTITY_ID and e.original == "https://shared.acme.local"
    ]
    assert len(entries) == 1
