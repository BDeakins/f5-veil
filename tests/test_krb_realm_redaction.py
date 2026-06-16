"""v1.2 Phase 2b — Kerberos realm walker."""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- public-TLD realm redacted ----------


def test_public_tld_realm_redacted():
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm ACME.COM\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.KRB_REALM, "ACME.COM") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "ACME.COM" not in sanitized
    assert "KRB_REALM_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_multi_label_public_realm():
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm ACME.CORP.NET\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.KRB_REALM, "ACME.CORP.NET") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "ACME.CORP.NET" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- internal-suffix realm dedupes with FQDN ----------


def test_internal_realm_already_registered_as_fqdn():
    """``ACME.LOCAL`` matches the FQDN walker's internal-suffix
    allowlist (case-insensitive), so FQDN should register it first.
    The KRB_REALM walker then short-circuits to avoid a duplicate."""
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm ACME.LOCAL\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # FQDN walker is case-insensitive on the suffix — it registers
    # the uppercase value verbatim.
    fqdn_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.FQDN and e.original == "ACME.LOCAL"
    ]
    krb_hits = [
        e for e in ledger.entries.values()
        if e.kind == Kind.KRB_REALM and e.original == "ACME.LOCAL"
    ]
    assert len(fqdn_hits) == 1
    assert len(krb_hits) == 0  # KRB walker short-circuited


# ---------- non-realm-shaped values rejected ----------


def test_lowercase_value_rejected():
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm any\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    krb_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.KRB_REALM
    ]
    assert krb_hits == []


def test_no_dot_value_rejected():
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm ACMECORP\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    krb_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.KRB_REALM
    ]
    assert krb_hits == []


def test_mixed_case_value_rejected():
    """The KRB_REALM walker only catches ALL-UPPERCASE shapes.
    Lowercase/mixed-case realms fall to the FQDN walker if their
    suffix is internal, or pass through otherwise."""
    src = (
        "apm sso kerberos /Common/sso {\n"
        "    realm Acme.Com\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    krb_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.KRB_REALM
    ]
    assert krb_hits == []


# ---------- multiple realms ----------


def test_multiple_realms_distinct_placeholders():
    src = (
        "apm sso kerberos /Common/sso_a {\n"
        "    realm ACME.COM\n"
        "}\n"
        "apm sso kerberos /Common/sso_b {\n"
        "    realm BOGUS.NET\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.KRB_REALM, "ACME.COM") in ledger.by_original
    assert (Kind.KRB_REALM, "BOGUS.NET") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("ACME.COM", "BOGUS.NET"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- same realm shared across two contexts ----------


def test_same_realm_shared_placeholder():
    src = (
        "apm sso kerberos /Common/a {\n"
        "    realm ACME.COM\n"
        "}\n"
        "apm aaa kerberos /Common/b {\n"
        "    realm ACME.COM\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.KRB_REALM and e.original == "ACME.COM"
    ]
    assert len(entries) == 1


# ---------- entry fields ----------


def test_krb_realm_entry_fields():
    src = "apm sso kerberos /Common/a {\n    realm ACME.COM\n}\n"
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.KRB_REALM, "ACME.COM")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.KRB_REALM
