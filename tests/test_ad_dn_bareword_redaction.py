"""v1.2 Phase 2c — extend AD_GROUP_DN walker to field-gated barewords.

The original v0.0.13 walker only scanned inside QSTRINGs. Phase 2c
adds a bareword pass gated to ``base-dn`` / ``search-base-dn`` /
``search-dn`` field names, since LDAP base DNs in TMSH are
commonly written as bareword DC=Foo,DC=local values.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- base-dn bareword ----------


def test_base_dn_bareword_redacted():
    src = (
        "apm aaa ldap /Common/p {\n"
        "    base-dn DC=Acme,DC=local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.AD_GROUP_DN, "DC=Acme,DC=local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "DC=Acme,DC=local" not in sanitized
    assert "AD_GROUP_DN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- search-base-dn bareword ----------


def test_search_base_dn_bareword_redacted():
    src = (
        "apm aaa ldap /Common/p {\n"
        "    search-base-dn OU=Users,DC=Acme,DC=local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.AD_GROUP_DN, "OU=Users,DC=Acme,DC=local") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "OU=Users,DC=Acme,DC=local" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- search-dn bareword ----------


def test_search_dn_bareword_redacted():
    src = (
        "ltm monitor ldap /Common/m {\n"
        "    search-dn DC=Acme,DC=net\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.AD_GROUP_DN, "DC=Acme,DC=net") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "DC=Acme,DC=net" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- bareword DN without CN qualifies (field-name gates) ----------


def test_bareword_dn_without_cn_qualifies():
    """The QSTRING walker requires CN+DC; the bareword walker only
    requires DC because the field-name (``base-dn``) already
    semantically guarantees the value is an LDAP DN."""
    src = (
        "apm aaa ldap /Common/p {\n"
        "    base-dn DC=onlydcs,DC=local\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.AD_GROUP_DN, "DC=onlydcs,DC=local") in ledger.by_original


# ---------- bareword without DC rejected ----------


def test_bareword_without_dc_rejected():
    """A bareword that LOOKS DN-shaped but has no DC= is rejected to
    avoid false positives on random key=value,key=value barewords."""
    src = (
        "apm aaa ldap /Common/p {\n"
        "    base-dn CN=foo,OU=bar\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ad_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.AD_GROUP_DN
    ]
    assert ad_hits == []


# ---------- non-DN bareword rejected ----------


def test_non_dn_bareword_rejected():
    src = (
        "apm aaa ldap /Common/p {\n"
        "    base-dn enabled\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ad_hits = [
        e for e in ledger.entries.values() if e.kind == Kind.AD_GROUP_DN
    ]
    assert ad_hits == []


# ---------- same DN shared between QSTRING and bareword ----------


def test_same_dn_dedup_across_qstring_and_bareword():
    """A DN that appears both inside a QSTRING (with CN+DC qualifier)
    and as a bareword base-dn value should share one placeholder."""
    src = (
        "apm aaa ldap /Common/p {\n"
        "    base-dn DC=acme,DC=local\n"
        '    admin-dn "CN=binder,DC=acme,DC=local"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    # The base-dn (no CN) and the bareword form
    # ``DC=acme,DC=local`` register; the inner DN in the QSTRING
    # registers separately as a CN-qualified form. These are
    # different originals so they each get their own placeholder.
    assert (Kind.AD_GROUP_DN, "DC=acme,DC=local") in ledger.by_original
    assert (Kind.AD_GROUP_DN, "CN=binder,DC=acme,DC=local") in ledger.by_original


# ---------- QSTRING walker still works (regression check) ----------


def test_qstring_walker_still_works():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        '            attribute "memberOf=CN=F5_Admins,DC=acme,DC=local"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    assert (Kind.AD_GROUP_DN, "CN=F5_Admins,DC=acme,DC=local") in ledger.by_original


# ---------- multiple base-dn fields, distinct values ----------


def test_multiple_base_dn_fields_distinct():
    src = (
        "apm aaa ldap /Common/a {\n"
        "    base-dn DC=acme,DC=local\n"
        "}\n"
        "apm aaa ldap /Common/b {\n"
        "    base-dn DC=bogus,DC=corp\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.AD_GROUP_DN, "DC=acme,DC=local") in ledger.by_original
    assert (Kind.AD_GROUP_DN, "DC=bogus,DC=corp") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for v in ("DC=acme", "DC=bogus"):
        assert v not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
