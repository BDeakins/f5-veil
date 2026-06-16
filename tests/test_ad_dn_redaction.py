"""v0.0.13 — LDAP / AD distinguished-name redaction.

Pass-1.9 (``ad_dn_discovery``) scans every QSTRING in the source for
``CN=...,DC=...`` substrings and interns each unique DN as
``Kind.AD_GROUP_DN``. Pass-2 substring-substitutes AD_GROUP_DN entries
inside every QSTRING globally — both inside ``ltm rule`` bodies (where
v0.0.12 already runs the full substring map) and outside (where prior
to v0.0.13 the QSTRING passed through verbatim with only the
``qstring_contains_identifier`` diagnostic firing).

Two real-world shapes from the EXAMPLE_CORPUS corpus drive the tests:

- ``auth remote-role role-info /Common/<name> { attribute "memberOf=CN=
  Group,OU=...,DC=corp,DC=example,DC=com" ... }`` — bare DN inside a
  ``memberOf=`` attribute QSTRING.
- ``apm policy access-policy /Common/<name> { ... expression "expr {[
  string tolower \\"CN=Group,DC=corp,DC=example,DC=com\\"]} ..." ... }``
  — DN embedded in a Tcl-shaped policy expression QSTRING.
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single-source shape: ``auth remote-role attribute`` ----------


def test_ad_dn_inside_attribute_qstring_redacted():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        '            attribute "memberOf=CN=F5_Admins,OU=Groups,DC=corp,DC=example,DC=com"\n'
        "            role administrator\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    # Customer-identifying domain components must not survive.
    assert "corp" not in sanitized or "DC=corp" not in sanitized
    assert "F5_Admins,OU=Groups,DC=corp,DC=example,DC=com" not in sanitized
    assert "AD_GROUP_DN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multi-source dedup ----------


def test_identical_dn_in_two_qstrings_dedupes_to_single_placeholder():
    """The same DN appearing in two separate QSTRINGs (e.g. an
    ``auth remote-role attribute`` field and an APM policy expression)
    interns once and substitutes both sites to the same placeholder."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        '            attribute "memberOf=CN=F5_Admins,DC=corp,DC=example,DC=com"\n'
        "        }\n"
        "    }\n"
        "}\n"
        "apm policy access-policy /Common/p1 {\n"
        '    expression "test \\"CN=F5_Admins,DC=corp,DC=example,DC=com\\" end"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert sanitized.count("AD_GROUP_DN_0001") == 2
    assert "AD_GROUP_DN_0002" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple distinct DNs ----------


def test_multiple_distinct_dns_get_distinct_placeholders():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/Admins {\n"
        '            attribute "memberOf=CN=Admins,DC=corp,DC=example,DC=com"\n'
        "        }\n"
        "        /Common/Guests {\n"
        '            attribute "memberOf=CN=Guests,DC=corp,DC=example,DC=com"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "AD_GROUP_DN_0001" in sanitized
    assert "AD_GROUP_DN_0002" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- APM access-policy expression shape ----------


def test_ad_dn_inside_apm_expression_qstring_redacted():
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    expression "expr {[string tolower [mcget {session.ad.last.attr.memberOf}]] contains [string tolower \\"CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com\\"]}"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "CN=Domain Admins" not in sanitized
    assert "DC=corp" not in sanitized
    assert "AD_GROUP_DN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- iRule body integration ----------


def test_ad_dn_inside_irule_body_qstring_redacted():
    """v0.0.12's iRule-body substring substitution and v0.0.13's AD DN
    handling co-exist — when an iRule QSTRING happens to contain a DN,
    the DN is substituted via the iRule's full map (which now includes
    AD_GROUP_DN entries)."""
    src = (
        "ltm rule /Common/r1 {\n"
        '    log local0. "matched CN=Admins,DC=corp,DC=example,DC=com"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "CN=Admins" not in sanitized
    assert "AD_GROUP_DN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- DN-shape regex behaviour ----------


def test_partial_dn_without_dc_does_not_qualify():
    """A single-RDN string like ``CN=foo`` lacks the customer-identifying
    domain component and must NOT qualify as an AD DN (false-positive
    guard against random ``key=value`` text)."""
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    expression "CN=foo,OU=stuff"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # No DC= component → not an AD DN → not interned.
    assert not any(
        e.kind == Kind.AD_GROUP_DN for e in ledger.entries.values()
    )
    assert "CN=foo" in sanitized


def test_dn_without_cn_qualifies_v1_2():
    """v1.2 relaxation: OU+DC (no CN=) shapes NOW qualify as an
    AD DN — the OU prefix carries identifying tenant-structure
    information. Pre-v1.2 the QSTRING walker required CN= AND DC=,
    causing leaks like
    ``base "OU=Service Accounts,OU=User Accounts,DC=Foo,DC=local"``
    where the OU prefix passed through verbatim alongside a
    correctly-redacted DC suffix. Now the whole DN is interned and
    substituted as a single placeholder."""
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    expression "OU=Groups,DC=corp,DC=example,DC=com"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (
        Kind.AD_GROUP_DN,
        "OU=Groups,DC=corp,DC=example,DC=com",
    ) in ledger.by_original
    sanitized, _ = substitute(src, ledger, diag)
    assert "OU=Groups" not in sanitized
    assert "DC=corp" not in sanitized


def test_dn_with_lowercase_cn_qualifies():
    """RFC 4514 allows arbitrary case on attribute names. ``cn=`` and
    ``dc=`` lowercase forms (as seen in the EXAMPLE_CORPUS corpus's
    ``memberOF=cn=domain admins,CN=Users,DC=Example,DC=local``) must be
    recognised."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/x {\n"
        '            attribute "memberOF=cn=domain admins,CN=Users,DC=example,DC=local"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "AD_GROUP_DN_0001" in sanitized
    assert "cn=domain admins" not in sanitized.lower() or "cn=AD_GROUP_DN" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- description QSTRINGs containing DNs are NOT interned twice ----------


def test_dn_inside_description_not_interned_as_ad_group_dn():
    """Pass-1.7 interns descriptions as DESC; pass-1.9 must skip DESC
    QSTRINGs to avoid orphan AD_GROUP_DN entries."""
    src = (
        'ltm pool /Common/p1 {\n'
        '    description "uses group CN=Admins,DC=corp,DC=example,DC=com"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    # No AD_GROUP_DN entry should exist — the description QSTRING is
    # covered by DESC redaction.
    assert not any(
        e.kind == Kind.AD_GROUP_DN for e in ledger.entries.values()
    )
    sanitized, diag = substitute(src, ledger, diag)
    # No orphan diagnostic — the DESC entry IS referenced.
    assert diag.orphan_entries == []
    # Description body redacted to DESC placeholder; DN inside it is gone.
    assert "CN=Admins" not in sanitized
    assert '"DESC_0001"' in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- diagnostic suppression ----------


def test_qstring_with_only_ad_dn_does_not_fire_diagnostic():
    """A QSTRING whose only ledger-original substring is an AD DN must
    NOT fire ``qstring_contains_identifier`` — v0.0.13 substitutes it,
    so the "not handled" diagnostic would be a noise regression."""
    src = (
        "apm policy access-policy /Common/p1 {\n"
        '    expression "compare CN=Admins,DC=corp,DC=example,DC=com here"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    assert diag.qstring_contains_identifier == []
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector recognises the new placeholder ----------


def test_leak_detector_does_not_flag_ad_group_dn_placeholder():
    from veil.leak_detector import scan_leaks
    sanitized = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/x {\n"
        '            attribute "memberOf=AD_GROUP_DN_0001"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    report = scan_leaks(sanitized)
    assert all(
        "AD_GROUP_DN_0001" not in lk.token for lk in report.leaks
    ), [lk for lk in report.leaks if "AD_GROUP_DN" in lk.token]


# ---------- ledger invariants ----------


def test_ad_dn_entry_has_no_partition():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/x {\n"
        '            attribute "memberOf=CN=Admins,DC=corp,DC=example,DC=com"\n'
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    entries = [
        e for e in ledger.entries.values() if e.kind == Kind.AD_GROUP_DN
    ]
    assert len(entries) == 1
    assert entries[0].partition is None
    assert entries[0].placeholder == "AD_GROUP_DN_0001"


def test_no_dn_anywhere_no_ad_group_dn_entries():
    src = (
        "ltm pool /Common/p1 {\n"
        "}\n"
        "ltm rule /Common/r1 {\n"
        '    log local0. "no dn here"\n'
        "}\n"
    )
    ledger, _ = scan(src)
    assert not any(
        e.kind == Kind.AD_GROUP_DN for e in ledger.entries.values()
    )
