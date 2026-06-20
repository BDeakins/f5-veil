"""v1.2.1 T3A — AD query-attrname non-standard attribute redaction.

Red-team finding: phase4c ``bigip.conf:7804`` —
``query-attrname { ... homeMDB ... msDS-ResultantPSO
extensionAttribute1 ... }``. Non-standard AD attrs fingerprint
directory schema and on-prem Exchange presence. The existing
``ldap_filter_discovery`` walker handles ``filter`` values inside
LDAP blocks but doesn't descend into ``query-attrname`` lists.

Walker scope:
- Context gate: LDAP-flavoured top-level block headers (same
  allowlist as ``ldap_filter_discovery``).
- Field gate: ``query-attrname { ... }`` braced bareword list at
  any depth inside the block.
- Allowlist: standard AD schema attrs (case-insensitive).
- Length floor: 4 chars (substring-sub over-fire protection).
"""

from __future__ import annotations

from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ----- standard AD attrs pass through verbatim ----------------------------


def test_standard_attrs_passthrough():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        sAMAccountName\n"
        "        mail\n"
        "        memberOf\n"
        "        userPrincipalName\n"
        "        displayName\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "sAMAccountName" in sanitized
    assert "mail" in sanitized
    assert "memberOf" in sanitized
    assert "userPrincipalName" in sanitized
    assert "displayName" in sanitized
    assert "AD_ATTR_" not in sanitized


def test_standard_attrs_case_insensitive_allowlist():
    # Real configs sometimes use lowercase or pascal-case for standard
    # attr names. LDAP is case-insensitive — allowlist match must be
    # too.
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        samaccountname\n"
        "        MAIL\n"
        "        MemberOf\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "samaccountname" in sanitized
    assert "MAIL" in sanitized
    assert "MemberOf" in sanitized
    assert "AD_ATTR_" not in sanitized


# ----- non-standard AD attrs are tokenized -------------------------------


def test_homemdb_exchange_attr_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "homeMDB" not in sanitized
    assert "AD_ATTR_0001" in sanitized


def test_msds_resultantpso_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        msDS-ResultantPSO\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "msDS-ResultantPSO" not in sanitized
    assert "AD_ATTR_0001" in sanitized


def test_extension_attribute_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        extensionAttribute1\n"
        "        extensionAttribute7\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "extensionAttribute1" not in sanitized
    assert "extensionAttribute7" not in sanitized
    assert "AD_ATTR_0001" in sanitized
    assert "AD_ATTR_0002" in sanitized


# ----- mixed list: standard pass-through + non-standard redacted ----------


def test_mixed_list_only_nonstandard_redacted():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        sAMAccountName\n"
        "        mail\n"
        "        homeMDB\n"
        "        memberOf\n"
        "        msDS-ResultantPSO\n"
        "        extensionAttribute1\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Standard attrs untouched.
    assert "sAMAccountName" in sanitized
    assert "mail" in sanitized
    assert "memberOf" in sanitized
    # Non-standard attrs redacted.
    assert "homeMDB" not in sanitized
    assert "msDS-ResultantPSO" not in sanitized
    assert "extensionAttribute1" not in sanitized
    assert "AD_ATTR_0001" in sanitized
    assert "AD_ATTR_0002" in sanitized
    assert "AD_ATTR_0003" in sanitized


# ----- short attr floor: skip <4 chars even if non-standard --------------


def test_short_attr_below_floor_passthrough():
    # ``pw`` and ``upn`` aren't in the allowlist BUT are <4 chars;
    # substring-sub would over-fire globally. Walker skips them.
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        pw\n"
        "        upn\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "pw" in sanitized
    assert "upn" in sanitized
    assert "AD_ATTR_" not in sanitized


# ----- context gate: only fires inside LDAP-flavoured blocks --------------


def test_no_redaction_outside_ldap_context():
    # ``query-attrname`` outside an LDAP-flavoured block — e.g.
    # inside an unrelated body — should not trigger the walker.
    # This is defensive: TMSH doesn't actually use the field outside
    # LDAP blocks, but the context gate is the safety belt.
    src = (
        "ltm pool /Common/pool1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # homeMDB is NOT tokenized — context gate kept the walker out.
    assert "homeMDB" in sanitized
    assert "AD_ATTR_" not in sanitized


# ----- multiple LDAP blocks: independent walks, shared ledger -------------


def test_multiple_ldap_blocks_share_ledger():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
        "apm aaa active-directory /Common/ad2 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "        msDS-ResultantPSO\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Same ``homeMDB`` interns once across blocks; second block adds
    # only ``msDS-ResultantPSO``.
    assert "homeMDB" not in sanitized
    assert "msDS-ResultantPSO" not in sanitized
    assert "AD_ATTR_0001" in sanitized
    assert "AD_ATTR_0002" in sanitized
    # Counters reflect only 2 distinct entries.
    assert ledger.counters.get(Kind.AD_ATTR, 0) == 2


# ----- other LDAP-flavoured headers also gate the walker -----------------


def test_auth_active_directory_header_gates():
    src = (
        "auth active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "homeMDB" not in sanitized
    assert "AD_ATTR_0001" in sanitized


def test_apm_aaa_ldap_header_gates():
    src = (
        "apm aaa ldap /Common/ldap1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "homeMDB" not in sanitized
    assert "AD_ATTR_0001" in sanitized


def test_apm_policy_agent_aaa_ad_inline_list():
    # Real-corpus shape: 4-word header, inline single-line braced list.
    # phase4c bigip.conf:7804 surfaced this form, which the initial
    # 3-word allowlist missed.
    src = (
        "apm policy agent aaa-active-directory /Common/query_ag_1 {\n"
        "    query-attrname { objectClass cn displayName homeMDB mail "
        "memberOf msDS-ResultantPSO sAMAccountName }\n"
        "    type query\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    assert "homeMDB" not in sanitized
    assert "msDS-ResultantPSO" not in sanitized
    # Standard attrs preserved even in single-line form.
    assert "sAMAccountName" in sanitized
    assert "objectClass" in sanitized
    assert "AD_ATTR_0001" in sanitized
    assert "AD_ATTR_0002" in sanitized


# ----- round-trip: byte-exact restore ------------------------------------


def test_roundtrip_byte_exact():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        sAMAccountName\n"
        "        mail\n"
        "        homeMDB\n"
        "        msDS-ResultantPSO\n"
        "        extensionAttribute1\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_roundtrip_with_other_ldap_fields():
    # Mix query-attrname (T3A) with filter (existing T1.85i) and
    # description (T1.7) to verify multi-walker round-trip.
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        '    description "Corporate AD"\n'
        '    filter "sAMAccountName=%username%"\n'
        "    query-attrname {\n"
        "        sAMAccountName\n"
        "        memberOf\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)
    # Non-standard attr redacted.
    assert "homeMDB" not in sanitized
    # Standard attrs preserved.
    assert "sAMAccountName" in sanitized
    assert "memberOf" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ----- ledger entry shape -----------------------------------------------


def test_ledger_entry_partition_none():
    src = (
        "apm aaa active-directory /Common/ad1 {\n"
        "    query-attrname {\n"
        "        homeMDB\n"
        "    }\n"
        "}\n"
    )
    ledger, _ = scan(src)
    placeholder = ledger.by_original[(Kind.AD_ATTR, "homeMDB")]
    entry = ledger.entries[placeholder]
    assert entry.kind == Kind.AD_ATTR
    assert entry.partition is None
    assert entry.original == "homeMDB"
    assert entry.placeholder == "AD_ATTR_0001"
