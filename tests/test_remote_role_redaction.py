"""v1.2 — ``auth remote-role role-info`` bucket-path redaction.

Pre-v1.2 the customer-defined role bucket names inside an
``auth remote-role { role-info { ... } }`` body (``/Common/F5_Admins``,
``/Common/Domain_Admins``, etc.) leaked verbatim because pass-1 hands
``auth remote-role`` to ``_record_unknown_top_level`` and never descends
into its body. Pass-1.85 (``remote_role_discovery``) closes that gap by
re-walking the token stream, finding the ``role-info`` sub-block, and
interning each bucket header path as ``Kind.REMOTE_ROLE``.

Substitution then goes through pass-2's existing WORD-token full-match
path — bucket leafs render as ``/Common/REMOTE_ROLE_NNNN``; non-Common
partitions get the usual ``PARTITION_NNNN`` treatment. Round-trip is
byte-exact.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single bucket ----------


def test_single_role_bucket_redacted():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        "            role administrator\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    # The bucket path is interned as REMOTE_ROLE.
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/F5_Admins" not in sanitized
    assert "/Common/REMOTE_ROLE_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple buckets get distinct placeholders ----------


def test_multiple_role_buckets_get_distinct_placeholders():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        "            role administrator\n"
        "        }\n"
        "        /Common/Domain_Admins {\n"
        "            role operator\n"
        "        }\n"
        "        /Common/Network_Ops {\n"
        "            role manager\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    assert (Kind.REMOTE_ROLE, "/Common/Domain_Admins") in ledger.by_original
    assert (Kind.REMOTE_ROLE, "/Common/Network_Ops") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    for leaf in ("F5_Admins", "Domain_Admins", "Network_Ops"):
        assert leaf not in sanitized
    assert "REMOTE_ROLE_0001" in sanitized
    assert "REMOTE_ROLE_0002" in sanitized
    assert "REMOTE_ROLE_0003" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- dedup: same bucket name should never appear twice in
# valid TMSH, but interning is idempotent if it ever does ----------


def test_same_bucket_path_interns_once():
    """Pre-v1.2 ``auth remote-role`` body was unknown; the main pass-1
    loop never registered the bucket. Pass-1.85 re-walks and interns;
    re-running pass-1.85 (or re-scanning the same source) must not
    mint a second placeholder."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.REMOTE_ROLE, "/Common/F5_Admins")]
    assert ph == "REMOTE_ROLE_0001"
    # Re-scan with the existing ledger frozen state would raise; but
    # confirm a fresh scan of the same source yields the same placeholder
    # ID (counter starts fresh, but only one entry).
    ledger2, _diag2 = scan(src)
    assert len(
        [e for e in ledger2.entries.values() if e.kind == Kind.REMOTE_ROLE]
    ) == 1


# ---------- non-Common partition gets PARTITION_NNNN ----------


def test_non_common_partition_role_bucket():
    """Role buckets normally live under ``/Common/``, but a customer
    using partitioned admin scopes could theoretically place one under
    a tenant partition. The non-Common partition gets the usual
    ``PARTITION_NNNN`` treatment and the leaf gets ``REMOTE_ROLE_NNNN``."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Tenant_A/Tenant_Admins {\n"
        "            role administrator\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PARTITION, "Tenant_A") in ledger.by_original
    assert (Kind.REMOTE_ROLE, "/Tenant_A/Tenant_Admins") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "Tenant_Admins" not in sanitized
    assert "/PARTITION_0001/REMOTE_ROLE_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- pass-1.85 cooperates with pass-1.9 (AD DN) ----------


def test_role_bucket_and_inner_ad_dn_both_redacted():
    """Real configs pair the bucket header with an inner ``attribute``
    QSTRING containing the AD DN that maps users into the bucket. Both
    must redact, and round-trip must stay byte-exact."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins {\n"
        '            attribute "memberOf=CN=F5_Admins,DC=corp,DC=example,DC=com"\n'
        "            role administrator\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    assert any(
        e.kind == Kind.AD_GROUP_DN for e in ledger.entries.values()
    )
    sanitized, diag = substitute(src, ledger, diag)
    assert "F5_Admins" not in sanitized
    assert "DC=corp" not in sanitized
    assert "REMOTE_ROLE_0001" in sanitized
    assert "AD_GROUP_DN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple auth remote-role blocks ----------


def test_multiple_auth_remote_role_blocks_handled():
    """Real configs have one ``auth remote-role`` block but the walker
    doesn't depend on that. Two blocks should yield independent bucket
    registrations."""
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/Domain_Admins { role operator }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    assert (Kind.REMOTE_ROLE, "/Common/Domain_Admins") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "F5_Admins" not in sanitized
    assert "Domain_Admins" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- auth remote-role with non-role-info attributes ----------


def test_default_role_attribute_does_not_confuse_walker():
    """``auth remote-role`` can hold non-``role-info`` attributes (e.g.
    ``default-role``). The walker should ignore them and only descend
    into ``role-info``."""
    src = (
        "auth remote-role {\n"
        "    default-role guest\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.REMOTE_ROLE, "/Common/F5_Admins") in ledger.by_original
    # No spurious REMOTE_ROLE entries for non-path attributes.
    role_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.REMOTE_ROLE
    ]
    assert len(role_entries) == 1
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- empty role-info body ----------


def test_empty_role_info_body_no_op():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    role_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.REMOTE_ROLE
    ]
    assert role_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector accepts REMOTE_ROLE placeholder ----------


def test_leak_detector_accepts_remote_role_placeholder():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    # The placeholder itself must not surface as a leak.
    for leak in report.leaks:
        assert "REMOTE_ROLE_0001" not in leak.token


# ---------- partition recorded correctly ----------


def test_remote_role_entry_partition_field_is_common():
    src = (
        "auth remote-role {\n"
        "    role-info {\n"
        "        /Common/F5_Admins { role administrator }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.REMOTE_ROLE, "/Common/F5_Admins")]
    entry = ledger.entries[ph]
    assert entry.partition == "Common"
    assert entry.kind == Kind.REMOTE_ROLE
    assert entry.original == "/Common/F5_Admins"
