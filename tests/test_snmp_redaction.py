"""v1.2 Phase 1a — ``sys snmp`` body walker.

Covers community / trap bucket headers, plaintext community-string
values, and ``sys-contact`` / ``sys-location`` free-text fields. Pre-
v1.2 all of this leaked verbatim because ``sys snmp`` lands in
``_record_unknown_top_level`` and pass-1 skips the body.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single community bucket ----------


def test_single_community_bucket_redacted():
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iSecretCommunity_1 {\n"
        "            community-name SecretCommunity\n"
        "            ip-version 4\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNMP_COMMUNITY, "/Common/iSecretCommunity_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "SecretCommunity") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/iSecretCommunity_1" not in sanitized
    assert "SecretCommunity" not in sanitized
    assert "/Common/SNMP_COMMUNITY_0001" in sanitized
    assert "SNMP_COMMUNITY_SECRET_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- single trap bucket ----------


def test_single_trap_bucket_redacted():
    src = (
        "sys snmp {\n"
        "    traps {\n"
        "        /Common/iAlertHost_1 {\n"
        "            community SecretCommunity\n"
        "            host 10.0.0.42\n"
        "            port 162\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNMP_TRAP, "/Common/iAlertHost_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "SecretCommunity") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/iAlertHost_1" not in sanitized
    assert "SecretCommunity" not in sanitized
    assert "/Common/SNMP_TRAP_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- sys-contact QSTRING form ----------


def test_sys_contact_qstring_redacted():
    src = (
        "sys snmp {\n"
        '    sys-contact "Acme Operator"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYS_CONTACT, "Acme Operator") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Acme Operator" not in sanitized
    assert "SYS_CONTACT_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- sys-contact bareword form ----------


def test_sys_contact_bareword_redacted():
    src = (
        "sys snmp {\n"
        "    sys-contact noc-team\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYS_CONTACT, "noc-team") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "noc-team" not in sanitized
    assert "SYS_CONTACT_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- sys-location QSTRING form ----------


def test_sys_location_qstring_redacted():
    src = (
        "sys snmp {\n"
        '    sys-location "Datacenter B Rack 17"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYS_LOCATION, "Datacenter B Rack 17") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Datacenter B Rack 17" not in sanitized
    assert "SYS_LOCATION_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- sys-location bareword form ----------


def test_sys_location_bareword_redacted():
    src = (
        "sys snmp {\n"
        "    sys-location HQ\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYS_LOCATION, "HQ") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "SYS_LOCATION_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple communities, multiple traps ----------


def test_multiple_communities_and_traps_get_distinct_placeholders():
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iAlpha_1 { community-name Alpha }\n"
        "        /Common/iBravo_1 { community-name Bravo }\n"
        "    }\n"
        "    traps {\n"
        "        /Common/iTrapHost1_1 { community Charlie host 10.0.0.1 }\n"
        "        /Common/iTrapHost2_1 { community Delta host 10.0.0.2 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNMP_COMMUNITY, "/Common/iAlpha_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY, "/Common/iBravo_1") in ledger.by_original
    assert (Kind.SNMP_TRAP, "/Common/iTrapHost1_1") in ledger.by_original
    assert (Kind.SNMP_TRAP, "/Common/iTrapHost2_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Alpha") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Bravo") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Charlie") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Delta") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    for secret in ("Alpha", "Bravo", "Charlie", "Delta"):
        assert secret not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- same secret in both community-name AND community shares ----------


def test_same_secret_shared_between_community_and_trap():
    """If the same community string is used as a ``community-name`` in
    a communities bucket AND as a ``community`` in a traps bucket, both
    intern under the same ``(kind, original)`` key and share one
    placeholder — the secret is the same secret regardless of context."""
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iShared_1 { community-name Shared }\n"
        "    }\n"
        "    traps {\n"
        "        /Common/iTrap_1 { community Shared host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    shared_entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.SNMP_COMMUNITY_SECRET and e.original == "Shared"
    ]
    assert len(shared_entries) == 1
    ph = ledger.by_original[(Kind.SNMP_COMMUNITY_SECRET, "Shared")]
    assert ph == "SNMP_COMMUNITY_SECRET_0001"


# ---------- empty bodies are no-ops ----------


def test_empty_sys_snmp_no_op():
    src = "sys snmp {\n}\n"
    ledger, diag = scan(src)
    snmp_entries = [
        e for e in ledger.entries.values()
        if e.kind in (
            Kind.SNMP_COMMUNITY, Kind.SNMP_TRAP,
            Kind.SNMP_COMMUNITY_SECRET,
            Kind.SYS_CONTACT, Kind.SYS_LOCATION,
        )
    ]
    assert snmp_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_empty_communities_and_traps_no_op():
    src = (
        "sys snmp {\n"
        "    communities { }\n"
        "    traps { }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    snmp_entries = [
        e for e in ledger.entries.values()
        if e.kind in (Kind.SNMP_COMMUNITY, Kind.SNMP_TRAP)
    ]
    assert snmp_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- full integrated sys snmp block ----------


def test_full_sys_snmp_block_all_fields_redacted():
    """Real-world shape: communities + traps + sys-contact +
    sys-location all in one block."""
    src = (
        "sys snmp {\n"
        '    sys-contact "Ops Team"\n'
        '    sys-location "Datacenter Alpha"\n'
        "    communities {\n"
        "        /Common/iPublicRW_1 {\n"
        "            community-name PublicRW\n"
        "            ip-version 4\n"
        "        }\n"
        "    }\n"
        "    traps {\n"
        "        /Common/iMonitor_1 {\n"
        "            community PublicRW\n"
        "            host 10.0.0.99\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    for sensitive in (
        "Ops Team", "Datacenter Alpha", "PublicRW",
        "/Common/iPublicRW_1", "/Common/iMonitor_1",
    ):
        assert sensitive not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple sys snmp blocks ----------


def test_multiple_sys_snmp_blocks_handled():
    """Real configs have one ``sys snmp`` block but the walker doesn't
    depend on that. Two blocks should yield independent registrations."""
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iAlpha_1 { community-name Alpha }\n"
        "    }\n"
        "}\n"
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iBravo_1 { community-name Bravo }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNMP_COMMUNITY, "/Common/iAlpha_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY, "/Common/iBravo_1") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Alpha") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY_SECRET, "Bravo") in ledger.by_original


# ---------- non-Common partition for community bucket ----------


def test_non_common_partition_community_bucket():
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Tenant_A/iTenantComm_1 {\n"
        "            community-name TenantSecret\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PARTITION, "Tenant_A") in ledger.by_original
    assert (Kind.SNMP_COMMUNITY, "/Tenant_A/iTenantComm_1") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "iTenantComm_1" not in sanitized
    assert "TenantSecret" not in sanitized
    assert "/PARTITION_0001/SNMP_COMMUNITY_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector accepts new placeholders ----------


def test_leak_detector_accepts_snmp_placeholders():
    src = (
        "sys snmp {\n"
        '    sys-contact "Acme Operator"\n'
        '    sys-location "DC Alpha"\n'
        "    communities {\n"
        "        /Common/iSecret_1 { community-name Secret }\n"
        "    }\n"
        "    traps {\n"
        "        /Common/iTrap_1 { community Secret host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "SNMP_COMMUNITY" not in leak.token
        assert "SNMP_TRAP" not in leak.token
        assert "SNMP_COMMUNITY_SECRET" not in leak.token
        assert "SYS_CONTACT" not in leak.token
        assert "SYS_LOCATION" not in leak.token


# ---------- bucket-name-embedded community substring catches via secret ----------


def test_bucket_name_embedded_community_substring_redacted():
    """TMSH auto-names communities as ``i<community>_<index>``. The
    bucket header itself substitutes to ``/Common/SNMP_COMMUNITY_NNNN``
    via the full-path match, and the embedded community substring is
    moot at that point. But if the same community appears as a substring
    elsewhere (e.g. in a comment or description) it should still get
    caught by the substring-sub of ``SNMP_COMMUNITY_SECRET``."""
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iCommSecret_1 { community-name CommSecret }\n"
        "    }\n"
        "}\n"
        "ltm pool /Common/some_pool {\n"
        '    description "uses CommSecret for snmp polling"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    # The bare community string in the description should be substituted
    # because SNMP_COMMUNITY_SECRET participates in substring sub.
    assert "CommSecret" not in sanitized


# ---------- ledger entry partition fields ----------


def test_snmp_community_entry_partition_field():
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iSecret_1 { community-name Secret }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    bucket_ph = ledger.by_original[(Kind.SNMP_COMMUNITY, "/Common/iSecret_1")]
    bucket_entry = ledger.entries[bucket_ph]
    assert bucket_entry.partition == "Common"
    assert bucket_entry.kind == Kind.SNMP_COMMUNITY
    secret_ph = ledger.by_original[(Kind.SNMP_COMMUNITY_SECRET, "Secret")]
    secret_entry = ledger.entries[secret_ph]
    assert secret_entry.partition is None
    assert secret_entry.kind == Kind.SNMP_COMMUNITY_SECRET
