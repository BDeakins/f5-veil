"""v1.2 Phase 1b — ``sys syslog`` body walker.

Covers remote-server bucket headers inside
``sys syslog { remote-servers { ... } }``. Pre-v1.2 these leaked
verbatim because ``sys syslog`` lands in
``_record_unknown_top_level`` and pass-1 skips the body.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single server bucket ----------


def test_single_server_bucket_redacted():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/log-collector-east {\n"
        "            host 10.0.0.42\n"
        "            remote-port 514\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYSLOG_SERVER, "/Common/log-collector-east") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "/Common/log-collector-east" not in sanitized
    assert "log-collector-east" not in sanitized
    assert "/Common/SYSLOG_SERVER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple servers get distinct placeholders ----------


def test_multiple_server_buckets_get_distinct_placeholders():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost-1 { host 10.0.0.1 remote-port 514 }\n"
        "        /Common/loghost-2 { host 10.0.0.2 remote-port 514 }\n"
        "        /Common/loghost-3 { host 10.0.0.3 remote-port 514 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for leaf in ("loghost-1", "loghost-2", "loghost-3"):
        assert (Kind.SYSLOG_SERVER, f"/Common/{leaf}") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    for leaf in ("loghost-1", "loghost-2", "loghost-3"):
        assert leaf not in sanitized
    for n in (1, 2, 3):
        assert f"SYSLOG_SERVER_000{n}" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- empty bodies are no-ops ----------


def test_empty_sys_syslog_no_op():
    src = "sys syslog {\n}\n"
    ledger, diag = scan(src)
    syslog_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SYSLOG_SERVER
    ]
    assert syslog_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_empty_remote_servers_no_op():
    src = (
        "sys syslog {\n"
        "    remote-servers { }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    syslog_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SYSLOG_SERVER
    ]
    assert syslog_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- non-remote-servers attributes ignored ----------


def test_sys_syslog_non_remote_servers_attributes_ignored():
    """``sys syslog`` can carry other settings (``console-log``,
    ``include``, ``iso-date``). The walker should only descend into
    ``remote-servers`` and ignore the rest — those continue to be
    surfaced via the unknown-block diagnostic."""
    src = (
        "sys syslog {\n"
        "    console-log enabled\n"
        "    iso-date enabled\n"
        "    remote-servers {\n"
        "        /Common/loghost { host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYSLOG_SERVER, "/Common/loghost") in ledger.by_original
    syslog_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SYSLOG_SERVER
    ]
    assert len(syslog_entries) == 1
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple sys syslog blocks ----------


def test_multiple_sys_syslog_blocks_handled():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost-a { host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost-b { host 10.0.0.2 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SYSLOG_SERVER, "/Common/loghost-a") in ledger.by_original
    assert (Kind.SYSLOG_SERVER, "/Common/loghost-b") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for leaf in ("loghost-a", "loghost-b"):
        assert leaf not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- non-Common partition ----------


def test_non_common_partition_server_bucket():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Tenant_A/tenant-logs { host 10.0.0.50 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.PARTITION, "Tenant_A") in ledger.by_original
    assert (Kind.SYSLOG_SERVER, "/Tenant_A/tenant-logs") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Tenant_A" not in sanitized
    assert "tenant-logs" not in sanitized
    assert "/PARTITION_0001/SYSLOG_SERVER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector accepts new placeholder ----------


def test_leak_detector_accepts_syslog_server_placeholder():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost { host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "SYSLOG_SERVER_0001" not in leak.token


# ---------- ledger entry partition / kind fields ----------


def test_syslog_server_entry_partition_field():
    src = (
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost { host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.SYSLOG_SERVER, "/Common/loghost")]
    entry = ledger.entries[ph]
    assert entry.partition == "Common"
    assert entry.kind == Kind.SYSLOG_SERVER
    assert entry.original == "/Common/loghost"


# ---------- coexists with sys snmp walker ----------


def test_syslog_and_snmp_coexist():
    """Both walkers run in pass-1 and should not interfere. Each
    intern path-shaped bucket headers under its own kind; placeholders
    are independent."""
    src = (
        "sys snmp {\n"
        "    communities {\n"
        "        /Common/iSecret_1 { community-name Secret }\n"
        "    }\n"
        "}\n"
        "sys syslog {\n"
        "    remote-servers {\n"
        "        /Common/loghost { host 10.0.0.1 }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SNMP_COMMUNITY, "/Common/iSecret_1") in ledger.by_original
    assert (Kind.SYSLOG_SERVER, "/Common/loghost") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for s in ("iSecret_1", "Secret", "loghost"):
        assert s not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src
