"""v1.2 Phase 1e — ``client-policy`` nested bucket walker.

Mirrors Phase 1d (cert-key-chain) in shape. The ``client-policy``
block lives inside an APM profile body that pass-1 brace-skips, so
the nested bucket-name bareword leaks verbatim pre-v1.2.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single bucket inside apm profile connectivity ----------


def test_single_client_policy_bucket_redacted():
    src = (
        "apm profile connectivity /Common/acme_conn {\n"
        "    adaptive-compression enabled\n"
        "    client-policy {\n"
        "        acme_conn_clientPolicy {\n"
        "            ec {\n"
        "                reuse-winlogon-creds true\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    compress-buffer-size 4096\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.CLIENT_POLICY, "acme_conn_clientPolicy") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "acme_conn_clientPolicy" not in sanitized
    assert "CLIENT_POLICY_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple buckets get distinct placeholders ----------


def test_multiple_client_policy_buckets_distinct():
    src = (
        "apm profile connectivity /Common/multi_conn {\n"
        "    client-policy {\n"
        "        bucket_alpha {\n"
        "            ec { reuse-winlogon-creds true }\n"
        "        }\n"
        "        bucket_bravo {\n"
        "            ec { reuse-winlogon-creds false }\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for name in ("bucket_alpha", "bucket_bravo"):
        assert (Kind.CLIENT_POLICY, name) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for name in ("bucket_alpha", "bucket_bravo"):
        assert name not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- empty client-policy body is a no-op ----------


def test_empty_client_policy_no_op():
    src = (
        "apm profile connectivity /Common/empty {\n"
        "    client-policy { }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    cp_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.CLIENT_POLICY
    ]
    assert cp_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- path-shaped name skipped ----------


def test_path_shaped_bucket_name_skipped():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    client-policy {\n"
        "        /Common/some_path_name { ec { reuse-winlogon-creds true } }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    cp_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.CLIENT_POLICY
    ]
    assert cp_entries == []


# ---------- idempotent on repeat ----------


def test_same_bucket_name_interns_once():
    src = (
        "apm profile connectivity /Common/p1 {\n"
        "    client-policy { shared_name { ec { } } }\n"
        "}\n"
        "apm profile connectivity /Common/p2 {\n"
        "    client-policy { shared_name { ec { } } }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.CLIENT_POLICY and e.original == "shared_name"
    ]
    assert len(entries) == 1


# ---------- coexists with cert-key-chain walker ----------


def test_client_policy_and_cert_key_chain_coexist():
    src = (
        "ltm profile client-ssl /Common/p_ssl {\n"
        "    cert-key-chain {\n"
        "        keychain_bucket { cert /Common/x.example.local }\n"
        "    }\n"
        "}\n"
        "apm profile connectivity /Common/p_conn {\n"
        "    client-policy {\n"
        "        policy_bucket { ec { reuse-winlogon-creds true } }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.CERT_KEY_CHAIN, "keychain_bucket") in ledger.by_original
    assert (Kind.CLIENT_POLICY, "policy_bucket") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for name in ("keychain_bucket", "policy_bucket"):
        assert name not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector accepts new placeholder ----------


def test_leak_detector_accepts_client_policy_placeholder():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    client-policy {\n"
        "        my_bucket { ec { reuse-winlogon-creds true } }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "CLIENT_POLICY_0001" not in leak.token


# ---------- entry kind / partition fields ----------


def test_client_policy_entry_fields():
    src = (
        "apm profile connectivity /Common/p {\n"
        "    client-policy {\n"
        "        my_bucket { ec { reuse-winlogon-creds true } }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.CLIENT_POLICY, "my_bucket")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.CLIENT_POLICY
    assert entry.original == "my_bucket"
