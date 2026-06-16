"""v1.2 Phase 1d — ``cert-key-chain`` nested bucket walker.

Covers bucket-name barewords inside
``ltm profile client-ssl { ... cert-key-chain { <bucket> { ... } } ... }``.
``ltm profile client-ssl`` is a known top-level kind whose body the
main pass-1 loop brace-skips, so the nested bucket name leaks
verbatim pre-v1.2.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single bucket inside client-ssl profile ----------


def test_single_cert_key_chain_bucket_redacted():
    src = (
        "ltm profile client-ssl /Common/myapp_clientssl {\n"
        "    cert /Common/myapp.example.local\n"
        "    cert-key-chain {\n"
        "        myapp_acme_root_ca_0 {\n"
        "            cert /Common/myapp.example.local\n"
        "            chain /Common/acme_root_ca\n"
        "            key /Common/myapp.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.CERT_KEY_CHAIN, "myapp_acme_root_ca_0") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "myapp_acme_root_ca_0" not in sanitized
    assert "CERT_KEY_CHAIN_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple buckets get distinct placeholders ----------


def test_multiple_cert_key_chain_buckets_distinct():
    src = (
        "ltm profile client-ssl /Common/multi_clientssl {\n"
        "    cert-key-chain {\n"
        "        bucket_alpha {\n"
        "            cert /Common/alpha.example.local\n"
        "        }\n"
        "        bucket_bravo {\n"
        "            cert /Common/bravo.example.local\n"
        "        }\n"
        "        bucket_charlie {\n"
        "            cert /Common/charlie.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    for name in ("bucket_alpha", "bucket_bravo", "bucket_charlie"):
        assert (Kind.CERT_KEY_CHAIN, name) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for name in ("bucket_alpha", "bucket_bravo", "bucket_charlie"):
        assert name not in sanitized
    for n in (1, 2, 3):
        assert f"CERT_KEY_CHAIN_000{n}" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple client-ssl profiles each with cert-key-chain ----------


def test_multiple_client_ssl_profiles_each_with_keychain():
    src = (
        "ltm profile client-ssl /Common/profile_a {\n"
        "    cert-key-chain {\n"
        "        bucket_in_a {\n"
        "            cert /Common/a.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm profile client-ssl /Common/profile_b {\n"
        "    cert-key-chain {\n"
        "        bucket_in_b {\n"
        "            cert /Common/b.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.CERT_KEY_CHAIN, "bucket_in_a") in ledger.by_original
    assert (Kind.CERT_KEY_CHAIN, "bucket_in_b") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for name in ("bucket_in_a", "bucket_in_b"):
        assert name not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- empty cert-key-chain body is a no-op ----------


def test_empty_cert_key_chain_no_op():
    src = (
        "ltm profile client-ssl /Common/empty_clientssl {\n"
        "    cert-key-chain { }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    keychain_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.CERT_KEY_CHAIN
    ]
    assert keychain_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- path-shaped bucket name is skipped ----------


def test_path_shaped_bucket_name_skipped():
    """Bucket names starting with ``/`` are not valid TMSH cert-key-chain
    identifiers but if such a token appears it should be ignored by
    this walker (path-shaped objects are someone else's job)."""
    src = (
        "ltm profile client-ssl /Common/weird {\n"
        "    cert-key-chain {\n"
        "        /Common/weird_path_bucket {\n"
        "            cert /Common/x.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    # The path-shaped name should NOT register as CERT_KEY_CHAIN.
    keychain_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.CERT_KEY_CHAIN
    ]
    assert keychain_entries == []


# ---------- idempotent on same bucket name appearing twice ----------


def test_same_bucket_name_interns_once():
    """If the same bucket name appears in two different client-ssl
    profiles (legal in TMSH because the bucket scope is per-profile),
    the substring-sub kind interns once globally — same placeholder."""
    src = (
        "ltm profile client-ssl /Common/profile_a {\n"
        "    cert-key-chain {\n"
        "        shared_bucket_name {\n"
        "            cert /Common/a.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
        "ltm profile client-ssl /Common/profile_b {\n"
        "    cert-key-chain {\n"
        "        shared_bucket_name {\n"
        "            cert /Common/b.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    entries = [
        e for e in ledger.entries.values()
        if e.kind == Kind.CERT_KEY_CHAIN and e.original == "shared_bucket_name"
    ]
    assert len(entries) == 1


# ---------- leak detector accepts new placeholder ----------


def test_leak_detector_accepts_cert_key_chain_placeholder():
    src = (
        "ltm profile client-ssl /Common/p {\n"
        "    cert-key-chain {\n"
        "        my_bucket {\n"
        "            cert /Common/x.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "CERT_KEY_CHAIN_0001" not in leak.token


# ---------- entry kind / partition fields ----------


def test_cert_key_chain_entry_fields():
    src = (
        "ltm profile client-ssl /Common/p {\n"
        "    cert-key-chain {\n"
        "        my_bucket {\n"
        "            cert /Common/x.example.local\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.CERT_KEY_CHAIN, "my_bucket")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.CERT_KEY_CHAIN
    assert entry.original == "my_bucket"
