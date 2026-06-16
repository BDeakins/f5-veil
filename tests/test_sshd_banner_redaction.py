"""v1.2 Phase 1c — ``sys sshd`` banner walker.

Covers ``banner-text`` / ``pre-login-banner`` / ``post-login-banner``
field values inside ``sys sshd { ... }``. Pre-v1.2 these multi-line
QSTRINGs leaked verbatim because ``sys sshd`` lands in
``_record_unknown_top_level`` and pass-1 skips the body.
"""

from __future__ import annotations

from veil.leak_detector import scan_leaks
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import reverse_substitute, substitute


# ---------- single-line banner-text ----------


def test_single_line_banner_text_redacted():
    src = (
        "sys sshd {\n"
        "    banner enabled\n"
        '    banner-text "Acme Corp authorized users only"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, "Acme Corp authorized users only") in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "Acme Corp" not in sanitized
    assert "SSHD_BANNER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multi-line banner-text ----------


def test_multi_line_banner_text_redacted():
    """Real-world banners span multiple lines as a single QSTRING.
    The tokenizer captures the full multi-line span; the substring
    walker substitutes the bare content (newlines included)."""
    banner_text = (
        "ACME CORP NETWORK - AUTHORIZED ACCESS ONLY\n"
        "All activity is monitored and logged\n"
        "Unauthorized access will be prosecuted"
    )
    src = (
        "sys sshd {\n"
        f'    banner-text "{banner_text}"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, banner_text) in ledger.by_original
    sanitized, diag = substitute(src, ledger, diag)
    assert "ACME CORP" not in sanitized
    assert "SSHD_BANNER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- pre-login-banner / post-login-banner alternate spellings ----------


def test_pre_login_banner_redacted():
    src = (
        "sys sshd {\n"
        '    pre-login-banner "Welcome to Acme datacenter"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, "Welcome to Acme datacenter") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme datacenter" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_post_login_banner_redacted():
    src = (
        "sys sshd {\n"
        '    post-login-banner "Acme — logout when done"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, "Acme — logout when done") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- all three banner fields coexist ----------


def test_all_three_banner_fields_redacted():
    src = (
        "sys sshd {\n"
        '    banner-text "Banner one"\n'
        '    pre-login-banner "Banner two"\n'
        '    post-login-banner "Banner three"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    for text in ("Banner one", "Banner two", "Banner three"):
        assert (Kind.SSHD_BANNER, text) in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for text in ("Banner one", "Banner two", "Banner three"):
        assert text not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- non-banner sub-fields ignored ----------


def test_sys_sshd_non_banner_fields_ignored():
    """``sys sshd`` carries other settings (``inactivity-timeout``,
    ``include``, ``port``). The walker should only intern banner
    fields and leave the rest to the unknown-block diagnostic."""
    src = (
        "sys sshd {\n"
        "    banner enabled\n"
        "    inactivity-timeout 3600\n"
        '    banner-text "Acme banner"\n'
        '    include "Ciphers aes256-ctr,aes128-ctr"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    banner_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SSHD_BANNER
    ]
    assert len(banner_entries) == 1
    assert banner_entries[0].original == "Acme banner"
    sanitized, _diag = substitute(src, ledger, diag)
    assert "Acme banner" not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- empty bodies are no-ops ----------


def test_empty_sys_sshd_no_op():
    src = "sys sshd {\n}\n"
    ledger, diag = scan(src)
    banner_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SSHD_BANNER
    ]
    assert banner_entries == []
    sanitized, _diag = substitute(src, ledger, diag)
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


def test_empty_banner_text_skipped():
    src = (
        "sys sshd {\n"
        '    banner-text ""\n'
        "}\n"
    )
    ledger, diag = scan(src)
    banner_entries = [
        e for e in ledger.entries.values() if e.kind == Kind.SSHD_BANNER
    ]
    assert banner_entries == []


# ---------- bareword form (uncommon but supported) ----------


def test_bareword_banner_redacted():
    src = (
        "sys sshd {\n"
        "    banner-text Welcome\n"
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, "Welcome") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    assert "SSHD_BANNER_0001" in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- multiple sys sshd blocks ----------


def test_multiple_sys_sshd_blocks_handled():
    src = (
        "sys sshd {\n"
        '    banner-text "First banner"\n'
        "}\n"
        "sys sshd {\n"
        '    banner-text "Second banner"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    assert (Kind.SSHD_BANNER, "First banner") in ledger.by_original
    assert (Kind.SSHD_BANNER, "Second banner") in ledger.by_original
    sanitized, _diag = substitute(src, ledger, diag)
    for text in ("First banner", "Second banner"):
        assert text not in sanitized
    restored = reverse_substitute(sanitized, ledger)
    assert restored == src


# ---------- leak detector accepts new placeholder ----------


def test_leak_detector_accepts_sshd_banner_placeholder():
    src = (
        "sys sshd {\n"
        '    banner-text "Acme corporate banner"\n'
        "}\n"
    )
    ledger, diag = scan(src)
    sanitized, _diag = substitute(src, ledger, diag)
    report = scan_leaks(sanitized)
    for leak in report.leaks:
        assert "SSHD_BANNER_0001" not in leak.token


# ---------- entry partition / kind fields ----------


def test_sshd_banner_entry_fields():
    src = (
        "sys sshd {\n"
        '    banner-text "Acme banner"\n'
        "}\n"
    )
    ledger, _diag = scan(src)
    ph = ledger.by_original[(Kind.SSHD_BANNER, "Acme banner")]
    entry = ledger.entries[ph]
    assert entry.partition is None
    assert entry.kind == Kind.SSHD_BANNER
    assert entry.original == "Acme banner"
