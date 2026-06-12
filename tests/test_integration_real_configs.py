"""Integration tests against real BIG-IP configs.

These tests skip unless real ``bigip.conf`` files are present at
``test_configs/customer/*.bigip.conf``. That directory is gitignored so
customer configs never get committed.

The assertions verify structural properties only — they never echo back
specific identifier names. Failure messages report aggregate counts so
test logs are safe to share. See ``tests/README.md`` for setup.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from veil.cli import EXIT_OK, main
from veil.ledger import Kind
from veil.scanner import scan
from veil.substitute import substitute

_REAL_CONFIGS_DIR = Path(__file__).resolve().parent.parent / "test_configs" / "customer"
_REAL_CONFIGS = (
    sorted(_REAL_CONFIGS_DIR.glob("*.bigip.conf"))
    if _REAL_CONFIGS_DIR.exists()
    else []
)

_SKIP_REASON = (
    "no real configs in test_configs/customer/*.bigip.conf "
    "— see tests/README.md for setup"
)

skip_if_no_real_configs = pytest.mark.skipif(
    not _REAL_CONFIGS, reason=_SKIP_REASON
)

# Kinds whose ``entry.original`` is a full ``/Partition/leaf`` path. The
# anti-leak invariant must hold for these: pass-2 substitution always
# rewrites them, and any appearance of the literal path in sanitized
# output indicates a parser miss. PARTITION is excluded because its
# bare name (e.g. ``Tenant_A``) can legitimately appear inside a
# ``description`` body or a ``QSTRING``, both of which are deferred
# Diagnostics gaps, not parser misses.
# Kinds whose ``entry.original`` is a full ``/Partition/leaf`` path that
# pass-2 MUST substitute everywhere. PARTITION is excluded because its
# bare name can legitimately appear inside descriptions or QSTRINGs
# (deferred Diagnostics gaps). UNKNOWN is excluded because it is a
# best-effort catch-all for unrecognised top-level block headers — it
# can still leak via substring inside longer non-header barewords in
# other blocks' bodies (no current diagnostic catches that), and via
# QSTRING contents (flagged by qstring_contains_identifier). The
# primary safety invariant — that NODE/VS/POOL/MON/IRULE full paths
# never appear in sanitized output — is enforced strictly.
_PATH_BEARING_KINDS = {
    Kind.POOL,
    Kind.VS,
    Kind.NODE,
    Kind.MON,
    Kind.IRULE,
}


def _config_id(p: Path) -> str:
    return p.stem


@skip_if_no_real_configs
@pytest.mark.parametrize("config_path", _REAL_CONFIGS, ids=_config_id)
def test_real_config_scan_succeeds_without_exception(config_path: Path):
    src = config_path.read_text(encoding="utf-8", errors="replace")
    ledger, diag = scan(src)
    # Surfacing aggregate counts only — never echo identifier names.
    print(
        f"\n[{config_path.stem}] discovered {len(ledger)} entries; "
        f"counters={dict(sorted((k.value, v) for k, v in ledger.counters.items()))}; "
        f"unknown_top_level={len(diag.unknown_top_level)}; "
        f"malformed_paths={len(diag.malformed_paths)}"
    )


@skip_if_no_real_configs
@pytest.mark.parametrize("config_path", _REAL_CONFIGS, ids=_config_id)
def test_real_config_round_trip_via_cli_is_byte_identical(
    config_path: Path, tmp_path: Path, monkeypatch
):
    src = config_path.read_text(encoding="utf-8", errors="replace")
    inp = tmp_path / "in.conf"
    inp.write_text(src, encoding="utf-8")
    answer = tmp_path / "a.enc"
    sanitized = tmp_path / "s.conf"
    restored = tmp_path / "r.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "integration-test")
    rc = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == EXIT_OK, f"obfuscate returned {rc}"

    rc = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert rc == EXIT_OK, f"deobfuscate returned {rc}"

    restored_text = restored.read_text(encoding="utf-8")
    if restored_text != src:
        # Report a structural delta only — never quote either text.
        src_lines = src.splitlines()
        restored_lines = restored_text.splitlines()
        diff_lines = sum(
            1 for a, b in zip(src_lines, restored_lines) if a != b
        )
        diff_lines += abs(len(src_lines) - len(restored_lines))
        pytest.fail(
            f"round-trip not byte-identical: "
            f"src_len={len(src)} restored_len={len(restored_text)} "
            f"diff_lines={diff_lines}"
        )


@skip_if_no_real_configs
@pytest.mark.parametrize("config_path", _REAL_CONFIGS, ids=_config_id)
def test_real_config_sanitized_does_not_leak_path_bearing_originals(
    config_path: Path,
):
    src = config_path.read_text(encoding="utf-8", errors="replace")
    ledger, diag = scan(src)
    sanitized, _ = substitute(src, ledger, diag)

    total_path_bearing = sum(
        1 for e in ledger.entries.values() if e.kind in _PATH_BEARING_KINDS
    )
    leaked_count = sum(
        1
        for e in ledger.entries.values()
        if e.kind in _PATH_BEARING_KINDS and e.original in sanitized
    )
    leaked_per_kind: dict[str, int] = {}
    for e in ledger.entries.values():
        if e.kind in _PATH_BEARING_KINDS and e.original in sanitized:
            leaked_per_kind[e.kind.value] = (
                leaked_per_kind.get(e.kind.value, 0) + 1
            )

    print(
        f"\n[{config_path.stem}] anti-leak: "
        f"{leaked_count}/{total_path_bearing} path-bearing originals "
        f"appear in sanitized output; per_kind={leaked_per_kind}"
    )
    assert leaked_count == 0, (
        f"{leaked_count}/{total_path_bearing} path-bearing originals "
        f"leaked into sanitized output (breakdown: {leaked_per_kind}). "
        f"Identifier names withheld; investigate locally."
    )


@skip_if_no_real_configs
@pytest.mark.parametrize("config_path", _REAL_CONFIGS, ids=_config_id)
def test_real_config_every_ledger_entry_has_at_least_one_reference(
    config_path: Path,
):
    src = config_path.read_text(encoding="utf-8", errors="replace")
    ledger, diag = scan(src)
    substitute(src, ledger, diag)
    # Pass-2 records every substitution as a Ref. Each discovered entry
    # is referenced at least once (at its own discovery site). Orphans
    # surface in diag.orphan_entries; this is the cross-reference
    # integrity contract.
    orphans = len(diag.orphan_entries)
    print(
        f"\n[{config_path.stem}] cross-ref integrity: "
        f"{orphans} orphan(s) out of {len(ledger)} entries"
    )
    assert orphans == 0, (
        f"{orphans} ledger entries received zero references during "
        f"pass-2 substitution (out of {len(ledger)}). This indicates "
        f"a discovery/substitution mismatch — investigate locally."
    )
