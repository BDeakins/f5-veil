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

# v1.2 — multi-file pair fixtures. Each subdirectory of
# ``test_configs/customer/`` that contains both ``bigip_base.conf`` and
# ``bigip.conf`` is treated as a real-world multi-file pair and exercised
# through scan_many / CLI multi-file mode. Skipped if no such pair exists.
_PAIR_DIRS = (
    [d for d in _REAL_CONFIGS_DIR.iterdir()
     if d.is_dir()
     and (d / "bigip_base.conf").exists()
     and (d / "bigip.conf").exists()]
    if _REAL_CONFIGS_DIR.exists()
    else []
)

skip_if_no_real_pair = pytest.mark.skipif(
    not _PAIR_DIRS, reason=(
        "no real config pair in test_configs/customer/<dir>/"
        "{bigip_base.conf,bigip.conf}"
    ),
)

# v1.2 — UCS archive fixtures. Any ``*.ucs`` file beneath
# ``test_configs/customer/`` is treated as a real-world UCS and
# exercised end-to-end through the CLI's UCS-input path. Skipped if
# no UCS is staged. Heavy (a UCS can be 500+ MB on disk with ~2 MB
# of config-member content) — keep assertions structural-only and
# never echo identifier names.
_REAL_UCS = (
    sorted(_REAL_CONFIGS_DIR.rglob("*.ucs"))
    if _REAL_CONFIGS_DIR.exists()
    else []
)

skip_if_no_real_ucs = pytest.mark.skipif(
    not _REAL_UCS,
    reason="no real UCS in test_configs/customer/**/*.ucs",
)


def _pair_id(p: Path) -> str:
    return p.name


def _ucs_id(p: Path) -> str:
    return p.stem

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


# ---------------------------------------------------------------------
# v1.2 — multi-file pair integration
# ---------------------------------------------------------------------


@skip_if_no_real_pair
@pytest.mark.parametrize("pair_dir", _PAIR_DIRS, ids=_pair_id)
def test_real_config_pair_scan_succeeds(pair_dir: Path):
    """``scan_many`` against a real ``bigip_base.conf`` +
    ``bigip.conf`` pair completes without exception and produces a
    ledger with both files' contributions."""
    from veil.scanner import scan_many
    base = (pair_dir / "bigip_base.conf").read_text(encoding="utf-8", errors="replace")
    main_src = (pair_dir / "bigip.conf").read_text(encoding="utf-8", errors="replace")
    ledger, diag = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main_src),
    ])
    print(
        f"\n[{pair_dir.name}] pair scan: {len(ledger)} entries; "
        f"counters={dict(sorted((k.value, v) for k, v in ledger.counters.items()))}; "
        f"unknown_top_level={len(diag.unknown_top_level)}"
    )


@skip_if_no_real_pair
@pytest.mark.parametrize("pair_dir", _PAIR_DIRS, ids=_pair_id)
def test_real_config_pair_round_trip_via_cli_is_byte_identical(
    pair_dir: Path, tmp_path: Path, monkeypatch
):
    """End-to-end CLI test: obfuscate the pair into ``--output-dir``,
    deobfuscate back, both files must restore byte-exact. This is the
    load-bearing acceptance test for v1.2 phase #1."""
    base_src = (pair_dir / "bigip_base.conf").read_text(encoding="utf-8", errors="replace")
    main_src = (pair_dir / "bigip.conf").read_text(encoding="utf-8", errors="replace")

    # Stage inputs in tmp_path so the CLI sees the canonical names.
    base_in = tmp_path / "bigip_base.conf"
    main_in = tmp_path / "bigip.conf"
    base_in.write_text(base_src, encoding="utf-8")
    main_in.write_text(main_src, encoding="utf-8")

    sanitized_dir = tmp_path / "sanitized"
    restored_dir = tmp_path / "restored"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "integration-test")
    rc = main([
        "obfuscate",
        "--input", str(base_in),
        "--input", str(main_in),
        "--output-dir", str(sanitized_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == EXIT_OK, f"obfuscate returned {rc}"
    assert (sanitized_dir / "bigip_base.conf").exists()
    assert (sanitized_dir / "bigip.conf").exists()

    rc = main([
        "deobfuscate",
        "--input", str(sanitized_dir / "bigip_base.conf"),
        "--input", str(sanitized_dir / "bigip.conf"),
        "--output-dir", str(restored_dir),
        "--answer-file", str(answer),
    ])
    assert rc == EXIT_OK, f"deobfuscate returned {rc}"

    # Byte-exact for both files.
    for label, original in [("bigip_base.conf", base_src),
                            ("bigip.conf", main_src)]:
        restored_text = (restored_dir / label).read_text(encoding="utf-8")
        if restored_text != original:
            orig_lines = original.splitlines()
            restored_lines = restored_text.splitlines()
            diff_lines = sum(
                1 for a, b in zip(orig_lines, restored_lines) if a != b
            )
            diff_lines += abs(len(orig_lines) - len(restored_lines))
            pytest.fail(
                f"{label} round-trip not byte-identical: "
                f"orig_len={len(original)} restored_len={len(restored_text)} "
                f"diff_lines={diff_lines}"
            )


@skip_if_no_real_pair
@pytest.mark.parametrize("pair_dir", _PAIR_DIRS, ids=_pair_id)
def test_real_config_pair_base_file_objects_visible_in_ledger(pair_dir: Path):
    """Pairing must surface base-file-only object kinds (VLAN /
    SELF_IP / ROUTE_DOMAIN / TRUNK) that scanning the main file alone
    would miss. Asserts at least one such kind appears."""
    from veil.scanner import scan_many
    base = (pair_dir / "bigip_base.conf").read_text(encoding="utf-8", errors="replace")
    main_src = (pair_dir / "bigip.conf").read_text(encoding="utf-8", errors="replace")
    led_main_only, _ = scan(main_src)
    led_pair, _ = scan_many([
        ("bigip_base.conf", base),
        ("bigip.conf", main_src),
    ])
    base_only_kinds = {Kind.VLAN, Kind.SELF_IP, Kind.ROUTE_DOMAIN, Kind.TRUNK}
    gained_kinds = set()
    for k in base_only_kinds:
        in_pair = led_pair.counters.get(k, 0)
        in_main_only = led_main_only.counters.get(k, 0)
        if in_pair > in_main_only:
            gained_kinds.add(k)
    print(
        f"\n[{pair_dir.name}] base-file kinds gained when paired: "
        f"{sorted(k.value for k in gained_kinds)}"
    )
    assert gained_kinds, (
        "scanning the pair produced no additional base-file kinds "
        "(VLAN / SELF_IP / ROUTE_DOMAIN / TRUNK) over scanning the main "
        "file alone. Either the base file has no such objects (unusual) "
        "or scan_many's ledger-sharing is broken."
    )


# ---------------------------------------------------------------------
# v1.2 — UCS archive integration
# ---------------------------------------------------------------------


@skip_if_no_real_ucs
@pytest.mark.parametrize("ucs_path", _REAL_UCS, ids=_ucs_id)
def test_real_ucs_extract_succeeds(ucs_path: Path):
    """The extractor opens a real-world UCS and produces the
    allowlisted config members. Structural assertions only — counts
    and member names are universal, no customer identifiers leak."""
    from veil.ucs_archive import (
        CONFIG_MEMBERS_REQUIRED,
        extract_ucs_configs,
    )

    result = extract_ucs_configs(ucs_path)
    extracted_names = [n for n, _ in result.configs]

    # Required members are present, base file first (load-bearing
    # for scan_many ordering).
    for required in CONFIG_MEMBERS_REQUIRED:
        assert required in extracted_names, (
            f"required UCS member {required!r} not found; "
            f"got {extracted_names!r}"
        )
    assert extracted_names[0] == "config/bigip_base.conf", (
        f"base file must be first in extraction order; "
        f"got {extracted_names!r}"
    )

    # Real UCS has hundreds to thousands of members; we should be
    # ignoring almost all of them.
    assert result.skipped_member_count >= 100, (
        f"skipped only {result.skipped_member_count} members; "
        f"real UCSes have hundreds — extractor may be reading "
        f"too much"
    )
    print(
        f"\n[{ucs_path.stem}] UCS extract: "
        f"{len(result.configs)} config member(s); "
        f"{result.skipped_member_count} ignored; "
        f"{result.total_member_count} total"
    )


@skip_if_no_real_ucs
@pytest.mark.parametrize("ucs_path", _REAL_UCS, ids=_ucs_id)
def test_real_ucs_round_trip_via_cli_is_byte_identical(
    ucs_path: Path, tmp_path: Path, monkeypatch
):
    """Obfuscate from a real UCS, deobfuscate the extracted
    sanitized text files, assert byte-exact round-trip for every
    extracted member.

    Load-bearing acceptance test for v1.2 UCS support — if this
    breaks, customer-sensitive content is being mangled by the
    obfuscation pipeline at real-world scale.
    """
    from veil.ucs_archive import extract_ucs_configs

    sanitized_dir = tmp_path / "sanitized"
    restored_dir = tmp_path / "restored"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "integration-test")
    rc = main([
        "obfuscate",
        "--input", str(ucs_path),
        "--output-dir", str(sanitized_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == EXIT_OK, f"obfuscate returned {rc}"

    # Snapshot the original config-member content from the UCS so
    # we can compare against the restored text files. The extractor
    # is the only way to get content; we trust it for this purpose
    # because test_real_ucs_extract_succeeds covers the extract
    # contract directly.
    original = dict(extract_ucs_configs(ucs_path).configs)
    extracted_basenames = [
        Path(name).name for name in original.keys()
    ]

    # Deobfuscate the sanitized text files. ``--input`` order must
    # match the answer file's recorded ``sources`` (base first, in
    # CONFIG_MEMBERS order).
    rc = main(
        ["deobfuscate"]
        + [
            arg
            for basename in extracted_basenames
            for arg in ("--input", str(sanitized_dir / basename))
        ]
        + [
            "--output-dir", str(restored_dir),
            "--answer-file", str(answer),
        ]
    )
    assert rc == EXIT_OK, f"deobfuscate returned {rc}"

    # Each restored file matches the original archive content
    # byte-for-byte.
    for archive_name, original_text in original.items():
        basename = Path(archive_name).name
        restored_text = (restored_dir / basename).read_text(
            encoding="utf-8"
        )
        if restored_text != original_text:
            # Report structural delta only — never quote content.
            orig_lines = original_text.splitlines()
            restored_lines = restored_text.splitlines()
            diff_lines = sum(
                1 for a, b in zip(orig_lines, restored_lines)
                if a != b
            )
            diff_lines += abs(
                len(orig_lines) - len(restored_lines)
            )
            pytest.fail(
                f"UCS member {archive_name!r} did not round-trip "
                f"byte-identical: "
                f"orig_len={len(original_text)} "
                f"restored_len={len(restored_text)} "
                f"diff_lines={diff_lines}"
            )
    print(
        f"\n[{ucs_path.stem}] UCS round-trip OK: "
        f"{len(original)} member(s) byte-identical"
    )
