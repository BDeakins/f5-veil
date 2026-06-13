"""Unit tests for ``veil.ucs_archive`` — UCS extract layer (v1.2).

Tests synthesize tarballs in ``tmp_path`` so they run without the
500 MB customer UCS fixture and stay portable.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from veil.ucs_archive import (
    CONFIG_MEMBERS,
    CONFIG_MEMBERS_OPTIONAL,
    CONFIG_MEMBERS_REQUIRED,
    MAX_CONFIG_MEMBER_BYTES,
    UcsExtractError,
    extract_ucs_configs,
    is_ucs_file,
)


# ---------- helpers ----------


def _add_file(tar: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mode = 0o644
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(content))


def _add_symlink(tar: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mode = 0o777
    tar.addfile(info)


def _add_dir(tar: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


def _build_ucs(
    path: Path,
    members: dict[str, bytes],
    *,
    symlinks: dict[str, str] | None = None,
    dirs: tuple[str, ...] = (),
    extra: dict[str, bytes] | None = None,
) -> None:
    """Build a synthetic UCS (gzipped tar) at ``path``.

    ``members`` maps archive path → bytes content for regular files.
    ``symlinks`` maps name → linkname. ``extra`` is identical to
    ``members`` but bypasses the allowlist (used for tar-bomb / non-
    config noise).
    """
    with tarfile.open(path, "w:gz") as tar:
        for d in dirs:
            _add_dir(tar, d)
        for name, content in members.items():
            _add_file(tar, name, content)
        for name, content in (extra or {}).items():
            _add_file(tar, name, content)
        for name, target in (symlinks or {}).items():
            _add_symlink(tar, name, target)


_MIN_BASE = b"net vlan /Common/vlan_internal { tag 100 }\n"
_MIN_MAIN = (
    b"ltm pool /Common/app_pool {\n"
    b"    members {\n"
    b"        /Common/10.0.0.10:80 { address 10.0.0.10 }\n"
    b"    }\n"
    b"}\n"
)
_MIN_SCRIPT = "# bigip_script.conf - empty fixture\n".encode("utf-8")
_MIN_USER = "# bigip_user.conf - empty fixture\n".encode("utf-8")


def _all_four(tmp_path: Path) -> Path:
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {
        "config/bigip_base.conf": _MIN_BASE,
        "config/bigip.conf": _MIN_MAIN,
        "config/bigip_script.conf": _MIN_SCRIPT,
        "config/bigip_user.conf": _MIN_USER,
    })
    return p


# ---------- is_ucs_file ----------


def test_is_ucs_file_happy(tmp_path):
    p = _all_four(tmp_path)
    assert is_ucs_file(p) is True


def test_is_ucs_file_wrong_extension(tmp_path):
    # Valid gzipped tar but named .tar.gz, not .ucs.
    p = tmp_path / "config.tar.gz"
    _build_ucs(p, {"config/bigip_base.conf": _MIN_BASE,
                   "config/bigip.conf": _MIN_MAIN})
    assert is_ucs_file(p) is False


def test_is_ucs_file_wrong_magic(tmp_path):
    # .ucs extension but plaintext content.
    p = tmp_path / "fake.ucs"
    p.write_text("this is not a tarball\n", encoding="utf-8")
    assert is_ucs_file(p) is False


def test_is_ucs_file_nonexistent(tmp_path):
    assert is_ucs_file(tmp_path / "does_not_exist.ucs") is False


def test_is_ucs_file_case_insensitive_extension(tmp_path):
    p = tmp_path / "BIG.UCS"
    _build_ucs(p, {"config/bigip_base.conf": _MIN_BASE,
                   "config/bigip.conf": _MIN_MAIN})
    assert is_ucs_file(p) is True


# ---------- extract_ucs_configs — happy paths ----------


def test_extract_all_allowlisted(tmp_path):
    p = _all_four(tmp_path)
    result = extract_ucs_configs(p)
    # _all_four also writes config/bigip_script.conf into the
    # synthetic UCS, but script.conf is NOT in the allowlist (see
    # CONFIG_MEMBERS_OPTIONAL docstring) so it gets ignored. We
    # extract base + main + user only.
    assert len(result.configs) == len(CONFIG_MEMBERS)
    assert result.skipped_member_count == 4 - len(CONFIG_MEMBERS)
    assert result.total_member_count == 4
    names = [n for n, _ in result.configs]
    # Order matches CONFIG_MEMBERS: base first, then main, then user.
    assert names == list(CONFIG_MEMBERS)
    assert "config/bigip_script.conf" not in names


def test_extract_required_only(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {
        "config/bigip_base.conf": _MIN_BASE,
        "config/bigip.conf": _MIN_MAIN,
    })
    result = extract_ucs_configs(p)
    names = [n for n, _ in result.configs]
    assert names == list(CONFIG_MEMBERS_REQUIRED)
    assert result.skipped_member_count == 0


def test_extract_preserves_content_byte_exact(tmp_path):
    p = _all_four(tmp_path)
    result = extract_ucs_configs(p)
    contents = dict(result.configs)
    assert contents["config/bigip_base.conf"] == _MIN_BASE.decode("utf-8")
    assert contents["config/bigip.conf"] == _MIN_MAIN.decode("utf-8")
    assert contents["config/bigip_user.conf"] == _MIN_USER.decode("utf-8")
    # bigip_script.conf is NOT in the allowlist — never extracted.
    assert "config/bigip_script.conf" not in contents


def test_extract_skips_non_config_members(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(
        p,
        members={
            "config/bigip_base.conf": _MIN_BASE,
            "config/bigip.conf": _MIN_MAIN,
        },
        extra={
            "config/.diffVersions/config/bigip.conf/bigip.conf": b"stale\n",
            "config/bigip.license": b"BIG IP LICENSE\n",
            "var/log/stuff.log": b"not interesting\n",
            "config/BigDB.dat": b"\x00\x01\x02\xff",  # non-UTF-8 binary, must NOT be read
        },
    )
    result = extract_ucs_configs(p)
    assert len(result.configs) == 2
    assert result.skipped_member_count == 4
    assert result.total_member_count == 6


def test_extract_optional_only_user_present(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {
        "config/bigip_base.conf": _MIN_BASE,
        "config/bigip.conf": _MIN_MAIN,
        "config/bigip_user.conf": _MIN_USER,
    })
    result = extract_ucs_configs(p)
    names = [n for n, _ in result.configs]
    # Order is CONFIG_MEMBERS order; script absent, user follows main.
    assert names == [
        "config/bigip_base.conf",
        "config/bigip.conf",
        "config/bigip_user.conf",
    ]


# ---------- extract_ucs_configs — rejections ----------


def test_extract_missing_required_main_conf_raises(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {"config/bigip_base.conf": _MIN_BASE})
    with pytest.raises(UcsExtractError, match="missing required"):
        extract_ucs_configs(p)


def test_extract_missing_required_base_conf_raises(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {"config/bigip.conf": _MIN_MAIN})
    with pytest.raises(UcsExtractError, match="missing required"):
        extract_ucs_configs(p)


def test_extract_symlink_for_allowlisted_member_raises(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(
        p,
        members={"config/bigip_base.conf": _MIN_BASE},
        symlinks={"config/bigip.conf": "/etc/passwd"},
    )
    with pytest.raises(UcsExtractError, match="is a link"):
        extract_ucs_configs(p)


def test_extract_directory_for_allowlisted_member_raises(tmp_path):
    # An entry named like an allowlisted member but recorded as a
    # directory (type=5) — refused.
    p = tmp_path / "synthetic.ucs"
    with tarfile.open(p, "w:gz") as tar:
        _add_file(tar, "config/bigip_base.conf", _MIN_BASE)
        _add_dir(tar, "config/bigip.conf")
    with pytest.raises(UcsExtractError, match="not a regular file"):
        extract_ucs_configs(p)


def test_extract_oversized_member_raises(tmp_path, monkeypatch):
    p = tmp_path / "synthetic.ucs"
    # Override the cap to something tiny so we don't have to build a
    # multi-MB synthetic fixture.
    monkeypatch.setattr("veil.ucs_archive.MAX_CONFIG_MEMBER_BYTES", 16)
    _build_ucs(p, {
        "config/bigip_base.conf": _MIN_BASE,  # > 16 bytes
        "config/bigip.conf": _MIN_MAIN,
    })
    with pytest.raises(UcsExtractError, match="exceeds"):
        extract_ucs_configs(p)


def test_extract_invalid_utf8_raises(tmp_path):
    p = tmp_path / "synthetic.ucs"
    _build_ucs(p, {
        "config/bigip_base.conf": b"\xff\xfe not utf8",
        "config/bigip.conf": _MIN_MAIN,
    })
    with pytest.raises(UcsExtractError, match="not valid UTF-8"):
        extract_ucs_configs(p)


def test_extract_not_a_tarball_raises(tmp_path):
    p = tmp_path / "synthetic.ucs"
    p.write_bytes(b"\x1f\x8b\x08\x00 garbage that isn't a gzipped tar")
    with pytest.raises(UcsExtractError, match="could not open"):
        extract_ucs_configs(p)


def test_extract_nonexistent_file_raises(tmp_path):
    with pytest.raises(UcsExtractError, match="could not open"):
        extract_ucs_configs(tmp_path / "nope.ucs")


# ---------- module-level invariants ----------


def test_config_members_ordering_base_first():
    """``scan_many`` relies on base-first ordering — pin it."""
    assert CONFIG_MEMBERS[0] == "config/bigip_base.conf"
    assert CONFIG_MEMBERS[1] == "config/bigip.conf"
    # Required come before optional.
    for req in CONFIG_MEMBERS_REQUIRED:
        for opt in CONFIG_MEMBERS_OPTIONAL:
            assert CONFIG_MEMBERS.index(req) < CONFIG_MEMBERS.index(opt)


def test_max_member_cap_is_sane():
    # If someone drops this to a value < real-world script.conf
    # (~1.5 MB observed), real UCSes will start failing extraction.
    assert MAX_CONFIG_MEMBER_BYTES >= 4 * 1024 * 1024
