"""v1.2 — CLI obfuscate with UCS-archive input.

Exercises the UCS detection + virtual-input expansion path in
``_cmd_obfuscate``. Synthetic UCS fixtures built in ``tmp_path``; no
500 MB customer archive needed.

Round-trip exercises the existing multi-file deobfuscate flow
against the four sanitized text files the UCS path emits — the
deobfuscate side does NOT (yet) read UCS archives directly.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from veil.cli import main


# ---------- helpers ----------


def _add_file(tar: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    info.mode = 0o644
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(content))


_BASE = (
    "net vlan /Common/vlan_internal { tag 100 }\n"
    "net self /Common/self_external {\n"
    "    address 10.0.0.5/24\n"
    "    vlan /Common/vlan_internal\n"
    "}\n"
)
_MAIN = (
    "ltm pool /Common/app_pool {\n"
    "    members {\n"
    "        /Common/10.0.0.10:80 { address 10.0.0.10 }\n"
    "    }\n"
    "}\n"
)
_SCRIPT = "# bigip_script.conf - empty fixture\n"
_USER = "# bigip_user.conf - empty fixture\n"


def _build_ucs(
    path: Path,
    *,
    base: str | None = _BASE,
    main_conf: str | None = _MAIN,
    script: str | None = _SCRIPT,
    user: str | None = _USER,
    noise: dict[str, bytes] | None = None,
) -> None:
    """Build a synthetic UCS with the requested members. Pass
    ``None`` to omit a member."""
    members = {}
    if base is not None:
        members["config/bigip_base.conf"] = base.encode("utf-8")
    if main_conf is not None:
        members["config/bigip.conf"] = main_conf.encode("utf-8")
    if script is not None:
        members["config/bigip_script.conf"] = script.encode("utf-8")
    if user is not None:
        members["config/bigip_user.conf"] = user.encode("utf-8")
    with tarfile.open(path, "w:gz") as tar:
        for name, content in members.items():
            _add_file(tar, name, content)
        for name, content in (noise or {}).items():
            _add_file(tar, name, content)


# ---------- happy-path round trip ----------


def test_ucs_obfuscate_emits_all_four_sanitized_files(tmp_path, monkeypatch):
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    # Every allowlisted member came out as a file under --output-dir,
    # named by basename only.
    assert (out_dir / "bigip_base.conf").exists()
    assert (out_dir / "bigip.conf").exists()
    assert (out_dir / "bigip_script.conf").exists()
    assert (out_dir / "bigip_user.conf").exists()
    assert answer.exists()

    # Customer-identifying tokens redacted.
    san_base = (out_dir / "bigip_base.conf").read_text(encoding="utf-8")
    san_main = (out_dir / "bigip.conf").read_text(encoding="utf-8")
    assert "vlan_internal" not in san_base
    assert "self_external" not in san_base
    assert "app_pool" not in san_main
    assert "10.0.0.10" not in san_main


def test_ucs_round_trip_via_text_deobfuscate(tmp_path, monkeypatch):
    """Obfuscate from UCS, then deobfuscate the four text outputs
    back to the originals. Round-trip is byte-exact."""
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    restored = tmp_path / "restored"
    # Deobfuscate against the four sanitized text files in
    # CONFIG_MEMBERS order (base first), matching the recorded
    # sources list in the answer file.
    rc2 = main([
        "deobfuscate",
        "--input", str(out_dir / "bigip_base.conf"),
        "--input", str(out_dir / "bigip.conf"),
        "--input", str(out_dir / "bigip_script.conf"),
        "--input", str(out_dir / "bigip_user.conf"),
        "--output-dir", str(restored),
        "--answer-file", str(answer),
    ])
    assert rc2 == 0
    assert (restored / "bigip_base.conf").read_text(encoding="utf-8") == _BASE
    assert (restored / "bigip.conf").read_text(encoding="utf-8") == _MAIN
    assert (restored / "bigip_script.conf").read_text(encoding="utf-8") == _SCRIPT
    assert (restored / "bigip_user.conf").read_text(encoding="utf-8") == _USER


def test_ucs_with_optional_members_missing(tmp_path, monkeypatch):
    """UCS without script.conf / user.conf still obfuscates the
    required pair successfully."""
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs, script=None, user=None)
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0
    assert (out_dir / "bigip_base.conf").exists()
    assert (out_dir / "bigip.conf").exists()
    assert not (out_dir / "bigip_script.conf").exists()
    assert not (out_dir / "bigip_user.conf").exists()


def test_ucs_noise_members_ignored(tmp_path, monkeypatch, capsys):
    """Non-config members (binaries, licenses, diffVersions) are
    counted and skipped — never read, never written."""
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs, noise={
        "config/BigDB.dat": b"\x00\x01\x02\xff",  # binary; would fail UTF-8 if read
        "config/bigip.license": b"LICENSE\n",
        "config/.diffVersions/config/bigip.conf/bigip.conf": b"stale\n",
        "var/log/audit.log": b"audit stuff\n",
    })
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0
    err = capsys.readouterr().err
    # The CLI announces the skipped member count for operator audit.
    assert "extracted 4" in err
    assert "ignored 4" in err


# ---------- rejections ----------


def test_ucs_mixed_with_plain_input_rejected(tmp_path, monkeypatch, capsys):
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    plain = tmp_path / "extra.conf"
    plain.write_text("ltm pool /Common/x { members { } }\n", encoding="utf-8")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--input", str(plain),
        "--output-dir", str(tmp_path / "out"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2  # EXIT_USER_ERROR
    err = capsys.readouterr().err
    assert "cannot be mixed" in err


def test_multiple_ucs_rejected(tmp_path, monkeypatch, capsys):
    ucs1 = tmp_path / "a.ucs"
    ucs2 = tmp_path / "b.ucs"
    _build_ucs(ucs1)
    _build_ucs(ucs2)
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(ucs1),
        "--input", str(ucs2),
        "--output-dir", str(tmp_path / "out"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "multiple UCS" in err


def test_ucs_output_flag_rejected(tmp_path, monkeypatch, capsys):
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output", str(tmp_path / "single.conf"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--output not valid" in err
    assert "--output-dir" in err


def test_ucs_output_dir_required(tmp_path, monkeypatch, capsys):
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--output-dir is required" in err


def test_ucs_extension_without_gzip_magic_rejected(tmp_path, monkeypatch, capsys):
    """Operator hands us a plaintext file named .ucs by mistake —
    fail loudly rather than try to parse it as a config."""
    fake = tmp_path / "looks_like.ucs"
    fake.write_text("net vlan /Common/x { tag 1 }\n", encoding="utf-8")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(fake),
        "--output", str(tmp_path / "out.conf"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert ".ucs extension but is not a gzipped tar" in err


def test_ucs_missing_required_member_rejected(tmp_path, monkeypatch, capsys):
    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs, base=None)  # missing bigip_base.conf
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(tmp_path / "out"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 3  # EXIT_IO_ERROR — extractor failure
    err = capsys.readouterr().err
    assert "missing required" in err


# ---------- answer file shape ----------


def test_ucs_answer_file_records_sources(tmp_path, monkeypatch):
    """The answer file's recorded sources list contains the basenames
    of the extracted UCS members, in CONFIG_MEMBERS order."""
    from veil.answer_file import read_answer_file

    ucs = tmp_path / "device.ucs"
    _build_ucs(ucs)
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(ucs),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    _ledger, _diag, sources = read_answer_file(answer, b"test-pass")
    assert sources == [
        "bigip_base.conf",
        "bigip.conf",
        "bigip_script.conf",
        "bigip_user.conf",
    ]
