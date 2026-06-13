"""v1.2 — multi-file CLI mode (``--input`` repeatable, ``--output-dir``).

Existing single-file CLI behavior is preserved (``test_cli.py`` covers
that). These tests exercise the new multi-file path: repeatable
``--input``, ``--output-dir``, and the answer file's recorded
``sources`` field with order-and-basename verification on deobfuscate.
"""

from __future__ import annotations

from pathlib import Path

from veil.cli import main


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


# ---------- round trip with two files ----------


def test_multi_file_round_trip(tmp_path, monkeypatch):
    base = tmp_path / "bigip_base.conf"
    main_conf = tmp_path / "bigip.conf"
    _write(base, "net vlan /Common/vlan_internal { tag 100 }\n")
    _write(main_conf,
        "ltm pool /Common/app_pool {\n"
        "    members {\n"
        "        /Common/10.0.0.10:80 { address 10.0.0.10 }\n"
        "    }\n"
        "}\n"
    )
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-pass")
    rc = main([
        "obfuscate",
        "--input", str(base),
        "--input", str(main_conf),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0
    assert (out_dir / "bigip_base.conf").exists()
    assert (out_dir / "bigip.conf").exists()
    assert answer.exists()

    # Customer-identifying tokens are gone in both files.
    san_base = (out_dir / "bigip_base.conf").read_text(encoding="utf-8")
    san_main = (out_dir / "bigip.conf").read_text(encoding="utf-8")
    assert "vlan_internal" not in san_base
    assert "app_pool" not in san_main

    # Deobfuscate both files back.
    restored_dir = tmp_path / "restored"
    rc2 = main([
        "deobfuscate",
        "--input", str(out_dir / "bigip_base.conf"),
        "--input", str(out_dir / "bigip.conf"),
        "--output-dir", str(restored_dir),
        "--answer-file", str(answer),
    ])
    assert rc2 == 0
    assert (restored_dir / "bigip_base.conf").read_text(encoding="utf-8") == \
        base.read_text(encoding="utf-8")
    assert (restored_dir / "bigip.conf").read_text(encoding="utf-8") == \
        main_conf.read_text(encoding="utf-8")


# ---------- validation: --output rejected in multi-file ----------


def test_multi_file_output_rejected_with_multiple_inputs(tmp_path, monkeypatch, capsys):
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    _write(a, "ltm pool /Common/p1 { members { } }\n")
    _write(b, "ltm pool /Common/p2 { members { } }\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(a),
        "--input", str(b),
        "--output", str(tmp_path / "out.conf"),  # invalid with 2 inputs
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2  # EXIT_USER_ERROR
    err = capsys.readouterr().err
    assert "--output" in err
    assert "multi-file" in err


def test_multi_file_output_dir_required_for_multi_input(tmp_path, monkeypatch, capsys):
    a = tmp_path / "a.conf"
    b = tmp_path / "b.conf"
    _write(a, "ltm pool /Common/p1 { members { } }\n")
    _write(b, "ltm pool /Common/p2 { members { } }\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(a),
        "--input", str(b),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--output-dir" in err
    assert "required" in err


def test_output_dir_rejected_in_single_file_mode(tmp_path, monkeypatch, capsys):
    a = tmp_path / "a.conf"
    _write(a, "ltm pool /Common/p1 { members { } }\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(a),
        "--output-dir", str(tmp_path / "sanitized"),  # invalid with 1 input
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--output-dir" in err
    assert "single-file" in err


def test_stdin_rejected_in_multi_file_mode(tmp_path, monkeypatch, capsys):
    a = tmp_path / "a.conf"
    _write(a, "ltm pool /Common/p1 { members { } }\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", "-",
        "--input", str(a),
        "--output-dir", str(tmp_path / "sanitized"),
        "--answer-file", str(tmp_path / "ans.enc"),
        "--allow-incomplete",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "stdin" in err.lower()


# ---------- sources verification on deobfuscate ----------


def test_deobfuscate_rejects_mismatched_input_filenames(tmp_path, monkeypatch, capsys):
    base = tmp_path / "bigip_base.conf"
    main_conf = tmp_path / "bigip.conf"
    _write(base, "net vlan /Common/vlan_internal { tag 100 }\n")
    _write(main_conf, "ltm pool /Common/p { members { } }\n")
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(base),
        "--input", str(main_conf),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    # Rename one of the sanitized files to break the basename match.
    renamed = tmp_path / "renamed_bigip.conf"
    (out_dir / "bigip.conf").rename(renamed)
    restored_dir = tmp_path / "restored"
    rc2 = main([
        "deobfuscate",
        "--input", str(out_dir / "bigip_base.conf"),
        "--input", str(renamed),
        "--output-dir", str(restored_dir),
        "--answer-file", str(answer),
    ])
    assert rc2 == 2
    err = capsys.readouterr().err
    assert "do not match" in err


def test_deobfuscate_rejects_reordered_inputs(tmp_path, monkeypatch, capsys):
    """Order is part of the recorded sources — feeding the same files
    in the wrong order is an operator error worth catching."""
    base = tmp_path / "bigip_base.conf"
    main_conf = tmp_path / "bigip.conf"
    _write(base, "net vlan /Common/vlan_internal { tag 100 }\n")
    _write(main_conf, "ltm pool /Common/p { members { } }\n")
    out_dir = tmp_path / "sanitized"
    answer = tmp_path / "answers.enc"
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(base),
        "--input", str(main_conf),
        "--output-dir", str(out_dir),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    restored_dir = tmp_path / "restored"
    rc2 = main([
        "deobfuscate",
        # Reversed order
        "--input", str(out_dir / "bigip.conf"),
        "--input", str(out_dir / "bigip_base.conf"),
        "--output-dir", str(restored_dir),
        "--answer-file", str(answer),
    ])
    assert rc2 == 2
    err = capsys.readouterr().err
    assert "do not match" in err


# ---------- single-file answer file still deobfuscates a single input ----------


def test_single_file_answer_file_no_sources_still_deobfuscates(tmp_path, monkeypatch):
    """Backward compatibility: an answer file with no ``sources`` field
    (single-file mode, or any v1.0/v1.1 file) deobfuscates one input
    normally — the reader returns ``None`` and the CLI skips the
    sources-matching check."""
    src = tmp_path / "bigip.conf"
    _write(src, "ltm pool /Common/p { members { } }\n")
    sanitized = tmp_path / "sanitized.conf"
    answer = tmp_path / "ans.enc"
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(src),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert rc == 0

    restored = tmp_path / "restored.conf"
    rc2 = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert rc2 == 0
    assert restored.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


# ---------- dry-run works in multi-file mode without --output-dir ----------


def test_multi_file_dry_run_does_not_require_output_dir(tmp_path, monkeypatch):
    a = tmp_path / "bigip_base.conf"
    b = tmp_path / "bigip.conf"
    _write(a, "net vlan /Common/vlan_internal { tag 100 }\n")
    _write(b, "ltm pool /Common/p { members { } }\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "x")
    rc = main([
        "obfuscate",
        "--input", str(a),
        "--input", str(b),
        "--dry-run",
        "--allow-incomplete",
    ])
    assert rc == 0
