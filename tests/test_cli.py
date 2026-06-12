import io

import pytest

from veil.cli import (
    EXIT_DECRYPTION_FAILED,
    EXIT_FAIL_CLOSED,
    EXIT_IO_ERROR,
    EXIT_LEAK_DETECTED,
    EXIT_OK,
    EXIT_USER_ERROR,
    main,
)


# ----- obfuscate ------------------------------------------------------


def test_obfuscate_round_trip_writes_answer_and_sanitized(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "bigip.answers.enc"
    sanitized = tmp_path / "bigip.sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test-passphrase")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK
    assert answer.exists()
    assert sanitized.exists()
    out = sanitized.read_text()
    assert "/Common/POOL_0001" in out
    assert "/Common/foo" not in out


def test_obfuscate_fails_closed_on_diagnostics_by_default(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    # gtm wideip triggers unknown_top_level diagnostic
    inp.write_text("gtm wideip /Common/app.example.com {\n  pools none\n}\n")
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_FAIL_CLOSED
    # Crash safety: no answer file written when fail-closed.
    assert not answer.exists()


def test_obfuscate_proceeds_with_allow_incomplete(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("gtm wideip /Common/app {\n}\n")
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert code == EXIT_OK
    assert sanitized.exists()
    assert answer.exists()


def test_obfuscate_dry_run_writes_nothing(tmp_path, monkeypatch, capsys):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--answer-file", str(answer),
        "--dry-run",
    ])
    assert code == EXIT_OK
    assert not answer.exists()
    captured = capsys.readouterr()
    assert "POOL" in captured.err
    assert "dry-run" in captured.err.lower()


def test_obfuscate_errors_when_output_exists_without_force(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"
    sanitized.write_text("existing")

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_USER_ERROR
    assert sanitized.read_text() == "existing"
    assert not answer.exists()


def test_obfuscate_force_overwrites_existing_output(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"
    sanitized.write_text("existing")

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--force",
    ])
    assert code == EXIT_OK
    assert "POOL_0001" in sanitized.read_text()


def test_obfuscate_errors_when_answer_file_exists_without_force(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"
    answer.write_text("existing")  # any content; should not be touched
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_USER_ERROR
    assert answer.read_text() == "existing"
    assert not sanitized.exists()


def test_obfuscate_requires_answer_file_unless_dry_run(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
    ])
    assert code == EXIT_USER_ERROR


def test_obfuscate_input_not_found_returns_io_error(tmp_path, monkeypatch):
    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(tmp_path / "missing.conf"),
        "--answer-file", str(tmp_path / "a.enc"),
    ])
    assert code == EXIT_IO_ERROR


# ----- deobfuscate ----------------------------------------------------


def _obfuscate_for_setup(tmp_path, monkeypatch, src, passphrase="test"):
    """Helper: produce sanitized + answer file pair from a src string."""
    inp = tmp_path / "bigip.conf"
    inp.write_text(src)
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"
    monkeypatch.setenv("VEIL_PASSPHRASE", passphrase)
    rc = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
    ])
    assert rc == EXIT_OK, f"setup obfuscate failed: rc={rc}"
    return sanitized, answer


def test_deobfuscate_round_trip_common_partition(tmp_path, monkeypatch):
    src = "ltm pool /Common/foo {\n}\n"
    sanitized, answer = _obfuscate_for_setup(tmp_path, monkeypatch, src)

    restored = tmp_path / "restored.conf"
    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK
    assert restored.read_text() == src


def test_deobfuscate_round_trip_non_common_partition(tmp_path, monkeypatch):
    src = (
        "ltm pool /Tenant_A/foo {\n"
        "}\n"
        "ltm virtual /Tenant_A/vs1 {\n"
        "    pool /Tenant_A/foo\n"
        "}\n"
    )
    sanitized, answer = _obfuscate_for_setup(tmp_path, monkeypatch, src)

    restored = tmp_path / "restored.conf"
    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK
    assert restored.read_text() == src


def test_deobfuscate_wrong_passphrase_returns_decryption_failed(tmp_path, monkeypatch):
    src = "ltm pool /Common/foo {\n}\n"
    sanitized, answer = _obfuscate_for_setup(
        tmp_path, monkeypatch, src, passphrase="correct"
    )

    restored = tmp_path / "restored.conf"
    monkeypatch.setenv("VEIL_PASSPHRASE", "wrong")
    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_DECRYPTION_FAILED
    assert not restored.exists()


def test_deobfuscate_errors_when_output_exists_without_force(tmp_path, monkeypatch):
    src = "ltm pool /Common/foo {\n}\n"
    sanitized, answer = _obfuscate_for_setup(tmp_path, monkeypatch, src)
    restored = tmp_path / "restored.conf"
    restored.write_text("existing")

    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_USER_ERROR
    assert restored.read_text() == "existing"


# ----- passphrase sources --------------------------------------------


def test_passphrase_file_overrides_env_var(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"
    pp_file = tmp_path / "pp.txt"
    pp_file.write_text("file-passphrase\n")

    monkeypatch.setenv("VEIL_PASSPHRASE", "env-passphrase")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--passphrase-file", str(pp_file),
    ])
    assert code == EXIT_OK

    # Now deobfuscate using the file passphrase explicitly — env var
    # holds a wrong value, but --passphrase-file should win.
    restored = tmp_path / "restored.conf"
    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
        "--passphrase-file", str(pp_file),
    ])
    assert code == EXIT_OK


def test_passphrase_file_strips_trailing_newline(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"
    pp_file = tmp_path / "pp.txt"
    pp_file.write_text("my-pass\r\n")  # CRLF

    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--passphrase-file", str(pp_file),
    ])
    assert code == EXIT_OK

    # Confirm the CRLF was stripped (env-var matches stripped form)
    restored = tmp_path / "restored.conf"
    monkeypatch.setenv("VEIL_PASSPHRASE", "my-pass")
    code = main([
        "deobfuscate",
        "--input", str(sanitized),
        "--output", str(restored),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK


# ----- stdin / stdout -------------------------------------------------


def test_stdin_input_works(tmp_path, monkeypatch):
    src = "ltm pool /Common/foo {\n}\n"
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setattr("sys.stdin", io.StringIO(src))
    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", "-",
        "--output", str(sanitized),
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK
    assert "POOL_0001" in sanitized.read_text()


def test_stdout_output_works(tmp_path, monkeypatch, capsys):
    inp = tmp_path / "bigip.conf"
    inp.write_text("ltm pool /Common/foo {\n}\n")
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", "-",
        "--answer-file", str(answer),
    ])
    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert "/Common/POOL_0001" in captured.out


# ----- argparse-level behaviour ---------------------------------------


def test_no_subcommand_prints_help_and_returns_user_error(capsys):
    code = main([])
    assert code == EXIT_USER_ERROR
    captured = capsys.readouterr()
    assert "obfuscate" in captured.err or "obfuscate" in captured.out


def test_help_flag_exits_zero():
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0


def test_obfuscate_requires_input_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["obfuscate"])
    # argparse exits with code 2 for missing required args.
    assert exc_info.value.code == 2


def test_deobfuscate_requires_input_and_answer_file(capsys):
    with pytest.raises(SystemExit):
        main(["deobfuscate"])


# ----- leak detector / --strict ---------------------------------------


# A config that fires BOTH the leak detector (identifier-shaped bareword)
# and the diagnostics fail-closed gate (gtm wideip is an unknown top-level
# block). Lets us exercise --strict and --allow-incomplete interactions.
# Pre-v0.0.4 this fixture used a description with an embedded IP, but
# v0.0.4 description redaction now scrubs both — needed a leak source the
# obfuscator can't handle.
_LEAKY_TOKEN = "widget_app_v2_pool"
_LEAKY_CFG = (
    "ltm pool /Common/foo {\n"
    f"    custom_attribute {_LEAKY_TOKEN}\n"
    "}\n"
    # ``security dos profile`` is still unrecognised in v0.0.9 — fires
    # ``unknown_top_level``. Each round of kind expansion forces this
    # fixture to migrate to whichever shape isn't yet handled.
    "security dos profile /Common/customer_dos_profile {\n"
    "    description none\n"
    "}\n"
)
_CLEAN_CFG = "ltm pool /Common/foo {\n}\n"


def test_obfuscate_strict_no_leaks_exit_ok(tmp_path, monkeypatch):
    inp = tmp_path / "bigip.conf"
    inp.write_text(_CLEAN_CFG)
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--strict",
    ])
    assert code == EXIT_OK
    assert sanitized.exists()
    assert answer.exists()


def test_obfuscate_strict_with_leaks_returns_5_writes_nothing(
    tmp_path, monkeypatch, capsys,
):
    inp = tmp_path / "bigip.conf"
    inp.write_text(_LEAKY_CFG)
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--allow-incomplete",
        "--strict",
    ])
    assert code == EXIT_LEAK_DETECTED
    # Crash safety: no answer file, no sanitized output on strict abort.
    assert not answer.exists()
    assert not sanitized.exists()
    captured = capsys.readouterr()
    assert "leak detector" in captured.err.lower()
    assert _LEAKY_TOKEN in captured.err


def test_obfuscate_default_with_leaks_warns_and_proceeds(
    tmp_path, monkeypatch, capsys,
):
    inp = tmp_path / "bigip.conf"
    inp.write_text(_LEAKY_CFG)
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--allow-incomplete",
    ])
    assert code == EXIT_OK
    assert sanitized.exists()
    assert answer.exists()
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
    assert "leak" in captured.err.lower()
    assert "--strict" in captured.err  # surfaces the upgrade hint


def test_obfuscate_dry_run_reports_leaks(tmp_path, monkeypatch, capsys):
    inp = tmp_path / "bigip.conf"
    inp.write_text(_LEAKY_CFG)
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--answer-file", str(answer),
        "--dry-run",
    ])
    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert "leak detector" in captured.err.lower()
    assert _LEAKY_TOKEN in captured.err


def test_obfuscate_dry_run_clean_input_reports_clean(
    tmp_path, monkeypatch, capsys,
):
    inp = tmp_path / "bigip.conf"
    inp.write_text(_CLEAN_CFG)
    answer = tmp_path / "answers.enc"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--answer-file", str(answer),
        "--dry-run",
    ])
    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert "leak detector: clean" in captured.err


def test_obfuscate_strict_flag_appears_in_help(capsys):
    with pytest.raises(SystemExit):
        main(["obfuscate", "--help"])
    captured = capsys.readouterr()
    assert "--strict" in captured.out


def test_strict_with_diagnostics_fail_closed_prefers_exit_1(
    tmp_path, monkeypatch,
):
    # When both gates would fire — diagnostics non-empty AND --strict
    # would catch a leak — the diagnostics fail-closed (exit 1) wins
    # because it indicates a more fundamental scanner gap. Leak detection
    # in that case operates on incomplete substitution and shouldn't be
    # the reported error.
    inp = tmp_path / "bigip.conf"
    inp.write_text(_LEAKY_CFG)
    answer = tmp_path / "answers.enc"
    sanitized = tmp_path / "sanitized.conf"

    monkeypatch.setenv("VEIL_PASSPHRASE", "test")
    code = main([
        "obfuscate",
        "--input", str(inp),
        "--output", str(sanitized),
        "--answer-file", str(answer),
        "--strict",
        # NB: NOT passing --allow-incomplete here.
    ])
    assert code == EXIT_FAIL_CLOSED  # diag wins over strict
    assert not answer.exists()
    assert not sanitized.exists()
