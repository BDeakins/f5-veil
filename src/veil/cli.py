"""f5-veil command-line interface.

Two subcommands:
- ``veil obfuscate``  — scan, substitute, write answer file (encrypted),
  then write sanitized output. Order matters: answer file always lands
  on disk *before* the sanitized output, so a crash mid-pipeline never
  produces a sanitized file orphaned from its decryption key.
- ``veil deobfuscate`` — read answer file, decrypt, reverse-substitute
  the sanitized input back to original identifiers.

Exit codes
----------
- 0 — success
- 1 — fail-closed (diagnostics non-empty without ``--allow-incomplete``)
- 2 — user / argument error (missing required flag, file already exists)
- 3 — I/O error (read or write failure)
- 4 — decryption failed (wrong passphrase or tampered answer file)
- 5 — leak detector tripped under ``--strict`` (sanitized output contained
  one or more substitution survivors that look like customer data)
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .answer_file import AnswerFileError, read_answer_file, write_answer_file
from .diagnostics import Diagnostics
from .leak_detector import LeakReport, scan_leaks
from .ledger import Ledger
from .scanner import scan
from .substitute import reverse_substitute, substitute


EXIT_OK = 0
EXIT_FAIL_CLOSED = 1
EXIT_USER_ERROR = 2
EXIT_IO_ERROR = 3
EXIT_DECRYPTION_FAILED = 4
EXIT_LEAK_DETECTED = 5


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return EXIT_USER_ERROR
    return args.func(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil",
        description=(
            "F5 BIG-IP config obfuscator/de-obfuscator for safe AI use."
        ),
    )
    sub = parser.add_subparsers(
        dest="command", metavar="{obfuscate,deobfuscate}"
    )

    obf = sub.add_parser("obfuscate", help="Obfuscate a bigip.conf")
    obf.add_argument(
        "--input", required=True,
        help="Path to bigip.conf (use '-' for stdin)",
    )
    obf.add_argument(
        "--output",
        help=(
            "Sanitized output path (default: derived from --input; "
            "use '-' for stdout)"
        ),
    )
    obf.add_argument(
        "--answer-file",
        help=(
            "Path to write the encrypted answer file. Required unless "
            "--dry-run."
        ),
    )
    obf.add_argument(
        "--passphrase-file",
        help=(
            "Read passphrase from first line of file (overrides "
            "VEIL_PASSPHRASE env var)."
        ),
    )
    obf.add_argument(
        "--dry-run", action="store_true",
        help="Scan and substitute in-memory; print summary; write nothing.",
    )
    obf.add_argument(
        "--allow-incomplete", action="store_true",
        help=(
            "Proceed even when diagnostics are non-empty. Default is to "
            "fail closed so partial obfuscation never lands on disk."
        ),
    )
    obf.add_argument(
        "--force", action="store_true",
        help="Overwrite existing --output and --answer-file paths.",
    )
    obf.add_argument(
        "--strict", action="store_true",
        help=(
            "Run the post-substitution leak detector and abort with exit "
            "code 5 if any potential leak survives. Without --strict, "
            "leaks are warned-to-stderr but obfuscation proceeds."
        ),
    )
    obf.set_defaults(func=_cmd_obfuscate)

    deobf = sub.add_parser(
        "deobfuscate", help="Deobfuscate a sanitized config"
    )
    deobf.add_argument(
        "--input", required=True,
        help="Path to sanitized config (use '-' for stdin)",
    )
    deobf.add_argument(
        "--output",
        help=(
            "Restored output path (default: derived from --input; "
            "use '-' for stdout)"
        ),
    )
    deobf.add_argument(
        "--answer-file", required=True,
        help="Path to the encrypted answer file.",
    )
    deobf.add_argument(
        "--passphrase-file",
        help=(
            "Read passphrase from first line of file (overrides "
            "VEIL_PASSPHRASE env var)."
        ),
    )
    deobf.add_argument(
        "--force", action="store_true",
        help="Overwrite existing --output path.",
    )
    deobf.set_defaults(func=_cmd_deobfuscate)

    return parser


# ---------------------------------------------------------------------
# Obfuscate command
# ---------------------------------------------------------------------


def _cmd_obfuscate(args: argparse.Namespace) -> int:
    try:
        src = _read_input(args.input)
    except OSError as exc:
        _err(f"could not read input: {exc!s}")
        return EXIT_IO_ERROR

    ledger, diag = scan(src)
    sanitized, diag = substitute(src, ledger, diag)
    diag_report = _diagnostics_summary(diag)
    leak_report = scan_leaks(sanitized)

    if args.dry_run:
        _err(_dry_run_summary(ledger, diag, leak_report))
        return EXIT_OK

    if diag_report and not args.allow_incomplete:
        _err("diagnostics non-empty; refusing to write sanitized output.")
        _err("use --allow-incomplete to proceed anyway.")
        _err(diag_report)
        return EXIT_FAIL_CLOSED
    if diag_report:
        _err("warning: proceeding with --allow-incomplete:")
        _err(diag_report)

    if leak_report:
        leak_summary = _leak_report_summary(leak_report)
        if args.strict:
            _err(
                f"leak detector found {len(leak_report)} potential leak(s); "
                f"--strict set, aborting before write:"
            )
            _err(leak_summary)
            return EXIT_LEAK_DETECTED
        _err(
            f"warning: leak detector found {len(leak_report)} potential "
            f"leak(s) (pass --strict to fail on this):"
        )
        _err(leak_summary)

    if not args.answer_file:
        _err("--answer-file is required (unless --dry-run)")
        return EXIT_USER_ERROR

    answer_path = Path(args.answer_file)
    output_arg = args.output or _derive_obfuscate_output(args.input)

    if not args.force:
        if answer_path.exists():
            _err(
                f"--answer-file already exists: {answer_path}. "
                f"Use --force to overwrite."
            )
            return EXIT_USER_ERROR
        if output_arg != "-" and Path(output_arg).exists():
            _err(
                f"--output already exists: {output_arg}. "
                f"Use --force to overwrite."
            )
            return EXIT_USER_ERROR

    try:
        passphrase = _get_passphrase(args.passphrase_file, confirm=True)
    except (KeyboardInterrupt, EOFError):
        _err("\npassphrase input cancelled")
        return EXIT_USER_ERROR
    except ValueError as exc:
        _err(f"{exc!s}")
        return EXIT_USER_ERROR
    except OSError as exc:
        _err(f"could not read passphrase file: {exc!s}")
        return EXIT_IO_ERROR

    # Crash safety: answer file BEFORE sanitized output (locked).
    try:
        write_answer_file(answer_path, ledger, passphrase, diagnostics=diag)
    except AnswerFileError as exc:
        _err(f"writing answer file: {exc!s}")
        return EXIT_IO_ERROR

    try:
        _write_output(output_arg, sanitized)
    except OSError as exc:
        _err(f"writing sanitized output: {exc!s}")
        return EXIT_IO_ERROR

    _err(
        f"obfuscated {len(ledger)} identifiers "
        f"across {len(ledger.counters)} kinds"
    )
    _err(f"answer file: {answer_path}")
    if output_arg != "-":
        _err(f"sanitized:   {output_arg}")
    return EXIT_OK


# ---------------------------------------------------------------------
# Deobfuscate command
# ---------------------------------------------------------------------


def _cmd_deobfuscate(args: argparse.Namespace) -> int:
    try:
        sanitized = _read_input(args.input)
    except OSError as exc:
        _err(f"could not read input: {exc!s}")
        return EXIT_IO_ERROR

    try:
        passphrase = _get_passphrase(args.passphrase_file, confirm=False)
    except (KeyboardInterrupt, EOFError):
        _err("\npassphrase input cancelled")
        return EXIT_USER_ERROR
    except ValueError as exc:
        _err(f"{exc!s}")
        return EXIT_USER_ERROR
    except OSError as exc:
        _err(f"could not read passphrase file: {exc!s}")
        return EXIT_IO_ERROR

    try:
        ledger, _diag = read_answer_file(args.answer_file, passphrase)
    except AnswerFileError as exc:
        if "decryption failed" in str(exc):
            _err(f"{exc!s} (wrong passphrase or tampered file)")
            return EXIT_DECRYPTION_FAILED
        _err(f"{exc!s}")
        return EXIT_IO_ERROR

    restored = reverse_substitute(sanitized, ledger)

    output_arg = args.output or _derive_deobfuscate_output(args.input)
    if (
        not args.force
        and output_arg != "-"
        and Path(output_arg).exists()
    ):
        _err(
            f"--output already exists: {output_arg}. "
            f"Use --force to overwrite."
        )
        return EXIT_USER_ERROR

    try:
        _write_output(output_arg, restored)
    except OSError as exc:
        _err(f"writing restored output: {exc!s}")
        return EXIT_IO_ERROR

    _err(f"deobfuscated using {len(ledger)} ledger entries")
    if output_arg != "-":
        _err(f"restored: {output_arg}")
    return EXIT_OK


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _read_input(input_arg: str) -> str:
    if input_arg == "-":
        return sys.stdin.read()
    return Path(input_arg).read_text(encoding="utf-8")


def _write_output(output_arg: str, content: str) -> None:
    if output_arg == "-":
        sys.stdout.write(content)
        sys.stdout.flush()
        return
    Path(output_arg).write_text(content, encoding="utf-8")


def _derive_obfuscate_output(input_arg: str) -> str:
    if input_arg == "-":
        return "-"
    p = Path(input_arg)
    if p.suffix:
        return str(p.with_name(p.stem + ".sanitized" + p.suffix))
    return str(p) + ".sanitized"


def _derive_deobfuscate_output(input_arg: str) -> str:
    if input_arg == "-":
        return "-"
    p = Path(input_arg)
    if not p.suffix:
        return str(p) + ".restored"
    stem = p.stem
    if stem.endswith(".sanitized"):
        stem = stem[: -len(".sanitized")] + ".restored"
    else:
        stem = stem + ".restored"
    return str(p.with_name(stem + p.suffix))


def _get_passphrase(
    passphrase_file: str | None, *, confirm: bool
) -> bytes:
    if passphrase_file:
        return _read_passphrase_file(passphrase_file)
    env = os.environ.get("VEIL_PASSPHRASE")
    if env:
        _err(
            "warning: reading passphrase from VEIL_PASSPHRASE env var "
            "(env vars leak via process listings; prefer "
            "--passphrase-file or interactive)"
        )
        return env.encode("utf-8")
    return _prompt_passphrase(confirm=confirm)


def _read_passphrase_file(path: str) -> bytes:
    p = Path(path)
    if os.name != "nt":
        try:
            mode = p.stat().st_mode & 0o777
            if mode & 0o077:
                _err(
                    f"warning: --passphrase-file is group/world-readable "
                    f"(mode {mode:o}); recommend chmod 600"
                )
        except OSError:
            pass  # stat failure handled by the read below
    with open(p, "rb") as f:
        line = f.readline()
    return line.rstrip(b"\r\n")


def _prompt_passphrase(*, confirm: bool) -> bytes:
    pw1 = getpass.getpass("passphrase: ")
    if not pw1:
        raise ValueError("empty passphrase")
    if confirm:
        pw2 = getpass.getpass("confirm:    ")
        if pw1 != pw2:
            raise ValueError("passphrases do not match")
    return pw1.encode("utf-8")


def _diagnostics_summary(diag: Diagnostics) -> str:
    lines: list[str] = []
    if diag.unknown_top_level:
        lines.append(
            f"  unknown top-level blocks: {len(diag.unknown_top_level)}"
        )
        for sig, line in diag.unknown_top_level[:5]:
            lines.append(f"    {sig} (line {line})")
        if len(diag.unknown_top_level) > 5:
            lines.append(
                f"    ... and {len(diag.unknown_top_level) - 5} more"
            )
    if diag.malformed_paths:
        lines.append(f"  malformed paths: {len(diag.malformed_paths)}")
        for kind, path, line in diag.malformed_paths[:5]:
            lines.append(f"    {kind} {path!r} (line {line})")
        if len(diag.malformed_paths) > 5:
            lines.append(
                f"    ... and {len(diag.malformed_paths) - 5} more"
            )
    if diag.unredacted_description:
        lines.append(
            f"  unredacted descriptions: "
            f"{len(diag.unredacted_description)}"
        )
    if diag.qstring_contains_identifier:
        lines.append(
            f"  qstrings containing identifiers: "
            f"{len(diag.qstring_contains_identifier)}"
        )
    if diag.orphan_entries:
        lines.append(
            f"  orphan ledger entries: {len(diag.orphan_entries)}"
        )
        for ph in diag.orphan_entries[:5]:
            lines.append(f"    {ph}")
        if len(diag.orphan_entries) > 5:
            lines.append(
                f"    ... and {len(diag.orphan_entries) - 5} more"
            )
    return "\n".join(lines)


def _dry_run_summary(
    ledger: Ledger, diag: Diagnostics, leak_report: LeakReport,
) -> str:
    lines = ["dry-run summary:"]
    lines.append(f"  total ledger entries: {len(ledger)}")
    for kind, count in sorted(
        ledger.counters.items(), key=lambda kv: kv[0].value
    ):
        lines.append(f"    {kind.value}: {count}")
    diag_report = _diagnostics_summary(diag)
    if diag_report:
        lines.append("diagnostics:")
        lines.append(diag_report)
    else:
        lines.append("diagnostics: clean")
    if leak_report:
        lines.append(f"leak detector: {len(leak_report)} potential leak(s)")
        lines.append(_leak_report_summary(leak_report))
    else:
        lines.append("leak detector: clean")
    return "\n".join(lines)


def _leak_report_summary(report: LeakReport) -> str:
    lines: list[str] = []
    for leak in report.leaks[:20]:
        lines.append(
            f"  line {leak.line}:{leak.col} [{leak.kind.value}] "
            f"{leak.token} ({leak.reason})"
        )
    if len(report.leaks) > 20:
        lines.append(f"  ... and {len(report.leaks) - 20} more")
    return "\n".join(lines)
