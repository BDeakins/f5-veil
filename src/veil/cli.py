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
from .scanner import scan, scan_many
from .substitute import reverse_substitute, substitute
from .ucs_archive import UcsExtractError, extract_ucs_configs, is_ucs_file


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
        "--input", required=True, action="append", metavar="PATH",
        help=(
            "Path to a BIG-IP config file (use '-' for stdin, single-"
            "file mode only). Repeat for multi-file mode (e.g. "
            "``--input bigip_base.conf --input bigip.conf``); base "
            "file goes first so its objects are in the ledger before "
            "main-file references resolve."
        ),
    )
    obf.add_argument(
        "--output",
        help=(
            "Sanitized output path for single-file mode (default: "
            "derived from --input; use '-' for stdout). Not valid in "
            "multi-file mode — use --output-dir."
        ),
    )
    obf.add_argument(
        "--output-dir",
        help=(
            "Output directory for multi-file mode. Each sanitized "
            "file is written to <dir>/<basename>. Not valid in single-"
            "file mode — use --output."
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
        "--input", required=True, action="append", metavar="PATH",
        help=(
            "Path to a sanitized config file (use '-' for stdin, "
            "single-file mode only). Repeat for multi-file mode; the "
            "filenames (basenames) must match the ``sources`` recorded "
            "in the answer file at obfuscation time."
        ),
    )
    deobf.add_argument(
        "--output",
        help=(
            "Restored output path for single-file mode (default: "
            "derived from --input; use '-' for stdout). Not valid in "
            "multi-file mode — use --output-dir."
        ),
    )
    deobf.add_argument(
        "--output-dir",
        help=(
            "Output directory for multi-file mode. Each restored file "
            "is written to <dir>/<basename>."
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
    input_args: list[str] = args.input

    # UCS detection happens before everything else: a UCS expands
    # into N virtual inputs (one per allowlisted config member), so
    # the multi/single decision and output-flag validation below
    # both need to see the expanded view.
    ucs_outcome = _maybe_expand_ucs_inputs(args, input_args)
    if isinstance(ucs_outcome, int):
        return ucs_outcome
    if ucs_outcome is not None:
        sources_data, ucs_skipped = ucs_outcome
        multi = True
        _err(
            f"UCS input: extracted {len(sources_data)} config "
            f"member(s); ignored {ucs_skipped} non-config member(s)"
        )
    else:
        multi = len(input_args) > 1

        # Validate input/output flag combinations before doing any work.
        err = _validate_obfuscate_output_flags(args, multi, input_args)
        if err is not None:
            return err

        # Read all inputs. Each entry is (label, content) where ``label``
        # is the original CLI argument (preserved for path-derivation and
        # error messages); the answer file gets the basenames only.
        try:
            sources_data = [(arg, _read_input(arg)) for arg in input_args]
        except OSError as exc:
            _err(f"could not read input: {exc!s}")
            return EXIT_IO_ERROR

    if multi:
        # ``scan_many`` shares the ledger across files; base file goes
        # first by convention so its objects are registered before
        # main-file references resolve.
        ledger, diag = scan_many(
            [(_label_for_answer_file(label), content)
             for label, content in sources_data]
        )
    else:
        ledger, diag = scan(sources_data[0][1])

    # Pass-2 per file against the merged ledger. The ``diag`` object
    # accumulates across calls (orphan-entry detection, etc.).
    sanitized_per_file: list[tuple[str, str]] = []
    for label, content in sources_data:
        san, diag = substitute(content, ledger, diag)
        sanitized_per_file.append((label, san))

    # Diagnostics and leak detection. Leak detector runs over the
    # concatenation so any cross-file leak surfaces; counts are
    # aggregated which is what the operator wants for fail-closed
    # decisions.
    diag_report = _diagnostics_summary(diag)
    warnings_report = _diagnostics_warnings_summary(diag)
    combined_sanitized = "\n".join(s for _, s in sanitized_per_file)
    leak_report = scan_leaks(combined_sanitized)

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
    if warnings_report:
        _err("informational warnings (round-trip remains exact):")
        _err(warnings_report)

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

    # Resolve output paths. Single-file uses ``--output`` (or derives
    # from the input); multi-file lays each sanitized file into
    # ``--output-dir`` keyed by basename.
    if multi:
        out_dir = Path(args.output_dir)
        output_paths = [
            str(out_dir / Path(label).name)
            for label, _ in sources_data
        ]
    else:
        output_paths = [args.output or _derive_obfuscate_output(input_args[0])]

    if not args.force:
        if answer_path.exists():
            _err(
                f"--answer-file already exists: {answer_path}. "
                f"Use --force to overwrite."
            )
            return EXIT_USER_ERROR
        for out in output_paths:
            if out != "-" and Path(out).exists():
                _err(
                    f"output already exists: {out}. "
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
    # Multi-file mode records the basenames so deobfuscate can verify
    # the operator is feeding in the matching set.
    answer_sources = (
        [_label_for_answer_file(label) for label, _ in sources_data]
        if multi else None
    )
    try:
        write_answer_file(
            answer_path, ledger, passphrase,
            diagnostics=diag, sources=answer_sources,
        )
    except AnswerFileError as exc:
        _err(f"writing answer file: {exc!s}")
        return EXIT_IO_ERROR

    if multi:
        try:
            Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _err(f"could not create --output-dir: {exc!s}")
            return EXIT_IO_ERROR

    try:
        for (_, san), out in zip(sanitized_per_file, output_paths):
            _write_output(out, san)
    except OSError as exc:
        _err(f"writing sanitized output: {exc!s}")
        return EXIT_IO_ERROR

    _err(
        f"obfuscated {len(ledger)} identifiers "
        f"across {len(ledger.counters)} kinds "
        f"({len(sources_data)} file(s))"
    )
    _err(f"answer file: {answer_path}")
    for out in output_paths:
        if out != "-":
            _err(f"sanitized:   {out}")
    return EXIT_OK


def _validate_obfuscate_output_flags(
    args: argparse.Namespace, multi: bool, input_args: list[str]
) -> int | None:
    """Cross-flag validation for obfuscate output options. Returns an
    exit code on error, ``None`` if everything's fine."""
    if multi:
        if args.output:
            _err("--output not valid in multi-file mode; use --output-dir")
            return EXIT_USER_ERROR
        if not args.output_dir and not args.dry_run:
            _err("--output-dir is required in multi-file mode")
            return EXIT_USER_ERROR
        if "-" in input_args:
            _err("stdin ('-') not supported in multi-file mode")
            return EXIT_USER_ERROR
    else:
        if args.output_dir:
            _err("--output-dir not valid in single-file mode; use --output")
            return EXIT_USER_ERROR
    return None


def _label_for_answer_file(input_arg: str) -> str:
    """Basename used as the per-file label in the answer-file
    ``sources`` list. Strips directory components so the answer file
    doesn't bake in the operator's working-directory layout."""
    return Path(input_arg).name


def _maybe_expand_ucs_inputs(
    args: argparse.Namespace, input_args: list[str]
) -> tuple[list[tuple[str, str]], int] | int | None:
    """If the operator passed a UCS archive as input, extract the
    allowlisted config members and return them as virtual
    ``(label, content)`` sources plus the skipped-member count.

    Return shapes:
    - ``None`` — no UCS in the input list; fall through to plain-file flow.
    - ``int`` (exit code) — UCS mode rejected for some reason; caller returns it.
    - ``(sources_data, skipped_count)`` — UCS mode engaged; caller uses these.

    UCS mode rejects:
    - ``--input`` mixed with a UCS and a plain file
    - more than one UCS in ``--input``
    - ``-`` (stdin) anywhere alongside a UCS
    - ``--output`` set (UCS always produces N files; use ``--output-dir``)
    - ``--output-dir`` absent (unless ``--dry-run``)
    - any :class:`UcsExtractError` from the extractor
    """
    ucs_inputs = [
        arg for arg in input_args
        if arg != "-" and is_ucs_file(arg)
    ]
    if not ucs_inputs:
        # No UCS detected. But if the operator named something with
        # a ``.ucs`` suffix that didn't pass the magic-byte check,
        # surface that early — a renamed plaintext file is almost
        # certainly an operator mistake.
        suspicious = [
            arg for arg in input_args
            if arg != "-" and Path(arg).suffix.lower() == ".ucs"
        ]
        if suspicious:
            _err(
                f"input has .ucs extension but is not a gzipped tar: "
                f"{suspicious!r}"
            )
            return EXIT_USER_ERROR
        return None

    if len(ucs_inputs) > 1:
        _err(
            f"multiple UCS inputs not supported (got {len(ucs_inputs)}); "
            f"process them one at a time"
        )
        return EXIT_USER_ERROR
    if len(input_args) > 1:
        _err(
            "UCS inputs cannot be mixed with plain --input files; "
            "the UCS already contains the full config set"
        )
        return EXIT_USER_ERROR
    if "-" in input_args:
        _err("stdin ('-') not supported with UCS input")
        return EXIT_USER_ERROR
    if args.output:
        _err(
            "--output not valid with UCS input; UCS expands to multiple "
            "files — use --output-dir"
        )
        return EXIT_USER_ERROR
    if not args.output_dir and not args.dry_run:
        _err("--output-dir is required with UCS input")
        return EXIT_USER_ERROR

    ucs_path = ucs_inputs[0]
    try:
        result = extract_ucs_configs(ucs_path)
    except UcsExtractError as exc:
        _err(f"{exc!s}")
        return EXIT_IO_ERROR

    # Use the archive-internal path as the label. The existing
    # multi-file machinery calls ``Path(label).name`` to derive the
    # per-file output name, which yields ``bigip_base.conf`` etc. —
    # exactly what we want in ``--output-dir``. The answer file's
    # ``sources`` list will likewise record basenames via
    # ``_label_for_answer_file``; that's adequate for session 1
    # (the four allowlisted basenames are unambiguous within the
    # config-member set).
    sources_data = [
        (member_name, content) for member_name, content in result.configs
    ]
    return sources_data, result.skipped_member_count


# ---------------------------------------------------------------------
# Deobfuscate command
# ---------------------------------------------------------------------


def _cmd_deobfuscate(args: argparse.Namespace) -> int:
    input_args: list[str] = args.input
    multi = len(input_args) > 1

    # Cross-flag validation mirrors the obfuscate side.
    if multi:
        if args.output:
            _err("--output not valid in multi-file mode; use --output-dir")
            return EXIT_USER_ERROR
        if not args.output_dir:
            _err("--output-dir is required in multi-file mode")
            return EXIT_USER_ERROR
        if "-" in input_args:
            _err("stdin ('-') not supported in multi-file mode")
            return EXIT_USER_ERROR
    else:
        if args.output_dir:
            _err("--output-dir not valid in single-file mode; use --output")
            return EXIT_USER_ERROR

    try:
        sanitized_inputs = [(arg, _read_input(arg)) for arg in input_args]
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
        ledger, _diag, recorded_sources = read_answer_file(
            args.answer_file, passphrase
        )
    except AnswerFileError as exc:
        if "decryption failed" in str(exc):
            _err(f"{exc!s} (wrong passphrase or tampered file)")
            return EXIT_DECRYPTION_FAILED
        _err(f"{exc!s}")
        return EXIT_IO_ERROR

    # If the answer file recorded a sources list (v1.2 multi-file),
    # require the operator to supply the matching set of inputs.
    # The basenames must match exactly and in the same order — order
    # carries semantic weight at obfuscation time (base file first), so
    # reusing the ledger against the wrong order is an operator error.
    if recorded_sources is not None:
        provided = [_label_for_answer_file(p) for p in input_args]
        if provided != recorded_sources:
            _err(
                "input filenames do not match the answer file's "
                f"recorded sources. Expected (in order): "
                f"{recorded_sources!r}; got: {provided!r}"
            )
            return EXIT_USER_ERROR

    # Resolve output paths.
    if multi:
        out_dir = Path(args.output_dir)
        output_paths = [
            str(out_dir / Path(label).name)
            for label, _ in sanitized_inputs
        ]
    else:
        output_paths = [args.output or _derive_deobfuscate_output(input_args[0])]

    if not args.force:
        for out in output_paths:
            if out != "-" and Path(out).exists():
                _err(
                    f"output already exists: {out}. "
                    f"Use --force to overwrite."
                )
                return EXIT_USER_ERROR

    if multi:
        try:
            Path(args.output_dir).mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _err(f"could not create --output-dir: {exc!s}")
            return EXIT_IO_ERROR

    try:
        for (_, sanitized), out in zip(sanitized_inputs, output_paths):
            restored = reverse_substitute(sanitized, ledger)
            _write_output(out, restored)
    except OSError as exc:
        _err(f"writing restored output: {exc!s}")
        return EXIT_IO_ERROR

    _err(
        f"deobfuscated using {len(ledger)} ledger entries "
        f"({len(sanitized_inputs)} file(s))"
    )
    for out in output_paths:
        if out != "-":
            _err(f"restored: {out}")
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


def _diagnostics_warnings_summary(diag: Diagnostics) -> str:
    """Diagnostics fields that are informational only — round-trip is
    intact and obfuscation is complete. Surfaced to the operator but
    never fail-closed."""
    lines: list[str] = []
    if diag.ipv4_subnet_collapsed:
        lines.append(
            f"  IPv4 source /24s collapsed into shared docs pool: "
            f"{len(diag.ipv4_subnet_collapsed)} "
            f"(round-trip exact; AI-side subnet co-location reduced)"
        )
        for net in diag.ipv4_subnet_collapsed[:5]:
            lines.append(f"    {net}")
        if len(diag.ipv4_subnet_collapsed) > 5:
            lines.append(
                f"    ... and {len(diag.ipv4_subnet_collapsed) - 5} more"
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
