"""bigip.conf pass-1 scanner — top-level object discovery.

Walks the token stream from :func:`veil.tokenizer.tokenize` and registers
every named top-level object in the ledger. Inside a block body the
scanner tracks brace depth and ignores token content — body substitution
is the concern of pass 2, not pass 1.

Tracer-bullet object scope (v0.1):
- ``ltm pool /<partition>/<name> { ... }``
- ``ltm virtual /<partition>/<name> { ... }``
- ``ltm node /<partition>/<name> { ... }``
- ``ltm monitor <subtype> /<partition>/<name> { ... }``
- ``ltm rule /<partition>/<name> { ... }``
- The partition path itself (``/Common/`` is exempt; everything else
  gets a ``PARTITION_NNNN`` placeholder).

Known gaps deferred to follow-up PRs (flagged by TEMPER, owned by HAMMER
to address before pass-2 substitution lands):
- TMSH ``description { brace-quoted string }`` is parsed as an opening
  LBRACE by the current tokenizer. Pass 1 never traverses descriptions
  so this is currently harmless, but pass-2 substitution must avoid
  treating a brace-quoted description body as a nested block.
- iRule (Tcl) bodies are brace-counted but not Tcl-lexed. Pass-2
  substitution inside an iRule body must skip Tcl strings and ``#``
  comments instead of blindly rewriting every match.
- Unknown ``ltm <subtype>`` headers (e.g. ``ltm dns ...``) are silently
  skipped — by design until the kind list expands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize

_TWO_WORD_KINDS = MappingProxyType({
    "pool": Kind.POOL,
    "virtual": Kind.VS,
    "node": Kind.NODE,
    "rule": Kind.IRULE,
})

# Top-level TMSH module words. Anything seen at depth 0 that starts with
# one of these but is not registered as a known kind goes into the
# scanner's Diagnostics. The leak detector (later PR) reads diagnostics
# to fail closed instead of silently passing customer-identifying data
# through unrecognised blocks.
_KNOWN_MODULES = frozenset({"ltm", "gtm", "net", "sys", "auth", "apm",
                            "asm", "pem", "security", "wom", "ilx", "cli"})


@dataclass
class Diagnostics:
    """Things pass 1 saw but did not register. The obfuscate command MUST
    refuse to write sanitized output while either list is non-empty (or
    the operator must explicitly opt-in to incompleteness)."""

    unknown_top_level: list[tuple[str, int]] = field(default_factory=list)
    """List of (header_signature, line) for top-level blocks the scanner
    did not recognise — e.g. ``('gtm wideip', 42)`` or ``('ltm dns', 17)``.
    Header signature is the first two words for ``ltm`` and similar
    module/subtype pairs; pure-module blocks log just the module word."""

    malformed_paths: list[tuple[str, str, int]] = field(default_factory=list)
    """List of (kind, raw_path, line) for object headers of a *recognised*
    kind whose path token is not a well-formed ``/Partition/leaf`` — e.g.
    ``('POOL', '/Common/', 5)``. Surfacing rather than silently dropping
    is the CRUCIBLE C-1 fail-closed requirement."""


def scan(
    src: str,
    ledger: Ledger | None = None,
    diagnostics: Diagnostics | None = None,
) -> tuple[Ledger, Diagnostics]:
    """Pass 1: discover named objects and populate the ledger.

    Returns ``(ledger, diagnostics)``. ``diagnostics.unknown_top_level``
    lists every top-level block the scanner did not register — pass 2
    callers MUST inspect this and fail closed on non-empty results unless
    the operator has explicitly opted into partial obfuscation.
    """
    if ledger is None:
        ledger = Ledger()
    if diagnostics is None:
        diagnostics = Diagnostics()
    tokens = list(tokenize(src))
    i = 0
    depth = 0
    while i < len(tokens):
        tok = tokens[i]
        if depth > 0:
            if tok.kind == TokKind.LBRACE:
                depth += 1
            elif tok.kind == TokKind.RBRACE:
                depth -= 1
            i += 1
            continue
        if tok.kind != TokKind.WORD:
            i += 1
            continue
        consumed = _try_match_object(tokens, i, ledger, diagnostics)
        if consumed > 0:
            i += consumed
            depth = 1
            continue
        # Unrecognised top-level header — record it and skip the block so
        # pass 2 callers can decide whether to fail closed.
        consumed = _record_unknown_top_level(tokens, i, diagnostics)
        if consumed > 0:
            i += consumed
            depth = 1
            continue
        i += 1
    return ledger, diagnostics


def _record_unknown_top_level(
    tokens: list[Token],
    i: int,
    diagnostics: Diagnostics,
) -> int:
    """If ``tokens[i:]`` looks like an unrecognised top-level block
    header (``<module> ... {``), log it to diagnostics and return the
    tokens consumed up to and including the opening ``{``. Else 0."""
    first = tokens[i].value
    if first not in _KNOWN_MODULES:
        return 0
    # Walk forward until we hit an LBRACE or run out of tokens.
    j = i + 1
    while j < len(tokens) and tokens[j].kind != TokKind.LBRACE:
        j += 1
    if j >= len(tokens):
        return 0
    # Build a short header signature for diagnostics (first 1-2 words).
    if j - i >= 2 and tokens[i + 1].kind == TokKind.WORD:
        signature = f"{first} {tokens[i + 1].value}"
    else:
        signature = first
    diagnostics.unknown_top_level.append((signature, tokens[i].line))
    return (j - i) + 1  # consume through the LBRACE


def _try_match_object(
    tokens: list[Token],
    i: int,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """If ``tokens[i:]`` matches an object header, register it (or log a
    malformed-path diagnostic) and return the number of tokens consumed
    including the opening ``{``. Else 0."""
    if i + 3 >= len(tokens):
        return 0
    if tokens[i].value != "ltm":
        return 0
    second = tokens[i + 1].value
    if second == "monitor":
        # ltm monitor <subtype> /path {
        if i + 4 >= len(tokens):
            return 0
        path_tok = tokens[i + 3]
        lbrace = tokens[i + 4]
        if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
            return 0
        _register(ledger, Kind.MON, path_tok, diagnostics)
        return 5
    kind = _TWO_WORD_KINDS.get(second)
    if kind is None:
        return 0
    # ltm <kind> /path {
    path_tok = tokens[i + 2]
    lbrace = tokens[i + 3]
    if path_tok.kind != TokKind.WORD or lbrace.kind != TokKind.LBRACE:
        return 0
    _register(ledger, kind, path_tok, diagnostics)
    return 4


def _split_partition_path(path: str) -> tuple[str, str] | None:
    """Parse ``/Partition/leaf`` -> ``(partition, leaf)``. Returns ``None``
    if the value is not a well-formed TMSH path (no partition, empty
    partition, or empty leaf — any of which would let a malformed config
    slip a garbage entry into the ledger)."""
    if not path.startswith("/"):
        return None
    parts = path.split("/")
    if len(parts) < 3:
        return None
    partition = parts[1]
    leaf = "/".join(parts[2:])
    if not partition or not leaf:
        return None
    return partition, leaf


def _register(
    ledger: Ledger,
    kind: Kind,
    path_tok: Token,
    diagnostics: Diagnostics,
) -> None:
    parsed = _split_partition_path(path_tok.value)
    if parsed is None:
        # Malformed path on a recognised object kind — fail closed by
        # surfacing to diagnostics rather than interning garbage.
        diagnostics.malformed_paths.append(
            (kind.value, path_tok.value, path_tok.line)
        )
        return
    partition, _leaf = parsed
    discovery = Ref(
        byte_offset=path_tok.offset,
        length=path_tok.length,
        line=path_tok.line,
    )
    # The partition substring sits inside the path token's byte span;
    # compute its absolute byte offset (skip the leading '/').
    part_discovery = Ref(
        byte_offset=path_tok.offset + 1,
        length=len(partition),
        line=path_tok.line,
    )
    ledger.intern_partition(partition, part_discovery)
    ledger.intern(kind, path_tok.value, discovery, partition=partition)
