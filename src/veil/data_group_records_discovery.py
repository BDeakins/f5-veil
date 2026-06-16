"""Pass 1.85l — Data-group records walker.

Walks the token stream for ``ltm data-group internal /Common/<name>
{ records { ... } }`` shapes (also matching ``ltm data-group
external`` for the rare case where an external data-group's records
are inlined). Inside the ``records`` body at depth 1, every
non-path bareword followed by ``{`` is a record bucket header —
operator-chosen lookup key. Interns each as ``Kind.DATA_GROUP_RECORD``.

Why this isn't just the FQDN walker
-----------------------------------
The FQDN walker (pass-2.0) skips public-TLD FQDNs by design to avoid
false-positives on legitimate public DNS references in monitor /
profile fields. Inside a data-group records body, every record key
is operator-chosen for iRule lookups — every entry IS identifying,
and the public-TLD restriction is wrong here. The context gate
replaces the TLD allowlist.

Shape gate
----------
Bucket headers must be non-path (do not start with ``/``) and
non-empty. Numeric IP-shape records (``10.0.0.1 { }``) are also
interned, accepting double-tokenization with pass-1.5's IPADDR
allocator; the substring-shadow exemption in
``_check_orphan_entries`` covers the dedup edge cases.

Scope (v1.2)
------------
- Both ``ltm data-group internal`` and ``ltm data-group external``
  top-level blocks are walked.
- Multiple data-groups in the source walked independently.
- Empty records bodies are no-ops.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_data_group_records(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every
    ``ltm data-group (internal|external) /path { records { ... } }``
    shape, and intern each record bucket bareword as
    ``Kind.DATA_GROUP_RECORD``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "data_group_records_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_data_group(tokens, i):
            i += 1
            continue
        # ``ltm data-group (internal|external) /path { ... }``
        # — header is 4 tokens up through the path, then LBRACE.
        # Skip past path WORD if present.
        j = i + 3  # past ``ltm`` ``data-group`` ``(internal|external)``
        if j < n and tokens[j].kind == TokKind.WORD:
            # path token (e.g. /Common/foo)
            j += 1
        if j < n and tokens[j].kind == TokKind.LBRACE:
            i = _walk_data_group_body(tokens, j + 1, ledger)
            continue
        i += 1
    return


def _starts_data_group(tokens: list[Token], i: int) -> bool:
    if i + 2 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "ltm"
        and tokens[i + 1].kind == TokKind.WORD
        and tokens[i + 1].value == "data-group"
        and tokens[i + 2].kind == TokKind.WORD
        and tokens[i + 2].value in ("internal", "external")
    )


def _walk_data_group_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk an ``ltm data-group <subtype> /path { ... }`` body. At
    depth 1, look for ``records { ... }`` and descend into it.
    Returns the index just past the matching outer RBRACE."""
    n = len(tokens)
    i = start
    depth = 1
    while i < n and depth > 0:
        tk = tokens[i]
        if tk.kind == TokKind.LBRACE:
            depth += 1
            i += 1
            continue
        if tk.kind == TokKind.RBRACE:
            depth -= 1
            i += 1
            continue
        if (
            depth == 1
            and tk.kind == TokKind.WORD
            and tk.value == "records"
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
        ):
            i = _walk_records_body(tokens, i + 2, ledger)
            continue
        i += 1
    return i


def _walk_records_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``records { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1, every non-path
    bareword followed by ``{`` is a record bucket header — intern as
    ``Kind.DATA_GROUP_RECORD``. Returns the index just past the
    matching RBRACE."""
    n = len(tokens)
    i = start
    depth = 1
    while i < n and depth > 0:
        tk = tokens[i]
        if tk.kind == TokKind.LBRACE:
            depth += 1
            i += 1
            continue
        if tk.kind == TokKind.RBRACE:
            depth -= 1
            i += 1
            continue
        if (
            depth == 1
            and tk.kind == TokKind.WORD
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
            and not tk.value.startswith("/")
        ):
            _intern_record_bucket(tk, ledger)
            i += 1
            continue
        i += 1
    return i


def _intern_record_bucket(name_tok: Token, ledger: Ledger) -> None:
    """Intern a record bucket bareword as ``Kind.DATA_GROUP_RECORD``
    with ``partition=None``. Idempotent."""
    if not name_tok.value:
        return
    if (Kind.DATA_GROUP_RECORD, name_tok.value) in ledger.by_original:
        return
    ref = Ref(
        byte_offset=name_tok.offset,
        length=name_tok.length,
        line=name_tok.line,
    )
    ledger.intern(
        Kind.DATA_GROUP_RECORD, name_tok.value, ref, partition=None,
    )
