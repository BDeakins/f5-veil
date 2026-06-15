"""Pass 1.85b — ``sys snmp`` body walker.

Pass-1's main loop hands ``sys snmp`` off to ``_record_unknown_top_level``
because it isn't on the registered top-level-kinds list, and the body is
then brace-skipped. That leaves a pile of sensitive content leaking
verbatim:

- Community bucket headers (``/Common/<name>``), which TMSH names with
  the community string embedded as ``i<community>_<index>``.
- Plaintext community-string values (``community-name <secret>``).
- Trap bucket headers (``/Common/<name>``), which TMSH commonly names
  with the trap-destination IP embedded as ``i<ip-underscored>_<index>``.
- ``community <secret>`` values inside trap buckets.
- Operator identity in ``sys-contact <value>`` (name / email).
- Device location in ``sys-location <value>``.

This pass walks the token stream a second time, finds ``sys snmp { ... }``
shapes, descends into the body once for ``communities { ... }``, once
for ``traps { ... }``, and field-walks ``sys-contact`` / ``sys-location``
at the top level of the body.

Bucket headers register as ``Kind.SNMP_COMMUNITY`` / ``Kind.SNMP_TRAP``
(path-shaped, substituted by pass-2's WORD-token full-match path —
same model as ``Kind.PROFILE`` etc.). Field values register as
``Kind.SNMP_COMMUNITY_SECRET`` / ``Kind.SYS_CONTACT`` /
``Kind.SYS_LOCATION`` with ``partition=None``; the substring-sub
machinery in pass-2 finds the bare value inside any WORD or QSTRING
content and renders the bare placeholder. The same secret used in
both ``community-name`` (under ``communities``) and ``community``
(under ``traps``) shares one placeholder because they intern under
the same ``(kind, original)`` key.

Scope (v1.2)
------------
- Only ``sys snmp`` is walked. Other unknown ``sys ...`` blocks are
  handled by their own walkers (``sys syslog`` — Phase 1b; ``sys
  sshd`` — Phase 1c).
- Multiple ``sys snmp`` blocks are handled (each walked independently).
  Real configs have one but the walker doesn't depend on it.
- Sub-blocks other than ``communities`` and ``traps`` are not descended
  (``users``, ``views``, etc. are deferred — extend the body walker
  when those surface as leaks).
"""

from __future__ import annotations

from .ledger import COMMON_PARTITION, Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_snmp(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``sys snmp { ... }`` shape, and
    intern community / trap bucket paths and their inner secret /
    free-text field values. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "snmp_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_sys_snmp(tokens, i):
            i += 1
            continue
        i = _walk_sys_snmp_body(tokens, i + 3, ledger)
    return


def _starts_sys_snmp(tokens: list[Token], i: int) -> bool:
    if i + 2 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "sys"
        and tokens[i + 1].kind == TokKind.WORD
        and tokens[i + 1].value == "snmp"
        and tokens[i + 2].kind == TokKind.LBRACE
    )


def _walk_sys_snmp_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``sys snmp { ... }`` body from ``start`` (token immediately
    after the opening ``{``). Descend into ``communities`` and ``traps``
    when seen at depth 1; intern ``sys-contact`` / ``sys-location``
    field values at depth 1. Returns the index just past the matching
    RBRACE."""
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
        if depth == 1 and tk.kind == TokKind.WORD:
            if (
                tk.value == "communities"
                and i + 1 < n
                and tokens[i + 1].kind == TokKind.LBRACE
            ):
                i = _walk_bucket_block(
                    tokens, i + 2, ledger,
                    bucket_kind=Kind.SNMP_COMMUNITY,
                    secret_field="community-name",
                )
                continue
            if (
                tk.value == "traps"
                and i + 1 < n
                and tokens[i + 1].kind == TokKind.LBRACE
            ):
                i = _walk_bucket_block(
                    tokens, i + 2, ledger,
                    bucket_kind=Kind.SNMP_TRAP,
                    secret_field="community",
                )
                continue
            if tk.value == "sys-contact":
                i = _intern_freetext_field(
                    tokens, i, ledger, Kind.SYS_CONTACT,
                )
                continue
            if tk.value == "sys-location":
                i = _intern_freetext_field(
                    tokens, i, ledger, Kind.SYS_LOCATION,
                )
                continue
        i += 1
    return i


def _walk_bucket_block(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
    *,
    bucket_kind: Kind,
    secret_field: str,
) -> int:
    """Walk a ``communities { ... }`` or ``traps { ... }`` body from
    ``start`` (token immediately after the opening ``{``). At depth 1
    inside the block, every ``/partition/leaf`` WORD followed by ``{``
    is a bucket header — intern as ``bucket_kind`` and descend into the
    bucket body to find ``secret_field <value>`` lines. Returns the
    index just past the matching RBRACE."""
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
            and tk.value.startswith("/")
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
        ):
            _register_bucket_path(ledger, tk, bucket_kind)
            # Descend into bucket body to find the secret field.
            i = _walk_bucket_body_for_secret(
                tokens, i + 2, ledger, secret_field,
            )
            continue
        i += 1
    return i


def _walk_bucket_body_for_secret(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
    secret_field: str,
) -> int:
    """Inside a single bucket body, find a ``<secret_field> <value>``
    line at depth 1 and intern the value as
    ``Kind.SNMP_COMMUNITY_SECRET``. Returns the index just past the
    matching RBRACE for the bucket body."""
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
            and tk.value == secret_field
            and i + 1 < n
        ):
            _intern_freetext_value(
                tokens[i + 1], ledger, Kind.SNMP_COMMUNITY_SECRET,
            )
            i += 2
            continue
        i += 1
    return i


def _intern_freetext_field(
    tokens: list[Token],
    field_idx: int,
    ledger: Ledger,
    kind: Kind,
) -> int:
    """Intern the value token immediately after ``tokens[field_idx]``
    (a field-name WORD like ``sys-contact``) as ``kind``. The value may
    be a QSTRING or a single WORD. Returns the index just past the
    consumed pair."""
    n = len(tokens)
    if field_idx + 1 >= n:
        return field_idx + 1
    value_tok = tokens[field_idx + 1]
    _intern_freetext_value(value_tok, ledger, kind)
    return field_idx + 2


def _intern_freetext_value(
    value_tok: Token,
    ledger: Ledger,
    kind: Kind,
) -> None:
    """Intern a free-text value token (QSTRING or WORD) as ``kind``
    with ``partition=None``. QSTRING contents are stored without the
    surrounding double quotes so the substring-sub machinery finds
    the bare text inside any token. Empty values are skipped."""
    if value_tok.kind == TokKind.QSTRING:
        # QSTRING token value includes the surrounding quotes; strip them.
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(kind, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        if not value_tok.value:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(kind, value_tok.value, ref, partition=None)
        return
    # Other token kinds (LBRACE, RBRACE, COMMENT) shouldn't appear as
    # a field value in well-formed TMSH; silently skip.


def _register_bucket_path(
    ledger: Ledger,
    path_tok: Token,
    bucket_kind: Kind,
) -> None:
    parsed = _split_partition_path(path_tok.value)
    if parsed is None:
        return
    if _path_already_registered_elsewhere(ledger, path_tok.value, bucket_kind):
        return
    partition, _leaf = parsed
    discovery = Ref(
        byte_offset=path_tok.offset,
        length=path_tok.length,
        line=path_tok.line,
    )
    part_discovery = Ref(
        byte_offset=path_tok.offset + 1,
        length=len(partition),
        line=path_tok.line,
    )
    if partition != COMMON_PARTITION:
        ledger.intern_partition(partition, part_discovery)
    ledger.intern(
        bucket_kind, path_tok.value, discovery, partition=partition,
    )


def _path_already_registered_elsewhere(
    ledger: Ledger,
    path: str,
    bucket_kind: Kind,
) -> bool:
    """Skip re-interning if the same path is already registered under a
    different more-specific kind. ``Kind.UNKNOWN`` does not count —
    pass-1 best-effort UNK entries are superseded. The bucket_kind
    itself is also exempt so a re-scan is idempotent."""
    for kind in Kind:
        if kind in (Kind.UNKNOWN, bucket_kind):
            continue
        if (kind, path) in ledger.by_original:
            return True
    return False


def _split_partition_path(path: str) -> tuple[str, str] | None:
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
