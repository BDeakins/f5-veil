"""Pass 1.85c — ``sys syslog`` body walker.

Pass-1's main loop hands ``sys syslog`` off to
``_record_unknown_top_level`` because it isn't on the registered
top-level-kinds list, and the body is then brace-skipped. That leaves
remote-server bucket headers leaking verbatim — operator-chosen
server names that frequently encode datacenter / hostname / tenant
information (``/Common/loki``, ``/Common/splunk-prod-east``,
``/Common/siem-syslog-collector``).

This pass walks the token stream a second time, finds
``sys syslog { ... remote-servers { /Common/X { ... } /Common/Y { ... } } }``
shapes, and interns each bucket header path as ``Kind.SYSLOG_SERVER``.
The existing pass-2 WORD-token substitution machinery handles the
mutation (same model as ``Kind.PROFILE`` / ``Kind.SNMP_COMMUNITY``
etc.) — partition is interned the usual way (``/Common/`` exempt;
other partitions get a ``PARTITION_NNNN``), and the leaf renders as
``SYSLOG_SERVER_NNNN``.

Scope (v1.2)
------------
- Only WORD-shaped bucket headers (``/Common/loki``) are recognised.
  QSTRING-wrapped names are rare-to-nonexistent in real configs.
- Only the ``remote-servers`` sub-block is descended. Other
  attributes inside ``sys syslog`` (``console-log``, ``iso-date``,
  ``include``, etc.) are left to the unknown-block diagnostic.
- Inner bucket body is NOT walked for sub-fields — ``host <ip>`` is
  already caught by pass-1.5 IP literal discovery, and there are no
  secret-string fields in the standard schema. If a future BIG-IP
  release adds one, extend the walker.
- Multiple ``sys syslog`` blocks are handled (each its own
  ``remote-servers`` walk). Real configs typically have one.
"""

from __future__ import annotations

from .ledger import COMMON_PARTITION, Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_syslog(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``sys syslog { ... }`` shape,
    and intern each remote-server bucket path as ``Kind.SYSLOG_SERVER``.
    Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "syslog_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_sys_syslog(tokens, i):
            i += 1
            continue
        i = _walk_sys_syslog_body(tokens, i + 3, ledger)
    return


def _starts_sys_syslog(tokens: list[Token], i: int) -> bool:
    if i + 2 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "sys"
        and tokens[i + 1].kind == TokKind.WORD
        and tokens[i + 1].value == "syslog"
        and tokens[i + 2].kind == TokKind.LBRACE
    )


def _walk_sys_syslog_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``sys syslog { ... }`` body from ``start`` (token
    immediately after the opening ``{``). Descend into
    ``remote-servers`` when seen at depth 1. Returns the index just
    past the matching RBRACE."""
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
            and tk.value == "remote-servers"
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
        ):
            i = _walk_remote_servers_body(tokens, i + 2, ledger)
            continue
        i += 1
    return i


def _walk_remote_servers_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``remote-servers { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1 inside the block,
    every ``/partition/leaf`` WORD followed by ``{`` is a server
    bucket header — intern as ``Kind.SYSLOG_SERVER``. Bucket body is
    skipped (no interesting sub-fields). Returns the index just past
    the matching RBRACE."""
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
            _register_server_path(ledger, tk)
            i += 1
            continue
        i += 1
    return i


def _register_server_path(ledger: Ledger, path_tok: Token) -> None:
    parsed = _split_partition_path(path_tok.value)
    if parsed is None:
        return
    if _path_already_registered_elsewhere(ledger, path_tok.value):
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
        Kind.SYSLOG_SERVER, path_tok.value, discovery, partition=partition,
    )


def _path_already_registered_elsewhere(ledger: Ledger, path: str) -> bool:
    """Skip re-interning if the same path is already registered under
    a different more-specific kind. ``Kind.UNKNOWN`` does not count —
    pass-1 best-effort UNK entries are superseded. ``Kind.SYSLOG_SERVER``
    itself is exempt so a re-scan is idempotent."""
    for kind in Kind:
        if kind in (Kind.UNKNOWN, Kind.SYSLOG_SERVER):
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
