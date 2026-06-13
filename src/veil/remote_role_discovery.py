"""Pass 1.85 — ``auth remote-role role-info`` bucket-path discovery.

Pass-1's main loop hands ``auth remote-role`` off to
``_record_unknown_top_level`` because it isn't on the registered
top-level-kinds list, and the body is then brace-skipped. That leaves
the customer-defined role bucket paths inside ``role-info { ... }``
(``/Common/F5_Admins``, ``/Common/Domain_Admins``, etc.) leaking
verbatim into sanitized output.

This pass walks the token stream a second time, finds the
``auth remote-role { ... role-info { /Common/X { ... } /Common/Y { ... } } }``
shape, and interns each bucket header path as ``Kind.REMOTE_ROLE``. The
existing pass-2 WORD-token substitution machinery handles the mutation
(same model as ``Kind.PROFILE`` / ``Kind.POOL`` / etc.) — the partition
is interned the usual way (``/Common/`` exempt; other partitions get a
``PARTITION_NNNN``), and the leaf renders as ``REMOTE_ROLE_NNNN``.

Scope (v1.2)
------------
- Only WORD-shaped bucket headers (``/Common/F5_Admins``) are recognised.
  QSTRING-wrapped bucket names (``"/Common/role with spaces"``) are
  rare-to-nonexistent in real configs and deferred.
- Only the ``role-info`` sub-block is descended. Other attributes
  inside ``auth remote-role`` (e.g. ``default-role``) are left to the
  unknown-block diagnostic.
- Multiple ``auth remote-role`` blocks are handled (each its own
  ``role-info`` walk). Real configs typically have one but the walker
  doesn't depend on it.

Skip rules
----------
- If the bucket path is already registered under a non-UNKNOWN kind
  (which would only happen if a config had a name collision between a
  role bucket and a top-level object — illegal in BIG-IP but cheap to
  guard against), don't re-intern under REMOTE_ROLE. This mirrors the
  conflict guard in ``_record_unknown_top_level``.
- If the path is already registered as ``Kind.UNKNOWN``, that's stale
  best-effort state — the role bucket is more specific so prefer the
  REMOTE_ROLE registration. (In practice this never fires because
  ``_record_unknown_top_level`` doesn't descend into bodies, but it
  keeps the invariant explicit.)
"""

from __future__ import annotations

from .ledger import COMMON_PARTITION, Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_remote_roles(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every ``auth remote-role { ... role-info
    { ... } }`` shape, and intern each ``/partition/leaf`` bucket header
    as ``Kind.REMOTE_ROLE``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "remote_role_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_auth_remote_role(tokens, i):
            i += 1
            continue
        # Consume ``auth remote-role {`` and walk the body until the
        # matching RBRACE, descending into ``role-info { ... }`` when
        # encountered at depth 1.
        i += 3
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
                and tk.value == "role-info"
                and i + 1 < n
                and tokens[i + 1].kind == TokKind.LBRACE
            ):
                i = _walk_role_info_body(tokens, i + 2, ledger)
                # Reaching here means the role-info RBRACE has been
                # consumed; we are back at depth 1 of the remote-role
                # body.
                continue
            i += 1
    return


def _starts_auth_remote_role(tokens: list[Token], i: int) -> bool:
    if i + 2 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "auth"
        and tokens[i + 1].kind == TokKind.WORD
        and tokens[i + 1].value == "remote-role"
        and tokens[i + 2].kind == TokKind.LBRACE
    )


def _walk_role_info_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``role-info { ... }`` body from ``start`` (the token
    immediately after the opening ``{``). Register each
    ``/partition/leaf`` WORD at depth 1 (each one heads a role-bucket
    sub-block). Returns the index just past the matching RBRACE."""
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
            _register_role_bucket(ledger, tk)
            # Consume the path WORD; the LBRACE will be picked up on
            # the next iteration and bump depth so the bucket body is
            # skipped without further interning.
            i += 1
            continue
        i += 1
    return i


def _register_role_bucket(ledger: Ledger, path_tok: Token) -> None:
    parsed = _split_partition_path(path_tok.value)
    if parsed is None:
        # Malformed bucket header — skip rather than intern garbage.
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
        Kind.REMOTE_ROLE, path_tok.value, discovery, partition=partition
    )


def _path_already_registered_elsewhere(ledger: Ledger, path: str) -> bool:
    """Skip re-interning if the same path is already registered under a
    more specific kind. ``Kind.UNKNOWN`` does not count — pass-1 best-
    effort UNK entries are superseded by REMOTE_ROLE."""
    for kind in Kind:
        if kind in (Kind.UNKNOWN, Kind.REMOTE_ROLE):
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
