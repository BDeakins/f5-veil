"""Pass 1.85f — ``client-policy`` nested bucket walker.

``client-policy { ... }`` lives inside an APM profile family body
(observed: ``apm profile connectivity``). The enclosing profile is
brace-skipped by pass-1's main loop (whether registered as
``Kind.APM_PROFILE`` or falling through to ``Kind.UNKNOWN``), so the
nested ``<bucket-name> { ... }`` bareword leaks verbatim. Bucket
names are typically derived from the parent connectivity profile
name itself, which embeds customer identity.

Mirrors ``cert_keychain_discovery`` in structure: global scan for the
``client-policy WORD LBRACE`` shape, descend into the body, intern
each non-path bareword at depth 1 as ``Kind.CLIENT_POLICY``.
Substring-sub substitution in pass-2 then finds the bareword inside
any QSTRING / WORD content and replaces with bare-placeholder
``CLIENT_POLICY_NNNN``.

Inner bucket-body fields (``ec { reuse-winlogon-creds true }`` etc.)
are NOT walked — they're generic protocol settings with no
customer-identifying content.

Scope (v1.2)
------------
- Global scan: ``client-policy`` is not a top-level kind. Observed
  only inside apm profile connectivity in the real corpus.
- Only WORD-shaped bucket identifiers are interned.
- Multiple ``client-policy`` blocks (one per profile) walked
  independently.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_client_policies(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream globally, find every
    ``client-policy { ... }`` shape, and intern each nested bucket
    bareword as ``Kind.CLIENT_POLICY``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "client_policy_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_client_policy(tokens, i):
            i += 1
            continue
        i = _walk_client_policy_body(tokens, i + 2, ledger)
    return


def _starts_client_policy(tokens: list[Token], i: int) -> bool:
    if i + 1 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "client-policy"
        and tokens[i + 1].kind == TokKind.LBRACE
    )


def _walk_client_policy_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``client-policy { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1 inside the block,
    every non-path bareword WORD followed by ``{`` is a bucket header
    — intern as ``Kind.CLIENT_POLICY``. Returns the index just past
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
            and i + 1 < n
            and tokens[i + 1].kind == TokKind.LBRACE
            and not tk.value.startswith("/")
        ):
            _intern_bucket_name(tk, ledger)
            i += 1
            continue
        i += 1
    return i


def _intern_bucket_name(name_tok: Token, ledger: Ledger) -> None:
    """Intern a ``client-policy`` bucket-name bareword as
    ``Kind.CLIENT_POLICY`` with ``partition=None``. Idempotent."""
    if not name_tok.value:
        return
    if (Kind.CLIENT_POLICY, name_tok.value) in ledger.by_original:
        return
    ref = Ref(
        byte_offset=name_tok.offset,
        length=name_tok.length,
        line=name_tok.line,
    )
    ledger.intern(
        Kind.CLIENT_POLICY, name_tok.value, ref, partition=None,
    )
