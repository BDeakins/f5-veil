"""Pass 1.85e — ``cert-key-chain`` nested bucket walker.

``cert-key-chain`` lives inside an ``ltm profile client-ssl`` body.
``ltm profile client-ssl`` IS a registered top-level kind
(``Kind.PROFILE``) — so pass-1's main loop enters depth>0 and
brace-skips the entire body. The nested
``cert-key-chain { <bucket-name> { ... } }`` is part of that skipped
content; the bucket-name bareword (typically composed from cert and
root-CA filenames, frequently encoding the customer's
organisation / FQDN) leaks verbatim.

This walker scans the token stream globally for the
``cert-key-chain WORD LBRACE`` shape — wherever it appears, regardless
of enclosing block depth — descends into the bucket-list body, and
interns each ``<bucket-name>`` bareword at depth 1 as
``Kind.CERT_KEY_CHAIN``. Substring-sub substitution in pass-2 then
finds the bareword inside any QSTRING / WORD content and replaces
with bare-placeholder ``CERT_KEY_CHAIN_NNNN``.

Inner field values (``cert /Common/foo``, ``chain /Common/bar``,
``key /Common/baz``) are NOT walked here — those reference cert
paths registered as ``Kind.UNKNOWN`` by ``sys file ssl-*`` top-level
blocks elsewhere in the config, and substitute via the existing UNK
substring-sub path.

Scope (v1.2)
------------
- Global scan: ``cert-key-chain`` is not a top-level kind, so finding
  it anywhere in the stream is safe — TMSH does not reuse the name
  in any other valid context.
- Only WORD-shaped bucket identifiers are interned. QSTRING-form
  bucket names would be unusual; not handled.
- Multiple ``cert-key-chain`` blocks (one per client-ssl profile) are
  each walked independently.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


def discover_cert_keychains(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream globally, find every
    ``cert-key-chain { ... }`` shape, and intern each nested bucket
    bareword as ``Kind.CERT_KEY_CHAIN``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "cert_keychain_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        if not _starts_cert_key_chain(tokens, i):
            i += 1
            continue
        # Consume the ``cert-key-chain`` WORD and LBRACE, then walk
        # the body for bucket headers.
        i = _walk_cert_key_chain_body(tokens, i + 2, ledger)
    return


def _starts_cert_key_chain(tokens: list[Token], i: int) -> bool:
    if i + 1 >= len(tokens):
        return False
    return (
        tokens[i].kind == TokKind.WORD
        and tokens[i].value == "cert-key-chain"
        and tokens[i + 1].kind == TokKind.LBRACE
    )


def _walk_cert_key_chain_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk a ``cert-key-chain { ... }`` body from ``start`` (token
    immediately after the opening ``{``). At depth 1 inside the block,
    every bareword WORD followed by ``{`` is a bucket header —
    intern as ``Kind.CERT_KEY_CHAIN``. Returns the index just past
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
    """Intern a ``cert-key-chain`` bucket-name bareword as
    ``Kind.CERT_KEY_CHAIN`` with ``partition=None``. Empty or
    placeholder-shaped names are skipped."""
    if not name_tok.value:
        return
    if (Kind.CERT_KEY_CHAIN, name_tok.value) in ledger.by_original:
        return
    ref = Ref(
        byte_offset=name_tok.offset,
        length=name_tok.length,
        line=name_tok.line,
    )
    ledger.intern(
        Kind.CERT_KEY_CHAIN, name_tok.value, ref, partition=None,
    )
