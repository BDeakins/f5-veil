"""Pass 1.85i — LDAP filter walker.

``filter`` is a generic field name that appears in many TMSH
contexts. Inside LDAP-flavoured blocks it carries an LDAP filter
expression that frequently embeds usernames or other
customer-identifying content. Outside LDAP context the field has
non-sensitive uses (PEM analytics, etc.).

This walker context-gates: it finds top-level blocks whose
two/three-word header matches an LDAP allowlist, walks the body
(any nested depth), and interns each ``filter <VALUE>`` pair as
``Kind.LDAP_FILTER``. Filter values are treated as opaque (whole
value, no parsing) — LDAP filter syntax is too varied to redact
piecewise safely.

Allowlist of parent block headers
---------------------------------
- ``apm aaa ldap``
- ``apm aaa active-directory``
- ``auth ldap``
- ``auth active-directory``
- ``ltm monitor ldap``

Each is a known two- or three-word top-level block header followed
by a ``/Common/<name>`` path and an LBRACE.

Scope (v1.2)
------------
- Only WORD-shaped or QSTRING-shaped values are interned.
- Empty values are skipped.
- Multiple LDAP blocks in the source are walked independently.
- Inside an LDAP block, ``filter`` field can appear at any depth
  (real configs typically have it at depth 1 inside the block body,
  but the walker scans the whole body to be robust).
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import Token, TokKind, tokenize


_LDAP_HEADERS = (
    # (length, words) — match left-anchored at depth 0.
    (3, ("apm", "aaa", "ldap")),
    (3, ("apm", "aaa", "active-directory")),
    (2, ("auth", "ldap")),
    (2, ("auth", "active-directory")),
    (3, ("ltm", "monitor", "ldap")),
)


def discover_ldap_filters(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — symmetry with sibling passes
) -> None:
    """Walk the token stream, find every LDAP-flavoured top-level
    block, descend into its body, and intern each ``filter <value>``
    pair as ``Kind.LDAP_FILTER``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "ldap_filter_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    n = len(tokens)
    i = 0
    while i < n:
        consumed = _try_match_ldap_header(tokens, i)
        if consumed > 0:
            # consumed = number of WORD tokens in header (2 or 3).
            # After the header, expect ``/Common/<name>`` WORD + LBRACE
            # (or directly LBRACE for some unparented forms — be
            # defensive). Skip forward to the LBRACE.
            j = i + consumed
            while j < n and tokens[j].kind == TokKind.WORD:
                j += 1
            if j < n and tokens[j].kind == TokKind.LBRACE:
                i = _walk_ldap_block_body(tokens, j + 1, ledger)
                continue
        i += 1
    return


def _try_match_ldap_header(tokens: list[Token], i: int) -> int:
    """Return the number of WORD tokens consumed if ``tokens[i:]``
    matches an LDAP-flavoured block header, else 0."""
    for length, words in _LDAP_HEADERS:
        if i + length > len(tokens):
            continue
        ok = True
        for k, w in enumerate(words):
            t = tokens[i + k]
            if t.kind != TokKind.WORD or t.value != w:
                ok = False
                break
        if ok:
            return length
    return 0


def _walk_ldap_block_body(
    tokens: list[Token],
    start: int,
    ledger: Ledger,
) -> int:
    """Walk an LDAP-block body from ``start`` (token immediately
    after the opening ``{``). At any depth >= 1, find
    ``filter <value>`` pairs and intern the value as
    ``Kind.LDAP_FILTER``. Returns the index just past the matching
    RBRACE that closes the outer block (depth 0)."""
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
            tk.kind == TokKind.WORD
            and tk.value == "filter"
            and i + 1 < n
        ):
            _intern_filter_value(tokens[i + 1], ledger)
            i += 2
            continue
        i += 1
    return i


def _intern_filter_value(value_tok: Token, ledger: Ledger) -> None:
    """Intern an LDAP filter value (QSTRING or WORD) as
    ``Kind.LDAP_FILTER`` with ``partition=None``. Empty values
    skipped. QSTRING quotes stripped."""
    if value_tok.kind == TokKind.QSTRING:
        if len(value_tok.value) < 2:
            return
        content = value_tok.value[1:-1]
        if not content:
            return
        if (Kind.LDAP_FILTER, content) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset + 1,
            length=len(content),
            line=value_tok.line,
        )
        ledger.intern(Kind.LDAP_FILTER, content, ref, partition=None)
        return
    if value_tok.kind == TokKind.WORD:
        v = value_tok.value
        if not v:
            return
        if (Kind.LDAP_FILTER, v) in ledger.by_original:
            return
        ref = Ref(
            byte_offset=value_tok.offset,
            length=value_tok.length,
            line=value_tok.line,
        )
        ledger.intern(Kind.LDAP_FILTER, v, ref, partition=None)
