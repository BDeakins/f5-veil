"""Pass 1.8 — Tcl ``#`` comment discovery inside iRule bodies.

Walks the token stream after pass-1 / pass-1.5 / pass-1.7 but before
ledger freeze, registering every COMMENT token whose textual position
falls inside an ``ltm rule /path { ... }`` body as
``Kind.IRULE_COMMENT``. Pass-2 substitution then emits the placeholder
in ``# IRULE_COMMENT_NNNN`` form.

Scope (locked v0.0.11):

- ONLY ``ltm rule`` bodies. iRule-shaped content embedded in data-groups,
  policies, or external monitor scripts is out of scope and emits
  verbatim.
- COMMENT tokens at TMSH top level (``#TMSH-VERSION:`` etc.) are
  intentionally NOT discovered — they are universal BIG-IP signal, not
  customer-identifying.
- Dedup model: ``original`` stores the full COMMENT token text including
  the leading ``#`` (tokenizer captures ``#`` through end-of-line,
  trailing newline excluded). Identical comment lines inside one or more
  iRule bodies share a placeholder.

Round-trip
----------
Pass-2 emits ``# IRULE_COMMENT_NNNN`` as the substituted COMMENT token
value; the tokenizer re-tokenizes the sanitized output back to a single
COMMENT token whose value is that placeholder, which the reverse pass
maps back to the original via :data:`Ledger.entries`.

Tcl line-continuation (``# foo \\<newline> bar``) is NOT folded — the
tokenizer breaks the logical comment into two physical tokens and each
gets its own placeholder. Real iRules use this pattern rarely; folding
is a v0.0.12+ refinement.
"""

from __future__ import annotations

from .ledger import Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize


def discover_irule_comments(
    src: str,
    ledger: Ledger,
    diagnostics=None,  # noqa: ARG001 — kept for symmetry with sibling discovery passes
) -> None:
    """Pass 1.8 — walk ``src``, intern every COMMENT token inside an
    ``ltm rule`` body as ``Kind.IRULE_COMMENT``. Must run before
    ``ledger.freeze()``.

    ``diagnostics`` is accepted for signature symmetry with the other
    discovery passes; this pass has no current failure modes that warrant
    a diagnostic field (un-discovered iRule comments simply pass through
    verbatim and any customer-identifying content they carry would be
    flagged by the post-substitution leak detector)."""
    if ledger.frozen:
        raise RuntimeError(
            "irule_comment_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    _walk_irule_comments(tokens, ledger)


def _walk_irule_comments(tokens, ledger) -> None:
    """State machine: track brace depth + 'inside iRule body' flag.

    We enter an iRule body when we see the three-token sequence
    ``ltm rule <path> {`` at the top level (depth 0 before the LBRACE).
    We exit when brace depth drops back to the depth at which we entered
    (i.e. the depth just before the rule's opening LBRACE)."""
    depth = 0
    rule_entry_depth: int | None = None  # depth BEFORE rule's opening LBRACE
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        # ---- detect entry into an iRule body (only at top level) ----
        if (
            rule_entry_depth is None
            and depth == 0
            and tok.kind == TokKind.WORD
            and tok.value == "ltm"
            and i + 3 < n
            and tokens[i + 1].kind == TokKind.WORD
            and tokens[i + 1].value == "rule"
            and tokens[i + 2].kind == TokKind.WORD
            and tokens[i + 3].kind == TokKind.LBRACE
        ):
            # Consume ``ltm rule <path>`` (3 tokens) and the LBRACE (1).
            # Record depth at which we entered so we know when to exit.
            rule_entry_depth = depth
            depth += 1  # entered the rule body
            i += 4
            continue
        # ---- exit / depth tracking ----
        if tok.kind == TokKind.LBRACE:
            depth += 1
            i += 1
            continue
        if tok.kind == TokKind.RBRACE:
            depth -= 1
            if rule_entry_depth is not None and depth == rule_entry_depth:
                rule_entry_depth = None
            i += 1
            continue
        # ---- comment interning inside iRule body ----
        if rule_entry_depth is not None and tok.kind == TokKind.COMMENT:
            ref = Ref(
                byte_offset=tok.offset,
                length=tok.length,
                line=tok.line,
            )
            ledger.intern(
                Kind.IRULE_COMMENT, tok.value, ref, partition=None,
            )
        i += 1
