"""Pass 1.7 — description body discovery.

Walks the token stream after pass-1 and pass-1.5 but before ledger
freeze, registering every ``description`` value as a ``Kind.DESC``
entry. Pass-2 substitution then redacts the body to its placeholder.

Supported forms (v0.0.4):

- ``description "quoted body"`` — QSTRING value. Most common in real
  configs. Full byte-exact round-trip.
- ``description bareword`` — single-WORD value. Full byte-exact
  round-trip.

Deferred to v0.0.5:

- ``description { braced body }`` — multi-line braced value. Today the
  body passes through verbatim and still surfaces in
  ``unredacted_description``; v0.0.5 will add per-reference whitespace
  metadata so inner-brace whitespace can round-trip byte-exactly. Real
  configs use the QSTRING form overwhelmingly, so this gap is small.

Dedup model: the ``original`` field stores the FULL token text including
its wrapping (so ``"primary node"`` for QSTRING form, ``primary`` for
bareword form). Different wrappings of the same substantive text yield
distinct placeholders, which lets the reverse path always restore the
exact original token byte-for-byte.

Empty bodies (``description ""``) are skipped — nothing to redact, and
no ``unredacted_description`` diagnostic fires for them.
"""

from __future__ import annotations

from .diagnostics import Diagnostics
from .ledger import Kind, Ledger, Ref
from .tokenizer import TokKind, tokenize


def discover_descriptions(
    src: str,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> None:
    """Pass 1.7 — walk ``src``, intern every ``description`` value into
    the ledger as ``Kind.DESC``. Must run before ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "description_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind != TokKind.WORD or tok.value != "description":
            i += 1
            continue
        if i + 1 >= len(tokens):
            break
        next_tok = tokens[i + 1]
        # QSTRING form: ``description "..."``
        if next_tok.kind == TokKind.QSTRING:
            content = next_tok.value[1:-1] if len(next_tok.value) >= 2 else ""
            if content:
                ref = Ref(
                    byte_offset=next_tok.offset,
                    length=next_tok.length,
                    line=next_tok.line,
                )
                ledger.intern(
                    Kind.DESC, next_tok.value, ref, partition=None,
                )
            i += 2
            continue
        # Bareword form: ``description value``
        if next_tok.kind == TokKind.WORD:
            ref = Ref(
                byte_offset=next_tok.offset,
                length=next_tok.length,
                line=next_tok.line,
            )
            ledger.intern(
                Kind.DESC, next_tok.value, ref, partition=None,
            )
            i += 2
            continue
        # Braced form deferred to v0.0.5 — leave the description for
        # pass-2 to surface as ``unredacted_description``.
        i += 1
