"""Pass 1.7 — description / caption / service-name body discovery.

Walks the token stream after pass-1 and pass-1.5 but before ledger
freeze, registering every value of a description-family field as a
``Kind.DESC`` entry. Pass-2 substitution then redacts the body to
its placeholder.

Description-family field names (v1.2.1):
- ``description`` (original, v0.0.10)
- ``caption`` (added v1.2, finding 13 — captions carry the same
  free-text disclosure risk as descriptions)
- ``service-name`` (added v1.2, finding 12c — referenced ACS service
  names that don't otherwise register elsewhere)
- ``claim-description`` / ``scope-description`` / ``claim-name`` /
  ``scope-name`` (added v1.2.1, red-team T1A — APM
  ``apm oauth oauth-claim`` / ``apm oauth oauth-scope`` nodes leaked
  third-party product names through their free-text description and
  name fields; over-redaction of generic OAuth names is acceptable
  since the fields are free-form by spec)

Supported forms:

- ``<field> "quoted body"`` — QSTRING value. Most common in real
  configs. Full byte-exact round-trip.
- ``<field> bareword`` — single-WORD value. Full byte-exact
  round-trip.
- ``<field> { braced body }`` — multi-line braced value. The full
  ``{...}`` span (including braces and inner whitespace) is stored as
  the entry's ``original``. Pass-2 emits ``"DESC_NNNN"`` (QSTRING form)
  in place; the reverse pass's qstring map restores the original
  braced span byte-exactly because the original IS the full
  braces-included text.

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


_DESC_FIELDS = frozenset({
    "description",
    "caption",
    "service-name",
    "claim-description",
    "scope-description",
    "claim-name",
    "scope-name",
})


def discover_descriptions(
    src: str,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> None:
    """Pass 1.7 — walk ``src``, intern every description-family
    field value into the ledger as ``Kind.DESC``. Must run before
    ``ledger.freeze()``."""
    if ledger.frozen:
        raise RuntimeError(
            "description_discovery must run before ledger.freeze()"
        )
    tokens = list(tokenize(src))
    _walk_descriptions(src, tokens, ledger)


def _walk_descriptions(src, tokens, ledger):
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind != TokKind.WORD or tok.value not in _DESC_FIELDS:
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
        # Braced form: ``description { ... }`` — walk to matching RBRACE
        # tracking brace depth, intern the full braced span (LBRACE
        # through RBRACE inclusive) including any internal whitespace.
        if next_tok.kind == TokKind.LBRACE:
            span_text = _collect_braced_span(src, tokens, i + 1)
            if span_text:
                ref = Ref(
                    byte_offset=next_tok.offset,
                    length=len(span_text),
                    line=next_tok.line,
                )
                ledger.intern(
                    Kind.DESC, span_text, ref, partition=None,
                )
            i += 1  # advance past description; the LBRACE/body/RBRACE
                    # are consumed by the substitute pass via its own
                    # walker (pass-1.7 just records what's there).
            continue
        i += 1


def _collect_braced_span(src, tokens, lbrace_idx) -> str:
    """Return the full ``{...}`` byte span starting at ``tokens[lbrace_idx]``
    (the LBRACE) through its matching RBRACE inclusive. Empty string if
    no matching RBRACE found (malformed input)."""
    if lbrace_idx >= len(tokens):
        return ""
    lbrace = tokens[lbrace_idx]
    if lbrace.kind != TokKind.LBRACE:
        return ""
    depth = 1
    j = lbrace_idx + 1
    while j < len(tokens) and depth > 0:
        t = tokens[j]
        if t.kind == TokKind.LBRACE:
            depth += 1
        elif t.kind == TokKind.RBRACE:
            depth -= 1
        if depth == 0:
            end_offset = t.offset + t.length
            return src[lbrace.offset:end_offset]
        j += 1
    return ""
