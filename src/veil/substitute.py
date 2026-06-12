"""bigip.conf pass-2 substitution — rewrite the source with placeholders.

Walks the token stream from :func:`veil.tokenizer.tokenize` and emits a
new string in which every WORD token whose value matches a ledger entry
is replaced with the entry's rendered placeholder. Inter-token whitespace
and comments are preserved byte-for-byte by copying gaps directly from
the source.

Path-piece rendering (locked architecture):
- ``/Common/foo_pool`` -> ``/Common/POOL_0001`` — the ``/Common/`` literal
  is preserved as universal BIG-IP signal.
- ``/Tenant_A/foo_pool`` -> ``/PARTITION_0001/POOL_0001`` — the partition
  itself is also placeholdered.

Known gaps deferred to follow-up PRs (each surfaces as a Diagnostics
entry so callers can fail closed):
- QSTRING content substitution. ``"foo /Common/bar baz"`` containing a
  ledger original surfaces ``qstring_contains_identifier`` but the
  string body is emitted verbatim.
- ``description "..."`` and ``description { ... }`` values pass through
  verbatim and surface in ``unredacted_description``. DESC_NNNN minting
  is deferred to a dedicated 'pass 1.5: free-text discovery' PR.
- Folder-nested object paths (``/Common/folder/sub/leaf``) collapse the
  folder into the leaf placeholder; folder semantics are not preserved.
- Tcl-lexer-aware iRule body substitution. Bare path-shaped barewords
  inside rule bodies are substituted normally; paths embedded in Tcl
  strings only surface as ``qstring_contains_identifier``.
- Tcl ``#`` comments inside iRule bodies are emitted verbatim with no
  diagnostic. The locked architecture says these need redaction (same
  posture as ``description``); deferred to the iRule-Tcl-lexer PR which
  must add brace-depth + rule-body tracking.
- Unterminated QSTRINGs (source has an opening quote with no close)
  scan to EOF; the qstring-contains-identifier check still runs on the
  EOF-truncated content. Edge case, deferred.
"""

from __future__ import annotations

from .diagnostics import Diagnostics
from .ledger import Kind, Ledger, LedgerEntry, Ref
from .tokenizer import Token, TokKind, tokenize


def substitute(
    src: str,
    ledger: Ledger,
    diagnostics: Diagnostics | None = None,
) -> tuple[str, Diagnostics]:
    """Pass 2: render the sanitized source from the source + ledger.

    Freezes the ledger if it isn't already (idempotent). Returns
    ``(sanitized_text, diagnostics)``. The returned diagnostics carries
    forward any pass-1 entries plus pass-2 findings (descriptions,
    qstring-embedded identifiers, orphan ledger entries).
    """
    if not ledger.frozen:
        ledger.freeze()
    if diagnostics is None:
        diagnostics = Diagnostics()
    tokens = list(tokenize(src))
    out: list[str] = []
    cursor = 0
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.offset > cursor:
            out.append(src[cursor:tok.offset])
        # Description handling: emit value verbatim, log diagnostic.
        if tok.kind == TokKind.WORD and tok.value == "description":
            consumed = _emit_description(tokens, i, src, out, diagnostics)
            last = tokens[i + consumed - 1]
            cursor = last.offset + last.length
            i += consumed
            continue
        out.append(_emit_token(tok, ledger, diagnostics))
        cursor = tok.offset + tok.length
        i += 1
    if cursor < len(src):
        out.append(src[cursor:])
    _check_orphan_entries(ledger, diagnostics)
    return "".join(out), diagnostics


def _emit_token(tok: Token, ledger: Ledger, diagnostics: Diagnostics) -> str:
    if tok.kind == TokKind.WORD:
        # A bareword can match at most one (kind, value) pair because
        # by_original is keyed on both, but the kind of an in-body
        # bareword isn't known up-front — scan all kinds.
        for kind in Kind:
            placeholder = ledger.by_original.get((kind, tok.value))
            if placeholder is None:
                continue
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(byte_offset=tok.offset, length=tok.length, line=tok.line),
            )
            return _render_placeholder(entry, ledger, tok)
        return tok.value
    if tok.kind == TokKind.QSTRING:
        _check_qstring_for_identifier(tok, ledger, diagnostics)
        return tok.value
    # LBRACE, RBRACE, COMMENT pass through verbatim.
    return tok.value


def _render_placeholder(entry: LedgerEntry, ledger: Ledger, tok: Token) -> str:
    leaf = entry.placeholder
    if entry.partition is None:
        return leaf
    if entry.partition == "Common":
        return f"/Common/{leaf}"
    part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
    if part_ph is None:
        # Pass 1 must register a non-Common partition before any object
        # inside it. If we get here, the ledger is inconsistent — refuse
        # to fall back to the literal partition name (which would leak
        # the customer's tenant label). Loud crash > silent leak.
        raise RuntimeError(
            f"ledger invariant violated: object {entry.placeholder} "
            f"references partition {entry.partition!r} which has no "
            f"PARTITION entry. Refusing to emit literal partition name "
            f"into sanitized output."
        )
    ledger.record_reference(
        part_ph,
        Ref(
            byte_offset=tok.offset + 1,
            length=len(entry.partition),
            line=tok.line,
        ),
    )
    return f"/{part_ph}/{leaf}"


def _check_qstring_for_identifier(
    tok: Token,
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> None:
    if len(tok.value) < 2:
        return
    content = tok.value[1:-1]
    if not content:
        return
    for (kind, original), placeholder in ledger.by_original.items():
        if original in content:
            diagnostics.qstring_contains_identifier.append(
                (placeholder, tok.offset, tok.line)
            )


def _emit_description(
    tokens: list[Token],
    i: int,
    src: str,
    out: list[str],
    diagnostics: Diagnostics,
) -> int:
    """Emit the ``description`` keyword and its value verbatim. Logs an
    unredacted_description diagnostic. Returns total tokens consumed
    (including the description keyword)."""
    desc_tok = tokens[i]
    diagnostics.unredacted_description.append((desc_tok.offset, desc_tok.line))
    out.append(desc_tok.value)
    if i + 1 >= len(tokens):
        return 1
    next_tok = tokens[i + 1]
    out.append(src[desc_tok.offset + desc_tok.length : next_tok.offset])
    if next_tok.kind == TokKind.QSTRING:
        out.append(next_tok.value)
        return 2
    if next_tok.kind == TokKind.LBRACE:
        # description { brace-quoted body } — emit through matching RBRACE
        # without invoking _emit_token, so no ledger substitution happens
        # inside the description body.
        out.append(next_tok.value)
        depth = 1
        j = i + 2
        prev_end = next_tok.offset + next_tok.length
        while j < len(tokens) and depth > 0:
            t = tokens[j]
            if t.offset > prev_end:
                out.append(src[prev_end:t.offset])
            out.append(t.value)
            if t.kind == TokKind.LBRACE:
                depth += 1
            elif t.kind == TokKind.RBRACE:
                depth -= 1
            prev_end = t.offset + t.length
            j += 1
        return j - i
    if next_tok.kind == TokKind.WORD:
        # description <bareword> — single-word description; emit verbatim
        # rather than risk substituting a path-shaped value inside a
        # description we're already passing through.
        out.append(next_tok.value)
        return 2
    return 1


def _check_orphan_entries(ledger: Ledger, diagnostics: Diagnostics) -> None:
    for placeholder, entry in ledger.entries.items():
        if not entry.references:
            diagnostics.orphan_entries.append(placeholder)
