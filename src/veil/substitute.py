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

Member-port suffix handling
---------------------------
WORD tokens like ``/Common/10.0.0.1:80`` are handled via longest-prefix
match with non-word-character boundary detection. The matched prefix
becomes the substituted placeholder; the suffix (``:80``, ``.80``,
``%rd0`` etc.) is preserved. Forward and reverse substitution use
symmetric logic so the round-trip works cleanly.

Kind.UNKNOWN handling
---------------------
Top-level blocks whose module/subtype isn't in the recognised set
(profiles, GTM, ASM, DG, etc.) get their header path registered as
``Kind.UNKNOWN`` so pass-2 substitutes it — without this, an unknown
block's header path (e.g. ``gtm pool /Common/<node>_servers``) would
leak any registered LTM identifier whose path is a prefix of it.
``Kind.UNKNOWN`` is best-effort: a UNK path can still leak via
substring inside a longer non-header bareword in another block's body
(no current diagnostic catches that), or via QSTRING contents
(flagged by ``qstring_contains_identifier``). The safety-critical
kinds (POOL/VS/NODE/MON/IRULE) do not have this caveat — their
substitution is strictly enforced.

Known gaps deferred to follow-up PRs (each surfaces as a Diagnostics
entry where applicable so callers can fail closed):
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
- Substring-in-bareword leaks for ``Kind.UNKNOWN`` paths. When a UNK
  header path is a substring of a longer non-header bareword reference
  elsewhere (with word-character boundary), prefix-match correctly
  rejects but the literal UNK path appears as substring. Closing this
  requires either tokenizer-level path detection or a substring
  diagnostic — deferred.
"""

from __future__ import annotations

from .diagnostics import Diagnostics
from .ledger import Kind, Ledger, LedgerEntry, Ref
from .tokenizer import Token, TokKind, tokenize

# Characters considered "word characters" — a prefix-match WORD token is
# rejected if the character at the boundary position falls in this set,
# so e.g. ``/Common/web`` is NOT a prefix of ``/Common/web_pool`` (word
# boundary failure) but IS a prefix of ``/Common/web:80`` (non-word ':').
# This covers both IPv4 ``:port`` and IPv6 ``.port`` / ``%route-domain``
# suffixes — anything not in this set qualifies as a boundary.
_WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)


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
        # Description handling: substitute body with DESC_NNNN placeholder
        # (QSTRING / bareword forms). Braced form deferred to v0.0.5.
        if tok.kind == TokKind.WORD and tok.value == "description":
            consumed = _emit_description(
                tokens, i, src, out, ledger, diagnostics,
            )
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
        # 1. Exact match — fast path for ordinary identifiers.
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
        # 2. Longest-prefix match with non-word boundary — covers
        # member-port suffix tokens like ``/Common/10.0.0.1:80`` and
        # IPv6 ``/Common/2001:db8::1.80`` / route-domain ``%rd0`` forms.
        # Without this, those leak the literal path via substring.
        prefix_hit = _find_longest_prefix_match(tok.value, ledger)
        if prefix_hit is not None:
            entry, prefix_len = prefix_hit
            ledger.record_reference(
                entry.placeholder,
                Ref(byte_offset=tok.offset, length=prefix_len, line=tok.line),
            )
            return (
                _render_placeholder(entry, ledger, tok) + tok.value[prefix_len:]
            )
        return tok.value
    if tok.kind == TokKind.QSTRING:
        _check_qstring_for_identifier(tok, ledger, diagnostics)
        return tok.value
    # LBRACE, RBRACE, COMMENT pass through verbatim.
    return tok.value


def _find_longest_prefix_match(
    value: str, ledger: Ledger
) -> tuple[LedgerEntry, int] | None:
    """Find the longest ledger original that is a strict prefix of
    ``value`` followed by a non-word-character boundary. Returns
    ``(entry, prefix_len)`` or ``None`` if no candidate matches."""
    best_entry: LedgerEntry | None = None
    best_len = 0
    value_len = len(value)
    for (_kind, original), placeholder in ledger.by_original.items():
        original_len = len(original)
        if original_len >= value_len or original_len <= best_len:
            continue
        if not value.startswith(original):
            continue
        if value[original_len] in _WORD_CHARS:
            continue
        best_entry = ledger.entries[placeholder]
        best_len = original_len
    if best_entry is None:
        return None
    return best_entry, best_len


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
    ledger: Ledger,
    diagnostics: Diagnostics,
) -> int:
    """Emit the ``description`` keyword and substitute its value with a
    ``DESC_NNNN`` placeholder. QSTRING and bareword forms are redacted
    in place; braced form falls back to verbatim emit + the legacy
    ``unredacted_description`` diagnostic (deferred to v0.0.5).

    Returns total tokens consumed (including the description keyword).
    """
    desc_tok = tokens[i]
    out.append(desc_tok.value)
    if i + 1 >= len(tokens):
        return 1
    next_tok = tokens[i + 1]
    out.append(src[desc_tok.offset + desc_tok.length : next_tok.offset])
    if next_tok.kind == TokKind.QSTRING:
        placeholder = ledger.by_original.get((Kind.DESC, next_tok.value))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=next_tok.offset,
                    length=next_tok.length,
                    line=next_tok.line,
                ),
            )
            out.append(f'"{entry.placeholder}"')
        else:
            # Empty body or otherwise not interned — leave verbatim. No
            # leak (empty body has nothing to redact) and no diagnostic.
            out.append(next_tok.value)
        return 2
    if next_tok.kind == TokKind.LBRACE:
        # Braced form — deferred to v0.0.5. Keep legacy verbatim emit
        # and surface ``unredacted_description`` so callers still
        # fail-closed on non-empty braced descriptions.
        diagnostics.unredacted_description.append(
            (desc_tok.offset, desc_tok.line)
        )
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
        placeholder = ledger.by_original.get((Kind.DESC, next_tok.value))
        if placeholder is not None:
            entry = ledger.entries[placeholder]
            ledger.record_reference(
                placeholder,
                Ref(
                    byte_offset=next_tok.offset,
                    length=next_tok.length,
                    line=next_tok.line,
                ),
            )
            out.append(entry.placeholder)
        else:
            out.append(next_tok.value)
        return 2
    return 1


def _check_orphan_entries(ledger: Ledger, diagnostics: Diagnostics) -> None:
    for placeholder, entry in ledger.entries.items():
        if not entry.references:
            diagnostics.orphan_entries.append(placeholder)


# ---------------------------------------------------------------------
# Reverse substitution (deobfuscation)
# ---------------------------------------------------------------------


def reverse_substitute(sanitized: str, ledger: Ledger) -> str:
    """Inverse of :func:`substitute`. Replaces rendered placeholders in
    ``sanitized`` with their original values from the (frozen) ledger.

    Walks the sanitized source as a token stream and replaces any WORD
    token whose value matches a rendered-placeholder key in the reverse
    map. Inter-token whitespace is preserved via cursor-tracking, so the
    output is byte-faithful to the sanitized input modulo the placeholder
    swap-outs.

    Tokens that don't match the reverse map pass through verbatim — this
    is how the AI's newly-introduced content (e.g. new iRule code) is
    preserved while still restoring any placeholder it referenced.

    Matching is symmetric with :func:`substitute`: exact match first,
    then longest-prefix match with non-word boundary, so port-suffix
    tokens like ``/Common/NODE_0001:80`` round-trip back to
    ``/Common/10.0.0.1:80`` cleanly.
    """
    reverse_map = _build_reverse_map(ledger)
    qstring_reverse_map = _build_qstring_reverse_map(ledger)
    tokens = list(tokenize(sanitized))
    out: list[str] = []
    cursor = 0
    for tok in tokens:
        if tok.offset > cursor:
            out.append(sanitized[cursor:tok.offset])
        if tok.kind == TokKind.WORD:
            if tok.value in reverse_map:
                out.append(reverse_map[tok.value])
            else:
                hit = _find_longest_reverse_prefix(tok.value, reverse_map)
                if hit is not None:
                    prefix_len, original = hit
                    out.append(original + tok.value[prefix_len:])
                else:
                    out.append(tok.value)
        elif tok.kind == TokKind.QSTRING:
            # DESC_NNNN placeholders inside QSTRINGs (description bodies
            # in QSTRING form). Key includes the quotes; the value is
            # the original QSTRING token (also quoted), so the wrapping
            # restores byte-exactly.
            if tok.value in qstring_reverse_map:
                out.append(qstring_reverse_map[tok.value])
            else:
                out.append(tok.value)
        else:
            out.append(tok.value)
        cursor = tok.offset + tok.length
    if cursor < len(sanitized):
        out.append(sanitized[cursor:])
    return "".join(out)


def _find_longest_reverse_prefix(
    value: str, reverse_map: dict[str, str]
) -> tuple[int, str] | None:
    """Symmetric counterpart to :func:`_find_longest_prefix_match` that
    walks the rendered-placeholder map instead of the ledger."""
    best_len = 0
    best_original: str | None = None
    value_len = len(value)
    for placeholder, original in reverse_map.items():
        placeholder_len = len(placeholder)
        if placeholder_len >= value_len or placeholder_len <= best_len:
            continue
        if not value.startswith(placeholder):
            continue
        if value[placeholder_len] in _WORD_CHARS:
            continue
        best_len = placeholder_len
        best_original = original
    if best_original is None:
        return None
    return best_len, best_original


def _build_qstring_reverse_map(ledger: Ledger) -> dict[str, str]:
    """Map quoted-placeholder QSTRING values back to their original
    quoted form, for description redaction in QSTRING form.

    Key: the quoted placeholder as it appears in the sanitized output
    (e.g. ``'"DESC_0001"'``).
    Value: the original quoted QSTRING (e.g. ``'"primary cluster"'``).

    DESC entries whose ``original`` does not begin with ``"`` are
    bareword form and handled by the standard WORD reverse map; skip
    them here."""
    rmap: dict[str, str] = {}
    for entry in ledger.entries.values():
        if entry.kind != Kind.DESC:
            continue
        if not entry.original.startswith('"'):
            continue
        rmap[f'"{entry.placeholder}"'] = entry.original
    return rmap


def _build_reverse_map(ledger: Ledger) -> dict[str, str]:
    """Build the rendered-placeholder -> original lookup table.

    Keys are the string forms that pass-2 substitution actually emits:
    bare ``PARTITION_NNNN`` for partition references, ``/Common/POOL_NNNN``
    for Common-partition objects, ``/PARTITION_NNNN/POOL_NNNN`` for
    non-Common objects, and bare ``POOL_NNNN`` for entries with no
    partition. Same partition-invariant guard as the forward path:
    if a non-Common object's partition has no ``PARTITION_NNNN`` entry,
    refuse — the ledger is inconsistent and deobfuscation would either
    fail silently or leak the literal partition name.
    """
    rmap: dict[str, str] = {}
    for entry in ledger.entries.values():
        # QSTRING-form DESC entries are routed through the qstring
        # reverse map; skip here to avoid spurious WORD-level matches.
        if entry.kind == Kind.DESC and entry.original.startswith('"'):
            continue
        if entry.kind == Kind.PARTITION:
            rmap[entry.placeholder] = entry.original
        elif entry.partition is None:
            rmap[entry.placeholder] = entry.original
        elif entry.partition == "Common":
            rmap[f"/Common/{entry.placeholder}"] = entry.original
        else:
            part_ph = ledger.by_original.get((Kind.PARTITION, entry.partition))
            if part_ph is None:
                raise RuntimeError(
                    f"ledger invariant violated during deobfuscation: "
                    f"object {entry.placeholder} references partition "
                    f"{entry.partition!r} which has no PARTITION entry."
                )
            rmap[f"/{part_ph}/{entry.placeholder}"] = entry.original
    return rmap
